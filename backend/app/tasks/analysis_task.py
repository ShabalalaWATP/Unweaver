"""
Background analysis task for Unweaver.

Manages the lifecycle of a single sample's deobfuscation analysis:
  1. Creates an Orchestrator with the sample code.
  2. Runs the full iterative analysis loop via orchestrator.run().
  3. Persists results (recovered text, strings, IOCs, findings, transforms)
     to the database.
  4. Tracks progress in an in-memory dict for polling by the status endpoint.
  5. Supports cancellation via a flag.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session
from app.models.db_models import (
    FindingRecord,
    IOCRecord,
    IterationState,
    Sample,
    StringRecord,
    TransformHistory,
)
from app.models.schemas import SampleStatus

logger = logging.getLogger(__name__)

# -- In-memory analysis tracker --
# Maps sample_id -> status dict
_running_analyses: Dict[str, Dict[str, Any]] = {}


def get_analysis_status(sample_id: str) -> Dict[str, Any] | None:
    """Return the current in-memory status for a running analysis, or None."""
    return _running_analyses.get(sample_id)


def request_stop(sample_id: str) -> bool:
    """Request cancellation of a running analysis."""
    status = _running_analyses.get(sample_id)
    if status is None:
        return False
    status["stop_requested"] = True
    return True


def is_running(sample_id: str) -> bool:
    """Check whether an analysis is currently in progress."""
    status = _running_analyses.get(sample_id)
    return status is not None and status.get("status") == "running"


async def run_analysis(sample_id: str) -> None:
    """Run the full analysis pipeline for a sample.

    Designed to be called as a FastAPI BackgroundTask.
    Manages its own database session and error handling.
    """
    _running_analyses[sample_id] = {
        "status": "running",
        "current_iteration": 0,
        "total_iterations": settings.MAX_ITERATIONS,
        "current_action": "initialising",
        "progress_pct": 0.0,
        "stop_requested": False,
        "error": None,
    }

    try:
        async with async_session() as db:
            await _run_analysis_inner(db, sample_id)
    except Exception as exc:
        logger.exception("Analysis failed for sample %s", sample_id)
        _running_analyses[sample_id]["status"] = "failed"
        _running_analyses[sample_id]["error"] = str(exc)
        try:
            async with async_session() as db:
                sample = await db.get(Sample, sample_id)
                if sample:
                    sample.status = SampleStatus.FAILED.value
                    await db.commit()
        except Exception:
            logger.exception("Failed to mark sample %s as failed in DB", sample_id)
    finally:
        tracker = _running_analyses.get(sample_id)
        if tracker and tracker["status"] == "running":
            tracker["status"] = "completed"


async def _run_analysis_inner(db: AsyncSession, sample_id: str) -> None:
    """Core analysis logic, run inside a managed session."""

    tracker = _running_analyses[sample_id]

    # Load sample — verify it still exists.
    sample = await db.get(Sample, sample_id)
    if sample is None:
        tracker["status"] = "failed"
        tracker["error"] = "Sample not found"
        return

    if not sample.original_text:
        tracker["status"] = "failed"
        tracker["error"] = "Sample has no code to analyse"
        sample.status = SampleStatus.FAILED.value
        await _safe_commit(db, "mark empty sample as failed")
        return

    sample.status = SampleStatus.RUNNING.value
    await _safe_commit(db, "mark sample as running")

    from app.services.analysis.orchestrator import Orchestrator

    tracker["current_action"] = "loading LLM provider"

    # Try to load the active LLM provider for intelligent analysis.
    llm_client = await _load_llm_client(db)

    tracker["current_action"] = "starting orchestrator"

    orchestrator = Orchestrator(
        sample_id=sample_id,
        original_code=sample.original_text,
        language=sample.language,
        db_session=db,
        llm_client=llm_client,
    )

    # Run the full multi-pass analysis loop.
    result = await orchestrator.run(
        auto_approve_threshold=settings.AUTO_APPROVE_THRESHOLD,
        min_confidence=settings.MIN_CONFIDENCE_THRESHOLD,
        max_iterations=settings.MAX_ITERATIONS,
        stall_limit=settings.STALL_THRESHOLD,
    )

    tracker["current_iteration"] = result.iterations
    tracker["progress_pct"] = 100.0
    tracker["current_action"] = f"completed: {result.stop_reason}"

    # ── Persist results in isolated batches ─────────────────────────
    # Re-fetch sample in case the session state drifted during the long
    # orchestration run.
    sample = await db.get(Sample, sample_id)
    if sample is None:
        tracker["status"] = "failed"
        tracker["error"] = "Sample was deleted during analysis"
        return

    sample.recovered_text = result.deobfuscated_code
    sample.language = result.language or sample.language
    sample.status = SampleStatus.COMPLETED.value
    await _safe_commit(db, "persist recovered text and status")

    # Transform history
    for tr in result.transform_history:
        try:
            db.add(TransformHistory(
                sample_id=sample_id,
                iteration=tr.iteration,
                action=tr.action,
                reason=tr.reason,
                inputs=tr.inputs,
                outputs=tr.outputs,
                confidence_before=tr.confidence_before,
                confidence_after=tr.confidence_after,
                readability_before=tr.readability_before,
                readability_after=tr.readability_after,
                success=tr.success,
                retry_revert=tr.retry_revert,
            ))
        except Exception:
            logger.exception("Failed to add transform record for iteration %d", tr.iteration)
    await _safe_commit(db, "persist transform history")

    # Strings
    for s in result.strings:
        try:
            db.add(StringRecord(
                sample_id=sample_id,
                value=(s.value or "")[:10_000],
                encoding=s.encoding,
                offset=s.offset,
                context=(s.context or "")[:500],
                decoded=s.decoded,
            ))
        except Exception:
            logger.exception("Failed to add string record")
    await _safe_commit(db, "persist strings")

    # Findings
    for f in result.findings:
        try:
            severity_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            db.add(FindingRecord(
                sample_id=sample_id,
                title=(f.title or "")[:500],
                severity=severity_val,
                description=(f.description or "")[:5000],
                evidence=(f.evidence or "")[:5000],
                confidence=f.confidence,
            ))
        except Exception:
            logger.exception("Failed to add finding record")
    await _safe_commit(db, "persist findings")

    # IOCs
    for ioc in result.iocs:
        try:
            ioc_type_val = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
            db.add(IOCRecord(
                sample_id=sample_id,
                ioc_type=ioc_type_val,
                value=(ioc.value or "")[:2000],
                context=(ioc.context or "")[:500],
                confidence=ioc.confidence,
            ))
        except Exception:
            logger.exception("Failed to add IOC record")
    await _safe_commit(db, "persist IOCs")

    # Final iteration state
    if result.state:
        try:
            db.add(IterationState(
                sample_id=sample_id,
                iteration_number=result.iterations,
                state_json=result.state.model_dump_json(),
            ))
            await _safe_commit(db, "persist final iteration state")
        except Exception:
            logger.exception("Failed to persist final iteration state")

    tracker["status"] = "completed"
    tracker["current_action"] = "analysis complete"


async def _load_llm_client(db: AsyncSession):
    """Try to load the active LLM provider and return an LLMClient.

    Returns None if no provider is configured or loading fails.
    Never raises.
    """
    try:
        from sqlalchemy import select
        from app.models.db_models import ProviderConfig
        from app.services.llm.client import LLMClient, _MAX_TOKENS_MAP

        result = await db.execute(
            select(ProviderConfig)
            .where(ProviderConfig.is_active == True)  # noqa: E712
            .order_by(ProviderConfig.created_at.desc())
            .limit(1)
        )
        provider = result.scalar_one_or_none()

        if provider is None:
            # No active provider — fall back to any provider.
            result = await db.execute(
                select(ProviderConfig)
                .order_by(ProviderConfig.created_at.desc())
                .limit(1)
            )
            provider = result.scalar_one_or_none()

        if provider is None:
            logger.info("No LLM provider configured; running in deterministic mode")
            return None

        max_tokens = _MAX_TOKENS_MAP.get(provider.max_tokens_preset, 4096)
        client = LLMClient(
            base_url=provider.base_url,
            api_key=provider.api_key_encrypted,
            model=provider.model_name,
            max_tokens=max_tokens,
            cert_bundle=provider.cert_bundle_path,
            use_system_trust=provider.use_system_trust,
        )
        logger.info(
            "Loaded LLM provider '%s' (model=%s) for analysis",
            provider.name,
            provider.model_name,
        )
        return client
    except Exception:
        logger.exception("Failed to load LLM provider; continuing without LLM")
        return None


async def _safe_commit(db: AsyncSession, context: str) -> bool:
    """Commit the current transaction, rolling back on failure.

    Returns True on success, False on failure.  Never raises.
    """
    try:
        await db.commit()
        return True
    except Exception:
        logger.exception("DB commit failed (%s); rolling back", context)
        try:
            await db.rollback()
        except Exception:
            logger.exception("DB rollback also failed (%s)", context)
        return False
