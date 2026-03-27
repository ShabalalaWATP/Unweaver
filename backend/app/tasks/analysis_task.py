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
from pathlib import Path
from typing import Any, Dict

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt_value
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
from app.services.reports.saved_analysis import persist_saved_analysis_snapshot
from app.services.analysis.state_manager import build_state_snapshot_payload

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


def is_active(sample_id: str) -> bool:
    """Check whether an analysis is queued or currently running."""
    status = _running_analyses.get(sample_id)
    return status is not None and status.get("status") in {"pending", "running"}


def queue_analysis(sample_id: str, total_iterations: int) -> None:
    """Seed tracker state before the background task starts running."""
    _running_analyses[sample_id] = {
        "status": "pending",
        "current_iteration": 0,
        "total_iterations": total_iterations,
        "current_action": "queued",
        "progress_pct": 0.0,
        "stop_requested": False,
        "error": None,
    }


def clear_tracker(sample_id: str) -> None:
    """Remove the in-memory tracker for a sample (cleanup after stale state)."""
    _running_analyses.pop(sample_id, None)


def emit_event(sample_id: str, event_type: str, data: dict | None = None) -> None:
    """Push a typed event into the tracker's event queue for WebSocket consumers.

    Event types: ``classification``, ``transform_start``, ``transform_end``,
    ``reflection``, ``planning``, ``confidence_update``, ``error``.
    Events are append-only; the WebSocket handler drains them on each tick.
    """
    tracker = _running_analyses.get(sample_id)
    if tracker is None:
        return
    events = tracker.setdefault("events", [])
    events.append({"event": event_type, **(data or {})})


async def run_analysis(sample_id: str) -> None:
    """Run the full analysis pipeline for a sample.

    Designed to be called as a FastAPI BackgroundTask.
    Manages its own database session and error handling.
    """
    tracker = _running_analyses.setdefault(
        sample_id,
        {
            "status": "pending",
            "current_iteration": 0,
            "total_iterations": settings.MAX_ITERATIONS,
            "current_action": "queued",
            "progress_pct": 0.0,
            "stop_requested": False,
            "error": None,
            "events": [],  # typed events for WebSocket consumers
        },
    )

    if tracker.get("stop_requested"):
        tracker["status"] = "stopped"
        tracker["current_action"] = "cancelled before start"
        try:
            async with async_session() as db:
                sample = await db.get(Sample, sample_id)
                if sample:
                    sample.status = SampleStatus.STOPPED.value
                    await db.commit()
        except Exception:
            logger.exception("Failed to mark sample %s as stopped before start", sample_id)
        return

    tracker["status"] = "running"
    tracker["current_action"] = "initialising"
    tracker["progress_pct"] = 0.0

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

    has_binary_source = bool(sample.content_kind == "dotnet_binary" and sample.stored_file_path)
    if not sample.original_text and not has_binary_source:
        tracker["status"] = "failed"
        tracker["error"] = "Sample has no code to analyse"
        sample.status = SampleStatus.FAILED.value
        await _safe_commit(db, "mark empty sample as failed")
        return

    sample.status = SampleStatus.RUNNING.value
    sample.recovered_text = None
    sample.saved_analysis = None
    sample.saved_analysis_at = None
    await _clear_previous_analysis_data(db, sample_id)
    await _safe_commit(db, "mark sample as running")

    from app.services.analysis.orchestrator import Orchestrator

    tracker["current_action"] = "loading LLM provider"

    # Try to load the active LLM provider for intelligent analysis.
    llm_client = await _load_llm_client(db)

    tracker["current_action"] = "starting orchestrator"

    analysis_code = sample.original_text
    analysis_language = sample.language
    workspace_iterations = getattr(settings, "MAX_WORKSPACE_ITERATIONS", settings.MAX_ITERATIONS)
    max_iterations = (
        workspace_iterations
        if sample.content_kind == "archive_bundle" or sample.language == "workspace"
        else settings.MAX_ITERATIONS
    )
    tracker["total_iterations"] = max_iterations
    if sample.content_kind == "dotnet_binary":
        if not sample.stored_file_path:
            tracker["status"] = "failed"
            tracker["error"] = "Binary sample has no stored file path"
            sample.status = SampleStatus.FAILED.value
            await _safe_commit(db, "mark binary sample as failed")
            return
        try:
            raw_bytes = Path(sample.stored_file_path).read_bytes()
        except OSError as exc:
            tracker["status"] = "failed"
            tracker["error"] = f"Failed to read binary sample: {exc}"
            sample.status = SampleStatus.FAILED.value
            await _safe_commit(db, "mark unreadable binary sample as failed")
            return
        analysis_code = raw_bytes.decode("latin-1")
        analysis_language = analysis_language or "dotnet"

    orchestrator = Orchestrator(
        sample_id=sample_id,
        original_code=analysis_code,
        language=analysis_language,
        db_session=db,
        llm_client=llm_client,
        analysis_metadata={
            "content_kind": sample.content_kind,
            "content_encoding": sample.content_encoding,
            "stored_file_path": sample.stored_file_path,
            "byte_size": sample.byte_size,
            "filename": sample.filename,
        },
    )

    # Progress callback: updates the in-memory tracker as the orchestrator
    # progresses through iterations.
    def _on_progress(iteration: int, total: int, action: str, pct: float) -> None:
        tracker["current_iteration"] = iteration
        tracker["total_iterations"] = total
        tracker["current_action"] = action
        tracker["progress_pct"] = pct

    # Event callback: pushes typed events into the tracker for WebSocket consumers.
    def _on_event(event_type: str, data: dict) -> None:
        emit_event(sample_id, event_type, data)

    # Run the full multi-pass analysis loop.
    result = await orchestrator.run(
        auto_approve_threshold=settings.AUTO_APPROVE_THRESHOLD,
        min_confidence=settings.MIN_CONFIDENCE_THRESHOLD,
        max_iterations=max_iterations,
        stall_limit=settings.STALL_THRESHOLD,
        progress_callback=_on_progress,
        stop_requested=lambda: bool(tracker.get("stop_requested")),
        event_callback=_on_event,
    )

    tracker["current_iteration"] = result.iterations
    tracker["progress_pct"] = 100.0
    if result.was_stopped:
        tracker["current_action"] = f"stopped: {result.stop_reason}"
        tracker["status"] = "stopped"
    elif result.success:
        tracker["current_action"] = f"completed: {result.stop_reason}"
        tracker["status"] = "completed"
    else:
        tracker["current_action"] = f"failed: {result.stop_reason}"
        tracker["status"] = "failed"
        tracker["error"] = result.fatal_error or result.stop_reason

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
    sample.status = (
        SampleStatus.STOPPED.value
        if result.was_stopped else
        SampleStatus.COMPLETED.value
        if result.success else
        SampleStatus.FAILED.value
    )
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
            await _upsert_iteration_state(
                db,
                sample_id=sample_id,
                iteration_number=result.iterations,
                state_json=build_state_snapshot_payload(
                    result.state,
                    result.deobfuscated_code,
                ),
            )
            await _safe_commit(db, "persist final iteration state")
        except Exception:
            logger.exception("Failed to persist final iteration state")

    try:
        sample = await db.get(Sample, sample_id)
        if sample is None:
            logger.warning("Sample %s deleted during analysis — skipping snapshot", sample_id)
            tracker["status"] = "failed"
            tracker["error"] = "Sample was deleted during result persistence"
            return
        await persist_saved_analysis_snapshot(
            db,
            sample,
            keep_existing_ai_summary=False,
        )
        await _safe_commit(db, "persist saved analysis snapshot")
    except Exception:
        logger.exception("Failed to persist saved analysis snapshot")

    # ── Auto-generate AI summary if LLM available ──────────────────
    if llm_client is not None and sample is not None and result.success:
        tracker["current_action"] = "generating AI summary"
        emit_event(sample_id, "planning", {"detail": "Auto-generating AI summary..."})
        try:
            from app.api.samples import generate_summary as _gen_summary
            # Call the endpoint function directly with the DB session
            # (FastAPI's Depends is only used when called via HTTP)
            await _gen_summary(sample_id, db)
            logger.info("Auto-generated AI summary for sample %s", sample_id)
        except Exception:
            logger.debug("Auto-summary generation failed (non-critical)", exc_info=True)

    if result.was_stopped:
        tracker["status"] = "stopped"
        tracker["current_action"] = "analysis stopped"
    elif result.success:
        tracker["status"] = "completed"
        tracker["current_action"] = "analysis complete"
    else:
        tracker["status"] = "failed"
        tracker["current_action"] = "analysis failed"


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

        context_window = _MAX_TOKENS_MAP.get(provider.max_tokens_preset, 131_072)
        client = LLMClient(
            base_url=provider.base_url,
            api_key=decrypt_value(provider.api_key_encrypted),
            model=provider.model_name,
            max_tokens=4096,
            context_window=context_window,
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


async def _clear_previous_analysis_data(db: AsyncSession, sample_id: str) -> None:
    """Replace prior persisted artifacts when a sample is analysed again."""
    for model in (
        TransformHistory,
        StringRecord,
        FindingRecord,
        IOCRecord,
        IterationState,
    ):
        await db.execute(delete(model).where(model.sample_id == sample_id))


async def _upsert_iteration_state(
    db: AsyncSession,
    *,
    sample_id: str,
    iteration_number: int,
    state_json: str,
) -> None:
    record = (
        await db.execute(
            select(IterationState)
            .where(IterationState.sample_id == sample_id)
            .where(IterationState.iteration_number == iteration_number)
            .limit(1)
        )
    ).scalar_one_or_none()
    if record is None:
        db.add(
            IterationState(
                sample_id=sample_id,
                iteration_number=iteration_number,
                state_json=state_json,
            )
        )
        return
    record.state_json = state_json


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
