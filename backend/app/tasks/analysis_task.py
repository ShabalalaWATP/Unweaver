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

    # Load sample
    sample = await db.get(Sample, sample_id)
    if sample is None:
        tracker["status"] = "failed"
        tracker["error"] = "Sample not found"
        return

    sample.status = SampleStatus.RUNNING.value
    await db.commit()

    # The orchestrator works fully deterministically without an LLM.
    from app.services.analysis.orchestrator import Orchestrator

    tracker["current_action"] = "starting orchestrator"

    orchestrator = Orchestrator(
        sample_id=sample_id,
        original_code=sample.original_text,
        language=sample.language,
        db_session=db,
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

    # Persist results
    sample.recovered_text = result.deobfuscated_code
    sample.language = result.language or sample.language
    sample.status = SampleStatus.COMPLETED.value

    # Transform history
    for tr in result.transform_history:
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

    # Strings
    for s in result.strings:
        db.add(StringRecord(
            sample_id=sample_id,
            value=s.value,
            encoding=s.encoding,
            offset=s.offset,
            context=s.context,
            decoded=s.decoded,
        ))

    # Findings
    for f in result.findings:
        severity_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        db.add(FindingRecord(
            sample_id=sample_id,
            title=f.title,
            severity=severity_val,
            description=f.description,
            evidence=f.evidence or "",
            confidence=f.confidence,
        ))

    # IOCs
    for ioc in result.iocs:
        ioc_type_val = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        db.add(IOCRecord(
            sample_id=sample_id,
            ioc_type=ioc_type_val,
            value=ioc.value,
            context=ioc.context or "",
            confidence=ioc.confidence,
        ))

    # Final iteration state
    if result.state:
        db.add(IterationState(
            sample_id=sample_id,
            iteration_number=result.iterations,
            state_json=result.state.model_dump_json(),
        ))

    await db.commit()

    tracker["status"] = "completed"
    tracker["current_action"] = "analysis complete"
