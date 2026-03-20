"""
Analysis control endpoints.

Start, poll status of, and stop deobfuscation analysis for a sample.
The actual work happens in a background task; these endpoints just
manage lifecycle.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.db_models import Sample
from app.models.schemas import AnalysisStatus, SampleStatus
from app.tasks.analysis_task import (
    clear_tracker,
    get_analysis_status,
    is_running,
    request_stop,
    run_analysis,
)

router = APIRouter(tags=["analysis"])


# ── POST /api/samples/{id}/analyze ──────────────────────────────────
@router.post(
    "/samples/{sample_id}/analyze",
    response_model=AnalysisStatus,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_analysis(
    sample_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> AnalysisStatus:
    """Kick off deobfuscation analysis for a sample.

    The analysis runs as a background task.  Poll
    ``GET /api/samples/{id}/analysis/status`` for progress.
    """
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    # Don't start if already running
    if is_running(sample_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Analysis is already running for this sample",
        )

    # Don't re-run a completed analysis without explicit intent
    # (the frontend should offer a "re-analyse" button that resets first)
    if sample.status in (SampleStatus.RUNNING.value,):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Analysis is already running for this sample",
        )

    # Reset status if previously completed / failed / stopped
    sample.status = SampleStatus.PENDING.value
    await db.commit()

    background_tasks.add_task(run_analysis, sample_id)

    return AnalysisStatus(
        sample_id=sample_id,
        status=SampleStatus.PENDING,
        current_iteration=0,
        total_iterations=0,
        current_action="queued",
        progress_pct=0.0,
    )


# ── GET /api/samples/{id}/analysis/status ───────────────────────────
@router.get(
    "/samples/{sample_id}/analysis/status",
    response_model=AnalysisStatus,
)
async def analysis_status(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> AnalysisStatus:
    """Poll the current status of a running (or recently finished) analysis."""
    # First check in-memory tracker
    tracker = get_analysis_status(sample_id)
    if tracker is not None:
        status_str = tracker.get("status", "pending")

        # Reconcile: if the tracker still says "running" but the DB has
        # moved to a terminal state (completed / failed / stopped), trust
        # the DB.  This handles cases where the tracker wasn't properly
        # cleaned up (e.g. exception during result persistence).
        if status_str == "running":
            sample = await db.get(Sample, sample_id)
            if sample and sample.status in (
                SampleStatus.COMPLETED.value,
                SampleStatus.FAILED.value,
                SampleStatus.STOPPED.value,
            ):
                clear_tracker(sample_id)
                try:
                    db_status = SampleStatus(sample.status)
                except ValueError:
                    db_status = SampleStatus.COMPLETED
                return AnalysisStatus(
                    sample_id=sample_id,
                    status=db_status,
                    current_iteration=tracker.get("current_iteration", 0),
                    total_iterations=tracker.get("total_iterations", 0),
                    current_action=sample.status,
                    progress_pct=100.0,
                )

        try:
            sample_status = SampleStatus(status_str)
        except ValueError:
            sample_status = SampleStatus.PENDING

        return AnalysisStatus(
            sample_id=sample_id,
            status=sample_status,
            current_iteration=tracker.get("current_iteration", 0),
            total_iterations=tracker.get("total_iterations", 0),
            current_action=tracker.get("current_action", ""),
            progress_pct=tracker.get("progress_pct", 0.0),
        )

    # Fall back to DB status
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    try:
        sample_status = SampleStatus(sample.status)
    except ValueError:
        sample_status = SampleStatus.PENDING

    progress = 100.0 if sample_status in (
        SampleStatus.COMPLETED, SampleStatus.FAILED, SampleStatus.STOPPED
    ) else 0.0

    return AnalysisStatus(
        sample_id=sample_id,
        status=sample_status,
        current_iteration=0,
        total_iterations=0,
        current_action=sample.status,
        progress_pct=progress,
    )


# ── POST /api/samples/{id}/analysis/stop ────────────────────────────
@router.post(
    "/samples/{sample_id}/analysis/stop",
    response_model=AnalysisStatus,
)
async def stop_analysis(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> AnalysisStatus:
    """Request cancellation of a running analysis.

    The analysis will stop at the end of its current iteration.
    """
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    if is_running(sample_id):
        # Normal case: analysis is actively running — request graceful stop
        request_stop(sample_id)
        tracker = get_analysis_status(sample_id)
        return AnalysisStatus(
            sample_id=sample_id,
            status=SampleStatus.RUNNING,
            current_iteration=tracker.get("current_iteration", 0) if tracker else 0,
            total_iterations=tracker.get("total_iterations", 0) if tracker else 0,
            current_action="stop requested",
            progress_pct=tracker.get("progress_pct", 0.0) if tracker else 0.0,
        )

    # Zombie case: DB says "running" but the in-memory tracker is gone
    # (e.g. server was restarted mid-analysis).  Reset the sample to stopped.
    if sample.status == SampleStatus.RUNNING.value:
        sample.status = SampleStatus.STOPPED.value
        await db.commit()
        return AnalysisStatus(
            sample_id=sample_id,
            status=SampleStatus.STOPPED,
            current_iteration=0,
            total_iterations=0,
            current_action="reset from zombie state",
            progress_pct=0.0,
        )

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="No running analysis to stop for this sample",
    )
