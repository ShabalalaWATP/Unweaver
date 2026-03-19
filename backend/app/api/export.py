"""
Export endpoints.

Generate downloadable reports in Markdown or JSON format for a sample's
analysis results.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.db_models import (
    FindingRecord,
    IOCRecord,
    IterationState,
    Sample,
    StringRecord,
    TransformHistory,
)
from app.services.reports.json_report import generate_json_report
from app.services.reports.markdown import generate_markdown_report

router = APIRouter(tags=["export"])


async def _gather_report_data(
    sample_id: str, db: AsyncSession
) -> dict:
    """Load all data needed for report generation."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    # Transforms
    result = await db.execute(
        select(TransformHistory)
        .where(TransformHistory.sample_id == sample_id)
        .order_by(TransformHistory.iteration)
    )
    transforms = [
        {
            "iteration": t.iteration,
            "action": t.action,
            "reason": t.reason,
            "inputs": t.inputs,
            "outputs": t.outputs,
            "confidence_before": t.confidence_before,
            "confidence_after": t.confidence_after,
            "readability_before": t.readability_before,
            "readability_after": t.readability_after,
            "success": t.success,
            "retry_revert": t.retry_revert,
        }
        for t in result.scalars().all()
    ]

    # Strings
    result = await db.execute(
        select(StringRecord).where(StringRecord.sample_id == sample_id)
    )
    strings = [
        {
            "value": s.value,
            "encoding": s.encoding,
            "offset": s.offset,
            "context": s.context,
            "decoded": s.decoded,
        }
        for s in result.scalars().all()
    ]

    # IOCs
    result = await db.execute(
        select(IOCRecord).where(IOCRecord.sample_id == sample_id)
    )
    iocs = [
        {
            "ioc_type": i.ioc_type,
            "value": i.value,
            "context": i.context,
            "confidence": i.confidence,
        }
        for i in result.scalars().all()
    ]

    # Findings
    result = await db.execute(
        select(FindingRecord).where(FindingRecord.sample_id == sample_id)
    )
    findings = [
        {
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "evidence": f.evidence,
            "confidence": f.confidence,
        }
        for f in result.scalars().all()
    ]

    # Iteration states
    result = await db.execute(
        select(IterationState)
        .where(IterationState.sample_id == sample_id)
        .order_by(IterationState.iteration_number)
    )
    iteration_states = [
        {
            "iteration_number": it.iteration_number,
            "state_json": it.state_json,
        }
        for it in result.scalars().all()
    ]

    return {
        "sample_id": sample.id,
        "filename": sample.filename,
        "language": sample.language,
        "status": sample.status,
        "original_text": sample.original_text,
        "recovered_text": sample.recovered_text,
        "analyst_notes": sample.analyst_notes,
        "created_at": sample.created_at,
        "transforms": transforms,
        "strings": strings,
        "iocs": iocs,
        "findings": findings,
        "iteration_states": iteration_states,
    }


# ── GET /api/samples/{id}/export/markdown ───────────────────────────
@router.get("/samples/{sample_id}/export/markdown")
async def export_markdown(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    """Generate and return a Markdown report for the sample."""
    data = await _gather_report_data(sample_id, db)
    md = generate_markdown_report(**data)
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="unweaver_report_{sample_id[:8]}.md"',
        },
    )


# ── GET /api/samples/{id}/export/json ───────────────────────────────
@router.get("/samples/{sample_id}/export/json")
async def export_json(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Generate and return a JSON report for the sample."""
    data = await _gather_report_data(sample_id, db)
    report = generate_json_report(**data)
    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": f'attachment; filename="unweaver_report_{sample_id[:8]}.json"',
        },
    )
