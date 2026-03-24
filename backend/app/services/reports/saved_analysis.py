"""Helpers for persisting reusable analysis snapshots on samples."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db_models import (
    FindingRecord,
    IOCRecord,
    IterationState,
    Sample,
    StringRecord,
    TransformHistory,
)
from app.models.schemas import AISummaryReport, SavedAnalysisSnapshot, SampleStatus
from app.services.ingest.workspace_bundle import extract_workspace_context, workspace_files_preview


def _parse_state_json(state_json: str | dict | None) -> dict[str, Any]:
    if not state_json:
        return {}
    if isinstance(state_json, dict):
        return state_json
    try:
        payload = json.loads(state_json)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _coerce_ai_summary(value: Any) -> AISummaryReport | None:
    if not isinstance(value, dict):
        return None
    try:
        return AISummaryReport.model_validate(value)
    except Exception:
        return None


async def _count_records(
    db: AsyncSession,
    model,
    sample_id: str,
) -> int:
    result = await db.execute(
        select(func.count()).select_from(model).where(model.sample_id == sample_id)
    )
    return int(result.scalar_one() or 0)


async def _latest_iteration_state(
    db: AsyncSession,
    sample_id: str,
) -> dict[str, Any]:
    result = await db.execute(
        select(IterationState.state_json)
        .where(IterationState.sample_id == sample_id)
        .order_by(IterationState.iteration_number.desc())
        .limit(1)
    )
    return _parse_state_json(result.scalar_one_or_none())


async def persist_saved_analysis_snapshot(
    db: AsyncSession,
    sample: Sample,
    *,
    ai_summary: AISummaryReport | None = None,
    keep_existing_ai_summary: bool = True,
) -> SavedAnalysisSnapshot:
    """Build and persist a reusable saved-analysis snapshot on a sample."""
    state_payload = await _latest_iteration_state(db, sample.id)

    workspace_context = state_payload.get("workspace_context")
    if not isinstance(workspace_context, dict):
        workspace_context = {}

    if sample.language == "workspace":
        original_context = extract_workspace_context(sample.original_text or "") or {}
        merged_context = {**original_context, **workspace_context}
        if "files_preview" not in merged_context:
            merged_context["files_preview"] = workspace_files_preview(sample.original_text or "")
        if sample.recovered_text:
            recovered_preview = workspace_files_preview(sample.recovered_text)
            if recovered_preview:
                merged_context["recovered_files_preview"] = recovered_preview
        workspace_context = merged_context

    confidence = state_payload.get("confidence")
    confidence_score = None
    if isinstance(confidence, dict):
        raw_confidence = confidence.get("overall")
        if isinstance(raw_confidence, (int, float)):
            confidence_score = float(raw_confidence)

    stored_ai_summary = None
    if keep_existing_ai_summary and isinstance(sample.saved_analysis, dict):
        stored_ai_summary = _coerce_ai_summary(sample.saved_analysis.get("ai_summary"))

    snapshot = SavedAnalysisSnapshot(
        saved_at=datetime.now(timezone.utc),
        sample_status=SampleStatus(sample.status) if sample.status in SampleStatus._value2member_map_ else None,
        transform_count=await _count_records(db, TransformHistory, sample.id),
        finding_count=await _count_records(db, FindingRecord, sample.id),
        ioc_count=await _count_records(db, IOCRecord, sample.id),
        string_count=await _count_records(db, StringRecord, sample.id),
        recovered_text_length=len(sample.recovered_text or ""),
        confidence_score=confidence_score,
        analysis_summary=str(state_payload.get("analysis_summary") or ""),
        workspace_context=workspace_context,
        ai_summary=ai_summary or stored_ai_summary,
    )

    sample.saved_analysis = snapshot.model_dump(mode="json")
    sample.saved_analysis_at = snapshot.saved_at
    await db.flush()
    return snapshot
