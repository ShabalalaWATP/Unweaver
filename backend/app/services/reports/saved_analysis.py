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


def _coerce_optional_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def extract_result_metadata_from_state(state_payload: dict[str, Any]) -> dict[str, Any]:
    iteration_state = state_payload.get("iteration_state", {})
    if not isinstance(iteration_state, dict):
        iteration_state = {}
    confidence = state_payload.get("confidence", {})
    if not isinstance(confidence, dict):
        confidence = {}

    raw_confidence = _coerce_optional_float(iteration_state.get("raw_confidence"))
    if raw_confidence is None:
        raw_confidence = _coerce_optional_float(confidence.get("overall"))
    coverage_adjusted_confidence = _coerce_optional_float(
        iteration_state.get("coverage_adjusted_confidence")
    )
    if coverage_adjusted_confidence is None:
        coverage_adjusted_confidence = raw_confidence

    confidence_scope_note = str(iteration_state.get("confidence_scope_note") or "").strip() or None
    return {
        "confidence_score": coverage_adjusted_confidence,
        "raw_confidence_score": raw_confidence,
        "coverage_adjusted_confidence": coverage_adjusted_confidence,
        "coverage_adjustment_factor": _coerce_optional_float(
            iteration_state.get("coverage_adjustment_factor")
        ),
        "confidence_scope_note": confidence_scope_note,
        "stop_reason": str(iteration_state.get("stop_reason") or "").strip() or None,
        "fatal_error": str(iteration_state.get("fatal_error") or "").strip() or None,
        "result_kind": str(iteration_state.get("result_kind") or "").strip() or None,
        "best_effort": bool(iteration_state.get("best_effort")),
    }


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
    result_metadata = extract_result_metadata_from_state(state_payload)

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
        if result_metadata.get("confidence_scope_note") and not merged_context.get("confidence_scope_note"):
            merged_context["confidence_scope_note"] = result_metadata["confidence_scope_note"]
        workspace_context = merged_context

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
        confidence_score=result_metadata["confidence_score"],
        raw_confidence_score=result_metadata["raw_confidence_score"],
        coverage_adjusted_confidence=result_metadata["coverage_adjusted_confidence"],
        coverage_adjustment_factor=result_metadata["coverage_adjustment_factor"],
        confidence_scope_note=result_metadata["confidence_scope_note"],
        stop_reason=result_metadata["stop_reason"],
        fatal_error=result_metadata["fatal_error"],
        result_kind=result_metadata["result_kind"],
        best_effort=result_metadata["best_effort"],
        analysis_summary=str(state_payload.get("analysis_summary") or ""),
        workspace_context=workspace_context,
        ai_summary=ai_summary or stored_ai_summary,
    )

    sample.saved_analysis = snapshot.model_dump(mode="json")
    sample.saved_analysis_at = snapshot.saved_at
    await db.flush()
    return snapshot
