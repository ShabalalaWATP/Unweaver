"""
Generate a structured JSON report from sample analysis data.

Produces the same data as the Markdown report but in a machine-readable
JSON format suitable for SIEM ingestion, ticketing integration, or
archival.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.services.ingest.workspace_bundle import (
    extract_workspace_context,
    pick_workspace_bundle_text,
    workspace_files_preview,
)


def _latest_workspace_context(iteration_states: List[Dict[str, Any]]) -> Dict[str, Any]:
    for state in reversed(iteration_states):
        state_data = state if isinstance(state, dict) else {}
        state_json_str = state_data.get("state_json", "{}")
        if not isinstance(state_json_str, str):
            continue
        try:
            parsed = json.loads(state_json_str)
        except (json.JSONDecodeError, TypeError):
            continue
        workspace_context = parsed.get("workspace_context", {})
        if isinstance(workspace_context, dict) and workspace_context:
            return workspace_context
    return {}


def generate_json_report(
    *,
    sample_id: str,
    filename: str,
    language: Optional[str],
    status: str,
    original_text: str,
    recovered_text: Optional[str],
    analyst_notes: Optional[str],
    created_at: datetime,
    transforms: List[Dict[str, Any]],
    strings: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    iteration_states: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return a complete report as a Python dict (JSON-serialisable)."""

    # ── Extract aggregated data from iteration states ────────────────
    techniques: list[str] = []
    suspicious_apis: list[str] = []
    confidence: Dict[str, float] = {}
    analysis_summary: str = ""

    for state in iteration_states:
        state_data = state if isinstance(state, dict) else {}
        state_json_str = state_data.get("state_json", "{}")
        if isinstance(state_json_str, str):
            try:
                parsed = json.loads(state_json_str)
                techniques.extend(parsed.get("detected_techniques", []))
                suspicious_apis.extend(parsed.get("suspicious_apis", []))
            except (json.JSONDecodeError, TypeError):
                pass

    # Use the last iteration state for confidence and summary
    if iteration_states:
        last_state = iteration_states[-1]
        last_data = last_state if isinstance(last_state, dict) else {}
        last_json = last_data.get("state_json", "{}")
        if isinstance(last_json, str):
            try:
                parsed = json.loads(last_json)
                confidence = parsed.get("confidence", {})
                analysis_summary = parsed.get("analysis_summary", "")
            except (json.JSONDecodeError, TypeError):
                pass

    report: Dict[str, Any] = {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "Unweaver",
        "metadata": {
            "sample_id": sample_id,
            "filename": filename,
            "language": language,
            "status": status,
            "created_at": created_at.isoformat() if created_at else None,
        },
        "detected_techniques": sorted(set(techniques)),
        "suspicious_apis": sorted(set(suspicious_apis)),
        "confidence": confidence,
        "analysis_summary": analysis_summary,
        "transforms": [
            {
                "iteration": t.get("iteration", 0),
                "action": t.get("action", ""),
                "reason": t.get("reason", ""),
                "confidence_before": t.get("confidence_before", 0.0),
                "confidence_after": t.get("confidence_after", 0.0),
                "readability_before": t.get("readability_before", 0.0),
                "readability_after": t.get("readability_after", 0.0),
                "success": t.get("success", True),
                "retry_revert": t.get("retry_revert", False),
            }
            for t in transforms
        ],
        "strings": [
            {
                "value": s.get("value", ""),
                "encoding": s.get("encoding", "utf-8"),
                "offset": s.get("offset"),
                "context": s.get("context"),
                "decoded": s.get("decoded"),
            }
            for s in strings
        ],
        "iocs": [
            {
                "type": ioc.get("ioc_type", ioc.get("type", "other")),
                "value": ioc.get("value", ""),
                "context": ioc.get("context"),
                "confidence": ioc.get("confidence", 0.5),
            }
            for ioc in iocs
        ],
        "findings": [
            {
                "title": f.get("title", ""),
                "severity": f.get("severity", "medium"),
                "description": f.get("description", ""),
                "evidence": f.get("evidence"),
                "confidence": f.get("confidence", 0.5),
            }
            for f in findings
        ],
        "analyst_notes": analyst_notes or "",
        "original_text": original_text,
        "recovered_text": recovered_text or "",
        "iteration_count": len(iteration_states),
    }

    bundle_text = pick_workspace_bundle_text(recovered_text, original_text)
    workspace_context = {
        **(extract_workspace_context(bundle_text or "") or {}),
        **_latest_workspace_context(iteration_states),
    }
    if workspace_context:
        report["workspace"] = {
            **workspace_context,
            "files_preview": workspace_context.get("files_preview")
            or workspace_files_preview(bundle_text or "", max_files=16),
        }

    return report
