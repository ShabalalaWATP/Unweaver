"""
Generate a Markdown report from sample analysis data.

The report includes metadata, transform history, decoded strings, IOCs,
findings, and analyst notes -- everything needed for a standalone
deobfuscation write-up.
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


def generate_markdown_report(
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
) -> str:
    """Return a complete Markdown report as a string."""

    lines: list[str] = []

    # ── Title & metadata ─────────────────────────────────────────────
    lines.append(f"# Unweaver Deobfuscation Report")
    lines.append("")
    lines.append(f"**Sample:** `{filename}`  ")
    lines.append(f"**ID:** `{sample_id}`  ")
    lines.append(f"**Language:** {language or 'unknown'}  ")
    lines.append(f"**Status:** {status}  ")
    lines.append(f"**Created:** {created_at.isoformat()}  ")
    lines.append("")

    bundle_text = pick_workspace_bundle_text(recovered_text, original_text)
    workspace_context = extract_workspace_context(bundle_text or "")
    if workspace_context:
        lines.append("## Workspace Context")
        lines.append("")
        lines.append(f"- Archive: `{workspace_context.get('archive_name') or filename}`")
        lines.append(f"- Included files: {workspace_context.get('included_files') or 0}")
        lines.append(f"- Omitted files: {workspace_context.get('omitted_files') or 0}")
        if workspace_context.get("entry_points"):
            lines.append("- Entry points: " + ", ".join(workspace_context["entry_points"][:8]))
        if workspace_context.get("suspicious_files"):
            lines.append("- Suspicious files: " + ", ".join(workspace_context["suspicious_files"][:8]))
        preview = workspace_files_preview(bundle_text or "", max_files=12)
        if preview:
            lines.append("")
            lines.append("### Prioritized Files")
            lines.append("")
            for item in preview:
                priority = ",".join(item.get("priority", [])) or "normal"
                lines.append(
                    f"- `{item.get('path')}` ({item.get('language')}, {priority}, {item.get('size_bytes')} bytes)"
                )
        lines.append("")

    # ── Techniques detected ──────────────────────────────────────────
    # Gather techniques from iteration states
    techniques: list[str] = []
    for state in iteration_states:
        state_data = state if isinstance(state, dict) else {}
        if isinstance(state_data.get("state_json"), str):
            try:
                parsed = json.loads(state_data["state_json"])
                techniques.extend(parsed.get("detected_techniques", []))
            except (json.JSONDecodeError, TypeError):
                pass
    if techniques:
        unique_techniques = sorted(set(techniques))
        lines.append("## Detected Techniques")
        lines.append("")
        for tech in unique_techniques:
            lines.append(f"- {tech}")
        lines.append("")

    # ── Transform sequence ───────────────────────────────────────────
    if transforms:
        lines.append("## Transform History")
        lines.append("")
        lines.append("| # | Action | Confidence Before | Confidence After | Success | Reverted |")
        lines.append("|---|--------|-------------------|------------------|---------|----------|")
        for t in transforms:
            iteration = t.get("iteration", "?")
            action = t.get("action", "")
            cb = t.get("confidence_before", 0.0)
            ca = t.get("confidence_after", 0.0)
            success = "Yes" if t.get("success", True) else "No"
            reverted = "Yes" if t.get("retry_revert", False) else "No"
            lines.append(
                f"| {iteration} | {action} | {cb:.2f} | {ca:.2f} | {success} | {reverted} |"
            )
        lines.append("")

        # Detailed reasons
        lines.append("### Transform Details")
        lines.append("")
        for t in transforms:
            iteration = t.get("iteration", "?")
            action = t.get("action", "")
            reason = t.get("reason", "")
            lines.append(f"**Iteration {iteration}: {action}**")
            if reason:
                lines.append(f"> {reason}")
            lines.append("")

    # ── Decoded strings ──────────────────────────────────────────────
    if strings:
        lines.append("## Extracted Strings")
        lines.append("")
        lines.append(f"Total: {len(strings)} string(s)")
        lines.append("")
        for i, s in enumerate(strings[:100], 1):  # cap at 100 for readability
            value = s.get("value", "")
            encoding = s.get("encoding", "utf-8")
            context = s.get("context", "")
            decoded = s.get("decoded", "")
            display = decoded if decoded else value
            lines.append(f"{i}. `{display[:120]}` (encoding: {encoding})")
            if context:
                lines.append(f"   - Context: {context}")
        if len(strings) > 100:
            lines.append(f"\n... and {len(strings) - 100} more strings (truncated)")
        lines.append("")

    # ── IOCs table ───────────────────────────────────────────────────
    if iocs:
        lines.append("## Indicators of Compromise (IOCs)")
        lines.append("")
        lines.append("| Type | Value | Confidence | Context |")
        lines.append("|------|-------|------------|---------|")
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", ioc.get("type", "other"))
            value = ioc.get("value", "")
            conf = ioc.get("confidence", 0.5)
            context = ioc.get("context", "") or ""
            lines.append(f"| {ioc_type} | `{value}` | {conf:.2f} | {context[:60]} |")
        lines.append("")

    # ── Suspicious APIs ──────────────────────────────────────────────
    suspicious_apis: list[str] = []
    for state in iteration_states:
        state_data = state if isinstance(state, dict) else {}
        if isinstance(state_data.get("state_json"), str):
            try:
                parsed = json.loads(state_data["state_json"])
                suspicious_apis.extend(parsed.get("suspicious_apis", []))
            except (json.JSONDecodeError, TypeError):
                pass
    if suspicious_apis:
        unique_apis = sorted(set(suspicious_apis))
        lines.append("## Suspicious APIs")
        lines.append("")
        for api in unique_apis:
            lines.append(f"- `{api}`")
        lines.append("")

    # ── Findings ─────────────────────────────────────────────────────
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            title = f.get("title", "Untitled")
            severity = f.get("severity", "medium")
            description = f.get("description", "")
            evidence = f.get("evidence", "")
            confidence = f.get("confidence", 0.5)
            lines.append(f"### {title}")
            lines.append(f"**Severity:** {severity} | **Confidence:** {confidence:.2f}")
            lines.append("")
            if description:
                lines.append(description)
                lines.append("")
            if evidence:
                lines.append("**Evidence:**")
                lines.append(f"```")
                lines.append(evidence[:2000])
                lines.append(f"```")
                lines.append("")

    # ── Confidence notes ─────────────────────────────────────────────
    # Extract final confidence from last iteration state
    if iteration_states:
        last_state = iteration_states[-1]
        state_data = last_state if isinstance(last_state, dict) else {}
        state_json_str = state_data.get("state_json", "{}")
        if isinstance(state_json_str, str):
            try:
                parsed = json.loads(state_json_str)
                confidence = parsed.get("confidence", {})
                if confidence:
                    lines.append("## Confidence Assessment")
                    lines.append("")
                    for key, val in confidence.items():
                        if isinstance(val, (int, float)):
                            lines.append(f"- **{key}:** {val:.2f}")
                    lines.append("")
                summary = parsed.get("analysis_summary", "")
                if summary:
                    lines.append("## Analysis Summary")
                    lines.append("")
                    lines.append(summary)
                    lines.append("")
            except (json.JSONDecodeError, TypeError):
                pass

    # ── Analyst notes ────────────────────────────────────────────────
    if analyst_notes:
        lines.append("## Analyst Notes")
        lines.append("")
        lines.append(analyst_notes)
        lines.append("")

    # ── Iteration summary ────────────────────────────────────────────
    if iteration_states:
        lines.append("## Iteration Summary")
        lines.append("")
        lines.append(f"Total iterations recorded: {len(iteration_states)}")
        lines.append("")
        for state in iteration_states:
            state_data = state if isinstance(state, dict) else {}
            it_num = state_data.get("iteration_number", "?")
            state_json_str = state_data.get("state_json", "{}")
            if isinstance(state_json_str, str):
                try:
                    parsed = json.loads(state_json_str)
                    overall = parsed.get("confidence", {}).get("overall", 0.0)
                    iter_info = parsed.get("iteration_state", {})
                    stall = iter_info.get("stall_counter", 0)
                    lines.append(
                        f"- **Iteration {it_num}:** overall confidence {overall:.2f}, "
                        f"stall counter {stall}"
                    )
                except (json.JSONDecodeError, TypeError):
                    lines.append(f"- **Iteration {it_num}:** (state unparseable)")
        lines.append("")

    # ── Recovered code ───────────────────────────────────────────────
    if recovered_text:
        lines.append("## Recovered Code")
        lines.append("")
        lang_tag = language or ""
        lines.append(f"```{lang_tag}")
        lines.append(recovered_text)
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by Unweaver at {datetime.now(timezone.utc).isoformat()}*")
    lines.append("")

    return "\n".join(lines)
