"""
Sample management endpoints.

Samples are individual obfuscated code files or text snippets that live
inside a project. They can be uploaded as single files, codebase archives,
or pasted directly.
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.crypto import decrypt_value
from app.core.database import get_db
from app.models.db_models import (
    FindingRecord,
    IOCRecord,
    IterationState,
    Project,
    ProviderConfig,
    Sample,
    StringRecord,
    TransformHistory,
)
from app.models.schemas import (
    AISummaryReport,
    AISummarySections,
    AnalystChatRequest,
    AnalystChatRetrievedFile,
    AnalystChatResponse,
    NotesSave,
    SampleDetail,
    SampleResponse,
    SampleStatus,
)
from app.services.ingest.workspace_bundle import (
    WORKSPACE_BUNDLE_HEADER,
    WorkspaceBundleError,
    build_workspace_bundle,
    extract_workspace_context,
    is_archive_upload,
    load_workspace_archive_from_path,
    parse_workspace_bundle,
    truncate_workspace_bundle,
    workspace_context_prompt,
)
from app.services.transforms.binary_analysis import (
    binary_preview_text,
    detect_upload_content_kind,
)
from app.services.llm.client import LLMClient, _MAX_TOKENS_MAP
from app.services.reports.saved_analysis import (
    extract_result_metadata_from_state,
    persist_saved_analysis_snapshot,
)
from app.tasks.analysis_task import get_analysis_status

logger = logging.getLogger(__name__)

from pydantic import BaseModel, Field


class _PasteBody(BaseModel):
    """JSON body for the paste-sample endpoint."""
    filename: str | None = "paste.txt"
    original_text: str = Field(..., min_length=1)
    language: str | None = None


router = APIRouter(tags=["samples"])

_MAX_FILE_SIZE = settings.MAX_FILE_SIZE
_MAX_ARCHIVE_FILE_SIZE = settings.MAX_ARCHIVE_FILE_SIZE

# Characters allowed in sanitised filenames
_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]")
_CHAT_SOURCE_TAG_RE = re.compile(r"\[(?:original|recovered|analysis|retrieved:[^\]]+)\]")
_WORKSPACE_QUERY_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:\\-]{3,}")
_WORKSPACE_PATH_HINT_RE = re.compile(r"(?:[A-Za-z0-9_.-]+[\\/])+[A-Za-z0-9_.-]+")
_WORKSPACE_SEARCH_STOPWORDS = {
    "about",
    "across",
    "after",
    "against",
    "also",
    "analysis",
    "anything",
    "assistant",
    "before",
    "between",
    "build",
    "changed",
    "check",
    "code",
    "compare",
    "could",
    "current",
    "does",
    "each",
    "entrypoint",
    "every",
    "explain",
    "file",
    "files",
    "from",
    "have",
    "into",
    "just",
    "look",
    "main",
    "most",
    "need",
    "output",
    "over",
    "project",
    "recovered",
    "results",
    "search",
    "should",
    "show",
    "still",
    "summarize",
    "that",
    "their",
    "them",
    "there",
    "they",
    "this",
    "what",
    "when",
    "where",
    "which",
    "with",
    "workspace",
}


def _sanitize_filename(name: str) -> str:
    """Strip directory components and dangerous characters from a filename."""
    # Take only the basename (no directory traversal)
    name = os.path.basename(name)
    # Replace unsafe chars
    name = _SAFE_FILENAME_RE.sub("_", name)
    # Fallback
    if not name or name.startswith("."):
        name = "upload.txt"
    return name[:255]


def _clip_text_for_prompt(text: str, max_chars: int) -> tuple[str, bool]:
    """Keep full text when possible, otherwise preserve both head and tail."""
    if max_chars <= 0 or len(text) <= max_chars:
        return text, False
    if max_chars < 160:
        return text[:max_chars], True
    head = max_chars // 2
    tail = max_chars - head - 64
    clipped = (
        text[:head].rstrip()
        + "\n\n... [truncated to fit model context] ...\n\n"
        + text[-max(0, tail):].lstrip()
    )
    return clipped, True


def _clip_code_context_for_prompt(text: str, max_chars: int) -> tuple[str, bool]:
    """Prefer workspace-aware trimming when the text is a bundle."""
    if text.startswith(WORKSPACE_BUNDLE_HEADER):
        trimmed = truncate_workspace_bundle(text, max_chars)
        return trimmed, len(trimmed) < len(text)
    return _clip_text_for_prompt(text, max_chars)


def _workspace_source_family(source: str) -> str:
    """Collapse retrieval sources into original vs recovered families."""
    return "recovered" if source == "recovered_bundle" else "original"


def _retrieved_source_tag(source: str, path: str) -> str:
    """Return a prompt-safe retrieval tag for inline source attribution."""
    source_prefix = {
        "recovered_bundle": "recovered",
        "original_bundle": "original",
        "archive_scan": "archive",
    }.get(source, "workspace")
    safe_path = path.replace("]", "%5D")
    return f"retrieved:{source_prefix}:{safe_path}"


def _build_workspace_search_space(
    *,
    sample: Sample,
    original_text: str,
    recovered_text: str,
) -> List[Dict[str, Any]]:
    """Merge recovered/original workspace bundles with the stored archive."""
    candidates: List[Dict[str, Any]] = []
    seen_entries: set[tuple[str, str]] = set()

    def add_candidate(
        *,
        path: str,
        language: str | None,
        text: str,
        size_bytes: int,
        priority: List[str],
        source: str,
    ) -> None:
        source_family = _workspace_source_family(source)
        candidate_key = (path, source_family)
        if not path or candidate_key in seen_entries or not text:
            return
        candidates.append(
            {
                "path": path,
                "language": language or "plaintext",
                "text": text,
                "size_bytes": size_bytes,
                "priority": priority,
                "source": source,
            }
        )
        seen_entries.add(candidate_key)

    for item in parse_workspace_bundle(recovered_text):
        add_candidate(
            path=item.path,
            language=item.language,
            text=item.text,
            size_bytes=item.size_bytes,
            priority=list(item.priority),
            source="recovered_bundle",
        )

    for item in parse_workspace_bundle(original_text):
        add_candidate(
            path=item.path,
            language=item.language,
            text=item.text,
            size_bytes=item.size_bytes,
            priority=list(item.priority),
            source="original_bundle",
        )

    if sample.content_kind == "archive_bundle" and sample.stored_file_path and os.path.exists(sample.stored_file_path):
        try:
            archive_scan = load_workspace_archive_from_path(
                sample.stored_file_path,
                archive_name=sample.filename,
                max_member_bytes=settings.MAX_ARCHIVE_MEMBER_SIZE,
                max_scan_files=settings.MAX_ARCHIVE_SCAN_FILES,
            )
        except Exception as exc:
            logger.warning("Workspace chat retrieval failed to index archive %s: %s", sample.id, exc)
        else:
            for item in archive_scan.files:
                add_candidate(
                    path=item.path,
                    language=item.language,
                    text=item.text,
                    size_bytes=item.size_bytes,
                    priority=list(item.priority_tags),
                    source="archive_scan",
                )

    return candidates


def _extract_workspace_query_terms(messages: List[AnalystChatMessage]) -> tuple[List[str], List[str]]:
    """Extract likely path hints and keywords from recent user turns."""
    user_text = "\n".join(
        message.content.strip()
        for message in messages[-6:]
        if message.role == "user" and message.content.strip()
    ).lower()
    if not user_text:
        return [], []

    path_terms: List[str] = []
    keyword_terms: List[str] = []
    strip_chars = "`'\"()[]{}<>,:;.!?"

    def add_path(raw_value: str) -> None:
        candidate = raw_value.replace("\\", "/").strip(strip_chars)
        if not candidate:
            return
        if "/" not in candidate:
            return
        if candidate not in path_terms:
            path_terms.append(candidate)

    def add_keyword(raw_value: str) -> None:
        token = raw_value.strip(strip_chars).lower()
        if not token or len(token) < 3 or token.isdigit():
            return
        if token in _WORKSPACE_SEARCH_STOPWORDS:
            return
        if token not in keyword_terms:
            keyword_terms.append(token)

    for match in _WORKSPACE_PATH_HINT_RE.findall(user_text):
        add_path(match)

    for raw_token in _WORKSPACE_QUERY_TOKEN_RE.findall(user_text):
        if "/" in raw_token or "\\" in raw_token:
            add_path(raw_token)
            basename = raw_token.replace("\\", "/").rsplit("/", 1)[-1]
            if "." in basename:
                add_keyword(basename)
            continue
        add_keyword(raw_token)

    return path_terms[:8], keyword_terms[:24]


def _score_workspace_candidate(
    candidate: Dict[str, Any],
    *,
    path_terms: List[str],
    keyword_terms: List[str],
) -> tuple[float, List[str]]:
    """Score a workspace file candidate against the current chat question."""
    path = str(candidate.get("path") or "").lower()
    text = str(candidate.get("text") or "").lower()
    source = str(candidate.get("source") or "")
    priority = {
        str(item).lower()
        for item in candidate.get("priority", [])
        if str(item).strip()
    }

    score = {
        "recovered_bundle": 4.0,
        "original_bundle": 2.5,
        "archive_scan": 1.0,
    }.get(source, 0.0)
    if "entrypoint" in priority:
        score += 1.2
    if "suspicious" in priority:
        score += 1.5
    if "manifest" in priority:
        score += 0.7

    matched_terms: List[str] = []
    basename = path.rsplit("/", 1)[-1]

    for term in path_terms:
        normalised = term.lower()
        basename_term = normalised.rsplit("/", 1)[-1]
        if path == normalised:
            score += 40.0
            matched_terms.append(term)
            continue
        if path.endswith(normalised):
            score += 26.0
            matched_terms.append(term)
            continue
        if normalised in path:
            score += 18.0
            matched_terms.append(term)
            continue
        if basename_term == basename:
            score += 12.0
            matched_terms.append(basename_term)

    for term in keyword_terms:
        if term in path:
            score += 6.0
            matched_terms.append(term)
        if term in text:
            score += min(text.count(term), 4) * 3.0
            matched_terms.append(term)

    unique_terms: List[str] = []
    for term in matched_terms:
        if term not in unique_terms:
            unique_terms.append(term)
    return score, unique_terms


def _build_numbered_excerpt(lines: List[str], start: int, end: int) -> str:
    """Format a line range with line numbers for prompt readability."""
    return "\n".join(
        f"{line_no:04d} | {lines[line_no - 1]}"
        for line_no in range(start + 1, end + 1)
    )


def _infer_fallback_source_tags(
    line: str,
    retrieved_files: List[AnalystChatRetrievedFile],
) -> List[str]:
    """Infer conservative source tags when the model omits them."""
    lowered = line.lower()
    tags: List[str] = []

    for file in retrieved_files[:8]:
        path = file.path.lower()
        basename = path.rsplit("/", 1)[-1]
        if path in lowered or (basename and basename in lowered):
            tags.append(f"[{_retrieved_source_tag(file.source, file.path)}]")

    if any(token in lowered for token in ("original", "uploaded source", "before deobfuscation")):
        tags.append("[original]")
    if any(token in lowered for token in ("recovered", "deobfus", "decoded", "after deobfuscation")):
        tags.append("[recovered]")
    if any(
        token in lowered
        for token in (
            "analysis",
            "finding",
            "findings",
            "ioc",
            "iocs",
            "indicator",
            "transform",
            "confidence",
            "technique",
            "suspicious api",
            "workspace context",
            "string",
        )
    ):
        tags.append("[analysis]")

    if not tags:
        tags.append("[analysis]")

    unique_tags: List[str] = []
    for tag in tags:
        if tag not in unique_tags:
            unique_tags.append(tag)
    return unique_tags


def _normalise_chat_source_tags(
    reply: str,
    *,
    retrieved_files: List[AnalystChatRetrievedFile],
) -> str:
    """Ensure non-code narrative lines carry at least one source tag."""
    if not reply.strip():
        return reply

    lines = reply.splitlines()
    tagged_lines: List[str] = []
    in_code_block = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            tagged_lines.append(line)
            continue
        if in_code_block or not stripped:
            tagged_lines.append(line)
            continue
        if _CHAT_SOURCE_TAG_RE.search(stripped):
            tagged_lines.append(line)
            continue
        if stripped.startswith("#") or stripped.startswith("|") or stripped.startswith("---"):
            tagged_lines.append(line)
            continue
        if not re.search(r"[A-Za-z]", stripped):
            tagged_lines.append(line)
            continue

        tags = _infer_fallback_source_tags(stripped, retrieved_files)
        tagged_lines.append(f"{line.rstrip()} {' '.join(tags)}")

    return "\n".join(tagged_lines).strip()


def _extract_workspace_excerpt(
    candidate: Dict[str, Any],
    *,
    matched_terms: List[str],
    max_chars: int,
) -> tuple[str, List[str], bool]:
    """Extract a compact, prompt-ready excerpt from a workspace file."""
    text = str(candidate.get("text") or "")
    lines = text.splitlines()
    if not text:
        return "", [], False

    lowered_terms = [term.lower() for term in matched_terms if term and len(term) >= 3]
    if len(lines) <= 2:
        clipped, truncated = _clip_text_for_prompt(text, max_chars)
        return clipped, [], truncated

    if lowered_terms:
        hit_indexes: List[int] = []
        for index, line in enumerate(lines):
            lowered_line = line.lower()
            if any(term in lowered_line for term in lowered_terms):
                hit_indexes.append(index)

        if hit_indexes:
            excerpt_blocks: List[str] = []
            ranges: List[str] = []
            used_chars = 0
            cursor = 0
            while cursor < len(hit_indexes) and len(excerpt_blocks) < 3:
                start = max(0, hit_indexes[cursor] - 2)
                end = min(len(lines), hit_indexes[cursor] + 3)
                cursor += 1
                while cursor < len(hit_indexes) and hit_indexes[cursor] <= end + 1:
                    end = min(len(lines), hit_indexes[cursor] + 3)
                    cursor += 1
                block = _build_numbered_excerpt(lines, start, end)
                extra_chars = len(block) + (5 if excerpt_blocks else 0)
                if excerpt_blocks and used_chars + extra_chars > max_chars:
                    return "\n...\n".join(excerpt_blocks), ranges, True
                if not excerpt_blocks and len(block) > max_chars:
                    clipped, _ = _clip_text_for_prompt(block, max_chars)
                    return clipped, [f"L{start + 1}-L{end}"], True
                excerpt_blocks.append(block)
                ranges.append(f"L{start + 1}-L{end}")
                used_chars += extra_chars
            return "\n...\n".join(excerpt_blocks), ranges, cursor < len(hit_indexes)

    preview_end = min(len(lines), 24)
    preview = _build_numbered_excerpt(lines, 0, preview_end)
    clipped, truncated = _clip_text_for_prompt(preview, max_chars)
    return clipped, [f"L1-L{preview_end}"], truncated or preview_end < len(lines)


def _build_workspace_retrieval_context(
    *,
    sample: Sample,
    original_text: str,
    recovered_text: str,
    messages: List[AnalystChatMessage],
    max_chars: int,
) -> tuple[str, List[AnalystChatRetrievedFile], bool, int]:
    """Retrieve the most relevant workspace files/snippets for the chat turn."""
    search_space = _build_workspace_search_space(
        sample=sample,
        original_text=original_text,
        recovered_text=recovered_text,
    )
    workspace_file_count = len(search_space)
    if not search_space or max_chars <= 0:
        return "", [], False, workspace_file_count

    path_terms, keyword_terms = _extract_workspace_query_terms(messages)
    scored_candidates = [
        {
            "candidate": candidate,
            "score": score,
            "matched_terms": matched_terms,
        }
        for candidate in search_space
        for score, matched_terms in [_score_workspace_candidate(
            candidate,
            path_terms=path_terms,
            keyword_terms=keyword_terms,
        )]
    ]
    scored_candidates.sort(
        key=lambda item: (-float(item["score"]), str(item["candidate"].get("path") or "")),
    )

    matched_candidates = [
        item for item in scored_candidates
        if item["matched_terms"] or float(item["score"]) >= 10.0
    ]
    selected_candidates = matched_candidates[:4] or scored_candidates[:4]
    if path_terms and selected_candidates:
        selected_keys = {
            (
                str(item["candidate"].get("path") or ""),
                str(item["candidate"].get("source") or ""),
            )
            for item in selected_candidates
        }
        for term in path_terms:
            normalised = term.lower()
            path_variants = [
                item for item in scored_candidates
                if (
                    str(item["candidate"].get("path") or "").lower() == normalised
                    or str(item["candidate"].get("path") or "").lower().endswith(normalised)
                )
            ]
            if len(path_variants) < 2:
                continue
            families = {
                _workspace_source_family(str(item["candidate"].get("source") or ""))
                for item in path_variants
            }
            if len(families) < 2:
                continue
            for item in path_variants:
                candidate_key = (
                    str(item["candidate"].get("path") or ""),
                    str(item["candidate"].get("source") or ""),
                )
                if candidate_key in selected_keys:
                    continue
                selected_candidates.append(item)
                selected_keys.add(candidate_key)
                if len(selected_candidates) >= 6:
                    break
            if len(selected_candidates) >= 6:
                break
    if not selected_candidates:
        return "", [], False, workspace_file_count

    per_file_budget = max(1_200, min(3_600, max_chars // max(1, len(selected_candidates))))
    prompt_sections: List[str] = []
    retrieved_files: List[AnalystChatRetrievedFile] = []
    context_truncated = False

    for item in selected_candidates:
        candidate = item["candidate"]
        matched_terms = list(item["matched_terms"])[:6]
        excerpt, line_ranges, excerpt_truncated = _extract_workspace_excerpt(
            candidate,
            matched_terms=matched_terms,
            max_chars=per_file_budget,
        )
        if not excerpt:
            continue
        source = str(candidate.get("source") or "archive_scan")
        source_label = {
            "recovered_bundle": "Recovered workspace file",
            "original_bundle": "Bundled original file",
            "archive_scan": "Original archive file",
        }.get(source, "Workspace file")
        language = str(candidate.get("language") or "plaintext")
        path = str(candidate.get("path") or "")
        source_tag = _retrieved_source_tag(source, path)
        prompt_sections.append(
            f"{source_label}: {path}\n"
            f"Source tag: [{source_tag}]\n"
            f"Matched terms: {', '.join(matched_terms) if matched_terms else 'workspace priority fallback'}\n"
            f"Line ranges: {', '.join(line_ranges) if line_ranges else 'excerpt only'}\n"
            f"Excerpt{' (truncated)' if excerpt_truncated else ''}:\n```{language}\n{excerpt}\n```"
        )
        retrieved_files.append(
            AnalystChatRetrievedFile(
                path=path,
                language=language,
                source=source,
                matched_terms=matched_terms,
                line_ranges=line_ranges,
                excerpt_truncated=excerpt_truncated,
            )
        )
        context_truncated = context_truncated or excerpt_truncated

    if not prompt_sections:
        return "", [], False, workspace_file_count

    retrieval_context = (
        f"Workspace search indexed {workspace_file_count} eligible file(s) for this sample.\n"
        "Retrieved workspace file excerpts for the current question:\n\n"
        + "\n\n".join(prompt_sections)
    )
    return retrieval_context, retrieved_files, context_truncated, workspace_file_count


async def _load_preferred_provider(db: AsyncSession) -> ProviderConfig | None:
    result = await db.execute(
        select(ProviderConfig)
        .where(ProviderConfig.is_active == True)  # noqa: E712
        .order_by(ProviderConfig.created_at.desc())
        .limit(1)
    )
    provider = result.scalar_one_or_none()
    if provider is not None:
        return provider

    result = await db.execute(
        select(ProviderConfig)
        .order_by(ProviderConfig.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _build_llm_client(provider: ProviderConfig) -> tuple[LLMClient, int]:
    context_window = _MAX_TOKENS_MAP.get(provider.max_tokens_preset, 131_072)
    return (
        LLMClient(
            base_url=provider.base_url,
            api_key=decrypt_value(provider.api_key_encrypted),
            model=provider.model_name,
            max_tokens=4096,
            context_window=context_window,
            cert_bundle=provider.cert_bundle_path,
            use_system_trust=provider.use_system_trust,
        ),
        context_window,
    )


def _build_workspace_context_section(latest_workspace_context: Dict[str, Any], original_text: str) -> str:
    workspace_summary = workspace_context_prompt(original_text)
    workspace_details: List[str] = []
    if isinstance(latest_workspace_context, dict):
        hotspots = latest_workspace_context.get("dependency_hotspots", []) or latest_workspace_context.get("symbol_hotspots", [])
        execution_paths = latest_workspace_context.get("execution_paths", [])
        graph_summary = latest_workspace_context.get("graph_summary", {})
        supported_file_count = latest_workspace_context.get("supported_file_count")
        targeted_file_count = latest_workspace_context.get("targeted_file_count")
        targeted_supported_ratio = latest_workspace_context.get("targeted_supported_ratio")
        supported_bundle_ratio = latest_workspace_context.get("supported_bundle_coverage_ratio")
        unsupported_languages = latest_workspace_context.get("unsupported_languages", [])
        coverage_scope_note = latest_workspace_context.get("coverage_scope_note")
        if hotspots:
            workspace_details.append(
                "Workspace hotspots: " + " | ".join(str(item) for item in hotspots[:6])
            )
        if execution_paths:
            workspace_details.append(
                "Execution paths: " + " | ".join(str(item) for item in execution_paths[:4])
            )
        if isinstance(graph_summary, dict) and graph_summary.get("cross_file_calls"):
            workspace_details.append(
                f"Cross-file calls: {graph_summary['cross_file_calls']}"
            )
        if isinstance(supported_file_count, int) and supported_file_count > 0:
            coverage_parts: List[str] = []
            if isinstance(targeted_file_count, int):
                coverage_parts.append(
                    f"Supported files targeted: {targeted_file_count}/{supported_file_count}"
                )
            if isinstance(targeted_supported_ratio, (int, float)):
                coverage_parts.append(
                    f"targeted coverage {round(float(targeted_supported_ratio) * 100)}%"
                )
            if isinstance(supported_bundle_ratio, (int, float)):
                coverage_parts.append(
                    f"bundled coverage {round(float(supported_bundle_ratio) * 100)}%"
                )
            if coverage_parts:
                workspace_details.append("Workspace coverage: " + ", ".join(coverage_parts))
        if isinstance(unsupported_languages, list) and unsupported_languages:
            workspace_details.append(
                "Unsupported languages visible in the scan: "
                + " | ".join(str(item) for item in unsupported_languages[:6])
            )
        if isinstance(coverage_scope_note, str) and coverage_scope_note.strip():
            workspace_details.append(coverage_scope_note.strip())
    if not workspace_summary and not workspace_details:
        return ""
    return (
        f"Workspace context:\n{workspace_summary}\n"
        + ("\n".join(workspace_details) + "\n\n" if workspace_details else "\n")
    )


def _combine_summary_sections(sections: Dict[str, str]) -> str:
    ordered_sections = [
        ("Deobfuscation Analysis", sections.get("deobfuscation_analysis", "")),
        ("Inferred Original Intent", sections.get("inferred_original_intent", "")),
        ("Actual Behavior", sections.get("actual_behavior", "")),
        ("Confidence Assessment", sections.get("confidence_assessment", "")),
    ]
    return "\n\n".join(
        f"{title}\n{body.strip()}"
        for title, body in ordered_sections
        if body and body.strip()
    )


def _parse_iteration_state_json(state_json: Any) -> Dict[str, Any] | None:
    if isinstance(state_json, dict):
        return dict(state_json)
    if isinstance(state_json, str):
        try:
            parsed = json.loads(state_json)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _serialise_iteration_record(record: IterationState) -> Dict[str, Any]:
    payload = _parse_iteration_state_json(record.state_json)
    state_json = (
        {
            key: value
            for key, value in payload.items()
            if key not in {"_code_snapshot", "_snapshot_meta"}
        }
        if payload is not None
        else record.state_json
    )
    code_snapshot = (
        payload.get("_code_snapshot")
        if payload is not None and isinstance(payload.get("_code_snapshot"), str)
        else None
    )
    snapshot_meta = (
        payload.get("_snapshot_meta")
        if payload is not None and isinstance(payload.get("_snapshot_meta"), dict)
        else {}
    )
    return {
        "id": record.id,
        "iteration_number": record.iteration_number,
        "state_json": state_json,
        "code_snapshot": code_snapshot,
        "snapshot_meta": snapshot_meta,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


def _infer_likely_intent(
    *,
    suspicious_apis: List[str],
    iocs: List[IOCRecord],
    findings: List[FindingRecord],
    recovered_text: str,
) -> str:
    lowered_apis = [api.lower() for api in suspicious_apis]
    lowered_text = recovered_text.lower()
    finding_text = " ".join(
        f"{f.title or ''} {f.description or ''} {f.evidence or ''}".lower()
        for f in findings
    )
    combined = " ".join(lowered_apis) + " " + lowered_text + " " + finding_text

    if any(token in combined for token in ("invoke-webrequest", "http", "https", "fetch(", "xmlhttprequest", "download")):
        return "The recovered code most likely tries to retrieve or exchange data over the network, suggesting a downloader, beacon, or remote payload fetch stage."
    if any(token in combined for token in ("powershell", "cmd.exe", "process.start", "createobject", "wscript.shell", "subprocess", "exec(", "eval(")):
        return "The recovered code most likely tries to stage or execute additional code, indicating a loader or execution wrapper around a secondary payload."
    if any(token in combined for token in ("registry", "regwrite", "autorun", "schtasks", "startup", "cron")):
        return "The recovered code most likely aims to establish persistence or system footholds after the obfuscation layer is removed."
    if any(token in combined for token in ("credential", "token", "cookie", "clipboard", "keylog")):
        return "The recovered code most likely attempts to collect or expose sensitive user or system data."
    if iocs:
        return "The recovered code most likely performs operational behavior tied to the extracted indicators of compromise, rather than being inert sample code."
    return "Based on the recovered logic, this looks like code intended to hide behavior behind layered obfuscation rather than a benign formatting or minification pass."


def _build_fallback_ai_summary(
    *,
    sample: Sample,
    detected_techniques: List[str],
    success_transforms: List[TransformHistory],
    reverted_transforms: List[TransformHistory],
    failed_transforms: List[TransformHistory],
    findings: List[FindingRecord],
    iocs: List[IOCRecord],
    strings: List[StringRecord],
    suspicious_apis: List[str],
    recovered_text: str,
    confidence_score: float | None,
    stop_reason: str | None = None,
    best_effort: bool = False,
    confidence_scope_note: str | None = None,
    result_kind: str | None = None,
) -> AISummaryReport:
    techniques_text = ", ".join(detected_techniques) if detected_techniques else "no explicit technique fingerprint was preserved in state"
    transform_names = ", ".join(t.action for t in success_transforms[:8]) if success_transforms else "no successful transforms were recorded"
    deobfuscation_analysis = (
        f"The sample appears to use {techniques_text}. "
        f"The deobfuscation pipeline produced {len(success_transforms)} successful transform(s), "
        f"{len(reverted_transforms)} reverted transform(s), and {len(failed_transforms)} failed attempt(s). "
        f"Successful steps included {transform_names}."
    )

    inferred_original_intent = _infer_likely_intent(
        suspicious_apis=suspicious_apis,
        iocs=iocs,
        findings=findings,
        recovered_text=recovered_text,
    )

    behavior_parts = [
        f"The recovered output is {len(recovered_text or '')} characters long.",
        f"{len(findings)} finding(s), {len(iocs)} IOC(s), and {len(strings)} extracted string(s) were captured from the analysis.",
    ]
    if suspicious_apis:
        behavior_parts.append(
            "Suspicious APIs observed in the recovered logic include "
            + ", ".join(suspicious_apis[:6])
            + "."
        )
    actual_behavior = " ".join(behavior_parts)

    if confidence_score is None:
        confidence_assessment = (
            "No final model confidence score was available, so confidence should be treated as qualitative only and validated against the recovered code and transform history."
        )
    else:
        confidence_pct = round(confidence_score * 100)
        confidence_assessment = (
            f"The current recovered output confidence is approximately {confidence_pct}%. "
            f"This should be read as confidence in the deobfuscated result, not certainty that every semantic detail is perfect."
        )
        if reverted_transforms or failed_transforms:
            confidence_assessment += " Reverted or failed transform attempts reduce certainty and suggest manual review is still warranted."
    if best_effort:
        kind_label = (result_kind or "partial_recovery").replace("_", " ")
        confidence_assessment += (
            f" The current output is a {kind_label} state rather than a guarantee of full semantic recovery."
        )
    if stop_reason:
        confidence_assessment += f" Run stop reason: {stop_reason}."
    if confidence_scope_note:
        confidence_assessment += f" {confidence_scope_note}"

    sections = AISummarySections(
        deobfuscation_analysis=deobfuscation_analysis,
        inferred_original_intent=inferred_original_intent,
        actual_behavior=actual_behavior,
        confidence_assessment=confidence_assessment,
    )
    return AISummaryReport(
        summary=_combine_summary_sections(sections.model_dump()),
        sections=sections,
        confidence_score=confidence_score,
    )


def _parse_ai_summary_sections(
    raw_text: str,
    *,
    fallback: AISummaryReport,
) -> AISummaryReport:
    candidate_text = raw_text.strip()
    payload: Dict[str, Any] | None = None

    for text in (candidate_text,):
        try:
            payload = json.loads(text)
            break
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if not match:
                continue
            try:
                payload = json.loads(match.group(0))
                break
            except json.JSONDecodeError:
                continue

    if not isinstance(payload, dict):
        sections = fallback.sections.model_dump()
        sections["deobfuscation_analysis"] = candidate_text or sections["deobfuscation_analysis"]
        return AISummaryReport(
            summary=_combine_summary_sections(sections),
            sections=AISummarySections(**sections),
            confidence_score=fallback.confidence_score,
        )

    sections_payload = payload.get("sections") if isinstance(payload.get("sections"), dict) else payload
    merged = fallback.sections.model_dump()
    for key in merged:
        value = sections_payload.get(key) if isinstance(sections_payload, dict) else None
        if isinstance(value, str) and value.strip():
            merged[key] = value.strip()

    confidence_value = payload.get("confidence_score")
    if not isinstance(confidence_value, (int, float)):
        confidence_value = fallback.confidence_score

    return AISummaryReport(
        summary=_combine_summary_sections(merged),
        sections=AISummarySections(**merged),
        confidence_score=float(confidence_value) if confidence_value is not None else None,
    )


async def _normalise_stale_pending_samples(
    db: AsyncSession,
    samples: List[Sample],
) -> None:
    """Repair legacy uploads stuck in pending without an active tracker."""
    changed = False
    for sample in samples:
        if sample.status != SampleStatus.PENDING.value:
            continue
        if get_analysis_status(sample.id) is not None:
            continue
        sample.status = SampleStatus.READY.value
        changed = True

    if changed:
        await db.commit()


# ── POST /api/projects/{project_id}/samples/upload ──────────────────
@router.post(
    "/projects/{project_id}/samples/upload",
    response_model=SampleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_sample(
    project_id: str,
    file: UploadFile = File(...),
    language: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Upload a code file or codebase archive as a new sample."""
    # Verify project exists
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )

    safe_name = _sanitize_filename(file.filename or "upload.txt")

    # Read file in chunks to enforce size limits before loading everything
    # into memory.  Use the archive limit as the upper bound — we refine
    # after we know whether the upload is an archive.
    hard_limit = _MAX_ARCHIVE_FILE_SIZE + 1  # read one byte past to detect oversize
    chunks: list[bytes] = []
    bytes_read = 0
    while True:
        chunk = await file.read(64 * 1024)  # 64 KB chunks
        if not chunk:
            break
        bytes_read += len(chunk)
        if bytes_read > hard_limit:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum size of {_MAX_ARCHIVE_FILE_SIZE // (1024 * 1024)} MB",
            )
        chunks.append(chunk)

    content_bytes = b"".join(chunks)
    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    archive_upload = is_archive_upload(safe_name, content_bytes)
    size_limit = _MAX_ARCHIVE_FILE_SIZE if archive_upload else _MAX_FILE_SIZE
    if len(content_bytes) > size_limit:
        limit_mb = size_limit // (1024 * 1024)
        kind = "Archive" if archive_upload else "File"
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{kind} exceeds maximum size of {limit_mb} MB",
        )

    sample_language = language
    content_kind = "archive_bundle" if archive_upload else "text"
    content_encoding = None
    if archive_upload:
        try:
            bundle = build_workspace_bundle(
                filename=safe_name,
                content_bytes=content_bytes,
                max_bundle_chars=settings.MAX_BUNDLED_SOURCE_SIZE,
                max_member_bytes=settings.MAX_ARCHIVE_MEMBER_SIZE,
                max_files=settings.MAX_ARCHIVE_FILES,
            )
        except WorkspaceBundleError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )
        original_text = bundle.bundle_text
        sample_language = bundle.language
        content_encoding = "workspace_bundle"
    else:
        content_kind = detect_upload_content_kind(safe_name, content_bytes)
        if content_kind == "dotnet_binary":
            original_text = binary_preview_text(safe_name, content_kind, len(content_bytes))
            sample_language = "dotnet"
            content_encoding = "binary"
        elif content_kind == "pe_binary":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Native binary uploads currently support .NET assemblies only.",
            )
        else:
            try:
                original_text = content_bytes.decode("utf-8")
                content_encoding = "utf-8"
            except UnicodeDecodeError:
                try:
                    original_text = content_bytes.decode("latin-1")
                    content_encoding = "latin-1"
                except UnicodeDecodeError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="File could not be decoded as UTF-8 or Latin-1 text",
                    )

    # Optionally persist the raw file to disk
    upload_dir = settings.ensure_upload_dir()
    disk_name = f"{uuid.uuid4().hex}_{safe_name}"
    disk_path = upload_dir / disk_name
    try:
        disk_path.write_bytes(content_bytes)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save uploaded file to disk: {exc}",
        )

    sample = Sample(
        project_id=project_id,
        filename=safe_name,
        original_text=original_text,
        language=sample_language,
        content_kind=content_kind,
        content_encoding=content_encoding,
        stored_file_path=str(disk_path),
        byte_size=len(content_bytes),
        status=SampleStatus.READY.value,
    )
    db.add(sample)
    await db.flush()
    await db.refresh(sample)
    return sample


# ── POST /api/projects/{project_id}/samples/paste ───────────────────
@router.post(
    "/projects/{project_id}/samples/paste",
    response_model=SampleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def paste_sample(
    project_id: str,
    body: _PasteBody,
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Create a new sample by pasting obfuscated text directly."""
    # Verify project
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )

    if not body.original_text or not body.original_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pasted text must not be empty",
        )

    if len(body.original_text.encode("utf-8")) > _MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Text exceeds maximum size of {_MAX_FILE_SIZE // (1024 * 1024)} MB",
        )

    sample = Sample(
        project_id=project_id,
        filename=body.filename or "paste.txt",
        original_text=body.original_text,
        language=body.language,
        status=SampleStatus.READY.value,
    )
    db.add(sample)
    await db.flush()
    await db.refresh(sample)
    return sample


# ── GET /api/projects/{project_id}/samples ──────────────────────────
@router.get(
    "/projects/{project_id}/samples",
    response_model=List[SampleResponse],
)
async def list_samples(
    project_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[Sample]:
    """List all samples in a project."""
    # Verify project
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )

    result = await db.execute(
        select(Sample)
        .where(Sample.project_id == project_id)
        .order_by(Sample.created_at.desc())
    )
    samples = list(result.scalars().all())
    await _normalise_stale_pending_samples(db, samples)
    return samples


# ── GET /api/samples/{id} ───────────────────────────────────────────
@router.get(
    "/samples/{sample_id}",
    response_model=SampleDetail,
)
async def get_sample(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Get full sample detail including recovered text and notes."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )
    await _normalise_stale_pending_samples(db, [sample])
    return sample


# ── GET /api/samples/{id}/original ──────────────────────────────────
@router.get("/samples/{sample_id}/original")
async def get_original_text(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return the original obfuscated text."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )
    return {"sample_id": sample_id, "original_text": sample.original_text}


# ── GET /api/samples/{id}/recovered ─────────────────────────────────
@router.get("/samples/{sample_id}/recovered")
async def get_recovered_text(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return the deobfuscated / recovered text."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )
    return {
        "sample_id": sample_id,
        "recovered_text": sample.recovered_text,
    }


# ── GET /api/samples/{id}/diff ──────────────────────────────────────
@router.get("/samples/{sample_id}/diff")
async def get_diff(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return a unified diff between original and recovered text."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    original_lines = (sample.original_text or "").splitlines(keepends=True)
    recovered_lines = (sample.recovered_text or "").splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        recovered_lines,
        fromfile="original",
        tofile="recovered",
        lineterm="",
    )
    diff_text = "\n".join(diff)

    return {
        "sample_id": sample_id,
        "diff": diff_text,
    }


# ── GET /api/samples/{id}/strings ───────────────────────────────────
@router.get("/samples/{sample_id}/strings")
async def get_strings(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return all extracted strings for this sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    result = await db.execute(
        select(StringRecord).where(StringRecord.sample_id == sample_id)
    )
    records = result.scalars().all()

    return {
        "sample_id": sample_id,
        "count": len(records),
        "strings": [
            {
                "id": r.id,
                "value": r.value,
                "encoding": r.encoding,
                "offset": r.offset,
                "context": r.context,
                "decoded": r.decoded,
            }
            for r in records
        ],
    }


# ── GET /api/samples/{id}/iocs ──────────────────────────────────────
@router.get("/samples/{sample_id}/iocs")
async def get_iocs(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return all IOCs extracted from this sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    result = await db.execute(
        select(IOCRecord).where(IOCRecord.sample_id == sample_id)
    )
    records = result.scalars().all()

    return {
        "sample_id": sample_id,
        "count": len(records),
        "iocs": [
            {
                "id": r.id,
                "type": r.ioc_type,
                "value": r.value,
                "context": r.context,
                "confidence": r.confidence,
            }
            for r in records
        ],
    }


# ── GET /api/samples/{id}/findings ──────────────────────────────────
@router.get("/samples/{sample_id}/findings")
async def get_findings(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return all findings for this sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    result = await db.execute(
        select(FindingRecord).where(FindingRecord.sample_id == sample_id)
    )
    records = result.scalars().all()

    return {
        "sample_id": sample_id,
        "count": len(records),
        "findings": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "description": r.description,
                "evidence": r.evidence,
                "confidence": r.confidence,
            }
            for r in records
        ],
    }


# ── GET /api/samples/{id}/transforms ────────────────────────────────
@router.get("/samples/{sample_id}/transforms")
async def get_transforms(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return the transform history for this sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    result = await db.execute(
        select(TransformHistory)
        .where(TransformHistory.sample_id == sample_id)
        .order_by(TransformHistory.iteration)
    )
    records = result.scalars().all()

    return {
        "sample_id": sample_id,
        "count": len(records),
        "transforms": [
            {
                "id": r.id,
                "iteration": r.iteration,
                "action": r.action,
                "reason": r.reason,
                "inputs": r.inputs,
                "outputs": r.outputs,
                "confidence_before": r.confidence_before,
                "confidence_after": r.confidence_after,
                "readability_before": r.readability_before,
                "readability_after": r.readability_after,
                "success": r.success,
                "retry_revert": r.retry_revert,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ],
    }


# ── GET /api/samples/{id}/iterations ────────────────────────────────
@router.get("/samples/{sample_id}/iterations")
async def get_iterations(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return the iteration state snapshots for this sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    result = await db.execute(
        select(IterationState)
        .where(IterationState.sample_id == sample_id)
        .order_by(IterationState.iteration_number)
    )
    records = result.scalars().all()

    return {
        "sample_id": sample_id,
        "count": len(records),
        "iterations": [_serialise_iteration_record(r) for r in records],
    }


# ── PUT /api/samples/{id}/notes ─────────────────────────────────────
@router.put("/samples/{sample_id}/notes")
async def save_notes(
    sample_id: str,
    payload: NotesSave,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Save or update analyst notes for a sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    sample.analyst_notes = payload.notes
    await db.flush()
    await db.refresh(sample)

    return {
        "sample_id": sample_id,
        "notes": sample.analyst_notes,
        "updated_at": sample.updated_at.isoformat() if sample.updated_at else None,
    }


# ── DELETE /api/samples/{id} ────────────────────────────────────────
@router.delete(
    "/samples/{sample_id}",
)
async def delete_sample(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a sample and all its related data (cascade)."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )
    await db.delete(sample)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── POST /api/samples/{id}/summary ─────────────────────────────────
@router.post(
    "/samples/{sample_id}/summary",
    response_model=AISummaryReport,
)
async def generate_summary(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> AISummaryReport:
    """Generate an AI-written analysis summary for a completed sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    # Gather analysis data
    transforms = (await db.execute(
        select(TransformHistory)
        .where(TransformHistory.sample_id == sample_id)
        .order_by(TransformHistory.iteration)
    )).scalars().all()

    findings = (await db.execute(
        select(FindingRecord)
        .where(FindingRecord.sample_id == sample_id)
    )).scalars().all()

    iocs = (await db.execute(
        select(IOCRecord)
        .where(IOCRecord.sample_id == sample_id)
    )).scalars().all()

    strings = (await db.execute(
        select(StringRecord)
        .where(StringRecord.sample_id == sample_id)
    )).scalars().all()

    # Get the latest iteration state for detected techniques
    iter_state_row = (await db.execute(
        select(IterationState)
        .where(IterationState.sample_id == sample_id)
        .order_by(IterationState.iteration_number.desc())
        .limit(1)
    )).scalar_one_or_none()

    detected_techniques: List[str] = []
    suspicious_apis: List[str] = []
    confidence_score: float | None = None
    latest_workspace_context: Dict[str, Any] = {}
    result_metadata: Dict[str, Any] = {}
    if iter_state_row and iter_state_row.state_json:
        try:
            state_data = iter_state_row.state_json
            if isinstance(state_data, str):
                state_data = json.loads(state_data)
            detected_techniques = state_data.get("detected_techniques", [])
            suspicious_apis = state_data.get("suspicious_apis", [])
            result_metadata = extract_result_metadata_from_state(state_data)
            confidence_score = result_metadata.get("confidence_score")
            latest_workspace_context = state_data.get("workspace_context", {})
        except Exception:
            pass

    # Build analysis context for the LLM
    success_transforms = [t for t in transforms if t.success and not t.retry_revert]
    failed_transforms = [t for t in transforms if not t.success]
    reverted_transforms = [t for t in transforms if t.retry_revert]

    original_text = sample.original_text or ""
    recovered_text = sample.recovered_text or ""
    original_snippet = truncate_workspace_bundle(original_text, 2000)
    recovered_snippet = truncate_workspace_bundle(recovered_text, 2000)
    workspace_context_section = _build_workspace_context_section(
        latest_workspace_context,
        original_text,
    )

    context = (
        f"Filename: {sample.filename}\n"
        f"Language: {sample.language or 'unknown'}\n"
        f"Original code length: {len(original_text)} chars\n"
        f"Recovered code length: {len(recovered_text)} chars\n\n"
        f"{workspace_context_section}"
        f"Detected obfuscation techniques: {detected_techniques}\n\n"
        f"Suspicious APIs: {suspicious_apis}\n"
        f"Recovered output confidence: {confidence_score}\n\n"
        f"Recovered output kind: {result_metadata.get('result_kind')}\n"
        f"Best-effort output: {result_metadata.get('best_effort')}\n"
        f"Stop reason: {result_metadata.get('stop_reason')}\n"
        f"Confidence scope note: {result_metadata.get('confidence_scope_note')}\n\n"
        f"Transform results: {len(success_transforms)} successful, "
        f"{len(reverted_transforms)} reverted, {len(failed_transforms)} failed\n"
        f"Successful transforms: {[t.action for t in success_transforms]}\n\n"
        f"Findings: {len(findings)}\n"
        f"IOCs extracted: {len(iocs)}\n"
        f"Strings extracted: {len(strings)}\n\n"
        f"--- Original code (first 2000 chars) ---\n{original_snippet}\n\n"
        f"--- Recovered code (first 2000 chars) ---\n{recovered_snippet}\n"
    )

    # Load LLM client
    provider = await _load_preferred_provider(db)

    if provider is None:
        summary = _build_fallback_ai_summary(
            sample=sample,
            detected_techniques=detected_techniques,
            success_transforms=success_transforms,
            reverted_transforms=reverted_transforms,
            failed_transforms=failed_transforms,
            findings=findings,
            iocs=iocs,
            strings=strings,
            suspicious_apis=suspicious_apis,
            recovered_text=recovered_text,
            confidence_score=confidence_score,
            stop_reason=result_metadata.get("stop_reason"),
            best_effort=bool(result_metadata.get("best_effort")),
            confidence_scope_note=result_metadata.get("confidence_scope_note"),
            result_kind=result_metadata.get("result_kind"),
        )
        await persist_saved_analysis_snapshot(
            db,
            sample,
            ai_summary=summary,
            keep_existing_ai_summary=False,
        )
        return summary

    fallback_summary = _build_fallback_ai_summary(
        sample=sample,
        detected_techniques=detected_techniques,
        success_transforms=success_transforms,
        reverted_transforms=reverted_transforms,
        failed_transforms=failed_transforms,
        findings=findings,
        iocs=iocs,
        strings=strings,
        suspicious_apis=suspicious_apis,
        recovered_text=recovered_text,
        confidence_score=confidence_score,
        stop_reason=result_metadata.get("stop_reason"),
        best_effort=bool(result_metadata.get("best_effort")),
        confidence_scope_note=result_metadata.get("confidence_scope_note"),
        result_kind=result_metadata.get("result_kind"),
    )

    client, _ = _build_llm_client(provider)

    prompt = (
        "You are a senior reverse engineer writing a structured deobfuscation assessment. "
        "Return valid JSON only, with these top-level keys exactly:\n"
        "{\n"
        '  "deobfuscation_analysis": string,\n'
        '  "inferred_original_intent": string,\n'
        '  "actual_behavior": string,\n'
        '  "confidence_assessment": string,\n'
        '  "confidence_score": number\n'
        "}\n\n"
        "Requirements:\n"
        "- deobfuscation_analysis: explain what obfuscation was present and how the deobfuscation progressed.\n"
        "- inferred_original_intent: infer what the original author likely wanted the code to do.\n"
        "- actual_behavior: describe what the recovered code now appears to do.\n"
        "- confidence_assessment: explain how confident you are in the recovered output and why.\n"
        "- confidence_score: a number from 0.0 to 1.0 representing your confidence in the recovered output.\n"
        "- Be specific, technical, and concise. Mention uncertainty where appropriate.\n\n"
        "--- Example output for a simple base64 + eval() dropper ---\n"
        "{\n"
        '  "deobfuscation_analysis": "The sample used two layers of obfuscation: '
        "an outer base64-encoded string passed to eval(), wrapping an inner "
        "hex-encoded payload. The base64 layer was decoded in iteration 1, "
        'revealing the hex payload which was decoded in iteration 2.",\n'
        '  "inferred_original_intent": "The code was designed to download and '
        "execute a second-stage payload from a remote C2 server while evading "
        'static analysis through encoding layers.",\n'
        '  "actual_behavior": "The recovered code constructs an HTTP request to '
        "hxxp://198.51.100.42/payload.bin, writes the response to a temporary "
        'file, and executes it via WScript.Shell.",\n'
        '  "confidence_assessment": "High confidence (0.85). Both encoding layers '
        "were fully decoded with deterministic transforms. The recovered control "
        "flow is structurally complete and the C2 URL is clearly visible. Minor "
        "uncertainty remains around whether additional runtime checks were present "
        'before the encoding.",\n'
        '  "confidence_score": 0.85\n'
        "}\n\n"
        "--- Example output for partially deobfuscated PowerShell ---\n"
        "{\n"
        '  "deobfuscation_analysis": "The sample used Invoke-Obfuscation with '
        "string reversal, backtick insertion, and variable-based concatenation. "
        "Backtick removal and string reversal were successfully applied. However, "
        "the inner payload uses a custom XOR routine with a key derived at runtime "
        'from environment variables, which could not be statically resolved.",\n'
        '  "inferred_original_intent": "Credential harvesting from browser '
        'password stores, staged via a PowerShell download cradle.",\n'
        '  "actual_behavior": "The outer download cradle is fully recovered '
        "(IEX + DownloadString from a staging URL). The inner payload remains "
        "partially obfuscated due to environment-keyed XOR decryption that "
        'requires runtime context to resolve.",\n'
        '  "confidence_assessment": "Moderate confidence (0.55). The download '
        "mechanism is clear but the final payload is only partially recovered. "
        "The XOR key depends on $env:COMPUTERNAME which cannot be determined "
        'statically.",\n'
        '  "confidence_score": 0.55\n'
        "}\n\n"
        f"{context}"
    )

    try:
        reply = await client.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=2048,
        )
        summary = _parse_ai_summary_sections(reply, fallback=fallback_summary)
        await persist_saved_analysis_snapshot(
            db,
            sample,
            ai_summary=summary,
            keep_existing_ai_summary=False,
        )
        return summary
    except Exception as exc:
        logger.error("Failed to generate AI summary: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM request failed: {type(exc).__name__}: {exc}",
        )


# ── POST /api/samples/{id}/chat ────────────────────────────────────
@router.post(
    "/samples/{sample_id}/chat",
    response_model=AnalystChatResponse,
)
async def chat_about_sample(
    sample_id: str,
    payload: AnalystChatRequest,
    db: AsyncSession = Depends(get_db),
) -> AnalystChatResponse:
    """Ask the configured LLM questions about a sample and its recovered output."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} not found",
        )

    provider = await _load_preferred_provider(db)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No AI provider is configured for analyst chat",
        )

    transforms = (await db.execute(
        select(TransformHistory)
        .where(TransformHistory.sample_id == sample_id)
        .order_by(TransformHistory.iteration)
    )).scalars().all()
    findings = (await db.execute(
        select(FindingRecord)
        .where(FindingRecord.sample_id == sample_id)
    )).scalars().all()
    iocs = (await db.execute(
        select(IOCRecord)
        .where(IOCRecord.sample_id == sample_id)
    )).scalars().all()
    strings = (await db.execute(
        select(StringRecord)
        .where(StringRecord.sample_id == sample_id)
    )).scalars().all()
    iter_state_row = (await db.execute(
        select(IterationState)
        .where(IterationState.sample_id == sample_id)
        .order_by(IterationState.iteration_number.desc())
        .limit(1)
    )).scalar_one_or_none()

    detected_techniques: List[str] = []
    suspicious_apis: List[str] = []
    confidence_score: float | None = None
    latest_workspace_context: Dict[str, Any] = {}
    result_metadata: Dict[str, Any] = {}
    if iter_state_row and iter_state_row.state_json:
        state_data = _parse_iteration_state_json(iter_state_row.state_json)
        if isinstance(state_data, dict):
            detected_techniques = state_data.get("detected_techniques", []) or []
            suspicious_apis = state_data.get("suspicious_apis", []) or []
            result_metadata = extract_result_metadata_from_state(state_data)
            confidence_score = result_metadata.get("confidence_score")
            latest_workspace_context = state_data.get("workspace_context", {}) or {}

    client, context_window = _build_llm_client(provider)
    original_text = sample.original_text or ""
    recovered_text = sample.recovered_text or ""
    workspace_sample = (
        sample.content_kind == "archive_bundle"
        or original_text.startswith(WORKSPACE_BUNDLE_HEADER)
        or recovered_text.startswith(WORKSPACE_BUNDLE_HEADER)
    )

    # Reserve space for instructions, transcript, and reply before filling code context.
    code_budget = max(16_000, min(context_window * 3 // 2, 180_000))
    retrieval_budget = max(0, int(code_budget * 0.34)) if workspace_sample else 0
    original_budget = max(6_000, int(code_budget * (0.26 if workspace_sample else 0.45)))
    recovered_budget = max(6_000, int(code_budget * (0.24 if workspace_sample else 0.45)))
    original_context, original_truncated = _clip_code_context_for_prompt(original_text, original_budget)
    recovered_context, recovered_truncated = _clip_code_context_for_prompt(recovered_text, recovered_budget)
    retrieved_workspace_context = ""
    retrieved_files: List[AnalystChatRetrievedFile] = []
    workspace_search_enabled = False
    workspace_file_count = 0
    retrieval_truncated = False
    if workspace_sample:
        retrieved_workspace_context, retrieved_files, retrieval_truncated, workspace_file_count = _build_workspace_retrieval_context(
            sample=sample,
            original_text=original_text,
            recovered_text=recovered_text,
            messages=payload.messages,
            max_chars=retrieval_budget,
        )
        workspace_search_enabled = workspace_file_count > 0
    context_truncated = original_truncated or recovered_truncated or retrieval_truncated

    workspace_context_section = _build_workspace_context_section(
        latest_workspace_context,
        original_text,
    )
    transform_summary = "\n".join(
        f"- iter {transform.iteration}: {transform.action} ({'success' if transform.success and not transform.retry_revert else 'reverted' if transform.retry_revert else 'failed'})"
        for transform in transforms[:20]
    ) or "- none recorded"
    finding_summary = "\n".join(
        f"- [{finding.severity}] {finding.title}: {finding.description}"
        for finding in findings[:12]
    ) or "- none recorded"
    ioc_summary = "\n".join(
        f"- {ioc.type}: {ioc.value}"
        for ioc in iocs[:20]
    ) or "- none recorded"
    string_summary = "\n".join(
        f"- {truncate_workspace_bundle(string.value, 140)}"
        for string in strings[:12]
        if string.value
    ) or "- none recorded"

    system_prompt = (
        "You are Unweaver's analyst chat. Answer questions about the uploaded sample, "
        "the original code, the recovered code, and the analysis artifacts. "
        "Use only the provided sample context, retrieved workspace excerpts, and transcript. "
        "If the recovered output is incomplete, say so clearly. "
        "Distinguish carefully between original and recovered code; do not blur them together unless they materially match. "
        "For workspace uploads, retrieved file excerpts are the strongest project-level evidence available for this turn. "
        "If the user asks about files that were not retrieved or are unavailable, say so clearly. "
        "For concrete claims, cite the source inline using short tags such as [original], [recovered], [analysis], "
        "or [retrieved:recovered:path/to/file], [retrieved:original:path/to/file], or [retrieved:archive:path/to/file]. "
        "If a claim depends on multiple sources, cite all relevant tags. "
        "If the evidence is partial, say so and cite the closest available source rather than overstating certainty. "
        "Never reveal chain-of-thought, hidden reasoning, or <think> tags. "
        "Do not narrate internal analysis steps. "
        "Render answers in clean Markdown for the in-app chat UI. "
        "You may use short headings, bullet lists, numbered lists, tables, blockquotes for caveats, "
        "and fenced code blocks with language tags. "
        "Use formatting deliberately to improve readability, not decoration. "
        "Do not use raw HTML. "
        "When quoting code, use fenced code blocks with a language tag when obvious. "
        "Prefer concise, technically grounded answers."
    )
    sample_context_parts = [
        f"Sample filename: {sample.filename}\n"
        f"Language: {sample.language or 'unknown'}\n"
        f"Status: {sample.status}\n"
        f"Original length: {len(original_text)} chars\n"
        f"Recovered length: {len(recovered_text)} chars\n"
        f"Recovered confidence: {confidence_score}\n"
        f"Recovered output kind: {result_metadata.get('result_kind')}\n"
        f"Best-effort output: {result_metadata.get('best_effort')}\n"
        f"Stop reason: {result_metadata.get('stop_reason')}\n"
        f"Confidence scope note: {result_metadata.get('confidence_scope_note')}\n"
        f"Detected techniques: {detected_techniques or ['none recorded']}\n"
        f"Suspicious APIs: {suspicious_apis or ['none recorded']}\n"
        "Source tag guide: [original] = uploaded source, [recovered] = deobfuscated output, "
        "[analysis] = transforms/findings/IOCs/strings/workspace context, "
        "[retrieved:recovered:path] = recovered workspace file excerpt, "
        "[retrieved:original:path] = bundled original workspace file excerpt, "
        "[retrieved:archive:path] = original archive file excerpt.\n\n",
        workspace_context_section,
    ]
    if retrieved_workspace_context:
        sample_context_parts.append(f"{retrieved_workspace_context}\n\n")
    sample_context_parts.extend(
        [
            "Transform history:\n",
            f"{transform_summary}\n\n",
            "Findings:\n",
            f"{finding_summary}\n\n",
            "IOCs:\n",
            f"{ioc_summary}\n\n",
            "Recovered strings:\n",
            f"{string_summary}\n\n",
            f"Original code{' (truncated)' if original_truncated else ''}:\n```{sample.language or ''}\n{original_context}\n```\n\n",
            f"Recovered code{' (truncated)' if recovered_truncated else ''}:\n```{sample.language or ''}\n{recovered_context}\n```",
        ]
    )
    sample_context = "".join(sample_context_parts)

    transcript = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": sample_context},
        *[
            {"role": message.role, "content": message.content.strip()}
            for message in payload.messages[-16:]
            if message.content.strip()
        ],
    ]

    if not any(message["role"] == "user" for message in transcript):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one user message is required",
        )

    try:
        reply = await client.chat(
            messages=transcript,
            temperature=0.2,
            max_tokens=1800,
        )
    except Exception as exc:
        logger.error("Failed to generate analyst chat reply: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM request failed: {type(exc).__name__}: {exc}",
        )

    cleaned_reply = re.sub(r"<think>[\s\S]*?</think>", "", reply, flags=re.IGNORECASE).strip()
    if not cleaned_reply:
        cleaned_reply = "No final answer was returned by the model."
    cleaned_reply = _normalise_chat_source_tags(
        cleaned_reply,
        retrieved_files=retrieved_files,
    )

    return AnalystChatResponse(
        answer=cleaned_reply,
        provider_name=provider.name,
        model_name=provider.model_name,
        context_truncated=context_truncated,
        workspace_search_enabled=workspace_search_enabled,
        workspace_file_count=workspace_file_count,
        retrieved_files=retrieved_files,
    )
