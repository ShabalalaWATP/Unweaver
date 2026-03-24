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
    NotesSave,
    SampleDetail,
    SampleResponse,
    SampleStatus,
)
from app.services.ingest.workspace_bundle import (
    WorkspaceBundleError,
    build_workspace_bundle,
    extract_workspace_context,
    is_archive_upload,
    truncate_workspace_bundle,
    workspace_context_prompt,
)
from app.services.llm.client import LLMClient, _MAX_TOKENS_MAP
from app.services.reports.saved_analysis import persist_saved_analysis_snapshot
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
    else:
        try:
            original_text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                original_text = content_bytes.decode("latin-1")
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
        "iterations": [
            {
                "id": r.id,
                "iteration_number": r.iteration_number,
                "state_json": r.state_json,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ],
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
    if iter_state_row and iter_state_row.state_json:
        try:
            state_data = iter_state_row.state_json
            if isinstance(state_data, str):
                state_data = json.loads(state_data)
            detected_techniques = state_data.get("detected_techniques", [])
            suspicious_apis = state_data.get("suspicious_apis", [])
            confidence_score = state_data.get("confidence", {}).get("overall")
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
    workspace_summary = workspace_context_prompt(original_text)
    workspace_details: List[str] = []
    if isinstance(latest_workspace_context, dict):
        hotspots = latest_workspace_context.get("dependency_hotspots", []) or latest_workspace_context.get("symbol_hotspots", [])
        execution_paths = latest_workspace_context.get("execution_paths", [])
        graph_summary = latest_workspace_context.get("graph_summary", {})
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
    workspace_context_section = (
        f"Workspace context:\n{workspace_summary}\n"
        + ("\n".join(workspace_details) + "\n\n" if workspace_details else "\n")
        if workspace_summary or workspace_details
        else ""
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
    result = await db.execute(
        select(ProviderConfig)
        .where(ProviderConfig.is_active == True)  # noqa: E712
        .order_by(ProviderConfig.created_at.desc())
        .limit(1)
    )
    provider = result.scalar_one_or_none()
    if provider is None:
        result = await db.execute(
            select(ProviderConfig)
            .order_by(ProviderConfig.created_at.desc())
            .limit(1)
        )
        provider = result.scalar_one_or_none()

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
    )

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
