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
    NotesSave,
    SampleDetail,
    SampleResponse,
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

    # Read file once, then branch based on whether this is a code archive.
    content_bytes = await file.read()
    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    safe_name = _sanitize_filename(file.filename or "upload.txt")
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
    return list(result.scalars().all())


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
@router.post("/samples/{sample_id}/summary")
async def generate_summary(
    sample_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
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
    if iter_state_row and iter_state_row.state_json:
        try:
            state_data = iter_state_row.state_json
            if isinstance(state_data, str):
                state_data = json.loads(state_data)
            detected_techniques = state_data.get("detected_techniques", [])
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
    workspace_context_section = (
        f"Workspace context:\n{workspace_summary}\n\n" if workspace_summary else ""
    )

    context = (
        f"Filename: {sample.filename}\n"
        f"Language: {sample.language or 'unknown'}\n"
        f"Original code length: {len(original_text)} chars\n"
        f"Recovered code length: {len(recovered_text)} chars\n\n"
        f"{workspace_context_section}"
        f"Detected obfuscation techniques: {detected_techniques}\n\n"
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
        # No LLM available — generate a basic summary from data
        workspace_context = extract_workspace_context(original_text)
        summary_parts = [
            f"Analysis of {sample.filename} ({sample.language or 'unknown'} code).",
            f"\nDeobfuscation applied {len(success_transforms)} successful transform(s) "
            f"across {len(transforms)} total attempt(s).",
        ]
        if workspace_context:
            summary_parts.append(
                f"\nWorkspace bundle included {workspace_context.get('included_files') or 0} "
                f"prioritized file(s) from {workspace_context.get('archive_name') or sample.filename}."
            )
        if detected_techniques:
            summary_parts.append(
                f"\nDetected techniques: {', '.join(detected_techniques)}."
            )
        if findings:
            summary_parts.append(f"\n{len(findings)} security finding(s) identified.")
        if iocs:
            summary_parts.append(f"\n{len(iocs)} indicator(s) of compromise extracted.")
        return {"summary": " ".join(summary_parts)}

    max_tokens = _MAX_TOKENS_MAP.get(provider.max_tokens_preset, 4096)
    client = LLMClient(
        base_url=provider.base_url,
        api_key=provider.api_key_encrypted,
        model=provider.model_name,
        max_tokens=max_tokens,
        cert_bundle=provider.cert_bundle_path,
        use_system_trust=provider.use_system_trust,
    )

    prompt = (
        "You are a malware analyst writing a deobfuscation report summary. "
        "Based on the following analysis data, write a clear, professional "
        "summary (3-5 paragraphs) covering:\n"
        "1. What the code is and what obfuscation was used\n"
        "2. What the deobfuscation engine did (transforms applied)\n"
        "3. Key findings and any IOCs discovered\n"
        "4. Overall assessment of the recovered code\n\n"
        "Be specific and reference actual data from the analysis. "
        "Write in a technical but readable style.\n\n"
        f"{context}"
    )

    try:
        reply = await client.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=2048,
        )
        return {"summary": reply.strip()}
    except Exception as exc:
        logger.error("Failed to generate AI summary: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM request failed: {type(exc).__name__}: {exc}",
        )
