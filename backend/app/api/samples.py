"""
Sample management endpoints.

Samples are individual obfuscated code files or text snippets that live
inside a project.  They can be uploaded as files or pasted directly.
"""

from __future__ import annotations

import difflib
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
    Sample,
    StringRecord,
    TransformHistory,
)
from app.models.schemas import (
    NotesSave,
    SampleDetail,
    SampleResponse,
)

from pydantic import BaseModel, Field


class _PasteBody(BaseModel):
    """JSON body for the paste-sample endpoint."""
    filename: str | None = "paste.txt"
    original_text: str = Field(..., min_length=1)
    language: str | None = None

router = APIRouter(tags=["samples"])

# Maximum file size (5 MB)
_MAX_FILE_SIZE = settings.MAX_FILE_SIZE

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
    """Upload an obfuscated code file as a new sample."""
    # Verify project exists
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )

    # Read file with size check
    content_bytes = await file.read()
    if len(content_bytes) > _MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {_MAX_FILE_SIZE // (1024 * 1024)} MB",
        )

    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # Decode to text
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

    safe_name = _sanitize_filename(file.filename or "upload.txt")

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
        language=language,
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
