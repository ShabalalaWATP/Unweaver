"""
LLM provider settings endpoints.

Manage OpenAI-compatible LLM provider configurations.  API keys are
stored in the database and are **always** masked when returned to the
client (first 4 + last 4 characters visible).
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Response,
    UploadFile,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models.db_models import ProviderConfig
from app.models.schemas import (
    ProviderSettingsCreate,
    ProviderSettingsResponse,
)
from app.services.llm.client import LLMClient, _MAX_TOKENS_MAP

router = APIRouter(tags=["providers"])


def _mask_key(raw: str) -> str:
    """Mask an API key, showing only the first 4 and last 4 characters."""
    if not raw:
        return ""
    if len(raw) <= 8:
        return "****"
    return f"{raw[:4]}{'*' * (len(raw) - 8)}{raw[-4:]}"


def _provider_to_response(p: ProviderConfig) -> Dict[str, Any]:
    """Convert a ProviderConfig ORM object to a response dict."""
    return {
        "id": p.id,
        "name": p.name,
        "base_url": p.base_url,
        "model_name": p.model_name,
        "api_key_masked": _mask_key(p.api_key_encrypted),
        "cert_bundle_path": p.cert_bundle_path,
        "use_system_trust": p.use_system_trust,
        "max_tokens_preset": p.max_tokens_preset,
        "is_active": p.is_active,
        "created_at": p.created_at,
    }


# ── POST /api/providers ─────────────────────────────────────────────
@router.post(
    "/providers",
    response_model=ProviderSettingsResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider(
    payload: ProviderSettingsCreate,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Create a new LLM provider configuration."""
    # Check for duplicate name
    existing = await db.execute(
        select(ProviderConfig).where(ProviderConfig.name == payload.name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A provider with name '{payload.name}' already exists",
        )

    provider = ProviderConfig(
        name=payload.name,
        base_url=payload.base_url,
        model_name=payload.model_name,
        api_key_encrypted=payload.api_key,
        cert_bundle_path=payload.cert_bundle_path,
        use_system_trust=payload.use_system_trust,
        max_tokens_preset=payload.max_tokens_preset,
    )
    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return _provider_to_response(provider)


# ── GET /api/providers ───────────────────────────────────────────────
@router.get(
    "/providers",
    response_model=List[ProviderSettingsResponse],
)
async def list_providers(
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List all configured LLM providers (API keys masked)."""
    result = await db.execute(
        select(ProviderConfig).order_by(ProviderConfig.created_at.desc())
    )
    providers = result.scalars().all()
    return [_provider_to_response(p) for p in providers]


# ── GET /api/providers/{id} ─────────────────────────────────────────
@router.get(
    "/providers/{provider_id}",
    response_model=ProviderSettingsResponse,
)
async def get_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get a single provider configuration (API key masked)."""
    provider = await db.get(ProviderConfig, provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider {provider_id} not found",
        )
    return _provider_to_response(provider)


# ── PUT /api/providers/{id} ─────────────────────────────────────────
@router.put(
    "/providers/{provider_id}",
    response_model=ProviderSettingsResponse,
)
async def update_provider(
    provider_id: str,
    payload: ProviderSettingsCreate,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Update an existing provider configuration."""
    provider = await db.get(ProviderConfig, provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider {provider_id} not found",
        )

    # Check name uniqueness if changed
    if payload.name != provider.name:
        existing = await db.execute(
            select(ProviderConfig).where(
                ProviderConfig.name == payload.name,
                ProviderConfig.id != provider_id,
            )
        )
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A provider with name '{payload.name}' already exists",
            )

    provider.name = payload.name
    provider.base_url = payload.base_url
    provider.model_name = payload.model_name
    provider.cert_bundle_path = payload.cert_bundle_path
    provider.use_system_trust = payload.use_system_trust
    provider.max_tokens_preset = payload.max_tokens_preset

    # Only update the API key if a non-empty value was provided
    # (so the frontend can send an empty string to mean "keep existing")
    if payload.api_key:
        provider.api_key_encrypted = payload.api_key

    await db.flush()
    await db.refresh(provider)
    return _provider_to_response(provider)


# ── DELETE /api/providers/{id} ──────────────────────────────────────
@router.delete(
    "/providers/{provider_id}",
)
async def delete_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a provider configuration."""
    provider = await db.get(ProviderConfig, provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider {provider_id} not found",
        )
    await db.delete(provider)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── POST /api/providers/{id}/test ───────────────────────────────────
@router.post("/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Test connectivity to an LLM provider by sending a simple message."""
    provider = await db.get(ProviderConfig, provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider {provider_id} not found",
        )

    max_tokens = _MAX_TOKENS_MAP.get(provider.max_tokens_preset, 4096)
    client = LLMClient(
        base_url=provider.base_url,
        api_key=provider.api_key_encrypted,
        model=provider.model_name,
        max_tokens=max_tokens,
        cert_bundle=provider.cert_bundle_path,
        use_system_trust=provider.use_system_trust,
    )

    success, message = await client.test_connection()

    return {
        "provider_id": provider_id,
        "success": success,
        "message": message,
    }


# ── POST /api/providers/{id}/upload-cert ────────────────────────────
@router.post("/providers/{provider_id}/upload-cert")
async def upload_cert(
    provider_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Upload a custom CA certificate bundle for an LLM provider.

    The file is saved to the uploads directory and the provider's
    ``cert_bundle_path`` is updated.
    """
    provider = await db.get(ProviderConfig, provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider {provider_id} not found",
        )

    # Read and validate
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # Limit cert files to 1 MB
    if len(content) > 1 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Certificate bundle exceeds 1 MB limit",
        )

    # Basic sanity check: PEM files start with -----BEGIN
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = ""

    if not text.strip().startswith("-----BEGIN"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File does not appear to be a PEM-format certificate bundle",
        )

    # Save to disk
    upload_dir = settings.ensure_upload_dir()
    certs_dir = upload_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{uuid.uuid4().hex}.pem"
    cert_path = certs_dir / safe_name
    try:
        cert_path.write_bytes(content)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save certificate to disk: {exc}",
        )

    # Update provider
    provider.cert_bundle_path = str(cert_path)
    await db.flush()
    await db.refresh(provider)

    return {
        "provider_id": provider_id,
        "cert_bundle_path": str(cert_path),
        "message": "Certificate bundle uploaded successfully",
    }
