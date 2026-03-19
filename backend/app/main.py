"""
Unweaver API -- FastAPI application entry point.

Run with:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.analysis import router as analysis_router
from app.api.export import router as export_router
from app.api.projects import router as projects_router
from app.api.providers import router as providers_router
from app.api.samples import router as samples_router
from app.core.config import settings
from app.core.database import init_db

logger = logging.getLogger(__name__)


# ── Lifespan (startup / shutdown) ────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Run one-time setup on startup and teardown on shutdown."""
    # Startup
    logger.info("Initialising database ...")
    await init_db()

    logger.info("Ensuring upload directory exists at %s", settings.UPLOAD_DIR)
    settings.ensure_upload_dir()

    logger.info("Unweaver API ready.")
    yield
    # Shutdown (nothing to clean up for now)
    logger.info("Unweaver API shutting down.")


# ── Application factory ─────────────────────────────────────────────
app = FastAPI(
    title="Unweaver API",
    description=(
        "Code deobfuscation workbench API.  Upload obfuscated scripts, "
        "run iterative LLM-assisted analysis, and export structured reports."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


# ── CORS ─────────────────────────────────────────────────────────────
_ALLOWED_ORIGINS = [
    "http://localhost:5173",   # Vite dev server
    "http://127.0.0.1:5173",
    "http://localhost:3000",   # common alternative
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ──────────────────────────────────────────────────────────
app.include_router(projects_router, prefix="/api")
app.include_router(samples_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(providers_router, prefix="/api")
app.include_router(export_router, prefix="/api")


# ── Health check ─────────────────────────────────────────────────────
@app.get("/api/health", tags=["system"])
async def health_check() -> Dict[str, Any]:
    """Simple liveness probe."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": app.version,
    }


# ── Global exception handlers ───────────────────────────────────────
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    """Catch stray ValueErrors and return 400 instead of 500."""
    logger.warning("ValueError on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(PermissionError)
async def permission_error_handler(
    request: Request, exc: PermissionError
) -> JSONResponse:
    """Catch permission errors (e.g. file-system issues)."""
    logger.error("PermissionError on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": "Permission denied"},
    )


@app.exception_handler(FileNotFoundError)
async def file_not_found_handler(
    request: Request, exc: FileNotFoundError
) -> JSONResponse:
    """Catch missing-file errors."""
    logger.warning("FileNotFoundError on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": "Requested resource not found"},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Last-resort handler -- log the full traceback but return a safe message."""
    logger.exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
