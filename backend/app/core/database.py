"""
Async SQLite database setup via SQLAlchemy + aiosqlite.

Provides:
    engine          – the async engine bound to the configured DATABASE_URL
    async_session   – a session factory (async_sessionmaker)
    Base            – declarative base for ORM models
    get_db()        – FastAPI dependency that yields an AsyncSession
    init_db()       – creates all tables on first startup
"""

from __future__ import annotations

import logging
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Engine ──────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    # SQLite-specific: allow the same connection across threads when using
    # the async driver (aiosqlite runs in a thread-pool internally).
    connect_args={"check_same_thread": False},
)

# ── Session factory ─────────────────────────────────────────────────────
async_session = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Declarative base ───────────────────────────────────────────────────
class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


# ── FastAPI dependency ──────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session and ensure it is closed afterwards."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Table creation ──────────────────────────────────────────────────────
async def init_db() -> None:
    """Create all tables that do not yet exist.

    Import the ORM models module so that every model is registered on
    ``Base.metadata`` before ``create_all`` is called.
    """
    import app.models.db_models  # noqa: F401  — registers models on Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_runtime_columns(conn)


async def _ensure_runtime_columns(conn) -> None:
    """Apply lightweight additive schema updates for SQLite installs.

    These are additive-only (ADD COLUMN) and idempotent — they check
    existence before altering.  Each migration is wrapped individually
    so a failure in one does not block the others.
    """
    _MIGRATIONS = [
        ("samples", "saved_analysis_json", "ALTER TABLE samples ADD COLUMN saved_analysis_json JSON"),
        ("samples", "saved_analysis_at", "ALTER TABLE samples ADD COLUMN saved_analysis_at DATETIME"),
        ("samples", "content_kind", "ALTER TABLE samples ADD COLUMN content_kind VARCHAR(64) NOT NULL DEFAULT 'text'"),
        ("samples", "content_encoding", "ALTER TABLE samples ADD COLUMN content_encoding VARCHAR(64)"),
        ("samples", "stored_file_path", "ALTER TABLE samples ADD COLUMN stored_file_path VARCHAR(2048)"),
        ("samples", "byte_size", "ALTER TABLE samples ADD COLUMN byte_size INTEGER"),
    ]

    for table, column, ddl in _MIGRATIONS:
        try:
            result = await conn.execute(text(f"PRAGMA table_info({table})"))
            columns = {row[1] for row in result.fetchall()}
            if column not in columns:
                await conn.execute(text(ddl))
                logger.info("Applied schema migration: added %s.%s", table, column)
        except Exception:
            logger.warning(
                "Schema migration failed for %s.%s (may already exist or table locked)",
                table, column,
                exc_info=True,
            )
