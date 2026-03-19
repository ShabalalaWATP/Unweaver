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

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

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
