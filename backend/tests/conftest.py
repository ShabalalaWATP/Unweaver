"""
Shared test fixtures for Unweaver backend tests.

Provides an in-memory SQLite database, async session factory, a FastAPI
TestClient, and reusable sample data.
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.database import Base, get_db
from app.main import app
from app.models.db_models import Project, Sample


# ── In-memory async engine (shared across a test session) ───────────────

TEST_DATABASE_URL = "sqlite+aiosqlite://"

_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

_TestSessionLocal = async_sessionmaker(
    bind=_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Database setup / teardown ──────────────────────────────────────────

@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    """Create tables before each test, drop them after."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ── Session fixture ────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async session bound to the test database."""
    async with _TestSessionLocal() as session:
        yield session


# ── Override the FastAPI get_db dependency ──────────────────────────────

async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


app.dependency_overrides[get_db] = _override_get_db


# ── Async HTTP client ──────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx AsyncClient wired to the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── Sample data fixtures ──────────────────────────────────────────────

@pytest_asyncio.fixture
async def sample_project(db_session: AsyncSession) -> Project:
    """Create and return a test project."""
    project = Project(name="Test Project", description="Automated test project")
    db_session.add(project)
    await db_session.commit()
    await db_session.refresh(project)
    return project


@pytest_asyncio.fixture
async def sample_js(sample_project: Project, db_session: AsyncSession) -> Sample:
    """Create and return a JavaScript sample attached to the test project."""
    sample = Sample(
        project_id=sample_project.id,
        filename="test.js",
        original_text='var x = atob("aGVsbG8gd29ybGQ="); eval(x);',
        language="javascript",
        status="pending",
    )
    db_session.add(sample)
    await db_session.commit()
    await db_session.refresh(sample)
    return sample


@pytest_asyncio.fixture
async def sample_ps(sample_project: Project, db_session: AsyncSession) -> Sample:
    """Create and return a PowerShell sample attached to the test project."""
    sample = Sample(
        project_id=sample_project.id,
        filename="test.ps1",
        original_text=(
            "$a = [System.Convert]::FromBase64String('aGVsbG8=')\n"
            "$url = [System.Text.Encoding]::UTF8.GetString($a)"
        ),
        language="powershell",
        status="pending",
    )
    db_session.add(sample)
    await db_session.commit()
    await db_session.refresh(sample)
    return sample


@pytest_asyncio.fixture
async def sample_py(sample_project: Project, db_session: AsyncSession) -> Sample:
    """Create and return a Python sample attached to the test project."""
    sample = Sample(
        project_id=sample_project.id,
        filename="test.py",
        original_text=(
            "import base64\n"
            "exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))"
        ),
        language="python",
        status="pending",
    )
    db_session.add(sample)
    await db_session.commit()
    await db_session.refresh(sample)
    return sample


# ── Raw code snippets (no DB) ─────────────────────────────────────────

@pytest.fixture
def js_code() -> str:
    return 'var x = atob("aGVsbG8gd29ybGQ="); eval(x);'


@pytest.fixture
def ps_code() -> str:
    return (
        "$a = [System.Convert]::FromBase64String('aGVsbG8=')\n"
        "$url = [System.Text.Encoding]::UTF8.GetString($a)"
    )


@pytest.fixture
def py_code() -> str:
    return (
        "import base64\n"
        "exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))"
    )


@pytest.fixture
def cs_code() -> str:
    return (
        'string s = Encoding.UTF8.GetString(Convert.FromBase64String("aGVsbG8="));\n'
        'Type t = Type.GetType("System.Diagnostics.Process");'
    )


@pytest.fixture
def hex_code() -> str:
    return r'var s = "\x68\x65\x6c\x6c\x6f";'
