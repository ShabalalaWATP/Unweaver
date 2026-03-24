from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import websocket as websocket_api
from app.models.db_models import Sample


class _SessionContext:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> AsyncSession:
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class TestResolveSampleStatus:
    @pytest.mark.asyncio
    async def test_pending_sample_without_tracker_resolves_to_ready(
        self,
        sample_project,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ):
        sample = Sample(
            project_id=sample_project.id,
            filename="legacy.js",
            original_text="console.log('legacy');",
            language="javascript",
            status="pending",
        )
        db_session.add(sample)
        await db_session.commit()
        await db_session.refresh(sample)

        monkeypatch.setattr(
            websocket_api,
            "async_session",
            lambda: _SessionContext(db_session),
        )

        payload = await websocket_api._resolve_sample_status(sample.id)

        assert payload["status"] == "ready"
        assert payload["current_action"] == "idle"
        assert payload["progress_pct"] == 100.0

    @pytest.mark.asyncio
    async def test_running_sample_without_tracker_keeps_running_status(
        self,
        sample_project,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ):
        sample = Sample(
            project_id=sample_project.id,
            filename="zombie.js",
            original_text="console.log('running');",
            language="javascript",
            status="running",
        )
        db_session.add(sample)
        await db_session.commit()
        await db_session.refresh(sample)

        monkeypatch.setattr(
            websocket_api,
            "async_session",
            lambda: _SessionContext(db_session),
        )

        payload = await websocket_api._resolve_sample_status(sample.id)

        assert payload["status"] == "running"
        assert payload["current_action"] == "running"
        assert payload["progress_pct"] == 0.0
