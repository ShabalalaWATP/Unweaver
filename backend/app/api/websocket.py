"""
WebSocket endpoint for live analysis status updates.

Instead of polling GET /api/samples/{id}/analysis/status, clients can
open a WebSocket at /api/ws/analysis/{sample_id} to receive push updates.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.database import async_session
from app.models.db_models import Sample
from app.models.schemas import SampleStatus
from app.tasks.analysis_task import get_analysis_status, emit_event

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


async def _resolve_sample_status(sample_id: str) -> dict[str, object]:
    """Return the persisted sample status when no live tracker exists."""
    async with async_session() as db:
        sample = await db.get(Sample, sample_id)

    if sample is None:
        return {
            "sample_id": sample_id,
            "status": SampleStatus.FAILED.value,
            "current_iteration": 0,
            "total_iterations": 0,
            "current_action": "sample not found",
            "progress_pct": 0.0,
        }

    status_str = sample.status or SampleStatus.READY.value
    if status_str == SampleStatus.PENDING.value:
        status_str = SampleStatus.READY.value

    terminal = {
        SampleStatus.READY.value,
        SampleStatus.COMPLETED.value,
        SampleStatus.FAILED.value,
        SampleStatus.STOPPED.value,
    }
    return {
        "sample_id": sample_id,
        "status": status_str,
        "current_iteration": 0,
        "total_iterations": 0,
        "current_action": "idle" if status_str == SampleStatus.READY.value else status_str,
        "progress_pct": 100.0 if status_str in terminal else 0.0,
    }


@router.websocket("/ws/analysis/{sample_id}")
async def analysis_ws(websocket: WebSocket, sample_id: str) -> None:
    """Push analysis status updates over a WebSocket connection.

    Sends JSON messages with the same shape as AnalysisStatus every ~1s
    while the analysis is active.  Closes when analysis completes or
    the client disconnects.
    """
    await websocket.accept()
    logger.info("WebSocket connected for analysis %s", sample_id)

    try:
        prev_data: str | None = None

        while True:
            tracker = get_analysis_status(sample_id)

            if tracker is not None:
                status_str = tracker.get("status", "pending")
                data = json.dumps({
                    "sample_id": sample_id,
                    "event": "status",
                    "status": status_str,
                    "current_iteration": tracker.get("current_iteration", 0),
                    "total_iterations": tracker.get("total_iterations", 0),
                    "current_action": tracker.get("current_action", ""),
                    "progress_pct": tracker.get("progress_pct", 0.0),
                })

                # Only send if something changed
                if data != prev_data:
                    await websocket.send_text(data)
                    prev_data = data

                # Drain and send typed events
                events = tracker.get("events", [])
                while events:
                    evt = events.pop(0)
                    await websocket.send_text(json.dumps({
                        "sample_id": sample_id,
                        "event": evt.get("event", "info"),
                        **{k: v for k, v in evt.items() if k != "event"},
                    }))

                # If terminal state, send final update and close
                if status_str not in ("running", "pending"):
                    logger.info("Analysis %s reached terminal state %s, closing WS", sample_id, status_str)
                    break
            else:
                payload = await _resolve_sample_status(sample_id)
                data = json.dumps(payload)
                if data != prev_data:
                    await websocket.send_text(data)
                    prev_data = data
                if payload["status"] not in ("running", "pending"):
                    break

            await asyncio.sleep(1.0)

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for analysis %s", sample_id)
    except Exception:
        logger.exception("WebSocket error for analysis %s", sample_id)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
