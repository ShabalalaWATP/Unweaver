"""
Project management endpoints.

Projects are top-level organisational containers that group related
obfuscated code samples together.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.db_models import Project
from app.models.schemas import ProjectCreate, ProjectResponse

router = APIRouter(tags=["projects"])


# ── POST /api/projects ───────────────────────────────────────────────
@router.post(
    "/projects",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_project(
    payload: ProjectCreate,
    db: AsyncSession = Depends(get_db),
) -> Project:
    """Create a new project."""
    project = Project(
        name=payload.name,
        description=payload.description,
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)
    return project


# ── GET /api/projects ────────────────────────────────────────────────
@router.get(
    "/projects",
    response_model=List[ProjectResponse],
)
async def list_projects(
    db: AsyncSession = Depends(get_db),
) -> list[Project]:
    """List all projects, ordered by most recently updated."""
    result = await db.execute(
        select(Project).order_by(Project.updated_at.desc())
    )
    return list(result.scalars().all())


# ── GET /api/projects/{id} ──────────────────────────────────────────
@router.get(
    "/projects/{project_id}",
    response_model=ProjectResponse,
)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
) -> Project:
    """Get a single project by ID."""
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )
    return project


# ── DELETE /api/projects/{id} ───────────────────────────────────────
@router.delete(
    "/projects/{project_id}",
)
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a project and all its associated samples (cascade)."""
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )
    await db.delete(project)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
