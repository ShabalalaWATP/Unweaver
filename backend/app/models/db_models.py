"""
SQLAlchemy ORM models for Unweaver.

All models inherit from the shared ``Base`` defined in
``app.core.database``.  Complex nested data (lists of dicts, etc.) is
stored as JSON-serialised TEXT columns — SQLite has no native JSON type,
but SQLAlchemy's ``JSON`` type transparently handles (de)serialisation
when backed by a TEXT column.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.database import Base


def _utcnow() -> datetime:
    """Return the current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    """Generate a new UUID4 as a string."""
    return str(uuid.uuid4())


# ════════════════════════════════════════════════════════════════════════
#  Project
# ════════════════════════════════════════════════════════════════════════

class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    # relationships
    samples: Mapped[list["Sample"]] = relationship(
        "Sample", back_populates="project", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Project id={self.id!r} name={self.name!r}>"


# ════════════════════════════════════════════════════════════════════════
#  Sample
# ════════════════════════════════════════════════════════════════════════

class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False, default="paste.txt")
    original_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recovered_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_kind: Mapped[str] = mapped_column(String(64), nullable=False, default="text")
    content_encoding: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stored_file_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    byte_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ready")
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    saved_analysis: Mapped[dict | None] = mapped_column("saved_analysis_json", JSON, nullable=True)
    saved_analysis_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    # relationships
    project: Mapped["Project"] = relationship("Project", back_populates="samples")
    transforms: Mapped[list["TransformHistory"]] = relationship(
        "TransformHistory", back_populates="sample", cascade="all, delete-orphan",
        order_by="TransformHistory.iteration",
    )
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord", back_populates="sample", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IOCRecord"]] = relationship(
        "IOCRecord", back_populates="sample", cascade="all, delete-orphan"
    )
    strings: Mapped[list["StringRecord"]] = relationship(
        "StringRecord", back_populates="sample", cascade="all, delete-orphan"
    )
    iteration_states: Mapped[list["IterationState"]] = relationship(
        "IterationState", back_populates="sample", cascade="all, delete-orphan",
        order_by="IterationState.iteration_number",
    )

    def __repr__(self) -> str:
        return f"<Sample id={self.id!r} filename={self.filename!r} status={self.status!r}>"


# ════════════════════════════════════════════════════════════════════════
#  Transform History
# ════════════════════════════════════════════════════════════════════════

class TransformHistory(Base):
    __tablename__ = "transform_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    action: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    inputs: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    outputs: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    confidence_before: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence_after: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    readability_before: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    readability_after: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    retry_revert: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # relationships
    sample: Mapped["Sample"] = relationship("Sample", back_populates="transforms")

    def __repr__(self) -> str:
        return (
            f"<TransformHistory id={self.id!r} sample_id={self.sample_id!r} "
            f"iteration={self.iteration} action={self.action!r}>"
        )


# ════════════════════════════════════════════════════════════════════════
#  Findings
# ════════════════════════════════════════════════════════════════════════

class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)

    # relationships
    sample: Mapped["Sample"] = relationship("Sample", back_populates="findings")

    def __repr__(self) -> str:
        return f"<FindingRecord id={self.id!r} title={self.title!r}>"


# ════════════════════════════════════════════════════════════════════════
#  IOC Records
# ════════════════════════════════════════════════════════════════════════

class IOCRecord(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False
    )
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False, default="other")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)

    # relationships
    sample: Mapped["Sample"] = relationship("Sample", back_populates="iocs")

    def __repr__(self) -> str:
        return f"<IOCRecord id={self.id!r} type={self.ioc_type!r} value={self.value!r}>"


# ════════════════════════════════════════════════════════════════════════
#  String Records
# ════════════════════════════════════════════════════════════════════════

class StringRecord(Base):
    __tablename__ = "strings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False
    )
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    encoding: Mapped[str | None] = mapped_column(String(32), nullable=True, default="utf-8")
    offset: Mapped[int | None] = mapped_column(Integer, nullable=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    decoded: Mapped[str | None] = mapped_column(Text, nullable=True)

    # relationships
    sample: Mapped["Sample"] = relationship("Sample", back_populates="strings")

    def __repr__(self) -> str:
        return f"<StringRecord id={self.id!r} value={self.value[:40]!r}>"


# ════════════════════════════════════════════════════════════════════════
#  Provider Config (LLM endpoints)
# ════════════════════════════════════════════════════════════════════════

class ProviderConfig(Base):
    __tablename__ = "provider_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cert_bundle_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    use_system_trust: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_tokens_preset: Mapped[str] = mapped_column(String(16), nullable=False, default="128k")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:
        return f"<ProviderConfig id={self.id!r} name={self.name!r} model={self.model_name!r}>"


# ════════════════════════════════════════════════════════════════════════
#  Benchmark Runs
# ════════════════════════════════════════════════════════════════════════

class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    provider_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("provider_configs.id", ondelete="SET NULL"), nullable=True
    )
    provider_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    provider_model: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    trigger_reason: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    corpus_name: Mapped[str] = mapped_column(String(128), nullable=False, default="js_recovery")
    corpus_version: Mapped[str] = mapped_column(String(64), nullable=False, default="js-corpus-v1")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    llm_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    case_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_case_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    pass_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    results_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    provider: Mapped[ProviderConfig | None] = relationship("ProviderConfig")

    def __repr__(self) -> str:
        return (
            f"<BenchmarkRun id={self.id!r} provider_id={self.provider_id!r} "
            f"status={self.status!r} score={self.overall_score!r}>"
        )


# ════════════════════════════════════════════════════════════════════════
#  Iteration State (JSON snapshots of AnalysisState)
# ════════════════════════════════════════════════════════════════════════

class IterationState(Base):
    __tablename__ = "iteration_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False
    )
    iteration_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # relationships
    sample: Mapped["Sample"] = relationship("Sample", back_populates="iteration_states")

    def __repr__(self) -> str:
        return (
            f"<IterationState id={self.id!r} sample_id={self.sample_id!r} "
            f"iteration={self.iteration_number}>"
        )
