"""
Pydantic schemas (request / response models) for the Unweaver API.

Every schema uses ``model_config = ConfigDict(from_attributes=True)`` so
that ORM objects can be serialised directly via ``.model_validate()``.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ════════════════════════════════════════════════════════════════════════
#  Enums
# ════════════════════════════════════════════════════════════════════════

class SampleStatus(str, enum.Enum):
    """Lifecycle status of a sample's analysis."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Severity(str, enum.Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(str, enum.Enum):
    """Indicator-of-compromise categories."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    FILEPATH = "filepath"
    REGISTRY = "registry"
    MUTEX = "mutex"
    OTHER = "other"


# ════════════════════════════════════════════════════════════════════════
#  Projects
# ════════════════════════════════════════════════════════════════════════

class ProjectCreate(BaseModel):
    """Payload for creating a new project."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    """Read-only representation of a project."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ════════════════════════════════════════════════════════════════════════
#  Samples
# ════════════════════════════════════════════════════════════════════════

class SampleCreate(BaseModel):
    """Create a sample by pasting obfuscated text directly."""

    project_id: str
    filename: Optional[str] = "paste.txt"
    original_text: str = Field(..., min_length=1)
    language: Optional[str] = None


class SampleUpload(BaseModel):
    """Metadata sent alongside a file upload (multipart)."""

    project_id: str
    language: Optional[str] = None


class SampleResponse(BaseModel):
    """Summary representation returned in list endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    filename: str
    language: Optional[str] = None
    status: SampleStatus = SampleStatus.PENDING
    created_at: datetime
    updated_at: datetime


class SampleDetail(BaseModel):
    """Full detail of a single sample, including recovered text and notes."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    filename: str
    original_text: str
    recovered_text: Optional[str] = None
    language: Optional[str] = None
    status: SampleStatus = SampleStatus.PENDING
    analyst_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ════════════════════════════════════════════════════════════════════════
#  Analysis internals
# ════════════════════════════════════════════════════════════════════════

class StringEntry(BaseModel):
    """A single string extracted / decoded from the sample."""

    value: str
    encoding: Optional[str] = "utf-8"
    offset: Optional[int] = None
    context: Optional[str] = None
    decoded: Optional[str] = None


class Finding(BaseModel):
    """An analyst-facing finding (suspicious behaviour, technique, etc.)."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    evidence: Optional[str] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class IOC(BaseModel):
    """Indicator of compromise extracted from the sample."""

    type: IOCType = IOCType.OTHER
    value: str
    context: Optional[str] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class TransformRecord(BaseModel):
    """One iteration of the deobfuscation loop."""

    iteration: int
    action: str
    reason: str = ""
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    readability_before: float = 0.0
    readability_after: float = 0.0
    success: bool = True
    retry_revert: bool = False


class AnalysisState(BaseModel):
    """
    Normalised internal model that the orchestrator maintains across
    iterations.  Stored as a JSON snapshot after every iteration.
    """

    language: Optional[str] = None
    parse_status: Optional[str] = None  # e.g. "ok", "partial", "failed"

    symbols: List[str] = Field(default_factory=list)
    strings: List[StringEntry] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    functions: List[str] = Field(default_factory=list)
    suspicious_apis: List[str] = Field(default_factory=list)
    detected_techniques: List[str] = Field(default_factory=list)
    recovered_literals: List[str] = Field(default_factory=list)

    transform_history: List[TransformRecord] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)

    confidence: Dict[str, float] = Field(
        default_factory=lambda: {
            "overall": 0.0,
            "naming": 0.0,
            "structure": 0.0,
            "strings": 0.0,
        }
    )
    analysis_summary: str = ""
    llm_suggestions: List[str] = Field(default_factory=list)

    iteration_state: Dict[str, Any] = Field(
        default_factory=lambda: {
            "current_iteration": 0,
            "stall_counter": 0,
            "last_confidence": 0.0,
            "stopped": False,
        }
    )


# ════════════════════════════════════════════════════════════════════════
#  Provider (LLM) settings
# ════════════════════════════════════════════════════════════════════════

class ProviderSettings(BaseModel):
    """Full provider config — used internally (never returned raw to clients)."""

    base_url: str
    model_name: str
    api_key: str = ""
    cert_bundle_path: Optional[str] = None
    use_system_trust: bool = True
    max_tokens_preset: Literal["128k", "200k"] = "128k"


class ProviderSettingsCreate(BaseModel):
    """Payload for creating / updating a provider configuration."""

    name: str = Field(..., min_length=1, max_length=255)
    base_url: str
    model_name: str
    api_key: str = ""
    cert_bundle_path: Optional[str] = None
    use_system_trust: bool = True
    max_tokens_preset: Literal["128k", "200k"] = "128k"


class ProviderSettingsResponse(BaseModel):
    """Provider config as seen by the frontend — api_key is always masked."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    base_url: str
    model_name: str
    api_key_masked: str = ""
    cert_bundle_path: Optional[str] = None
    use_system_trust: bool = True
    max_tokens_preset: Literal["128k", "200k"] = "128k"
    is_active: bool = True
    created_at: datetime

    @field_validator("api_key_masked", mode="before")
    @classmethod
    def mask_api_key(cls, v: Any) -> str:  # noqa: N805
        """Mask everything except the last four characters."""
        raw = str(v) if v else ""
        if len(raw) <= 4:
            return "****"
        return "*" * (len(raw) - 4) + raw[-4:]


# ════════════════════════════════════════════════════════════════════════
#  Analysis status (for progress polling)
# ════════════════════════════════════════════════════════════════════════

class AnalysisStatus(BaseModel):
    """Lightweight status object returned by the progress endpoint."""

    sample_id: str
    status: SampleStatus = SampleStatus.PENDING
    current_iteration: int = 0
    total_iterations: int = 0
    current_action: str = ""
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0)


# ════════════════════════════════════════════════════════════════════════
#  Export / Notes
# ════════════════════════════════════════════════════════════════════════

class ExportRequest(BaseModel):
    """Parameters for exporting an analysis report."""

    sample_id: str
    format: Literal["json", "markdown", "html", "pdf"] = "json"
    include_transforms: bool = True
    include_findings: bool = True
    include_iocs: bool = True
    include_strings: bool = True


class NotesSave(BaseModel):
    """Payload for saving / updating analyst notes on a sample."""

    sample_id: str
    notes: str = ""
