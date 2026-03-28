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

    READY = "ready"
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
    content_kind: str = "text"
    byte_size: Optional[int] = None
    status: SampleStatus = SampleStatus.READY
    saved_analysis_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class AISummarySections(BaseModel):
    """Structured AI-written summary sections for a deobfuscation run."""

    deobfuscation_analysis: str
    inferred_original_intent: str
    actual_behavior: str
    confidence_assessment: str


class AISummaryReport(BaseModel):
    """Structured AI-written assessment returned to the frontend."""

    summary: str
    sections: AISummarySections
    confidence_score: Optional[float] = None


class AnalystChatMessage(BaseModel):
    """Single message in the analyst chat transcript."""

    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1)


class AnalystChatRequest(BaseModel):
    """Chat payload sent from the analyst UI."""

    messages: List[AnalystChatMessage] = Field(default_factory=list)


class AnalystChatRetrievedFile(BaseModel):
    """Workspace file context pulled into a chat answer."""

    path: str
    language: Optional[str] = None
    source: Literal["recovered_bundle", "original_bundle", "archive_scan"]
    matched_terms: List[str] = Field(default_factory=list)
    line_ranges: List[str] = Field(default_factory=list)
    excerpt_truncated: bool = False


class AnalystChatResponse(BaseModel):
    """Assistant reply for the analyst chat panel."""

    answer: str
    provider_name: str
    model_name: str
    context_truncated: bool = False
    workspace_search_enabled: bool = False
    workspace_file_count: int = 0
    retrieved_files: List[AnalystChatRetrievedFile] = Field(default_factory=list)


class SavedAnalysisSnapshot(BaseModel):
    """Persisted analysis snapshot for reopening a completed run later."""

    saved_at: Optional[datetime] = None
    sample_status: Optional[SampleStatus] = None
    transform_count: int = 0
    finding_count: int = 0
    ioc_count: int = 0
    string_count: int = 0
    recovered_text_length: int = 0
    confidence_score: Optional[float] = None
    raw_confidence_score: Optional[float] = None
    coverage_adjusted_confidence: Optional[float] = None
    coverage_adjustment_factor: Optional[float] = None
    confidence_scope_note: Optional[str] = None
    stop_reason: Optional[str] = None
    fatal_error: Optional[str] = None
    result_kind: Optional[str] = None
    best_effort: bool = False
    analysis_summary: str = ""
    workspace_context: Dict[str, Any] = Field(default_factory=dict)
    ai_summary: Optional[AISummaryReport] = None


class SampleDetail(BaseModel):
    """Full detail of a single sample, including recovered text and notes."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    filename: str
    original_text: str
    recovered_text: Optional[str] = None
    language: Optional[str] = None
    content_kind: str = "text"
    byte_size: Optional[int] = None
    status: SampleStatus = SampleStatus.READY
    analyst_notes: Optional[str] = None
    saved_analysis: Optional[SavedAnalysisSnapshot] = None
    saved_analysis_at: Optional[datetime] = None
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
    workspace_context: Dict[str, Any] = Field(default_factory=dict)

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
            "stop_reason": "",
            "fatal_error": None,
            "result_kind": "in_progress",
            "best_effort": False,
            "raw_confidence": 0.0,
            "coverage_adjusted_confidence": None,
            "coverage_adjustment_factor": None,
            "confidence_scope_note": "",
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


class ProviderBenchmarkScheduleResponse(BaseModel):
    provider_id: str
    scheduled: bool = False
    reason: str = ""


class ProviderBenchmarkRunResponse(BaseModel):
    id: str
    provider_id: Optional[str] = None
    provider_name: str = ""
    provider_model: str = ""
    trigger_reason: str = ""
    corpus_name: str = ""
    corpus_version: str = ""
    status: str = ""
    llm_enabled: bool = False
    case_count: int = 0
    completed_case_count: int = 0
    overall_score: Optional[float] = None
    pass_rate: Optional[float] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    results: List[Dict[str, Any]] = Field(default_factory=list)
    error_text: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime


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
