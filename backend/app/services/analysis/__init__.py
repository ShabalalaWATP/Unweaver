"""
Analysis orchestration engine for Unweaver.

Multi-pass agentic deobfuscation harness with deterministic transforms,
priority-based action scheduling, state management with rollback, and
findings synthesis.
"""

from app.services.analysis.action_queue import (
    ActionQueue,
    ActionStatus,
    QueuedAction,
)
from app.services.analysis.findings_generator import FindingsGenerator
from app.services.analysis.orchestrator import (
    ActionSelector,
    AnalysisResult,
    Executor,
    Orchestrator,
    Planner,
    PlannedAction,
    StopAction,
    StopDecision,
    StopVerdict,
    Verifier,
)
from app.services.analysis.state_manager import (
    StateManager,
    StateSnapshot,
)

__all__ = [
    # Orchestrator & result
    "Orchestrator",
    "AnalysisResult",
    # Sub-components
    "Planner",
    "PlannedAction",
    "ActionSelector",
    "Executor",
    "Verifier",
    "StopDecision",
    "StopAction",
    "StopVerdict",
    # State
    "StateManager",
    "StateSnapshot",
    # Queue
    "ActionQueue",
    "ActionStatus",
    "QueuedAction",
    # Findings
    "FindingsGenerator",
]
