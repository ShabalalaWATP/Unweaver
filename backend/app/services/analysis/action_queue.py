"""
Priority queue for pending deobfuscation actions.

Tracks attempted, failed, and succeeded actions to prevent infinite loops
and enable intelligent scheduling. High-confidence deterministic actions
are auto-approved while lower-confidence actions are queued as suggestions.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class ActionStatus(str, Enum):
    """Lifecycle of a queued action."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(order=True)
class QueuedAction:
    """A single action sitting in the priority queue.

    Lower ``priority`` numbers run first.  Ties are broken by insertion
    order (``seq``).  The ``action_name`` field is NOT used for ordering.
    """

    priority: float
    seq: int
    action_name: str = field(compare=False)
    reason: str = field(compare=False, default="")
    confidence: float = field(compare=False, default=0.5)
    auto_approve: bool = field(compare=False, default=False)
    status: ActionStatus = field(compare=False, default=ActionStatus.PENDING)
    attempt_count: int = field(compare=False, default=0)
    max_attempts: int = field(compare=False, default=2)


class ActionQueue:
    """Priority queue that governs which transforms are attempted next.

    Features
    --------
    * Deterministic high-confidence actions are auto-approved.
    * Actions that have already failed are suppressed up to ``max_attempts``.
    * A global attempt ledger prevents infinite retry loops.
    * ``drain`` pops the next eligible action without removing failed guards.
    """

    # Actions considered deterministic and safe to auto-approve above the
    # configured threshold.
    DETERMINISTIC_ACTIONS: Set[str] = {
        "profile_workspace",
        "deobfuscate_workspace_files",
        "detect_language",
        "fingerprint_obfuscation",
        "extract_strings",
        "analyze_entropy",
        "decode_base64",
        "decode_hex",
        "normalize_unicode",
        "deobfuscate_js_bundle",
        "decrypt_strings",
        "constant_fold",
        "simplify_junk_code",
        "unflatten_control_flow",
        "apply_renames",
        "extract_iocs",
        "powershell_decode",
        "python_decode",
        "detect_eval_exec_reflection",
        "identify_string_resolver",
        "suggest_renames",
        "generate_findings",
    }

    def __init__(self, auto_approve_threshold: float = 0.85) -> None:
        self._heap: List[QueuedAction] = []
        self._seq: int = 0
        self._auto_threshold = auto_approve_threshold

        # Ledger: action_name -> list of ActionStatus for each attempt.
        self._ledger: Dict[str, List[ActionStatus]] = {}

        # Hard cap on total enqueues for any single action name.
        self._max_global_attempts: int = 4

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def pending_count(self) -> int:
        return sum(
            1 for a in self._heap if a.status == ActionStatus.PENDING
        )

    @property
    def is_empty(self) -> bool:
        return self.pending_count == 0

    def history(self, action_name: str) -> List[ActionStatus]:
        """Return the status history for *action_name*."""
        return list(self._ledger.get(action_name, []))

    def failure_count(self, action_name: str) -> int:
        return sum(
            1 for s in self._ledger.get(action_name, [])
            if s == ActionStatus.FAILED
        )

    def failure_streak(self, action_name: str) -> int:
        """Return the trailing run of failed attempts for *action_name*.

        This is more useful than total historical failures when deciding
        whether an action should be retried later after other transforms
        have changed the code shape.
        """
        streak = 0
        for status in reversed(self._ledger.get(action_name, [])):
            if status == ActionStatus.FAILED:
                streak += 1
                continue
            break
        return streak

    def success_count(self, action_name: str) -> int:
        return sum(
            1 for s in self._ledger.get(action_name, [])
            if s == ActionStatus.SUCCEEDED
        )

    def total_attempts(self, action_name: str) -> int:
        return len(self._ledger.get(action_name, []))

    def has_been_tried(self, action_name: str) -> bool:
        return action_name in self._ledger

    def is_capped(self, action_name: str) -> bool:
        """Return True if the action has hit its global attempt or failure cap."""
        if self.total_attempts(action_name) >= self._max_global_attempts:
            return True
        if self.failure_streak(action_name) >= 2:  # default max_attempts
            return True
        return False

    # ------------------------------------------------------------------
    # Enqueue / dequeue
    # ------------------------------------------------------------------

    def enqueue(
        self,
        action_name: str,
        *,
        confidence: float = 0.5,
        reason: str = "",
        priority: Optional[float] = None,
        max_attempts: int = 2,
    ) -> bool:
        """Add an action to the queue.

        Returns ``False`` (and does NOT enqueue) when:
        * The action has already been attempted ``_max_global_attempts`` times.
        * The action has failed ``max_attempts`` consecutive times.
        * An identical PENDING entry already exists.
        """
        # Global attempt cap.
        if self.total_attempts(action_name) >= self._max_global_attempts:
            return False

        # Consecutive-failure cap. Historical failures should not permanently
        # suppress an action after a later success or code-shape change.
        if self.failure_streak(action_name) >= max_attempts:
            return False

        # Duplicate-pending guard.
        if any(
            a.action_name == action_name and a.status == ActionStatus.PENDING
            for a in self._heap
        ):
            return False

        # Determine auto-approve eligibility.
        auto = (
            confidence >= self._auto_threshold
            and action_name in self.DETERMINISTIC_ACTIONS
        )

        # Priority: lower == sooner.  Invert confidence so high-confidence
        # actions sort first.  Deterministic actions get an extra bonus.
        if priority is None:
            base = 1.0 - confidence
            if action_name in self.DETERMINISTIC_ACTIONS:
                base -= 0.5  # deterministic bonus
            priority = base

        item = QueuedAction(
            priority=priority,
            seq=self._seq,
            action_name=action_name,
            reason=reason,
            confidence=confidence,
            auto_approve=auto,
            max_attempts=max_attempts,
        )
        self._seq += 1
        heapq.heappush(self._heap, item)
        return True

    def dequeue(self) -> Optional[QueuedAction]:
        """Pop the highest-priority PENDING action.

        Returns ``None`` when the queue has no eligible items.
        """
        # Rebuild a clean heap of only PENDING items, then pop.
        pending = [a for a in self._heap if a.status == ActionStatus.PENDING]
        if not pending:
            return None
        heapq.heapify(pending)
        chosen = heapq.heappop(pending)
        # Mark it as running in the original heap.
        for a in self._heap:
            if a.seq == chosen.seq:
                a.status = ActionStatus.RUNNING
                break
        chosen.status = ActionStatus.RUNNING
        chosen.attempt_count += 1
        return chosen

    def peek(self) -> Optional[QueuedAction]:
        """Look at the next action without removing it."""
        pending = [a for a in self._heap if a.status == ActionStatus.PENDING]
        if not pending:
            return None
        heapq.heapify(pending)
        return pending[0]

    # ------------------------------------------------------------------
    # Feedback (after execution)
    # ------------------------------------------------------------------

    def mark_succeeded(self, action_name: str) -> None:
        self._ledger.setdefault(action_name, []).append(ActionStatus.SUCCEEDED)
        for a in self._heap:
            if a.action_name == action_name and a.status == ActionStatus.RUNNING:
                a.status = ActionStatus.SUCCEEDED
                break

    def mark_failed(self, action_name: str) -> None:
        self._ledger.setdefault(action_name, []).append(ActionStatus.FAILED)
        for a in self._heap:
            if a.action_name == action_name and a.status == ActionStatus.RUNNING:
                a.status = ActionStatus.FAILED
                break

    def mark_skipped(self, action_name: str) -> None:
        self._ledger.setdefault(action_name, []).append(ActionStatus.SKIPPED)
        for a in self._heap:
            if a.action_name == action_name and a.status == ActionStatus.RUNNING:
                a.status = ActionStatus.SKIPPED
                break

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def enqueue_many(
        self,
        actions: List[Dict[str, object]],
    ) -> int:
        """Enqueue several actions at once.

        Each dict in *actions* should have at minimum ``"action_name"`` and
        optionally ``"confidence"``, ``"reason"``, ``"priority"``.

        Returns the count of actions actually enqueued (some may be rejected).
        """
        added = 0
        for spec in actions:
            name = str(spec["action_name"])
            ok = self.enqueue(
                name,
                confidence=float(spec.get("confidence", 0.5)),
                reason=str(spec.get("reason", "")),
                priority=float(spec["priority"]) if "priority" in spec else None,
                max_attempts=int(spec.get("max_attempts", 2)),
            )
            if ok:
                added += 1
        return added

    def clear_pending(self) -> int:
        """Remove all PENDING items.  Returns how many were removed."""
        before = len(self._heap)
        self._heap = [
            a for a in self._heap if a.status != ActionStatus.PENDING
        ]
        return before - len(self._heap)

    def snapshot(self) -> List[Dict[str, object]]:
        """Serialise the current queue state for persistence / debugging."""
        return [
            {
                "action_name": a.action_name,
                "priority": a.priority,
                "confidence": a.confidence,
                "status": a.status.value,
                "attempt_count": a.attempt_count,
                "reason": a.reason,
                "auto_approve": a.auto_approve,
            }
            for a in sorted(self._heap)
        ]
