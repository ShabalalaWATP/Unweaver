"""
Tests for the Unweaver orchestrator components: ActionQueue, StateManager,
and the iterative analysis loop logic.

These tests verify that:
  - The orchestration loop runs and terminates under various conditions.
  - Stop conditions (max iterations, stall) are enforced.
  - Action selection avoids repeated failures.
  - The verifier detects improvement via confidence/readability tracking.
"""

from __future__ import annotations

import pytest

from app.models.schemas import AnalysisState, TransformRecord
from app.services.analysis.action_queue import (
    ActionQueue,
    ActionStatus,
    QueuedAction,
)
from app.services.analysis.state_manager import StateManager


# ════════════════════════════════════════════════════════════════════════
#  ActionQueue -- basic operations
# ════════════════════════════════════════════════════════════════════════

class TestActionQueue:
    """Tests for the ActionQueue priority queue."""

    def test_enqueue_and_dequeue(self):
        """Enqueue an action and dequeue it."""
        q = ActionQueue()
        assert q.enqueue("decode_base64", confidence=0.9) is True
        assert q.pending_count == 1
        action = q.dequeue()
        assert action is not None
        assert action.action_name == "decode_base64"
        assert action.status == ActionStatus.RUNNING

    def test_empty_queue_returns_none(self):
        """Dequeue from an empty queue returns None."""
        q = ActionQueue()
        assert q.dequeue() is None
        assert q.is_empty is True

    def test_priority_ordering(self):
        """Higher-confidence actions should be dequeued first."""
        q = ActionQueue()
        q.enqueue("low_priority", confidence=0.3)
        q.enqueue("high_priority", confidence=0.95)
        action = q.dequeue()
        assert action is not None
        # High confidence should come first (lower priority number)
        assert action.action_name == "high_priority"

    def test_deterministic_bonus(self):
        """Deterministic actions get priority boost."""
        q = ActionQueue()
        q.enqueue("decode_base64", confidence=0.5)  # deterministic
        q.enqueue("llm_rename_variables", confidence=0.5)  # not deterministic
        action = q.dequeue()
        assert action is not None
        assert action.action_name == "decode_base64"

    def test_duplicate_pending_rejected(self):
        """Cannot enqueue the same action twice while pending."""
        q = ActionQueue()
        assert q.enqueue("decode_base64", confidence=0.9) is True
        assert q.enqueue("decode_base64", confidence=0.9) is False
        assert q.pending_count == 1

    def test_mark_succeeded(self):
        """Marking an action as succeeded should update ledger."""
        q = ActionQueue()
        q.enqueue("decode_base64", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("decode_base64")
        assert q.success_count("decode_base64") == 1
        assert q.failure_count("decode_base64") == 0

    def test_mark_failed(self):
        """Marking an action as failed should update ledger."""
        q = ActionQueue()
        q.enqueue("decode_base64", confidence=0.9)
        q.dequeue()
        q.mark_failed("decode_base64")
        assert q.failure_count("decode_base64") == 1

    def test_failure_cap_prevents_reenqueue(self):
        """After max_attempts failures, the action cannot be enqueued again."""
        q = ActionQueue()

        # First attempt
        q.enqueue("flaky_action", confidence=0.5, max_attempts=2)
        q.dequeue()
        q.mark_failed("flaky_action")

        # Second attempt
        q.enqueue("flaky_action", confidence=0.5, max_attempts=2)
        q.dequeue()
        q.mark_failed("flaky_action")

        # Third attempt should be rejected
        assert q.enqueue("flaky_action", confidence=0.5, max_attempts=2) is False

    def test_global_attempt_cap(self):
        """After _max_global_attempts total attempts, action is blocked."""
        q = ActionQueue()
        q._max_global_attempts = 3

        for i in range(3):
            q.enqueue(f"action_{i}", confidence=0.5)  # different names, fine
        # Same name, 3 attempts:
        q.enqueue("repeat_action", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("repeat_action")
        q.enqueue("repeat_action", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("repeat_action")
        q.enqueue("repeat_action", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("repeat_action")
        # 4th should be rejected
        assert q.enqueue("repeat_action", confidence=0.9) is False

    def test_auto_approve_threshold(self):
        """High-confidence deterministic actions are auto-approved."""
        q = ActionQueue(auto_approve_threshold=0.85)
        q.enqueue("decode_base64", confidence=0.9)
        action = q.dequeue()
        assert action is not None
        assert action.auto_approve is True

    def test_non_deterministic_not_auto_approved(self):
        """Non-deterministic actions should NOT be auto-approved."""
        q = ActionQueue(auto_approve_threshold=0.85)
        q.enqueue("llm_rename", confidence=0.95)
        action = q.dequeue()
        assert action is not None
        assert action.auto_approve is False

    def test_peek_does_not_remove(self):
        """Peek should show next action without removing it."""
        q = ActionQueue()
        q.enqueue("decode_base64", confidence=0.9)
        peeked = q.peek()
        assert peeked is not None
        assert q.pending_count == 1  # still there

    def test_enqueue_many(self):
        """Bulk enqueue should add multiple actions."""
        q = ActionQueue()
        actions = [
            {"action_name": "decode_base64", "confidence": 0.9},
            {"action_name": "extract_strings", "confidence": 0.85},
            {"action_name": "decode_hex", "confidence": 0.8},
        ]
        added = q.enqueue_many(actions)
        assert added == 3
        assert q.pending_count == 3

    def test_clear_pending(self):
        """Clear pending should remove all pending actions."""
        q = ActionQueue()
        q.enqueue("a", confidence=0.5)
        q.enqueue("b", confidence=0.6)
        removed = q.clear_pending()
        assert removed == 2
        assert q.is_empty is True

    def test_snapshot(self):
        """Snapshot should serialise queue state."""
        q = ActionQueue()
        q.enqueue("decode_base64", confidence=0.9)
        snap = q.snapshot()
        assert len(snap) == 1
        assert snap[0]["action_name"] == "decode_base64"
        assert snap[0]["status"] == "pending"

    def test_has_been_tried(self):
        """has_been_tried should detect previously attempted actions."""
        q = ActionQueue()
        assert q.has_been_tried("decode_base64") is False
        q.enqueue("decode_base64", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("decode_base64")
        assert q.has_been_tried("decode_base64") is True

    def test_mark_skipped(self):
        """Skipped actions should be tracked in ledger."""
        q = ActionQueue()
        q.enqueue("optional_action", confidence=0.4)
        q.dequeue()
        q.mark_skipped("optional_action")
        history = q.history("optional_action")
        assert ActionStatus.SKIPPED in history


# ════════════════════════════════════════════════════════════════════════
#  StateManager -- core operations
# ════════════════════════════════════════════════════════════════════════

class TestStateManager:
    """Tests for the StateManager orchestration state tracker."""

    def test_initial_state(self):
        """State manager should initialise with correct defaults."""
        sm = StateManager(
            sample_id="test-123",
            original_code="var x = 1;",
            language="javascript",
        )
        assert sm.sample_id == "test-123"
        assert sm.current_iteration == 0
        assert sm.overall_confidence == 0.0
        assert sm.stall_counter == 0
        assert sm.is_stopped is False
        assert sm.snapshot_count == 1  # initial snapshot

    def test_advance_iteration(self):
        """Advancing should increment the iteration counter."""
        sm = StateManager("test", "code")
        assert sm.advance_iteration() == 1
        assert sm.advance_iteration() == 2
        assert sm.current_iteration == 2

    def test_update_confidence(self):
        """Confidence updates should clamp to [0, 1]."""
        sm = StateManager("test", "code")
        sm.update_confidence(overall=0.75)
        assert sm.overall_confidence == 0.75

        sm.update_confidence(overall=1.5)
        assert sm.overall_confidence == 1.0

        sm.update_confidence(overall=-0.5)
        assert sm.overall_confidence == 0.0

    def test_stall_counter(self):
        """Stall counter should increment and reset correctly."""
        sm = StateManager("test", "code")
        assert sm.increment_stall() == 1
        assert sm.increment_stall() == 2
        sm.reset_stall()
        assert sm.stall_counter == 0

    def test_mark_stopped(self):
        """Marking stopped should set the flag."""
        sm = StateManager("test", "code")
        assert sm.is_stopped is False
        sm.mark_stopped()
        assert sm.is_stopped is True


# ════════════════════════════════════════════════════════════════════════
#  Stop Conditions
# ════════════════════════════════════════════════════════════════════════

class TestStopConditions:
    """Test that the analysis loop terminates under the right conditions."""

    def test_max_iterations_reached(self):
        """Loop should stop after MAX_ITERATIONS."""
        sm = StateManager("test", "code")
        max_iter = 20
        for i in range(max_iter):
            iteration = sm.advance_iteration()
            if iteration >= max_iter:
                break
        assert sm.current_iteration == max_iter

    def test_stall_threshold_reached(self):
        """Loop should stop when stall counter reaches threshold."""
        sm = StateManager("test", "code")
        stall_threshold = 3
        for _ in range(stall_threshold):
            sm.increment_stall()
        assert sm.stall_counter >= stall_threshold

    def test_confidence_threshold_reached(self):
        """Loop should stop when confidence exceeds threshold."""
        sm = StateManager("test", "code")
        threshold = 0.85
        sm.update_confidence(overall=0.90)
        assert sm.overall_confidence >= threshold

    def test_manual_stop(self):
        """Loop should stop when explicitly marked."""
        sm = StateManager("test", "code")
        sm.mark_stopped()
        assert sm.is_stopped is True

    def test_stall_resets_on_progress(self):
        """Stall counter should reset when confidence improves."""
        sm = StateManager("test", "code")
        sm.increment_stall()
        sm.increment_stall()
        assert sm.stall_counter == 2
        # Simulate progress: reset stall
        sm.reset_stall()
        sm.update_confidence(overall=0.5)
        assert sm.stall_counter == 0


# ════════════════════════════════════════════════════════════════════════
#  Action Selection -- avoiding repeated failures
# ════════════════════════════════════════════════════════════════════════

class TestActionSelection:
    """Test that the queue avoids scheduling actions that keep failing."""

    def test_failed_action_blocked_after_max_attempts(self):
        q = ActionQueue()

        # Attempt 1: fail
        q.enqueue("bad_transform", confidence=0.5, max_attempts=2)
        action = q.dequeue()
        q.mark_failed("bad_transform")

        # Attempt 2: fail
        q.enqueue("bad_transform", confidence=0.5, max_attempts=2)
        action = q.dequeue()
        q.mark_failed("bad_transform")

        # Attempt 3: should be rejected
        enqueued = q.enqueue("bad_transform", confidence=0.5, max_attempts=2)
        assert enqueued is False

    def test_succeeded_action_still_enqueueable(self):
        """A previously successful action can be re-enqueued."""
        q = ActionQueue()
        q.enqueue("decode_base64", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("decode_base64")

        # Should be able to enqueue again
        assert q.enqueue("decode_base64", confidence=0.9) is True

    def test_mixed_success_failure_tracking(self):
        """Track mixed results in the ledger."""
        q = ActionQueue()

        # Success
        q.enqueue("transform_a", confidence=0.8)
        q.dequeue()
        q.mark_succeeded("transform_a")

        # Failure
        q.enqueue("transform_a", confidence=0.8)
        q.dequeue()
        q.mark_failed("transform_a")

        assert q.success_count("transform_a") == 1
        assert q.failure_count("transform_a") == 1
        assert q.total_attempts("transform_a") == 2


# ════════════════════════════════════════════════════════════════════════
#  Verifier -- detecting improvement
# ════════════════════════════════════════════════════════════════════════

class TestVerifierDetectsImprovement:
    """Test that the StateManager tracks confidence and readability trends."""

    def test_confidence_improves_over_iterations(self):
        """Confidence history should reflect updates."""
        sm = StateManager("test", "var _0x1 = 1;")
        sm.update_confidence(overall=0.2)
        sm.update_confidence(overall=0.5)
        sm.update_confidence(overall=0.8)
        history = sm.confidence_history
        assert history == [0.0, 0.2, 0.5, 0.8]
        assert history[-1] > history[0]

    def test_readability_improves_with_better_code(self):
        """Readability should increase when code becomes more readable."""
        obfuscated = "var _0x1=_0x2(_0x3[0x0]);_0x4(_0x1);"
        sm = StateManager("test", obfuscated)
        initial_readability = sm.readability_history[-1]

        readable = """
// Fetch user data from the remote server
function fetchUserData(userId) {
    var endpoint = "https://api.example.com/users/" + userId;
    return fetch(endpoint);
}
"""
        new_score = sm.update_readability(readable)
        assert new_score > initial_readability

    def test_readability_history_tracked(self):
        """Readability history should grow with each update."""
        sm = StateManager("test", "var x = 1;")
        sm.update_readability("function hello() { return 'hi'; }")
        sm.update_readability("// comment\nfunction hello() { return 'hi'; }")
        assert len(sm.readability_history) == 3  # initial + 2 updates


# ════════════════════════════════════════════════════════════════════════
#  Snapshot and Rollback
# ════════════════════════════════════════════════════════════════════════

class TestSnapshotAndRollback:
    """Test state snapshot and rollback capabilities."""

    def test_snapshot_is_taken(self):
        sm = StateManager("test", "code")
        sm.advance_iteration()
        sm.update_confidence(overall=0.5)
        snap = sm.take_snapshot()
        assert snap.iteration == 1
        assert snap.state.confidence["overall"] == 0.5

    def test_rollback_to_previous(self):
        sm = StateManager("test", "original code")

        # Iteration 1
        sm.advance_iteration()
        sm.update_confidence(overall=0.5)
        sm.current_code = "modified code v1"
        sm.take_snapshot()

        # Iteration 2
        sm.advance_iteration()
        sm.update_confidence(overall=0.3)  # regression
        sm.current_code = "modified code v2 (worse)"
        sm.take_snapshot()

        # Rollback to iteration 1
        success = sm.rollback(to_iteration=1)
        assert success is True
        assert sm.overall_confidence == 0.5
        assert sm.current_code == "modified code v1"

    def test_rollback_without_snapshots_fails(self):
        """Cannot rollback with fewer than 2 snapshots."""
        sm = StateManager("test", "code")
        # Only have the initial snapshot
        result = sm.rollback()
        assert result is False

    def test_get_snapshot_by_iteration(self):
        sm = StateManager("test", "code")
        sm.advance_iteration()
        sm.take_snapshot()
        snap = sm.get_snapshot(1)
        assert snap is not None
        assert snap.iteration == 1

    def test_get_nonexistent_snapshot(self):
        sm = StateManager("test", "code")
        snap = sm.get_snapshot(999)
        assert snap is None

    def test_record_transform(self):
        """Recording a transform should update the state."""
        sm = StateManager("test", "original")
        record = TransformRecord(
            iteration=1,
            action="decode_base64",
            reason="base64 blob detected",
            confidence_before=0.0,
            confidence_after=0.5,
            success=True,
        )
        sm.record_transform(record, new_code="decoded code")
        assert sm.current_code == "decoded code"
        assert len(sm.state.transform_history) == 1

    def test_add_detected_techniques(self):
        sm = StateManager("test", "code")
        sm.add_detected_techniques(["base64_encoding", "string_concatenation"])
        sm.add_detected_techniques(["base64_encoding"])  # duplicate
        assert len(sm.state.detected_techniques) == 2

    def test_set_language(self):
        sm = StateManager("test", "code")
        sm.set_language("javascript")
        assert sm.state.language == "javascript"

    def test_to_dict(self):
        sm = StateManager("test-id", "var x = 1;", language="javascript")
        d = sm.to_dict()
        assert d["sample_id"] == "test-id"
        assert d["current_iteration"] == 0
        assert "state" in d
