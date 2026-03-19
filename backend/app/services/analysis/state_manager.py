"""
State manager for the deobfuscation orchestrator.

Maintains the normalised ``AnalysisState`` across iterations, tracks
confidence and readability evolution, persists iteration snapshots,
and supports state rollback for backtracking.
"""

from __future__ import annotations

import copy
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.schemas import (
    AnalysisState,
    Finding,
    IOC,
    StringEntry,
    TransformRecord,
)

logger = logging.getLogger(__name__)


class StateSnapshot:
    """Immutable snapshot of analysis state at a given iteration."""

    __slots__ = ("iteration", "state", "code", "timestamp")

    def __init__(self, iteration: int, state: AnalysisState, code: str) -> None:
        self.iteration = iteration
        self.state = state.model_copy(deep=True)
        self.code = code
        self.timestamp = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return (
            f"<StateSnapshot iter={self.iteration} "
            f"confidence={self.state.confidence.get('overall', 0):.2f}>"
        )


class StateManager:
    """Tracks and manages the evolving analysis state.

    Responsibilities
    ----------------
    * Initialise the state from sample metadata.
    * Update state after each transform.
    * Keep a full snapshot history for backtracking.
    * Compute readability and confidence deltas.
    * Optionally persist snapshots to a DB session.
    """

    def __init__(
        self,
        sample_id: str,
        original_code: str,
        language: Optional[str] = None,
        db_session: Any = None,
    ) -> None:
        self.sample_id = sample_id
        self.original_code = original_code
        self.current_code = original_code
        self.db_session = db_session

        # The live state object.
        self.state = AnalysisState(language=language)

        # Full history of snapshots for rollback.
        self._snapshots: List[StateSnapshot] = []

        # Confidence / readability history for trend analysis.
        self._confidence_history: List[float] = [0.0]
        self._readability_history: List[float] = [self._estimate_readability(original_code)]

        # Take the initial snapshot (iteration 0).
        self._take_snapshot(0)

    # ------------------------------------------------------------------
    #  Properties
    # ------------------------------------------------------------------

    @property
    def current_iteration(self) -> int:
        return int(self.state.iteration_state.get("current_iteration", 0))

    @property
    def overall_confidence(self) -> float:
        return float(self.state.confidence.get("overall", 0.0))

    @property
    def stall_counter(self) -> int:
        return int(self.state.iteration_state.get("stall_counter", 0))

    @property
    def is_stopped(self) -> bool:
        return bool(self.state.iteration_state.get("stopped", False))

    @property
    def confidence_history(self) -> List[float]:
        return list(self._confidence_history)

    @property
    def readability_history(self) -> List[float]:
        return list(self._readability_history)

    @property
    def snapshot_count(self) -> int:
        return len(self._snapshots)

    # ------------------------------------------------------------------
    #  State update API
    # ------------------------------------------------------------------

    def advance_iteration(self) -> int:
        """Increment and return the new iteration number."""
        current = self.current_iteration + 1
        self.state.iteration_state["current_iteration"] = current
        return current

    def record_transform(
        self,
        record: TransformRecord,
        new_code: Optional[str] = None,
    ) -> None:
        """Append a transform record and optionally update the current code."""
        self.state.transform_history.append(record)
        if new_code is not None:
            self.current_code = new_code

    def update_confidence(
        self,
        overall: Optional[float] = None,
        naming: Optional[float] = None,
        structure: Optional[float] = None,
        strings: Optional[float] = None,
    ) -> None:
        """Selectively update confidence sub-scores."""
        if overall is not None:
            self.state.confidence["overall"] = max(0.0, min(1.0, overall))
        if naming is not None:
            self.state.confidence["naming"] = max(0.0, min(1.0, naming))
        if structure is not None:
            self.state.confidence["structure"] = max(0.0, min(1.0, structure))
        if strings is not None:
            self.state.confidence["strings"] = max(0.0, min(1.0, strings))
        self._confidence_history.append(self.overall_confidence)

    def update_readability(self, code: Optional[str] = None) -> float:
        """Recompute readability for the current (or given) code.

        Returns the new readability score.
        """
        target = code if code is not None else self.current_code
        score = self._estimate_readability(target)
        self._readability_history.append(score)
        return score

    def add_strings(self, entries: List[StringEntry]) -> None:
        existing_values = {s.value for s in self.state.strings}
        for entry in entries:
            if entry.value not in existing_values:
                self.state.strings.append(entry)
                existing_values.add(entry.value)

    def add_detected_techniques(self, techniques: List[str]) -> None:
        existing = set(self.state.detected_techniques)
        for t in techniques:
            if t not in existing:
                self.state.detected_techniques.append(t)
                existing.add(t)

    def add_suspicious_apis(self, apis: List[str]) -> None:
        existing = set(self.state.suspicious_apis)
        for api in apis:
            if api not in existing:
                self.state.suspicious_apis.append(api)
                existing.add(api)

    def add_recovered_literals(self, literals: List[str]) -> None:
        existing = set(self.state.recovered_literals)
        for lit in literals:
            if lit not in existing:
                self.state.recovered_literals.append(lit)
                existing.add(lit)

    def add_imports(self, imports: List[str]) -> None:
        existing = set(self.state.imports)
        for imp in imports:
            if imp not in existing:
                self.state.imports.append(imp)
                existing.add(imp)

    def add_functions(self, functions: List[str]) -> None:
        existing = set(self.state.functions)
        for fn in functions:
            if fn not in existing:
                self.state.functions.append(fn)
                existing.add(fn)

    def set_language(self, language: str) -> None:
        self.state.language = language

    def set_parse_status(self, status: str) -> None:
        self.state.parse_status = status

    def increment_stall(self) -> int:
        counter = self.stall_counter + 1
        self.state.iteration_state["stall_counter"] = counter
        return counter

    def reset_stall(self) -> None:
        self.state.iteration_state["stall_counter"] = 0

    def mark_stopped(self) -> None:
        self.state.iteration_state["stopped"] = True

    def set_summary(self, summary: str) -> None:
        self.state.analysis_summary = summary

    # ------------------------------------------------------------------
    #  Snapshot & rollback
    # ------------------------------------------------------------------

    def take_snapshot(self) -> StateSnapshot:
        """Take a snapshot of the current state."""
        return self._take_snapshot(self.current_iteration)

    def _take_snapshot(self, iteration: int) -> StateSnapshot:
        snap = StateSnapshot(iteration, self.state, self.current_code)
        self._snapshots.append(snap)
        logger.debug("Snapshot taken at iteration %d", iteration)
        return snap

    def rollback(self, to_iteration: Optional[int] = None) -> bool:
        """Roll back to a previous iteration's state.

        If *to_iteration* is ``None``, rolls back to the most recent
        snapshot before the current one.

        Returns ``True`` on success, ``False`` if no valid snapshot exists.
        """
        if len(self._snapshots) < 2:
            logger.warning("Cannot rollback: fewer than 2 snapshots available")
            return False

        if to_iteration is not None:
            target = None
            for snap in reversed(self._snapshots):
                if snap.iteration <= to_iteration:
                    target = snap
                    break
            if target is None:
                logger.warning("No snapshot found at or before iteration %d", to_iteration)
                return False
        else:
            # Roll back to the snapshot before the last one.
            target = self._snapshots[-2]

        logger.info(
            "Rolling back from iteration %d to %d",
            self.current_iteration,
            target.iteration,
        )
        self.state = target.state.model_copy(deep=True)
        self.current_code = target.code
        # Trim snapshots after the rollback point.
        self._snapshots = [
            s for s in self._snapshots if s.iteration <= target.iteration
        ]
        # Trim histories.
        keep = target.iteration + 1
        self._confidence_history = self._confidence_history[:keep]
        self._readability_history = self._readability_history[:keep]
        return True

    def get_snapshot(self, iteration: int) -> Optional[StateSnapshot]:
        """Retrieve a specific snapshot by iteration number."""
        for snap in self._snapshots:
            if snap.iteration == iteration:
                return snap
        return None

    # ------------------------------------------------------------------
    #  Persistence
    # ------------------------------------------------------------------

    async def persist_snapshot(self) -> None:
        """Persist the current state snapshot to the database.

        This is a no-op when no db_session is available.  The actual
        ORM model will be provided by ``app.models.db_models`` once it
        exists; for now we store the JSON payload and log.
        """
        if self.db_session is None:
            return

        try:
            payload = {
                "sample_id": self.sample_id,
                "iteration": self.current_iteration,
                "state_json": self.state.model_dump(),
                "code_snapshot": self.current_code[:50_000],  # cap size
                "overall_confidence": self.overall_confidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            # If the session has an ``execute`` method (SQLAlchemy AsyncSession),
            # store as raw insert. Otherwise just log.
            if hasattr(self.db_session, "execute"):
                logger.debug(
                    "Persisting snapshot for sample %s iteration %d",
                    self.sample_id,
                    self.current_iteration,
                )
                # Actual INSERT will go here when ORM models are ready.
                # For now, we just commit the intent.
            else:
                logger.debug("DB session has no execute method; skipping persist")
        except Exception:
            logger.exception("Failed to persist state snapshot")

    # ------------------------------------------------------------------
    #  Readability heuristic
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_readability(code: str) -> float:
        """Quick heuristic readability score for code (0.0 to 1.0).

        Heuristics used:
        * Average identifier length (longer is usually more readable).
        * Ratio of alphanumeric characters to total.
        * Ratio of printable lines to total lines.
        * Presence of comments.
        * Average line length penalty (extremely long lines are bad).
        """
        if not code or not code.strip():
            return 0.0

        lines = code.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return 0.0

        # --- Metric 1: printable ratio ---
        total_chars = len(code)
        alpha_count = sum(1 for c in code if c.isalnum() or c in " _\n\t")
        alpha_ratio = alpha_count / total_chars if total_chars else 0.0

        # --- Metric 2: average line length penalty ---
        avg_line_len = total_chars / total_lines
        # Sweet spot: 40-80 chars.  Penalise very short or very long.
        if avg_line_len < 5:
            line_score = 0.2
        elif avg_line_len <= 100:
            line_score = 1.0
        elif avg_line_len <= 300:
            line_score = 0.5
        else:
            line_score = 0.1

        # --- Metric 3: comment presence ---
        comment_markers = ("#", "//", "/*", "<!--", "<#", "REM ")
        comment_lines = sum(
            1 for line in lines
            if line.strip().startswith(comment_markers)
        )
        comment_ratio = min(comment_lines / total_lines, 0.3) / 0.3  # cap at 30%

        # --- Metric 4: short-identifier penalty ---
        # Count tokens that look like identifiers (alphanumeric + underscore).
        import re
        identifiers = re.findall(r"\b[a-zA-Z_]\w*\b", code)
        if identifiers:
            avg_id_len = sum(len(i) for i in identifiers) / len(identifiers)
            id_score = min(avg_id_len / 8.0, 1.0)  # 8+ chars is good
        else:
            id_score = 0.3

        # --- Metric 5: non-whitespace line ratio ---
        non_empty = sum(1 for line in lines if line.strip())
        content_ratio = non_empty / total_lines if total_lines else 0.0

        # Weighted combination.
        score = (
            0.25 * alpha_ratio
            + 0.20 * line_score
            + 0.15 * comment_ratio
            + 0.25 * id_score
            + 0.15 * content_ratio
        )
        return max(0.0, min(1.0, score))

    # ------------------------------------------------------------------
    #  Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Full serialisation of the manager for debugging / export."""
        return {
            "sample_id": self.sample_id,
            "current_iteration": self.current_iteration,
            "overall_confidence": self.overall_confidence,
            "stall_counter": self.stall_counter,
            "is_stopped": self.is_stopped,
            "confidence_history": self._confidence_history,
            "readability_history": self._readability_history,
            "snapshot_count": len(self._snapshots),
            "state": self.state.model_dump(),
            "current_code_length": len(self.current_code),
        }
