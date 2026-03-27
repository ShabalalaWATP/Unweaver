"""
Base class for LLM-powered transforms.

Extends BaseTransform with async LLM call capabilities, prompt construction
helpers, response parsing, and token budget management.  Falls back to a
no-op when no LLM client is available so the pipeline never crashes.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from abc import abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.services.ingest.workspace_bundle import (
    load_workspace_archive_file_from_path,
    load_workspace_archive_from_path,
    overlay_workspace_files,
    truncate_workspace_bundle,
    validate_workspace_bundle_candidate,
    workspace_context_prompt,
)
from app.services.llm.client import LLMClient
from app.services.transforms.base import BaseTransform, TransformResult
from app.services.transforms.js_tooling import validate_javascript_source
from app.services.transforms.readability_scorer import compute_readability_score
from app.services.transforms.source_preprocessor import normalize_source_anomalies

logger = logging.getLogger(__name__)

# Hard cap on code sent to the LLM (chars, not tokens — conservative).
# Used as fallback when the client has no context_window attribute.
_MAX_CODE_CHARS = 12_000
_MAX_RESPONSE_TOKENS = 4096
_MIN_RESPONSE_TOKENS = 512
_TOKENS_PER_CHAR = 0.3  # conservative estimate for code

# Task-specific multipliers: response tokens needed relative to input tokens.
_TASK_MULTIPLIERS: Dict[str, float] = {
    "deobfuscate": 1.5,
    "classify": 0.05,
    "reflect": 0.1,
    "rename": 0.8,
    "summarize": 0.3,
    "confidence": 0.05,
    "select": 0.05,
}


class LLMTransform(BaseTransform):
    """Base class for transforms that call an LLM.

    Subclasses implement ``build_messages()`` and ``parse_response()``
    instead of ``apply()``.  The base handles the actual LLM call,
    error recovery, and fallback behaviour.

    LLM transforms are identified by ``is_llm = True`` so the executor
    can await them asynchronously.
    """

    is_llm: bool = True

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        self._client = llm_client

    @property
    def has_client(self) -> bool:
        return self._client is not None

    def set_client(self, client: LLMClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    #  Subclass API
    # ------------------------------------------------------------------

    @abstractmethod
    def build_messages(
        self, code: str, language: str, state: dict
    ) -> List[Dict[str, str]]:
        """Construct the chat messages to send to the LLM."""
        ...

    @abstractmethod
    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        """Parse the LLM reply into a TransformResult."""
        ...

    def get_temperature(self) -> float:
        """Override to change the sampling temperature (default 0.2)."""
        return 0.2

    def get_max_tokens(self) -> int:
        """Override to change the max response tokens."""
        return _MAX_RESPONSE_TOKENS

    def _task_type(self) -> str:
        """Override to declare the task type for dynamic token budgeting."""
        return "deobfuscate"

    @staticmethod
    def compute_token_budget(
        input_chars: int,
        task: str = "deobfuscate",
        ceiling: int = _MAX_RESPONSE_TOKENS,
    ) -> int:
        """Compute appropriate max_tokens based on input size and task type.

        Returns a value clamped between ``_MIN_RESPONSE_TOKENS`` and *ceiling*.
        """
        input_tokens_est = int(input_chars * _TOKENS_PER_CHAR)
        multiplier = _TASK_MULTIPLIERS.get(task, 1.0)
        budget = int(input_tokens_est * multiplier)
        return max(_MIN_RESPONSE_TOKENS, min(ceiling, budget))

    def _max_code_chars(self) -> int:
        """Compute max code chars based on the provider's context window.

        Reserves ~30% of the context for system prompt, state context, and
        response tokens.  Converts the remaining token budget to chars at
        ~4 chars/token.  Falls back to the hardcoded ``_MAX_CODE_CHARS``
        when no client or context_window is available.
        """
        if not self._client:
            return _MAX_CODE_CHARS
        context_window = getattr(self._client, "context_window", 131_072)
        available_tokens = int(context_window * 0.70)
        max_chars = available_tokens * 4
        return max(8_000, min(max_chars, 400_000))

    # ------------------------------------------------------------------
    #  BaseTransform interface
    # ------------------------------------------------------------------

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        """LLM transforms are applicable when a client is available and
        there is code to analyse."""
        return self.has_client and bool(code and code.strip())

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        """Synchronous fallback — should not be called directly.

        The executor detects ``is_llm`` and calls ``apply_async`` instead.
        If called synchronously for some reason, return a no-op.
        """
        return TransformResult(
            success=False,
            output=code,
            confidence=0.0,
            description=f"{self.name}: requires async execution with LLM.",
            details={"error": "sync_fallback"},
        )

    async def apply_async(
        self, code: str, language: str, state: dict
    ) -> TransformResult:
        """Async entry point called by the executor for LLM transforms."""
        if not self.has_client:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description=f"{self.name}: no LLM provider configured.",
                details={"skipped": True},
            )

        try:
            messages = self.build_messages(code, language, state)
            # Use dynamic token budget unless subclass overrides get_max_tokens
            max_tok = self.get_max_tokens()
            if max_tok == _MAX_RESPONSE_TOKENS:
                max_tok = self.compute_token_budget(len(code), self._task_type())
            reply = await self._client.chat(
                messages=messages,
                temperature=self.get_temperature(),
                max_tokens=max_tok,
            )
            return self.parse_response(reply, code, language, state)
        except Exception as exc:
            logger.exception("%s LLM call failed", self.name)
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description=f"{self.name} failed: {exc}",
                details={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    #  Helpers available to subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def truncate_code(code: str, max_chars: int = _MAX_CODE_CHARS) -> str:
        """Truncate code to fit within token budget."""
        if len(code) <= max_chars:
            return code
        workspace_excerpt = truncate_workspace_bundle(code, max_chars)
        if workspace_excerpt != code[:max_chars]:
            return workspace_excerpt
        segment = max(max_chars // 3, 1)
        middle_start = max((len(code) // 2) - (segment // 2), 0)
        middle_end = middle_start + segment
        return (
            code[:segment]
            + f"\n\n... [middle omitted, {len(code) - (segment * 3)} characters truncated] ...\n\n"
            + code[middle_start:middle_end]
            + "\n\n... [tail excerpt follows] ...\n\n"
            + code[-segment:]
        )

    @staticmethod
    def extract_json(text: str) -> Optional[Dict[str, Any]]:
        """Try to extract a JSON object from LLM response text.

        Handles markdown code fences, leading text, etc.
        """
        # Try direct parse first.
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try extracting from code fences.
        fence_match = re.search(
            r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL
        )
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except (json.JSONDecodeError, TypeError):
                pass

        # Try finding first { ... } block.
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except (json.JSONDecodeError, TypeError):
                pass

        return None

    @staticmethod
    def extract_code_block(text: str) -> Optional[str]:
        """Extract code from a markdown-fenced block in LLM output."""
        fence_match = re.search(
            r"```(?:\w+)?\s*\n(.*?)\n```", text, re.DOTALL
        )
        if fence_match:
            return fence_match.group(1).strip()

        # If no fence, but the whole reply looks like code, return it.
        lines = text.strip().splitlines()
        if len(lines) > 3 and not text.startswith("{"):
            return text.strip()

        return None

    @staticmethod
    def build_state_context(
        state: dict,
        *,
        code: Optional[str] = None,
        compact: bool = False,
        max_strings: int = 8,
        max_transforms: int = 6,
        max_literals: int = 6,
    ) -> str:
        """Build a compact state summary for prompts.

        LLM transforms were previously prompted with little more than the raw
        code. Passing the distilled state materially improves planning and
        deobfuscation quality without blowing the token budget.

        When *compact* is True, produces a shorter summary suitable for
        orchestrator-level LLM calls (classification, selection, reflection).
        """
        if compact:
            max_strings = 4
            max_transforms = 3
            max_literals = 3

        parts: List[str] = []

        language = state.get("language")
        if language:
            parts.append(f"Language: {language}")

        iteration_state = state.get("iteration_state", {})
        if isinstance(iteration_state, dict):
            js_hard_mode = iteration_state.get("js_hard_mode")
            if isinstance(js_hard_mode, dict) and js_hard_mode.get("enabled"):
                score = js_hard_mode.get("score")
                score_text = (
                    f" (score {float(score):.1f})"
                    if isinstance(score, (int, float))
                    else ""
                )
                parts.append(f"JavaScript hard mode: enabled{score_text}")
                signals = [
                    str(item)
                    for item in js_hard_mode.get("signals", [])[:6]
                    if str(item).strip()
                ]
                if signals:
                    parts.append("Hard-mode signals: " + " | ".join(signals))

            llm_classification = iteration_state.get("llm_classification")
            if isinstance(llm_classification, dict):
                obfuscation_type = str(
                    llm_classification.get("obfuscation_type", "")
                ).strip()
                if obfuscation_type:
                    parts.append(f"Classifier verdict: {obfuscation_type}")
                tools = [
                    str(item)
                    for item in llm_classification.get("tools_identified", [])[:6]
                    if str(item).strip()
                ]
                if tools:
                    parts.append("Classifier tools: " + " | ".join(tools))

        confidence = state.get("confidence", {})
        overall = confidence.get("overall")
        if isinstance(overall, (int, float)):
            parts.append(f"Overall confidence: {overall:.2f}")

        techniques = state.get("detected_techniques", [])
        if techniques:
            parts.append(
                "Detected techniques: " + ", ".join(str(t) for t in techniques[:12])
            )

        suspicious_apis = state.get("suspicious_apis", [])
        if suspicious_apis:
            parts.append(
                "Suspicious APIs: " + ", ".join(str(api) for api in suspicious_apis[:10])
            )

        imports = state.get("imports", [])
        if imports:
            parts.append(
                "Imports: " + " | ".join(str(item)[:100] for item in imports[:10])
            )

        functions = state.get("functions", [])
        if functions:
            parts.append(
                "Functions: " + " | ".join(str(item)[:100] for item in functions[:10])
            )

        workspace_context = state.get("workspace_context", {})
        if isinstance(workspace_context, dict):
            indexed_file_count = workspace_context.get("indexed_file_count")
            bundled_file_count = workspace_context.get("bundled_file_count")
            if isinstance(indexed_file_count, int):
                bundle_text = (
                    f" ({bundled_file_count} currently bundled)"
                    if isinstance(bundled_file_count, int)
                    else ""
                )
                parts.append(f"Workspace indexed files: {indexed_file_count}{bundle_text}")
            entry_points = workspace_context.get("entry_points", [])
            if entry_points:
                parts.append(
                    "Workspace entry points: "
                    + " | ".join(str(item) for item in entry_points[:6])
                )
            suspicious_files = workspace_context.get("suspicious_files", [])
            if suspicious_files:
                parts.append(
                    "Workspace suspicious files: "
                    + " | ".join(str(item) for item in suspicious_files[:6])
                )
            dependency_hotspots = workspace_context.get("dependency_hotspots", [])
            if dependency_hotspots:
                parts.append(
                    "Workspace hotspots: "
                    + " | ".join(str(item) for item in dependency_hotspots[:6])
                )
            unbundled_hotspots = workspace_context.get("unbundled_hotspots", [])
            if unbundled_hotspots:
                parts.append(
                    "Deferred hotspots: "
                    + " | ".join(str(item) for item in unbundled_hotspots[:6])
                )
            execution_paths = workspace_context.get("execution_paths", [])
            if execution_paths:
                parts.append(
                    "Workspace execution paths: "
                    + " | ".join(str(item) for item in execution_paths[:4])
                )
            prioritized_files = workspace_context.get("prioritized_files", [])
            if prioritized_files:
                hotspot_paths: List[str] = []
                for item in prioritized_files[:6]:
                    if isinstance(item, dict):
                        value = str(item.get("path", "")).strip()
                    else:
                        value = str(item).strip()
                    if value:
                        hotspot_paths.append(value)
                if hotspot_paths:
                    parts.append(
                        "Prioritized files: " + " | ".join(hotspot_paths)
                    )
            llm_focus_paths = workspace_context.get("llm_focus_paths", [])
            if llm_focus_paths:
                parts.append(
                    "LLM focus paths: "
                    + " | ".join(str(item) for item in llm_focus_paths[:8])
                )
            graph_summary = workspace_context.get("graph_summary", {})
            if isinstance(graph_summary, dict) and graph_summary:
                graph_parts: List[str] = []
                for key in ("local_edges", "external_edges", "cross_file_calls", "execution_paths", "bundle_expansion_candidates"):
                    value = graph_summary.get(key)
                    if isinstance(value, int):
                        graph_parts.append(f"{key}={value}")
                if graph_parts:
                    parts.append("Workspace graph: " + ", ".join(graph_parts))

            workspace_focus_excerpt = LLMTransform._build_workspace_focus_excerpt(
                state,
                code=code,
                compact=compact,
            )
            if workspace_focus_excerpt:
                parts.append(workspace_focus_excerpt)

        recovered_literals = state.get("recovered_literals", [])
        if recovered_literals:
            literal_sample = [str(v)[:80] for v in recovered_literals[:max_literals]]
            parts.append(f"Recovered literals: {literal_sample}")

        strings = state.get("strings", [])
        if strings:
            string_sample: List[str] = []
            for item in strings[:max_strings]:
                if isinstance(item, dict):
                    value = str(item.get("value", ""))[:80]
                else:
                    value = str(getattr(item, "value", item))[:80]
                if value:
                    string_sample.append(value)
            if string_sample:
                parts.append(f"String sample: {string_sample}")

        history = state.get("transform_history", [])
        if history:
            recent: List[str] = []
            for item in history[-max_transforms:]:
                if isinstance(item, dict):
                    action = item.get("action", "unknown")
                    success = item.get("success", False)
                else:
                    action = getattr(item, "action", "unknown")
                    success = getattr(item, "success", False)
                recent.append(f"{action}:{'ok' if success else 'fail'}")
            if recent:
                parts.append("Recent transforms: " + " -> ".join(recent))

        llm_suggestions = state.get("llm_suggestions", [])
        if llm_suggestions:
            parts.append(
                "Prior suggestions: " + " | ".join(str(s)[:100] for s in llm_suggestions[:6])
            )

        evidence_digest = LLMTransform.build_evidence_digest(
            state,
            source_text=code or "",
            compact=compact,
        )
        if evidence_digest:
            parts.append(evidence_digest)

        return "\n".join(parts) if parts else "No prior analysis context."

    @staticmethod
    def build_workspace_context(code: str) -> Optional[str]:
        """Return a workspace summary when the input is a bundled codebase."""
        return workspace_context_prompt(code)

    @staticmethod
    def _build_workspace_focus_excerpt(
        state: dict,
        *,
        code: str = "",
        compact: bool = False,
    ) -> Optional[str]:
        workspace_context = state.get("workspace_context", {})
        if not isinstance(workspace_context, dict):
            return None

        iteration_state = state.get("iteration_state", {})
        if not isinstance(iteration_state, dict):
            return None
        sample_metadata = iteration_state.get("sample_metadata", {})
        if not isinstance(sample_metadata, dict):
            return None
        if sample_metadata.get("content_kind") != "archive_bundle":
            return None

        archive_path = str(sample_metadata.get("stored_file_path", "")).strip()
        if not archive_path:
            return None

        focus_paths: List[str] = []
        for key in ("llm_focus_paths", "dependency_hotspots", "symbol_hotspots", "bundle_expansion_paths"):
            for value in workspace_context.get(key, []):
                path = str(value).strip()
                if path and path not in focus_paths:
                    focus_paths.append(path)
        if not focus_paths:
            return None

        try:
            scan = load_workspace_archive_from_path(
                archive_path,
                archive_name=str(sample_metadata.get("filename") or Path(archive_path).name),
                max_member_bytes=getattr(settings, "MAX_ARCHIVE_MEMBER_SIZE", 2 * 1024 * 1024),
                max_scan_files=getattr(settings, "MAX_ARCHIVE_SCAN_FILES", 0) or None,
            )
        except Exception:
            return None

        overlaid_files = overlay_workspace_files(code, scan.files)
        by_path = {item.path: item for item in overlaid_files}
        max_files = 3 if compact else getattr(settings, "MAX_WORKSPACE_LLM_FOCUS_FILES", 8)
        max_chars = 3200 if compact else 9000
        excerpts: List[str] = []
        used_chars = 0

        for path in focus_paths:
            file = by_path.get(path)
            if file is None:
                file = load_workspace_archive_file_from_path(
                    archive_path,
                    member_path=path,
                    archive_name=str(sample_metadata.get("filename") or Path(archive_path).name),
                    max_member_bytes=getattr(settings, "MAX_ARCHIVE_MEMBER_SIZE", 2 * 1024 * 1024),
                )
            if file is None:
                continue
            remaining = max_chars - used_chars
            if remaining < 280:
                break
            snippet_budget = min(1400 if not compact else 700, max(remaining - 160, 120))
            snippet = file.text[:snippet_budget].rstrip()
            excerpts.append(f"[{file.path}] ({file.language})\n{snippet}")
            used_chars += len(excerpts[-1]) + 2
            if len(excerpts) >= max_files:
                break

        if not excerpts:
            return None
        return "Workspace focus excerpts:\n" + "\n\n".join(excerpts)

    @staticmethod
    def _state_text_value(item: Any) -> str:
        if isinstance(item, dict):
            for key in ("value", "decoded", "context", "path", "name", "type"):
                value = item.get(key)
                if value:
                    return str(value)
            return ""
        return str(getattr(item, "value", item))

    @staticmethod
    def _clean_evidence_value(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip())[:140]

    @staticmethod
    def _is_salient_evidence(text: str, kind: str) -> bool:
        if not text:
            return False
        if text.lower() in {"none", "unknown", "null", "true", "false"}:
            return False
        if not any(ch.isalnum() for ch in text):
            return False

        min_len = 4
        if kind in {"api", "import", "function"}:
            min_len = 3
        if len(text) < min_len:
            return False

        if kind in {"string", "literal"} and re.fullmatch(r"[A-Za-z_]\w{0,3}", text):
            return False
        return True

    @classmethod
    def collect_evidence_items(
        cls,
        state: Optional[dict],
        *,
        source_text: str = "",
        max_items: int = 12,
    ) -> List[Dict[str, str]]:
        state = state or {}
        items: List[Dict[str, str]] = []
        seen: set[str] = set()

        def add(kind: str, raw_value: Any) -> None:
            value = cls._clean_evidence_value(cls._state_text_value(raw_value))
            if not cls._is_salient_evidence(value, kind):
                return
            key = f"{kind}:{value.lower()}"
            if key in seen:
                return
            seen.add(key)
            items.append({"kind": kind, "value": value})

        for value in state.get("recovered_literals", [])[: max_items * 2]:
            add("literal", value)
        for value in state.get("suspicious_apis", [])[: max_items * 2]:
            add("api", value)
        for value in state.get("imports", [])[:max_items]:
            add("import", value)
        for value in state.get("functions", [])[:max_items]:
            add("function", value)
        for value in state.get("evidence_references", [])[:max_items]:
            add("evidence", value)
        for value in state.get("strings", [])[: max_items * 2]:
            add("string", value)

        excerpt = source_text[:40_000]
        patterns = [
            ("url", re.compile(r"https?://[^\s'\"`<>]+", re.IGNORECASE)),
            ("registry", re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s'\"`<>]+", re.IGNORECASE)),
            ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
            ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
            ("domain", re.compile(r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b", re.IGNORECASE)),
        ]
        for kind, pattern in patterns:
            for match in pattern.findall(excerpt):
                add(kind, match)
                if len(items) >= max_items:
                    break
            if len(items) >= max_items:
                break

        return items[:max_items]

    @classmethod
    def build_evidence_digest(
        cls,
        state: Optional[dict],
        *,
        source_text: str = "",
        compact: bool = False,
    ) -> str:
        max_items = 4 if compact else 6
        items = cls.collect_evidence_items(
            state,
            source_text=source_text,
            max_items=max_items,
        )
        if not items:
            return ""
        rendered = [
            f"{item['kind']}={item['value']}"
            for item in items[:max_items]
        ]
        return "Evidence anchors: " + " | ".join(rendered)

    @staticmethod
    def validate_candidate_code(
        original: str,
        candidate: str,
        language: str,
    ) -> Dict[str, Any]:
        """Run lightweight structural validation on a candidate rewrite."""
        issues: List[str] = []
        workspace_validation: Optional[Dict[str, Any]] = None
        if not candidate or not candidate.strip():
            return {
                "accepted": False,
                "issues": ["empty_candidate"],
                "delimiter_balance_ok": False,
                "syntax_ok": False,
                "workspace_validation": None,
            }

        lang = (language or "").lower()
        delimiter_balance_ok = LLMTransform._has_balanced_delimiters(candidate)
        if not delimiter_balance_ok:
            issues.append("unbalanced_delimiters")

        syntax_ok: Optional[bool] = None
        if lang in {"python", "py"}:
            syntax_ok = LLMTransform._python_syntax_ok(candidate)
            if not syntax_ok:
                issues.append("python_syntax_error")
        elif lang in {"javascript", "js", "jsx", "mjs", "cjs", "typescript", "ts", "tsx"}:
            syntax_ok = LLMTransform._javascript_syntax_ok(candidate, language=lang)
            if not syntax_ok:
                issues.append("javascript_syntax_error")
        elif lang == "json":
            syntax_ok = LLMTransform._json_syntax_ok(candidate)
            if not syntax_ok:
                issues.append("json_syntax_error")

        accepted = True
        if syntax_ok is False:
            accepted = False
        elif (
            not delimiter_balance_ok
            and lang in {
                "javascript", "js", "typescript", "ts", "powershell",
                "jsx", "tsx", "ps1", "ps", "csharp", "cs", "java", "php", "go", "rust",
            }
        ):
            accepted = False

        # If the original looked structurally balanced but the candidate does
        # not, treat it as suspicious even for unknown languages.
        if accepted and LLMTransform._has_balanced_delimiters(original) and not delimiter_balance_ok:
            accepted = False

        if workspace_context_prompt(original):
            workspace_validation = validate_workspace_bundle_candidate(original, candidate)
            if not workspace_validation["accepted"]:
                accepted = False
                issues.extend(workspace_validation["issues"])

        return {
            "accepted": accepted,
            "issues": issues,
            "delimiter_balance_ok": delimiter_balance_ok,
            "syntax_ok": syntax_ok,
            "workspace_validation": workspace_validation,
        }

    @classmethod
    def assess_candidate_rewrite(
        cls,
        original: str,
        candidate: str,
        language: str,
        state: Optional[dict],
        *,
        artifacts: Optional[List[Any]] = None,
        allow_noop: bool = False,
        min_readability_delta: Optional[float] = None,
        require_evidence_retention: bool = True,
    ) -> Dict[str, Any]:
        validation = cls.validate_candidate_code(original, candidate, language)
        issues = validation["issues"]

        readability_before, _ = compute_readability_score(original)
        readability_after, _ = compute_readability_score(candidate)
        readability_delta = round(readability_after - readability_before, 1)

        normalized_original = re.sub(r"\s+", "", original)
        normalized_candidate = re.sub(r"\s+", "", candidate)
        noop = normalized_original == normalized_candidate

        evidence_items = cls.collect_evidence_items(
            state,
            source_text=original,
            max_items=10,
        )
        evidence_haystack = "\n".join(
            [candidate] + [str(item) for item in (artifacts or []) if item]
        ).lower()
        retained = [
            item for item in evidence_items
            if item["value"].lower() in evidence_haystack
        ]
        critical_kinds = {"url", "registry", "ip", "email", "domain", "literal", "api", "evidence"}
        required = any(item["kind"] in critical_kinds for item in evidence_items)

        if noop and not allow_noop:
            issues.append("rewrite_no_effect")
            validation["accepted"] = False

        if min_readability_delta is not None and readability_delta < min_readability_delta:
            issues.append("readability_regressed")
            validation["accepted"] = False

        if require_evidence_retention and required and not retained:
            issues.append("evidence_dropped")
            validation["accepted"] = False

        validation["readability_before"] = readability_before
        validation["readability_after"] = readability_after
        validation["readability_delta"] = readability_delta
        validation["noop"] = noop
        validation["evidence"] = {
            "required": required,
            "anchors": evidence_items,
            "retained": retained,
            "retained_count": len(retained),
            "missing_count": max(len(evidence_items) - len(retained), 0),
        }
        return validation

    @staticmethod
    def _python_syntax_ok(code: str) -> bool:
        code, _ = normalize_source_anomalies(code)
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False

    @staticmethod
    def _javascript_syntax_ok(code: str, *, language: str = "javascript") -> bool:
        code, _ = normalize_source_anomalies(code)
        if not code.strip():
            return False
        validation = validate_javascript_source(code, language=language)
        if validation.get("ok") is True:
            return True
        return validation.get("error") in {"node_unavailable", "worker_missing", "tooling_unavailable"}

    @staticmethod
    def _json_syntax_ok(code: str) -> bool:
        code, _ = normalize_source_anomalies(code)
        try:
            json.loads(code)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def _has_balanced_delimiters(code: str) -> bool:
        """Best-effort delimiter balance check that skips strings/comments."""
        code, _ = normalize_source_anomalies(code)
        pairs = {"(": ")", "{": "}", "[": "]"}
        closing = {value: key for key, value in pairs.items()}
        stack: List[str] = []

        i = 0
        quote: Optional[str] = None
        in_line_comment = False
        in_block_comment = False

        while i < len(code):
            ch = code[i]
            nxt = code[i + 1] if i + 1 < len(code) else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if quote is not None:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue

            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == "#":
                in_line_comment = True
                i += 1
                continue
            if ch in {"'", '"', "`"}:
                quote = ch
                i += 1
                continue

            if ch in pairs:
                stack.append(ch)
            elif ch in closing:
                if not stack or stack[-1] != closing[ch]:
                    return False
                stack.pop()
            i += 1

        return not stack and quote is None and not in_block_comment
