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
from typing import Any, Dict, List, Optional

from app.services.ingest.workspace_bundle import (
    truncate_workspace_bundle,
    validate_workspace_bundle_candidate,
    workspace_context_prompt,
)
from app.services.llm.client import LLMClient
from app.services.transforms.base import BaseTransform, TransformResult

logger = logging.getLogger(__name__)

# Hard cap on code sent to the LLM (chars, not tokens — conservative).
_MAX_CODE_CHARS = 12_000
_MAX_RESPONSE_TOKENS = 4096


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
            reply = await self._client.chat(
                messages=messages,
                temperature=self.get_temperature(),
                max_tokens=self.get_max_tokens(),
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
        max_strings: int = 8,
        max_transforms: int = 6,
        max_literals: int = 6,
    ) -> str:
        """Build a compact state summary for prompts.

        LLM transforms were previously prompted with little more than the raw
        code. Passing the distilled state materially improves planning and
        deobfuscation quality without blowing the token budget.
        """
        parts: List[str] = []

        language = state.get("language")
        if language:
            parts.append(f"Language: {language}")

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

        return "\n".join(parts) if parts else "No prior analysis context."

    @staticmethod
    def build_workspace_context(code: str) -> Optional[str]:
        """Return a workspace summary when the input is a bundled codebase."""
        return workspace_context_prompt(code)

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
                "ps1", "ps", "csharp", "cs", "java", "php", "go", "rust",
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

    @staticmethod
    def _python_syntax_ok(code: str) -> bool:
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False

    @staticmethod
    def _json_syntax_ok(code: str) -> bool:
        try:
            json.loads(code)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def _has_balanced_delimiters(code: str) -> bool:
        """Best-effort delimiter balance check that skips strings/comments."""
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
