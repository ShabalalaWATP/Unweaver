"""
Base class for LLM-powered transforms.

Extends BaseTransform with async LLM call capabilities, prompt construction
helpers, response parsing, and token budget management.  Falls back to a
no-op when no LLM client is available so the pipeline never crashes.
"""

from __future__ import annotations

import json
import logging
import re
from abc import abstractmethod
from typing import Any, Dict, List, Optional

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
        half = max_chars // 2
        return (
            code[:half]
            + f"\n\n... [{len(code) - max_chars} characters truncated] ...\n\n"
            + code[-half:]
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
