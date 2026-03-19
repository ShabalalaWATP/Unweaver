"""
LLM-powered code deobfuscation transform.

Sends obfuscated code to the LLM and asks it to produce a cleaner,
more readable equivalent.  This handles obfuscation patterns that are
too complex for regex (custom encoding schemes, multi-layer wrapping,
control-flow flattening, etc.).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.services.transforms.base import TransformResult
from app.services.transforms.llm_base import LLMTransform

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an expert code deobfuscation assistant specialising in malware analysis.
Your task is to take obfuscated code and produce a functionally equivalent but
MUCH more readable version.

Rules:
- Preserve the code's behaviour exactly — do not add, remove, or alter logic.
- Decode encoded strings, resolve dynamic lookups, inline constants.
- Replace meaningless variable/function names with descriptive ones based on
  what the code does (e.g. downloadUrl, decryptPayload, registryKey).
- Flatten unnecessarily nested control flow.
- Remove dead code and junk no-op statements.
- Add short inline comments explaining non-obvious operations.
- Output ONLY the cleaned code inside a single markdown code fence.
- Do NOT include explanations outside the code fence.
"""


class LLMDeobfuscator(LLMTransform):
    """Use the LLM to perform deep, semantic deobfuscation."""

    name = "LLMDeobfuscator"
    description = "LLM-assisted deep code deobfuscation."

    def get_temperature(self) -> float:
        return 0.1  # Low creativity for faithful deobfuscation.

    def build_messages(
        self, code: str, language: str, state: dict
    ) -> List[Dict[str, str]]:
        truncated = self.truncate_code(code)

        # Include context from prior analysis if available.
        context_parts: List[str] = []
        techniques = state.get("detected_techniques", [])
        if techniques:
            context_parts.append(
                f"Detected obfuscation techniques: {', '.join(techniques[:10])}"
            )
        lang = language or state.get("language", "unknown")
        context_parts.append(f"Language: {lang}")

        context = "\n".join(context_parts)

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Deobfuscate the following code.\n\n"
                    f"Context:\n{context}\n\n"
                    f"```\n{truncated}\n```"
                ),
            },
        ]

    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        cleaned = self.extract_code_block(reply)
        if not cleaned or len(cleaned.strip()) < 10:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.2,
                description="LLM deobfuscation returned empty or invalid output.",
                details={"raw_reply_length": len(reply)},
            )

        # Basic quality check: the result should be meaningfully different
        # but not wildly different in size (±80%).
        len_ratio = len(cleaned) / max(len(code), 1)
        if len_ratio > 3.0 or len_ratio < 0.05:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.1,
                description=(
                    f"LLM output size ratio ({len_ratio:.1f}x) is suspicious; "
                    "discarding to be safe."
                ),
                details={"len_ratio": len_ratio},
            )

        return TransformResult(
            success=True,
            output=cleaned,
            confidence=0.75,
            description="LLM deobfuscation applied successfully.",
            details={
                "original_length": len(code),
                "cleaned_length": len(cleaned),
                "len_ratio": round(len_ratio, 2),
            },
        )
