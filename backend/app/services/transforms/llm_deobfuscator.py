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
- For JavaScript/TypeScript, prefer conventional handwritten names:
  use stringTable / resolveString / decodeString where appropriate,
  booleans with is/has/should, plural collection names, callback/handler
  verbs, and Element suffixes for DOM nodes when the role is clear.
- Flatten unnecessarily nested control flow.
- Remove dead code and junk no-op statements.
- When the sample shows hard JavaScript obfuscation, prioritise collapsing
  helper wrappers, string-array resolvers, constructor/eval chains,
  control-flow dispatchers, and self-defending / debugger / domain-lock
  scaffolding only when those guards are analysis-hostile wrappers rather
  than business logic.
- Add short inline comments explaining non-obvious operations.
- Return JSON with exactly these fields:
  {
    "cleaned_code": "the rewritten code",
    "decoded_artifacts": ["decoded strings, URLs, commands, or payload fragments"],
    "renames": {"oldName": "newName"},
    "remaining_uncertainties": ["anything still ambiguous or unresolved"],
    "confidence": 0.0 to 1.0
  }
- The cleaned_code field must contain the full rewritten code, not a summary.
- Do not omit code just because parts remain unclear; preserve those sections.
- If the input is a workspace bundle with <<<FILE ...>>> markers, preserve the
  file markers and keep edits scoped to the relevant file blocks.
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
        truncated = self.truncate_code(code, max_chars=self._max_code_chars())
        lang = language or state.get("language", "unknown")
        context = self.build_state_context(state, code=code)
        workspace = self.build_workspace_context(code)

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Deobfuscate the following code.\n\n"
                    f"Declared language: {lang}\n"
                    f"Context:\n{context}\n\n"
                    + (f"Workspace context:\n{workspace}\n\n" if workspace else "")
                    + (
                    f"```\n{truncated}\n```"
                    )
                ),
            },
        ]

    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        data = self.extract_json(reply)
        decoded_artifacts: List[str] = []
        renames: Dict[str, str] = {}
        remaining_uncertainties: List[str] = []
        confidence = 0.75

        if isinstance(data, dict):
            cleaned = str(data.get("cleaned_code", "")).strip()
            decoded_artifacts = [
                str(item)[:500] for item in data.get("decoded_artifacts", [])[:20]
            ]
            raw_renames = data.get("renames", {})
            if isinstance(raw_renames, dict):
                renames = {
                    str(old): str(new)
                    for old, new in list(raw_renames.items())[:30]
                    if isinstance(old, str) and isinstance(new, str)
                }
            remaining_uncertainties = [
                str(item)[:200]
                for item in data.get("remaining_uncertainties", [])[:10]
            ]
            raw_confidence = data.get("confidence", confidence)
            if isinstance(raw_confidence, (int, float)):
                confidence = float(raw_confidence)
        else:
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

        validation = self.assess_candidate_rewrite(
            code,
            cleaned,
            language,
            state,
            artifacts=decoded_artifacts + remaining_uncertainties,
            allow_noop=False,
            min_readability_delta=-3.0,
            require_evidence_retention=True,
        )
        if not validation["accepted"]:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.1,
                description=(
                    "LLM deobfuscation produced structurally unsafe output; "
                    "discarding candidate."
                ),
                details={
                    "len_ratio": len_ratio,
                    "validation": validation,
                },
            )

        return TransformResult(
            success=True,
            output=cleaned,
            confidence=min(max(confidence, 0.3), 0.9),
            description="LLM deobfuscation applied successfully.",
            details={
                "original_length": len(code),
                "cleaned_length": len(cleaned),
                "len_ratio": round(len_ratio, 2),
                "decoded_artifacts": decoded_artifacts,
                "renames": renames,
                "remaining_uncertainties": remaining_uncertainties,
                "validation": validation,
            },
        )
