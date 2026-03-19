"""
LLM-powered semantic variable/function renaming.

Asks the LLM to analyse code and suggest meaningful names for obfuscated
identifiers based on their usage context — far more accurate than the
heuristic rename suggester.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from app.services.transforms.base import TransformResult
from app.services.transforms.llm_base import LLMTransform

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a reverse engineering expert. Analyse the following code and suggest
meaningful, descriptive names for obfuscated identifiers.

Rules:
- Only rename identifiers that are clearly obfuscated (e.g. _0x4a3f, a1b2,
  single-letter variables used many times, etc.).
- Suggest names based on how the identifier is actually used in the code.
- Use camelCase for variables/functions, PascalCase for classes.
- Return your answer as a JSON object mapping old names to new names.
- Only include identifiers you are confident about (≥70% sure).
- Maximum 30 renames per response.

Example output:
```json
{
  "_0x4a3f": "decryptedPayload",
  "_0x1b2c": "downloadUrl",
  "a": "loopCounter",
  "fn1": "decodeBase64String"
}
```
"""


class LLMRenamer(LLMTransform):
    """Use the LLM to suggest semantic variable/function renames."""

    name = "LLMRenamer"
    description = "LLM-assisted semantic identifier renaming."

    def get_temperature(self) -> float:
        return 0.15

    def build_messages(
        self, code: str, language: str, state: dict
    ) -> List[Dict[str, str]]:
        truncated = self.truncate_code(code)
        lang = language or state.get("language", "unknown")

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Language: {lang}\n\n"
                    f"```\n{truncated}\n```\n\n"
                    "Return the rename mapping as JSON."
                ),
            },
        ]

    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        mapping = self.extract_json(reply)
        if not mapping or not isinstance(mapping, dict):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.2,
                description="LLM renamer did not return a valid mapping.",
                details={"raw_reply_length": len(reply)},
            )

        # Filter to only valid renames (old name must exist in code).
        valid_renames: Dict[str, str] = {}
        for old, new in mapping.items():
            if (
                isinstance(old, str)
                and isinstance(new, str)
                and old in code
                and re.match(r"^[a-zA-Z_]\w*$", new)
                and old != new
            ):
                valid_renames[old] = new

        if not valid_renames:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.2,
                description="LLM renamer suggestions did not match any identifiers.",
                details={"raw_mapping_size": len(mapping)},
            )

        # Apply renames using word-boundary-safe replacement.
        new_code = code
        applied = 0
        for old, new in valid_renames.items():
            # Use word boundary regex so we don't replace partial matches.
            pattern = re.compile(r"\b" + re.escape(old) + r"\b")
            replaced = pattern.sub(new, new_code)
            if replaced != new_code:
                new_code = replaced
                applied += 1

        return TransformResult(
            success=applied > 0,
            output=new_code if applied > 0 else code,
            confidence=min(0.5 + applied * 0.05, 0.9),
            description=f"LLM renamed {applied} identifier(s) semantically.",
            details={
                "renames_applied": applied,
                "renames_suggested": len(valid_renames),
                "suggestions": valid_renames,
            },
        )
