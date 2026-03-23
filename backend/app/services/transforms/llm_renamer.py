"""
LLM-powered semantic variable/function renaming.

Asks the LLM to analyse code and suggest meaningful names for obfuscated
identifiers based on their usage context — far more accurate than the
heuristic rename suggester.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from app.services.ingest.workspace_bundle import (
    ParsedWorkspaceFile,
    parse_workspace_bundle,
    rebuild_workspace_bundle,
)
from app.services.transforms.base import TransformResult
from app.services.transforms.deterministic_renamer import (
    KEYWORDS,
    _build_string_mask,
    _safe_rename,
)
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
- If the input is a workspace bundle with <<<FILE ...>>> markers, preserve the
  markers and only rename identifiers inside the relevant file blocks.

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
        context = self.build_state_context(state)
        workspace = self.build_workspace_context(code)

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Language: {lang}\n"
                    f"Context:\n{context}\n\n"
                    + (f"Workspace context:\n{workspace}\n\n" if workspace else "")
                    + (
                    f"```\n{truncated}\n```\n\n"
                    "Return the rename mapping as JSON."
                    )
                ),
            },
        ]

    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        mapping = self.extract_json(reply)
        if isinstance(mapping, dict) and "renames" in mapping and isinstance(mapping["renames"], dict):
            mapping = mapping["renames"]
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
                and new not in KEYWORDS
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

        # Apply renames using the same string/comment-aware replacement logic
        # as the deterministic renamer so semantic renames do not corrupt
        # literals, comments, or embedded payloads.
        workspace_files = parse_workspace_bundle(code)
        if workspace_files:
            new_code, applied_names = self._apply_workspace_renames(
                code,
                workspace_files,
                valid_renames,
            )
        else:
            new_code, applied_names = self._apply_text_renames(code, valid_renames)

        applied = len(applied_names)

        validation: Dict[str, Any] = {
            "accepted": False,
            "issues": [],
            "delimiter_balance_ok": False,
            "syntax_ok": None,
            "workspace_validation": None,
        }
        if applied > 0:
            validation = self.validate_candidate_code(code, new_code, language)
            if not validation["accepted"]:
                return TransformResult(
                    success=False,
                    output=code,
                    confidence=0.2,
                    description="LLM renamer produced structurally unsafe output.",
                    details={
                        "renames_suggested": len(valid_renames),
                        "suggestions": valid_renames,
                        "validation": validation,
                    },
                )

        return TransformResult(
            success=applied > 0,
            output=new_code if applied > 0 else code,
            confidence=min(0.5 + applied * 0.05, 0.9),
            description=f"LLM renamed {applied} identifier(s) semantically.",
            details={
                "renames_applied": applied,
                "renames_suggested": len(valid_renames),
                "suggestions": valid_renames,
                "validation": validation,
            },
        )

    @staticmethod
    def _apply_text_renames(
        code: str,
        valid_renames: Dict[str, str],
    ) -> Tuple[str, set[str]]:
        new_code = code
        applied_names: set[str] = set()
        for old in sorted(valid_renames, key=len, reverse=True):
            new = valid_renames[old]
            protected_spans = _build_string_mask(new_code)
            replaced = _safe_rename(new_code, old, new, protected_spans)
            if replaced != new_code:
                new_code = replaced
                applied_names.add(old)
        return new_code, applied_names

    @classmethod
    def _apply_workspace_renames(
        cls,
        bundle_text: str,
        workspace_files: List[ParsedWorkspaceFile],
        valid_renames: Dict[str, str],
    ) -> Tuple[str, set[str]]:
        rewritten_files: List[ParsedWorkspaceFile] = []
        applied_names: set[str] = set()

        for item in workspace_files:
            new_text, file_applied_names = cls._apply_text_renames(item.text, valid_renames)
            applied_names.update(file_applied_names)
            rewritten_files.append(
                ParsedWorkspaceFile(
                    path=item.path,
                    language=item.language,
                    priority=item.priority,
                    size_bytes=item.size_bytes,
                    text=new_text,
                )
            )

        return rebuild_workspace_bundle(bundle_text, rewritten_files), applied_names
