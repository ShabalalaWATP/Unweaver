"""
PowerShellDecoder transform -- handles PowerShell-specific obfuscation
techniques:

  - -EncodedCommand / -enc  (UTF-16LE base64)
  - String replacement chains:  -replace 'x','y'
  - Format string abuse:        "{0}{1}" -f "pow","ershell"
  - Backtick insertion:          p`ow`er`sh`ell
  - Layered encoding combinations
"""

from __future__ import annotations

import base64
import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Encoded command
# ---------------------------------------------------------------------------

_ENCODED_CMD = re.compile(
    r"-(?:EncodedCommand|enc|ec)\s+['\"]?([A-Za-z0-9+/=\s]{20,})['\"]?",
    re.IGNORECASE,
)


def _decode_encoded_command(blob: str) -> str | None:
    """Decode a PowerShell -EncodedCommand payload (UTF-16LE base64)."""
    cleaned = blob.replace(" ", "").replace("\n", "").replace("\r", "")
    # Add padding if needed
    missing = len(cleaned) % 4
    if missing:
        cleaned += "=" * (4 - missing)
    try:
        raw = base64.b64decode(cleaned, validate=True)
        return raw.decode("utf-16-le")
    except Exception:
        try:
            raw = base64.b64decode(cleaned)
            return raw.decode("utf-8")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Backtick removal
# ---------------------------------------------------------------------------

_BACKTICK = re.compile(r"`(?=[a-zA-Z0-9])")

# Also handle caret escape (cmd.exe style sometimes leaks into PS)
_CARET_ESCAPE = re.compile(r"\^(?=[a-zA-Z])")


def _remove_backticks(code: str) -> tuple[str, int]:
    """Remove obfuscation backticks. Return (cleaned, count)."""
    count = len(_BACKTICK.findall(code))
    cleaned = _BACKTICK.sub("", code)
    return cleaned, count


# ---------------------------------------------------------------------------
# Format string abuse:  "{0}{1}{2}" -f "pow","er","shell"
# ---------------------------------------------------------------------------

_FORMAT_STRING = re.compile(
    r"""(?:"((?:[^"\\`]|`.|"")*?)"|'((?:[^']|'')*?)')\s*-f\s*"""
    r"""((?:(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')\s*,?\s*)+)""",
    re.IGNORECASE,
)


def _resolve_format_string(m: re.Match) -> str | None:
    """Resolve a PowerShell format string expression."""
    fmt = m.group(1) if m.group(1) is not None else m.group(2)
    args_raw = m.group(3)

    # Extract the arguments
    args: list[str] = []
    for am in re.finditer(r"""(?:"((?:[^"\\`]|`.|"")*)"|'((?:[^']|'')*)')""", args_raw):
        args.append(am.group(1) if am.group(1) is not None else am.group(2))

    # Replace {0}, {1}, ... with args
    result = fmt
    for i, arg in enumerate(args):
        result = result.replace(f"{{{i}}}", arg)

    # Check if all placeholders were resolved
    if re.search(r"\{\d+\}", result):
        return None  # unresolved placeholders remain
    return result


# ---------------------------------------------------------------------------
# String replacement chains:  'abc' -replace 'a','x' -replace 'b','y'
# ---------------------------------------------------------------------------

_REPLACE_CHAIN = re.compile(
    r"""(?:"((?:[^"\\`]|`.|"")*)"|'((?:[^']|'')*)')\s*"""
    r"""((?:\s*-(?:replace|creplace|ireplace)\s+"""
    r"""(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')\s*,\s*"""
    r"""(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')\s*)+)""",
    re.IGNORECASE,
)

_REPLACE_STEP = re.compile(
    r"""-(?:replace|creplace|ireplace)\s+"""
    r"""(?:"((?:[^"\\`]|`.|"")*)"|'((?:[^']|'')*)')\s*,\s*"""
    r"""(?:"((?:[^"\\`]|`.|"")*)"|'((?:[^']|'')*)')""",
    re.IGNORECASE,
)


def _apply_replace_chain(m: re.Match) -> str | None:
    """Apply a chain of -replace operations."""
    base = m.group(1) if m.group(1) is not None else m.group(2)
    chain_text = m.group(3)

    result = base
    for step in _REPLACE_STEP.finditer(chain_text):
        old = step.group(1) if step.group(1) is not None else step.group(2)
        new = step.group(3) if step.group(3) is not None else step.group(4)
        if old is None:
            continue
        new = new if new is not None else ""
        try:
            result = re.sub(re.escape(old), new, result, flags=re.IGNORECASE)
        except Exception:
            result = result.replace(old, new)

    return result


# ---------------------------------------------------------------------------
# Concatenation with + operator between strings
# ---------------------------------------------------------------------------

_PS_CONCAT = re.compile(
    r"""(?:(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')\s*\+\s*){1,}"""
    r"""(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')"""
)


def _fold_ps_concat(match_text: str) -> str | None:
    """Fold PowerShell string concatenation."""
    parts = re.findall(
        r"""(?:"((?:[^"\\`]|`.|"")*)"|'((?:[^']|'')*)')""", match_text
    )
    if not parts:
        return None
    combined = ""
    for double, single in parts:
        combined += double if double is not None else single
    return combined


# ---------------------------------------------------------------------------
# [Convert]::ToInt16 / [char][int] patterns
# ---------------------------------------------------------------------------

_CHAR_INT_CONCAT = re.compile(
    r"(?:\[char\]\s*(0x[0-9a-fA-F]+|\d+)\s*\+?\s*){2,}",
    re.IGNORECASE,
)


def _fold_char_ints(m: re.Match) -> str | None:
    nums = re.findall(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)", m.group(0), re.IGNORECASE)
    try:
        chars = []
        for n in nums:
            val = int(n, 16) if n.lower().startswith("0x") else int(n)
            chars.append(chr(val))
        return "".join(chars)
    except Exception:
        return None


class PowerShellDecoder(BaseTransform):
    name = "powershell_decoder"
    description = (
        "Decode PowerShell obfuscation: EncodedCommand, format strings, "
        "replacement chains, backticks"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        # Apply if the language is PowerShell, or if we detect PS markers
        if lang in ("powershell", "ps1", "ps"):
            return True
        ps_indicators = [
            r"-(?:EncodedCommand|enc)\b",
            r"\bInvoke-Expression\b",
            r"\biex\b",
            r"\[System\.Convert\]",
            r"\[ScriptBlock\]",
            r"-(?:replace|creplace)\s",
            r"`[a-zA-Z]",  # backtick obfuscation
            r"\"\s*-f\s",  # format string
        ]
        return any(re.search(p, code, re.IGNORECASE) for p in ps_indicators)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        changes: list[dict[str, Any]] = []

        # --- Backtick removal ---
        cleaned, backtick_count = _remove_backticks(output)
        if backtick_count > 0:
            changes.append({
                "type": "backtick_removal",
                "count": backtick_count,
            })
            output = cleaned

        # Also remove caret escapes
        caret_count = len(_CARET_ESCAPE.findall(output))
        if caret_count > 0:
            output = _CARET_ESCAPE.sub("", output)
            changes.append({
                "type": "caret_removal",
                "count": caret_count,
            })

        # --- Encoded command ---
        for m in _ENCODED_CMD.finditer(output):
            decoded = _decode_encoded_command(m.group(1))
            if decoded:
                changes.append({
                    "type": "encoded_command",
                    "encoded": m.group(1)[:80],
                    "decoded": decoded,
                })
                output = output.replace(
                    m.group(0),
                    f"# DECODED EncodedCommand:\n{decoded}",
                    1,
                )

        # --- Format strings ---
        def _replace_fmt(m: re.Match) -> str:
            resolved = _resolve_format_string(m)
            if resolved is not None:
                changes.append({
                    "type": "format_string",
                    "original": m.group(0)[:120],
                    "resolved": resolved,
                })
                return f'"{resolved}"'
            return m.group(0)

        output = _FORMAT_STRING.sub(_replace_fmt, output)

        # --- Replace chains ---
        def _replace_chain_cb(m: re.Match) -> str:
            resolved = _apply_replace_chain(m)
            if resolved is not None:
                changes.append({
                    "type": "replace_chain",
                    "original": m.group(0)[:120],
                    "resolved": resolved,
                })
                return f'"{resolved}"'
            return m.group(0)

        output = _REPLACE_CHAIN.sub(_replace_chain_cb, output)

        # --- String concatenation ---
        def _replace_concat(m: re.Match) -> str:
            folded = _fold_ps_concat(m.group(0))
            if folded is not None:
                changes.append({
                    "type": "string_concat",
                    "original": m.group(0)[:120],
                    "folded": folded,
                })
                return f'"{folded}"'
            return m.group(0)

        output = _PS_CONCAT.sub(_replace_concat, output)

        # --- [char] int concatenation ---
        def _replace_char_int(m: re.Match) -> str:
            folded = _fold_char_ints(m)
            if folded is not None:
                changes.append({
                    "type": "char_int",
                    "original": m.group(0)[:120],
                    "folded": folded,
                })
                return f'"{folded}"'
            return m.group(0)

        output = _CHAR_INT_CONCAT.sub(_replace_char_int, output)

        if not changes:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No PowerShell obfuscation patterns decoded.",
            )

        state.setdefault("ps_decoded", []).extend(changes)

        type_counts: dict[str, int] = {}
        for c in changes:
            t = c["type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        confidence = min(0.95, 0.70 + 0.04 * len(changes))
        summary = ", ".join(f"{v} {k}" for k, v in type_counts.items())

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=f"Decoded PowerShell obfuscation: {summary}.",
            details={
                "change_count": len(changes),
                "type_counts": type_counts,
                "changes": changes,
            },
        )
