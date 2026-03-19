"""
ConstantFolder transform -- simplifies constant expressions that obfuscators
introduce to hide real values.

Handles:
  - String concatenation:  "a" + "b" + "c"  ->  "abc"
  - Numeric folding:       0x41 + 0x42       ->  131
  - String.fromCharCode(72,101,108)          ->  "Hel"
  - chr() in Python
  - [char] casts in PowerShell
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# String concatenation folding
# ---------------------------------------------------------------------------

# "a" + "b" + "c"  or  'a' + 'b' + 'c'  (or mixed, though risky)
_STR_CONCAT = re.compile(
    r"""(?:(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+\s*){1,}"""
    r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
)

# PowerShell string concat with + operator
_PS_STR_CONCAT = re.compile(
    r"""(?:(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')\s*\+\s*){1,}"""
    r"""(?:"(?:[^"\\`]|`.|"")*"|'(?:[^']|'')*')"""
)


def _fold_string_concat(match_text: str) -> str | None:
    """Fold a matched string concatenation expression."""
    # Extract individual quoted strings
    parts = re.findall(r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""", match_text)
    if not parts:
        return None
    combined = ""
    for double, single in parts:
        combined += double if double else single
    return combined


# ---------------------------------------------------------------------------
# Numeric constant folding
# ---------------------------------------------------------------------------

# Simple numeric expressions: 0x41 + 0x42, 0xFF ^ 0x12, 100 - 3, etc.
_NUMERIC_EXPR = re.compile(
    r"\b(0x[0-9a-fA-F]+|\d+)"
    r"(\s*[+\-*/^&|%]\s*"
    r"(?:0x[0-9a-fA-F]+|\d+))+"
    r"\b"
)

_SAFE_OPS = {"+", "-", "*", "/", "^", "&", "|", "%", "//"}


def _fold_numeric(expr: str) -> int | None:
    """Evaluate a simple numeric expression safely."""
    # Convert 0x... to Python int literals
    converted = re.sub(
        r"0x([0-9a-fA-F]+)", lambda m: str(int(m.group(1), 16)), expr
    )
    # Only allow digits, whitespace, and basic operators
    if not re.fullmatch(r"[\d\s+\-*/^&|%()]+", converted):
        return None
    # Replace ^ with ** for XOR? No -- ^ in Python is already XOR.
    # But in JS/C# context ^ is XOR too. We keep it as Python XOR.
    try:
        result = eval(converted, {"__builtins__": {}}, {})
        if isinstance(result, (int, float)):
            return int(result)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# String.fromCharCode / chr / [char] folding
# ---------------------------------------------------------------------------

# JavaScript: String.fromCharCode(72, 101, 108, 108, 111)
_FROM_CHAR_CODE = re.compile(
    r"String\.fromCharCode\s*\(\s*"
    r"((?:0x[0-9a-fA-F]+|\d+)"
    r"(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+))*)"
    r"\s*\)"
)

# Python: chr(72) + chr(101) + chr(108)
_PY_CHR_CONCAT = re.compile(
    r"(?:chr\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*\+?\s*){2,}"
)

# Individual chr() call
_PY_CHR_SINGLE = re.compile(r"chr\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)")

# PowerShell: [char]72 + [char]101 ...
_PS_CHAR = re.compile(
    r"(?:\[char\]\s*(0x[0-9a-fA-F]+|\d+)\s*\+?\s*){2,}",
    re.IGNORECASE,
)

_PS_CHAR_SINGLE = re.compile(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)


def _parse_int(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def _fold_from_char_code(m: re.Match) -> str:
    """Fold String.fromCharCode(...)."""
    nums = re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))
    try:
        return '"' + "".join(chr(_parse_int(n)) for n in nums) + '"'
    except Exception:
        return m.group(0)


def _fold_chr_concat(m: re.Match) -> str:
    """Fold chr(72)+chr(101)+..."""
    nums = re.findall(r"chr\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", m.group(0))
    try:
        return '"' + "".join(chr(_parse_int(n)) for n in nums) + '"'
    except Exception:
        return m.group(0)


def _fold_ps_char(m: re.Match) -> str:
    """Fold [char]72+[char]101+..."""
    nums = re.findall(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)", m.group(0), re.IGNORECASE)
    try:
        return '"' + "".join(chr(_parse_int(n)) for n in nums) + '"'
    except Exception:
        return m.group(0)


class ConstantFolder(BaseTransform):
    name = "constant_folder"
    description = (
        "Fold constant expressions: string concat, numeric ops, "
        "charCode/chr/[char] conversions"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(
            _STR_CONCAT.search(code)
            or _FROM_CHAR_CODE.search(code)
            or _PY_CHR_CONCAT.search(code)
            or _PS_CHAR.search(code)
            or _NUMERIC_EXPR.search(code)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        changes: list[dict[str, Any]] = []
        lang = (language or "").lower().strip()

        # --- String.fromCharCode ---
        def _replace_fcc(m: re.Match) -> str:
            folded = _fold_from_char_code(m)
            if folded != m.group(0):
                changes.append({
                    "type": "fromCharCode",
                    "original": m.group(0),
                    "folded": folded,
                })
            return folded

        output = _FROM_CHAR_CODE.sub(_replace_fcc, output)

        # --- Python chr() concat ---
        def _replace_chr(m: re.Match) -> str:
            folded = _fold_chr_concat(m)
            if folded != m.group(0):
                changes.append({
                    "type": "chr_concat",
                    "original": m.group(0),
                    "folded": folded,
                })
            return folded

        output = _PY_CHR_CONCAT.sub(_replace_chr, output)

        # --- PowerShell [char] ---
        def _replace_ps(m: re.Match) -> str:
            folded = _fold_ps_char(m)
            if folded != m.group(0):
                changes.append({
                    "type": "ps_char",
                    "original": m.group(0),
                    "folded": folded,
                })
            return folded

        output = _PS_CHAR.sub(_replace_ps, output)

        # --- String concatenation ---
        def _replace_str_concat(m: re.Match) -> str:
            folded = _fold_string_concat(m.group(0))
            if folded is not None:
                result = f'"{folded}"'
                changes.append({
                    "type": "string_concat",
                    "original": m.group(0),
                    "folded": result,
                })
                return result
            return m.group(0)

        concat_pat = _PS_STR_CONCAT if lang in ("powershell", "ps1", "ps") else _STR_CONCAT
        output = concat_pat.sub(_replace_str_concat, output)

        # --- Numeric constant folding ---
        def _replace_numeric(m: re.Match) -> str:
            folded = _fold_numeric(m.group(0))
            if folded is not None:
                changes.append({
                    "type": "numeric",
                    "original": m.group(0),
                    "folded": str(folded),
                })
                return str(folded)
            return m.group(0)

        output = _NUMERIC_EXPR.sub(_replace_numeric, output)

        if not changes:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No constant expressions to fold.",
            )

        state.setdefault("constant_folds", []).extend(changes)

        confidence = min(0.95, 0.80 + 0.02 * len(changes))
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=f"Folded {len(changes)} constant expression(s).",
            details={
                "fold_count": len(changes),
                "changes": changes,
            },
        )
