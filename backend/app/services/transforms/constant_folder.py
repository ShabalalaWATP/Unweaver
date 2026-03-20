"""
ConstantFolder transform -- simplifies constant expressions that obfuscators
introduce to hide real values.

Handles:
  - String concatenation:  "a" + "b" + "c"  ->  "abc"
  - Numeric folding:       0x41 + 0x42       ->  131
  - Bitwise shift folding: 0xFF << 8         ->  65280
  - String.fromCharCode(72,101,108)          ->  "Hel"
  - chr() in Python
  - [char] casts in PowerShell
  - Math.* functions:      Math.floor(3.7)   ->  3
  - parseInt/parseFloat/Number folding
  - Array.prototype.join:  ["a","b"].join("") -> "ab"
"""

from __future__ import annotations

import math
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
# Numeric constant folding (safe recursive descent evaluator)
# ---------------------------------------------------------------------------

# Simple numeric expressions: 0x41 + 0x42, 0xFF ^ 0x12, 100 - 3,
# 0xFF << 8, 1 >> 4, etc.
_NUMERIC_EXPR = re.compile(
    r"\b(0x[0-9a-fA-F]+|\d+)"
    r"(\s*(?:[+\-*/%^&|]|<<|>>|>>>)\s*"
    r"(?:0x[0-9a-fA-F]+|\d+))+"
    r"\b"
)


def _fold_numeric(expr: str) -> int | None:
    """Evaluate a simple numeric expression safely using recursive descent."""
    # Convert hex literals to decimal
    converted = re.sub(
        r"0x([0-9a-fA-F]+)", lambda m: str(int(m.group(1), 16)), expr
    )
    # Only allow digits, whitespace, and operators
    if not re.fullmatch(r"[\d\s+\-*/^&|%~()<>]+", converted):
        return None
    try:
        return _safe_numeric_eval(converted.strip())
    except Exception:
        return None


def _safe_numeric_eval(expr: str) -> int:
    """Recursive descent parser for numeric expressions with +, -, *, /, %, ^, &, |, ~, <<, >>."""
    tokens = _tokenize_numeric(expr)
    pos = [0]
    result = _parse_bitwise_or(tokens, pos)
    if pos[0] != len(tokens):
        raise ValueError("Unexpected token")
    return result


def _tokenize_numeric(expr: str) -> list[str]:
    """Tokenize a numeric expression into numbers and operators."""
    tokens: list[str] = []
    i = 0
    while i < len(expr):
        if expr[i].isspace():
            i += 1
            continue
        # Multi-character operators
        if i + 2 <= len(expr) and expr[i : i + 3] == ">>>":
            tokens.append(">>>")
            i += 3
            continue
        if i + 1 < len(expr) and expr[i : i + 2] in ("<<", ">>"):
            tokens.append(expr[i : i + 2])
            i += 2
            continue
        # Single-character operators and parens
        if expr[i] in "+-*/%^&|~()":
            tokens.append(expr[i])
            i += 1
            continue
        # Numbers
        if expr[i].isdigit():
            j = i
            while j < len(expr) and expr[j].isdigit():
                j += 1
            tokens.append(expr[i:j])
            i = j
            continue
        raise ValueError(f"Unexpected character: {expr[i]}")
    return tokens


def _parse_bitwise_or(tokens: list[str], pos: list[int]) -> int:
    """Parse bitwise OR expressions (lowest precedence)."""
    left = _parse_bitwise_xor(tokens, pos)
    while pos[0] < len(tokens) and tokens[pos[0]] == "|":
        pos[0] += 1
        right = _parse_bitwise_xor(tokens, pos)
        left = left | right
    return left


def _parse_bitwise_xor(tokens: list[str], pos: list[int]) -> int:
    """Parse bitwise XOR expressions."""
    left = _parse_bitwise_and(tokens, pos)
    while pos[0] < len(tokens) and tokens[pos[0]] == "^":
        pos[0] += 1
        right = _parse_bitwise_and(tokens, pos)
        left = left ^ right
    return left


def _parse_bitwise_and(tokens: list[str], pos: list[int]) -> int:
    """Parse bitwise AND expressions."""
    left = _parse_shift(tokens, pos)
    while pos[0] < len(tokens) and tokens[pos[0]] == "&":
        pos[0] += 1
        right = _parse_shift(tokens, pos)
        left = left & right
    return left


def _parse_shift(tokens: list[str], pos: list[int]) -> int:
    """Parse shift expressions (<<, >>, >>>)."""
    left = _parse_additive(tokens, pos)
    while pos[0] < len(tokens) and tokens[pos[0]] in ("<<", ">>", ">>>"):
        op = tokens[pos[0]]
        pos[0] += 1
        right = _parse_additive(tokens, pos)
        if op == "<<":
            left = left << right
        elif op == ">>":
            left = left >> right
        else:  # >>>
            # Unsigned right shift (JS-style): treat as 32-bit unsigned
            if left < 0:
                left = left & 0xFFFFFFFF
            left = left >> right
    return left


def _parse_additive(tokens: list[str], pos: list[int]) -> int:
    """Parse addition and subtraction."""
    left = _parse_multiplicative(tokens, pos)
    while pos[0] < len(tokens) and tokens[pos[0]] in ("+", "-"):
        op = tokens[pos[0]]
        pos[0] += 1
        right = _parse_multiplicative(tokens, pos)
        if op == "+":
            left = left + right
        else:
            left = left - right
    return left


def _parse_multiplicative(tokens: list[str], pos: list[int]) -> int:
    """Parse multiplication, division, and modulo."""
    left = _parse_unary(tokens, pos)
    while pos[0] < len(tokens) and tokens[pos[0]] in ("*", "/", "%"):
        op = tokens[pos[0]]
        pos[0] += 1
        right = _parse_unary(tokens, pos)
        if op == "*":
            left = left * right
        elif op == "/":
            if right == 0:
                raise ValueError("Division by zero")
            left = int(left / right)
        else:
            if right == 0:
                raise ValueError("Modulo by zero")
            left = left % right
    return left


def _parse_unary(tokens: list[str], pos: list[int]) -> int:
    """Parse unary operators (-, ~)."""
    if pos[0] < len(tokens) and tokens[pos[0]] == "-":
        pos[0] += 1
        operand = _parse_unary(tokens, pos)
        return -operand
    if pos[0] < len(tokens) and tokens[pos[0]] == "~":
        pos[0] += 1
        operand = _parse_unary(tokens, pos)
        return ~operand
    return _parse_primary(tokens, pos)


def _parse_primary(tokens: list[str], pos: list[int]) -> int:
    """Parse primary expressions: numbers and parenthesized expressions."""
    if pos[0] >= len(tokens):
        raise ValueError("Unexpected end of expression")
    token = tokens[pos[0]]
    if token == "(":
        pos[0] += 1
        result = _parse_bitwise_or(tokens, pos)
        if pos[0] >= len(tokens) or tokens[pos[0]] != ")":
            raise ValueError("Missing closing parenthesis")
        pos[0] += 1
        return result
    if token.isdigit() or (len(token) > 1 and token[0].isdigit()):
        pos[0] += 1
        return int(token)
    raise ValueError(f"Unexpected token: {token}")


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


# ---------------------------------------------------------------------------
# Math.* function folding
# ---------------------------------------------------------------------------

# Match Math.func(...) where args are numeric literals (int or float)
_MATH_CALL = re.compile(
    r"Math\.(floor|ceil|abs|round|pow|max|min|sqrt|trunc|sign)"
    r"\s*\(\s*"
    r"([-+]?(?:\d+\.?\d*|\.\d+)"
    r"(?:\s*,\s*[-+]?(?:\d+\.?\d*|\.\d+))*)"
    r"\s*\)"
)

_MATH_FUNCS: dict[str, Any] = {
    "floor": math.floor,
    "ceil": math.ceil,
    "abs": abs,
    "round": round,
    "pow": pow,
    "max": max,
    "min": min,
    "sqrt": math.isqrt,
    "trunc": math.trunc,
    "sign": lambda x: (1 if x > 0 else (-1 if x < 0 else 0)),
}


def _fold_math_call(m: re.Match) -> str | None:
    """Fold a Math.func(...) call with numeric literal arguments."""
    func_name = m.group(1)
    args_str = m.group(2)
    func = _MATH_FUNCS.get(func_name)
    if func is None:
        return None
    try:
        args = [float(a.strip()) for a in args_str.split(",")]
        # Validate argument count
        if func_name in ("pow",) and len(args) != 2:
            return None
        if func_name in ("max", "min") and len(args) < 1:
            return None
        if func_name in ("floor", "ceil", "abs", "round", "sqrt", "trunc", "sign") and len(args) != 1:
            return None
        result = func(*args)
        # Return as int if the result is a whole number
        if isinstance(result, float) and result == int(result):
            return str(int(result))
        return str(result)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# parseInt / parseFloat / Number folding
# ---------------------------------------------------------------------------

# parseInt("0xFF", 16) or parseInt("42") or parseInt("42", 10)
_PARSE_INT = re.compile(
    r"parseInt\s*\(\s*"
    r"""(?:"([^"]*?)"|'([^']*?)')"""
    r"(?:\s*,\s*(\d+))?"
    r"\s*\)"
)

# parseFloat("3.14")
_PARSE_FLOAT = re.compile(
    r"parseFloat\s*\(\s*"
    r"""(?:"([^"]*?)"|'([^']*?)')"""
    r"\s*\)"
)

# Number("42") or Number("3.14")
_NUMBER_CALL = re.compile(
    r"Number\s*\(\s*"
    r"""(?:"([^"]*?)"|'([^']*?)')"""
    r"\s*\)"
)


def _fold_parse_int(m: re.Match) -> str | None:
    """Fold parseInt("...", base) calls."""
    value_str = m.group(1) if m.group(1) is not None else m.group(2)
    base_str = m.group(3)
    try:
        if base_str is not None:
            base = int(base_str)
            result = int(value_str, base)
        else:
            # parseInt auto-detects base: "0x" prefix means hex
            val = value_str.strip()
            if val.lower().startswith("0x"):
                result = int(val, 16)
            else:
                result = int(val, 10)
        return str(result)
    except Exception:
        return None


def _fold_parse_float(m: re.Match) -> str | None:
    """Fold parseFloat("...") calls."""
    value_str = m.group(1) if m.group(1) is not None else m.group(2)
    try:
        result = float(value_str.strip())
        if result == int(result):
            return str(int(result))
        return str(result)
    except Exception:
        return None


def _fold_number_call(m: re.Match) -> str | None:
    """Fold Number("...") calls."""
    value_str = m.group(1) if m.group(1) is not None else m.group(2)
    try:
        val = value_str.strip()
        # Try int first, then float
        if val.lower().startswith("0x"):
            result = int(val, 16)
            return str(result)
        try:
            result = int(val)
            return str(result)
        except ValueError:
            result = float(val)
            if result == int(result):
                return str(int(result))
            return str(result)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Array.prototype.join folding
# ---------------------------------------------------------------------------

# ["a","b","c"].join("")  or  ["a","b","c"].join(",")
_ARRAY_JOIN = re.compile(
    r"\[\s*"
    r"((?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')"
    r"(?:\s*,\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'))*)"
    r"\s*\]\s*\.\s*join\s*\(\s*"
    r"""(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')"""
    r"\s*\)"
)


def _fold_array_join(m: re.Match) -> str | None:
    """Fold ["a","b","c"].join(",") into a single string."""
    elements_str = m.group(1)
    separator = m.group(2) if m.group(2) is not None else m.group(3)
    if separator is None:
        return None
    try:
        # Extract individual string values from the array
        parts = re.findall(
            r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""",
            elements_str,
        )
        if not parts:
            return None
        elements = []
        for double, single in parts:
            elements.append(double if double else single)
        joined = separator.join(elements)
        return f'"{joined}"'
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _parse_int_val(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def _fold_from_char_code(m: re.Match) -> str:
    """Fold String.fromCharCode(...)."""
    nums = re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))
    try:
        return '"' + "".join(chr(_parse_int_val(n)) for n in nums) + '"'
    except Exception:
        return m.group(0)


def _fold_chr_concat(m: re.Match) -> str:
    """Fold chr(72)+chr(101)+..."""
    nums = re.findall(r"chr\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", m.group(0))
    try:
        return '"' + "".join(chr(_parse_int_val(n)) for n in nums) + '"'
    except Exception:
        return m.group(0)


def _fold_ps_char(m: re.Match) -> str:
    """Fold [char]72+[char]101+..."""
    nums = re.findall(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)", m.group(0), re.IGNORECASE)
    try:
        return '"' + "".join(chr(_parse_int_val(n)) for n in nums) + '"'
    except Exception:
        return m.group(0)


# ---------------------------------------------------------------------------
# Transform class
# ---------------------------------------------------------------------------

class ConstantFolder(BaseTransform):
    name = "constant_folder"
    description = (
        "Fold constant expressions: string concat, numeric ops, "
        "charCode/chr/[char] conversions, Math.*, parseInt/parseFloat, "
        "Array.join"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(
            _STR_CONCAT.search(code)
            or _FROM_CHAR_CODE.search(code)
            or _PY_CHR_CONCAT.search(code)
            or _PS_CHAR.search(code)
            or _NUMERIC_EXPR.search(code)
            or _MATH_CALL.search(code)
            or _PARSE_INT.search(code)
            or _PARSE_FLOAT.search(code)
            or _NUMBER_CALL.search(code)
            or _ARRAY_JOIN.search(code)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        changes: list[dict[str, Any]] = []
        lang = (language or "").lower().strip()

        # --- Math.* function folding ---
        def _replace_math(m: re.Match) -> str:
            folded = _fold_math_call(m)
            if folded is not None:
                changes.append({
                    "type": "math_call",
                    "original": m.group(0),
                    "folded": folded,
                })
                return folded
            return m.group(0)

        output = _MATH_CALL.sub(_replace_math, output)

        # --- parseInt / parseFloat / Number folding ---
        def _replace_parse_int(m: re.Match) -> str:
            folded = _fold_parse_int(m)
            if folded is not None:
                changes.append({
                    "type": "parseInt",
                    "original": m.group(0),
                    "folded": folded,
                })
                return folded
            return m.group(0)

        output = _PARSE_INT.sub(_replace_parse_int, output)

        def _replace_parse_float(m: re.Match) -> str:
            folded = _fold_parse_float(m)
            if folded is not None:
                changes.append({
                    "type": "parseFloat",
                    "original": m.group(0),
                    "folded": folded,
                })
                return folded
            return m.group(0)

        output = _PARSE_FLOAT.sub(_replace_parse_float, output)

        def _replace_number(m: re.Match) -> str:
            folded = _fold_number_call(m)
            if folded is not None:
                changes.append({
                    "type": "Number",
                    "original": m.group(0),
                    "folded": folded,
                })
                return folded
            return m.group(0)

        output = _NUMBER_CALL.sub(_replace_number, output)

        # --- Array.join folding ---
        def _replace_array_join(m: re.Match) -> str:
            folded = _fold_array_join(m)
            if folded is not None:
                changes.append({
                    "type": "array_join",
                    "original": m.group(0),
                    "folded": folded,
                })
                return folded
            return m.group(0)

        output = _ARRAY_JOIN.sub(_replace_array_join, output)

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
