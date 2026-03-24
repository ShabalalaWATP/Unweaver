"""
JavaScriptArrayResolver transform -- resolves array-based string obfuscation
patterns commonly produced by tools like javascript-obfuscator.

Detected patterns:
  - var _0x1234 = ["str1", "str2", ...]; then _0x1234[0], _0x1234[1]
  - Array rotation/shuffling functions that reorder the lookup array
  - Wrapper functions: function _0xabcd(i){ return _0x1234[i]; }
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Pattern: var _0xHEX = ["...", "...", ...];
# ---------------------------------------------------------------------------

# Array declaration with hex-style or short variable name
_ARRAY_DECL = re.compile(
    r"""(?:var|let|const)\s+"""
    r"""((?:_0x[0-9a-fA-F]+|_[a-zA-Z0-9]+|[a-zA-Z]\w{0,3}))\s*=\s*"""
    r"""\[\s*((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
    r"""(?:\s*,\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'))*)\s*\]\s*;""",
    re.DOTALL,
)

# Array access: _0x1234[0] or _0x1234[0x1a]
_ARRAY_ACCESS = re.compile(
    r"""((?:_0x[0-9a-fA-F]+|_[a-zA-Z0-9]+|[a-zA-Z]\w{0,3}))"""
    r"""\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]"""
)

# ---------------------------------------------------------------------------
# Pattern: rotation / shuffle function
#   (function(_0xArr, _0xRot) {
#       var _0xPush = function(n) { while(--n) { _0xArr.push(_0xArr.shift()); } };
#       _0xPush(++_0xRot);
#   })(_0x1234, 0x1a3);
# ---------------------------------------------------------------------------

_ROTATION_FUNC = re.compile(
    r"""\(\s*function\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*\{"""
    r"""[^}]*?\.push\s*\(\s*\1\.shift\s*\(\s*\)\s*\)[^}]*"""
    r"""\}\s*\)\s*\(\s*(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*;?""",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Pattern: wrapper function
#   function _0xabcd(_0xParam) { return _0x1234[_0xParam]; }
#   or with subtraction: return _0x1234[_0xParam - 0x1a3];
# ---------------------------------------------------------------------------

_WRAPPER_FUNC = re.compile(
    r"""function\s+(\w+)\s*\(\s*(\w+)\s*(?:,\s*\w+\s*)*\)\s*\{"""
    r"""[^}]*?return\s+(\w+)\s*\[\s*\2\s*"""
    r"""(?:\s*-\s*(0x[0-9a-fA-F]+|\d+))?\s*\]\s*;?\s*\}""",
    re.DOTALL,
)

# Wrapper call: _0xabcd(0x1a3) or _0xabcd(42)
_WRAPPER_CALL = re.compile(
    r"""\b(\w+)\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)"""
)


def _parse_int(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _extract_strings(raw: str) -> list[str]:
    """Extract quoted strings from the array literal body."""
    strings: list[str] = []
    for m in re.finditer(r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""", raw):
        strings.append(m.group(1) if m.group(1) is not None else m.group(2))
    return strings


def _rotate_array(arr: list[str], count: int) -> list[str]:
    """Rotate an array left by *count* positions."""
    if not arr:
        return arr
    count = count % len(arr)
    return arr[count:] + arr[:count]


class JavaScriptArrayResolver(BaseTransform):
    name = "js_array_resolver"
    description = (
        "Resolve JavaScript array-based string obfuscation patterns"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang and lang not in ("javascript", "js", "typescript", "ts", ""):
            return False
        return bool(_ARRAY_DECL.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        replacements: list[dict[str, Any]] = []

        # 1. Find all array declarations — filter to obfuscation-like arrays only
        arrays: dict[str, list[str]] = {}
        for m in _ARRAY_DECL.finditer(code):
            var_name = m.group(1)
            strings = _extract_strings(m.group(2))

            # Only target arrays that look like obfuscation tables:
            # - Variable name matches obfuscated pattern (_0x..., _a, short etc.)
            # - OR array has 5+ elements (obfuscation tables are large)
            # - OR array is referenced by a rotation function
            is_obfuscated_name = bool(re.match(
                r"^(?:_0x[0-9a-fA-F]+|_[a-zA-Z0-9]{1,4}|[a-zA-Z]{1,2}\d+)$",
                var_name,
            ))
            is_large_table = len(strings) >= 5
            has_rotation_ref = bool(re.search(
                r"\.push\s*\(\s*" + re.escape(var_name) + r"\.shift",
                code,
            ))
            has_wrapper_ref = bool(re.search(
                r"return\s+" + re.escape(var_name) + r"\s*\[",
                code,
            ))

            if is_obfuscated_name or is_large_table or has_rotation_ref or has_wrapper_ref:
                arrays[var_name] = strings

        if not arrays:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No array-based obfuscation patterns found.",
            )

        # 2. Check for rotation functions (handle chained/multiple rotations)
        rotation_applied: dict[str, int] = {}  # track total rotation per array
        for m in _ROTATION_FUNC.finditer(code):
            target_arr = m.group(3)
            rotation_count = _parse_int(m.group(4))
            if target_arr in arrays:
                total = rotation_applied.get(target_arr, 0) + rotation_count
                rotation_applied[target_arr] = total

        # Apply cumulative rotations
        for arr_name, total_rotation in rotation_applied.items():
            if arr_name in arrays:
                arrays[arr_name] = _rotate_array(arrays[arr_name], total_rotation)

        # 3. Find wrapper functions
        wrappers: dict[str, tuple[str, int]] = {}  # func_name -> (array_name, offset)
        for m in _WRAPPER_FUNC.finditer(code):
            func_name = m.group(1)
            array_name = m.group(3)
            offset = _parse_int(m.group(4)) if m.group(4) else 0
            if array_name in arrays:
                wrappers[func_name] = (array_name, offset)

        # 4. Replace wrapper function calls: _0xabcd(0x1a3) -> "resolved"
        def _replace_wrapper(m: re.Match) -> str:
            func_name = m.group(1)
            if func_name not in wrappers:
                return m.group(0)
            arr_name, offset = wrappers[func_name]
            if arr_name not in arrays:
                return m.group(0)
            idx = _parse_int(m.group(2)) - offset
            arr = arrays[arr_name]
            if 0 <= idx < len(arr):
                resolved = arr[idx]
                replacements.append({
                    "type": "wrapper_call",
                    "original": m.group(0),
                    "resolved": resolved,
                    "function": func_name,
                    "index": idx,
                })
                return f'"{resolved}"'
            return m.group(0)

        if wrappers:
            output = _WRAPPER_CALL.sub(_replace_wrapper, output)

        # 5. Replace direct array accesses: _0x1234[0] -> "resolved"
        def _replace_access(m: re.Match) -> str:
            arr_name = m.group(1)
            if arr_name not in arrays:
                return m.group(0)
            idx = _parse_int(m.group(2))
            arr = arrays[arr_name]
            if 0 <= idx < len(arr):
                resolved = arr[idx]
                replacements.append({
                    "type": "array_access",
                    "original": m.group(0),
                    "resolved": resolved,
                    "array": arr_name,
                    "index": idx,
                })
                return f'"{resolved}"'
            return m.group(0)

        output = _ARRAY_ACCESS.sub(_replace_access, output)

        if not replacements:
            return TransformResult(
                success=True,
                output=code,
                confidence=0.3,
                description=(
                    f"Found {len(arrays)} obfuscation array(s) but no "
                    f"resolvable lookups."
                ),
                details={"arrays_found": len(arrays)},
            )

        state.setdefault("js_resolved", []).extend(replacements)

        confidence = min(0.95, 0.75 + 0.02 * len(replacements))
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=(
                f"Resolved {len(replacements)} array lookup(s) across "
                f"{len(arrays)} obfuscation array(s)."
            ),
            details={
                "arrays_found": len(arrays),
                "rotation_applied": bool(_ROTATION_FUNC.search(code)),
                "wrappers_found": len(wrappers),
                "replacement_count": len(replacements),
                "replacements": replacements,
            },
        )
