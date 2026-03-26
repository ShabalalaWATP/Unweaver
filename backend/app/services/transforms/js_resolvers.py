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
from .constant_folder import _fold_numeric

# ---------------------------------------------------------------------------
# Pattern: var _0xHEX = ["...", "...", ...];
# ---------------------------------------------------------------------------

# Array declaration with hex-style or short variable name
_ARRAY_DECL = re.compile(
    r"""(var|let|const)\s+"""
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
    r"""\}\s*\)\s*\(\s*(\w+)\s*,\s*([^)]+?)\s*\)\s*;?""",
    re.DOTALL,
)

_RIGHT_ROTATION_FUNC = re.compile(
    r"""\(\s*function\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*\{"""
    r"""[^}]*?\.unshift\s*\(\s*\1\.pop\s*\(\s*\)\s*\)[^}]*"""
    r"""\}\s*\)\s*\(\s*(\w+)\s*,\s*([^)]+?)\s*\)\s*;?""",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Pattern: wrapper function
#   function _0xabcd(_0xParam) { return _0x1234[_0xParam]; }
#   var _0xabcd = function(_0xParam) { _0xParam -= 0x1a3; var x = _0x1234[_0xParam]; return x; };
# ---------------------------------------------------------------------------

_WRAPPER_FUNC_DECL_START = re.compile(
    r"""function\s+(\w+)\s*\(\s*(\w+)\s*(?:,\s*\w+\s*)*\)\s*\{""",
    re.DOTALL,
)
_WRAPPER_FUNC_EXPR_START = re.compile(
    r"""(?:var|let|const)\s+(\w+)\s*=\s*function\s*\(\s*(\w+)\s*(?:,\s*\w+\s*)*\)\s*\{""",
    re.DOTALL,
)

_WRAPPER_DIRECT_RETURN = re.compile(
    r"""return\s+(\w+)\s*\[\s*{param}\s*(?:-\s*(0x[0-9a-fA-F]+|\d+))?\s*\]\s*;?""",
    re.DOTALL,
)
_WRAPPER_ALIAS_ASSIGN = re.compile(
    r"""var\s+(\w+)\s*=\s*(\w+)\s*\[\s*{param}\s*(?:-\s*(0x[0-9a-fA-F]+|\d+))?\s*\]\s*;?""",
    re.DOTALL,
)
_WRAPPER_PARAM_OFFSET = re.compile(
    r"""\b{param}\s*=\s*{param}\s*-\s*(0x[0-9a-fA-F]+|\d+)\s*;?""",
    re.DOTALL,
)

# Wrapper call: _0xabcd(0x1a3), _0xabcd(42), or _0xabcd("0x1a3")
_WRAPPER_CALL = re.compile(
    r"""\b(\w+)\s*\(\s*(?:(['"])(0x[0-9a-fA-F]+|\d+)\2|(0x[0-9a-fA-F]+|\d+))\s*\)"""
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


def _apply_text_edits(code: str, edits: list[tuple[int, int, str]]) -> str:
    output = code
    cursor = len(output) + 1
    for start, end, replacement in sorted(edits, key=lambda item: (item[0], item[1]), reverse=True):
        if start < 0 or end < start or end > cursor:
            continue
        output = output[:start] + replacement + output[end:]
        cursor = start
    return output


def _render_array_declaration(kind: str, name: str, values: list[str]) -> str:
    quoted = ", ".join(f'"{value}"' for value in values)
    return f"{kind} {name} = [{quoted}];"


def _evaluate_rotation_count(expr: str) -> int | None:
    candidate = expr.strip()
    if not candidate:
        return None
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", candidate):
        return _parse_int(candidate)
    folded = _fold_numeric(candidate)
    return int(folded) if folded is not None else None


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    idx = open_idx

    while idx < len(text):
        char = text[idx]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            idx += 1
            continue

        if char in {"'", '"', "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1

    return -1


def _iter_wrapper_candidates(code: str):
    for pattern in (_WRAPPER_FUNC_DECL_START, _WRAPPER_FUNC_EXPR_START):
        for match in pattern.finditer(code):
            open_brace = code.find("{", match.end() - 1)
            if open_brace == -1:
                continue
            close_brace = _find_matching_brace(code, open_brace)
            if close_brace == -1:
                continue
            end = close_brace + 1
            while end < len(code) and code[end].isspace():
                end += 1
            if end < len(code) and code[end] == ";":
                end += 1
            yield (
                match.group(1),
                match.group(2),
                code[open_brace + 1:close_brace],
                code[match.start():end],
            )


def _iter_rotation_candidates(code: str, arrays: dict[str, list[str]]):
    for pattern, direction in ((_ROTATION_FUNC, "left"), (_RIGHT_ROTATION_FUNC, "right")):
        for match in pattern.finditer(code):
            target_arr = match.group(3)
            rotation_count = _evaluate_rotation_count(match.group(4))
            if target_arr not in arrays or rotation_count is None:
                continue
            yield {
                "start": match.start(),
                "end": match.end(),
                "array": target_arr,
                "count": rotation_count,
                "direction": direction,
            }


def _skip_js_trivia(code: str, idx: int) -> int:
    while idx < len(code):
        if code[idx].isspace():
            idx += 1
            continue
        if code.startswith("//", idx):
            newline = code.find("\n", idx + 2)
            return len(code) if newline == -1 else newline + 1
        if code.startswith("/*", idx):
            close = code.find("*/", idx + 2)
            return len(code) if close == -1 else close + 2
        break
    return idx


def _find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    idx = open_idx

    while idx < len(text):
        char = text[idx]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            idx += 1
            continue

        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1

    return -1


def _find_named_array_declaration(code: str, array_name: str) -> re.Match[str] | None:
    for match in _ARRAY_DECL.finditer(code):
        if match.group(2) == array_name:
            return match
    return None


def _identifier_occurs_outside_ranges(
    code: str,
    name: str,
    ignore_ranges: list[tuple[int, int]],
) -> bool:
    pattern = re.compile(rf"""\b{re.escape(name)}\b""")
    for match in pattern.finditer(code):
        if any(start <= match.start() < end for start, end in ignore_ranges):
            continue
        return True
    return False


def _find_adjacent_rotation_helper(
    code: str,
    decl_end: int,
    array_name: str,
) -> tuple[int, int] | None:
    start = _skip_js_trivia(code, decl_end)
    if start >= len(code):
        return None

    probe = start
    while probe < len(code) and code[probe] in "!~+-":
        probe += 1
        probe = _skip_js_trivia(code, probe)

    function_start = probe
    if probe < len(code) and code[probe] == "(":
        probe += 1
        probe = _skip_js_trivia(code, probe)
        function_start = probe

    func_match = re.match(
        r"""function\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*\{""",
        code[function_start:],
        re.DOTALL,
    )
    if func_match is None:
        return None

    array_param = func_match.group(1)
    open_brace = code.find("{", function_start + func_match.start())
    if open_brace == -1:
        return None
    close_brace = _find_matching_brace(code, open_brace)
    if close_brace == -1:
        return None

    body = code[open_brace + 1:close_brace]
    push_shift = re.search(
        rf"""{re.escape(array_param)}\s*(?:\.\s*push|\[\s*['"]push['"]\s*\])\s*\(\s*"""
        rf"""{re.escape(array_param)}\s*(?:\.\s*shift|\[\s*['"]shift['"]\s*\])\s*\(\s*\)\s*\)""",
        body,
        re.DOTALL,
    )
    unshift_pop = re.search(
        rf"""{re.escape(array_param)}\s*(?:\.\s*unshift|\[\s*['"]unshift['"]\s*\])\s*\(\s*"""
        rf"""{re.escape(array_param)}\s*(?:\.\s*pop|\[\s*['"]pop['"]\s*\])\s*\(\s*\)\s*\)""",
        body,
        re.DOTALL,
    )
    if push_shift is None and unshift_pop is None:
        return None

    after_body = _skip_js_trivia(code, close_brace + 1)
    if after_body < len(code) and code[after_body] == ")":
        after_body = _skip_js_trivia(code, after_body + 1)
    if after_body >= len(code) or code[after_body] != "(":
        return None

    close_paren = _find_matching_paren(code, after_body)
    if close_paren == -1:
        return None

    args = code[after_body + 1:close_paren]
    target_match = re.match(r"""\s*(\w+)\s*(?:,|$)""", args)
    if target_match is None or target_match.group(1) != array_name:
        return None

    end = close_paren + 1
    end = _skip_js_trivia(code, end)
    if end < len(code) and code[end] == ")":
        end += 1
        end = _skip_js_trivia(code, end)
    if end < len(code) and code[end] == ";":
        end += 1

    return start, end


def _extract_wrapper_definition(
    func_name: str,
    param_name: str,
    body: str,
    arrays: dict[str, list[str]],
) -> tuple[str, int] | None:
    """Resolve array-backed wrapper helpers, including self-redefining ones."""
    param_pattern = re.escape(param_name)
    offset = 0

    offset_match = re.search(
        _WRAPPER_PARAM_OFFSET.pattern.format(param=param_pattern),
        body,
        re.DOTALL,
    )
    if offset_match:
        offset = _parse_int(offset_match.group(1))

    direct_return = re.search(
        _WRAPPER_DIRECT_RETURN.pattern.format(param=param_pattern),
        body,
        re.DOTALL,
    )
    if direct_return:
        array_name = direct_return.group(1)
        direct_offset = _parse_int(direct_return.group(2)) if direct_return.group(2) else 0
        if array_name in arrays:
            return array_name, offset + direct_offset

    alias_assign = re.search(
        _WRAPPER_ALIAS_ASSIGN.pattern.format(param=param_pattern),
        body,
        re.DOTALL,
    )
    if alias_assign:
        alias_name = alias_assign.group(1)
        array_name = alias_assign.group(2)
        alias_offset = _parse_int(alias_assign.group(3)) if alias_assign.group(3) else 0
        if (
            array_name in arrays
            and re.search(rf"""return\s+{re.escape(alias_name)}\s*;?""", body)
        ):
            return array_name, offset + alias_offset

    if (
        func_name in body
        and re.search(rf"""{re.escape(func_name)}\s*\[\s*['"]initialized['"]\s*\]""", body)
    ):
        nested_candidates = [
            match
            for match in re.finditer(
                rf"""(\w+)\s*=\s*(\w+)\s*\[\s*{param_pattern}\s*\]\s*;""",
                body,
            )
        ]
        for candidate in nested_candidates:
            array_name = candidate.group(2)
            alias_name = candidate.group(1)
            if array_name in arrays and re.search(rf"""return\s+{re.escape(alias_name)}\s*;?""", body):
                return array_name, offset

    return None


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
        static_rewrites: list[dict[str, Any]] = []

        # 1. Find all array declarations — filter to obfuscation-like arrays only
        arrays: dict[str, list[str]] = {}
        array_declarations: dict[str, dict[str, Any]] = {}
        for m in _ARRAY_DECL.finditer(code):
            decl_kind = m.group(1)
            var_name = m.group(2)
            strings = _extract_strings(m.group(3))

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
                array_declarations[var_name] = {
                    "kind": decl_kind,
                    "match": m,
                    "original": strings[:],
                }

        if not arrays:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No array-based obfuscation patterns found.",
            )

        # 2. Check for rotation functions (handle chained/multiple rotations)
        rotation_applied: dict[str, int] = {}  # track signed rotation per array
        rotation_matches: list[dict[str, Any]] = []
        for rotation in _iter_rotation_candidates(code, arrays):
            signed = rotation["count"] if rotation["direction"] == "left" else -rotation["count"]
            total = rotation_applied.get(rotation["array"], 0) + signed
            rotation_applied[rotation["array"]] = total
            rotation_matches.append(rotation)

        # Apply cumulative rotations
        for arr_name, total_rotation in rotation_applied.items():
            if arr_name in arrays:
                arrays[arr_name] = _rotate_array(arrays[arr_name], total_rotation)

        rewrite_edits: list[tuple[int, int, str]] = []
        for arr_name, meta in array_declarations.items():
            rotated = arrays.get(arr_name, [])
            if rotated != meta["original"]:
                match = meta["match"]
                rewrite_edits.append(
                    (
                        match.start(),
                        match.end(),
                        _render_array_declaration(meta["kind"], arr_name, rotated),
                    )
                )
                static_rewrites.append(
                    {
                        "type": "array_rotation_fold",
                        "array": arr_name,
                        "rotation": rotation_applied.get(arr_name, 0),
                    }
                )
        for rotation in rotation_matches:
            rewrite_edits.append((rotation["start"], rotation["end"], ""))
            static_rewrites.append(
                {
                    "type": "rotation_runtime_removed",
                    "array": rotation["array"],
                    "direction": rotation["direction"],
                    "count": rotation["count"],
                }
            )

        if rewrite_edits:
            output = _apply_text_edits(output, rewrite_edits)

        # 3. Find wrapper functions
        wrappers: dict[str, tuple[str, int]] = {}  # func_name -> (array_name, offset)
        wrapper_sources: dict[str, str] = {}
        for func_name, param_name, body, source_text in _iter_wrapper_candidates(output):
            if not func_name:
                continue
            wrapper_def = _extract_wrapper_definition(func_name, param_name, body, arrays)
            if wrapper_def is None:
                continue
            wrappers[func_name] = wrapper_def
            wrapper_sources[func_name] = source_text

        wrapper_replacement_counts: dict[str, int] = {name: 0 for name in wrappers}

        # 4. Replace wrapper function calls: _0xabcd(0x1a3) -> "resolved"
        def _replace_wrapper(m: re.Match) -> str:
            func_name = m.group(1)
            if func_name not in wrappers:
                return m.group(0)
            arr_name, offset = wrappers[func_name]
            if arr_name not in arrays:
                return m.group(0)
            arg_text = m.group(3) or m.group(4)
            if arg_text is None:
                return m.group(0)
            idx = _parse_int(arg_text) - offset
            arr = arrays[arr_name]
            if 0 <= idx < len(arr):
                resolved = arr[idx]
                wrapper_replacement_counts[func_name] += 1
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

        for func_name, source_text in wrapper_sources.items():
            if wrapper_replacement_counts.get(func_name, 0) <= 0:
                continue
            if re.search(rf"""\b{re.escape(func_name)}\s*\(""", output):
                continue
            output = output.replace(source_text, "", 1)
            static_rewrites.append(
                {
                    "type": "wrapper_runtime_removed",
                    "function": func_name,
                }
            )

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

        cleanup_edits: list[tuple[int, int, str]] = []
        for arr_name in array_declarations:
            decl_match = _find_named_array_declaration(output, arr_name)
            if decl_match is None:
                continue
            ignore_ranges = [(decl_match.start(), decl_match.end())]
            helper_range = _find_adjacent_rotation_helper(output, decl_match.end(), arr_name)
            if helper_range is not None:
                ignore_ranges.append(helper_range)
            if _identifier_occurs_outside_ranges(output, arr_name, ignore_ranges):
                continue

            cleanup_edits.append((decl_match.start(), decl_match.end(), ""))
            static_rewrites.append({
                "type": "unused_array_removed",
                "array": arr_name,
            })
            if helper_range is not None:
                cleanup_edits.append((helper_range[0], helper_range[1], ""))
                static_rewrites.append({
                    "type": "unused_rotation_helper_removed",
                    "array": arr_name,
                })

        if cleanup_edits:
            output = _apply_text_edits(output, cleanup_edits)
            output = re.sub(r"\n{3,}", "\n\n", output).strip()

        if not replacements and not static_rewrites:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.2,
                description=(
                    f"Found {len(arrays)} obfuscation array(s) but no "
                    f"resolvable lookups."
                ),
                details={"arrays_found": len(arrays)},
            )

        state.setdefault("js_resolved", []).extend(replacements)

        techniques = ["array_lookup_resolution"]
        if rotation_matches:
            techniques.append("deterministic_array_rotation_fold")

        confidence = min(
            0.97,
            0.72 + 0.02 * len(replacements) + 0.03 * len(static_rewrites),
        )
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=(
                f"Resolved {len(replacements)} array lookup(s), folded "
                f"{len(rotation_matches)} deterministic rotation(s), and "
                f"rewrote {len(static_rewrites)} array helper segment(s)."
            ),
            details={
                "arrays_found": len(arrays),
                "rotation_applied": bool(rotation_matches),
                "wrappers_found": len(wrappers),
                "replacement_count": len(replacements),
                "replacements": replacements,
                "static_rewrites": static_rewrites,
                "detected_techniques": techniques,
            },
        )
