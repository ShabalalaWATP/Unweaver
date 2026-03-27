"""
StringDecryptor transform -- identifies and resolves custom string
decryption / deobfuscation function calls in obfuscated code.

Many obfuscators replace string literals with calls to a custom decrypt
function that is defined once and invoked everywhere:

    function decrypt(s) { return s.split('').reverse().join(''); }
    var x = decrypt("pleh");   // -> "help"

This transform:
  1. Detects candidate decryption functions by inspecting their body.
  2. Classifies the decryption algorithm (reverse, ROT13, XOR, base64, ...).
  3. Statically evaluates every call site whose arguments are literals.
  4. Replaces resolved calls with the decrypted string value.
  5. Annotates unresolvable calls with a descriptive comment.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

def _parse_int(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


# Names that strongly suggest obfuscation
_OBFUSCATED_NAME = re.compile(
    r"^(?:_0x[0-9a-fA-F]+|_[a-zA-Z0-9]{1,4}|[a-zA-Z]{1,2}\d+|d|dec|decrypt"
    r"|_d|_s|_r|_decode|_dec|_str|deobf|unscramble)$"
)

# Body keywords that hint at string transformation
_DECRYPT_BODY_KEYWORDS = [
    "split", "reverse", "join", "fromCharCode", "charCodeAt",
    "String.fromCharCode", "chr", "ord", "replace", "substring",
    "substr", "atob", "btoa", "b64decode", "base64",
]

# XOR operator in body
_XOR_IN_BODY = re.compile(r"\^")

# ---------------------------------------------------------------------------
# Function declaration patterns (JS / Python / generic)
# ---------------------------------------------------------------------------

# JavaScript: function name(param, ...) { body }
_JS_FUNC_DECL = re.compile(
    r"function\s+(\w+)\s*\(\s*(\w+(?:\s*,\s*\w+)*)\s*\)\s*\{"
)

# JavaScript arrow / var form: var name = function(param) { body }
_JS_VAR_FUNC = re.compile(
    r"(?:var|let|const)\s+(\w+)\s*=\s*function\s*\(\s*(\w+(?:\s*,\s*\w+)*)\s*\)\s*\{"
)

# Python: def name(param, ...):
_PY_FUNC_DECL = re.compile(
    r"def\s+(\w+)\s*\(\s*(\w+(?:\s*,\s*\w+)*)\s*\)\s*:"
)


def _extract_brace_body(code: str, open_pos: int) -> str | None:
    """Return the body between balanced braces starting at *open_pos*."""
    if open_pos >= len(code) or code[open_pos] != "{":
        return None
    depth = 0
    for i in range(open_pos, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[open_pos + 1 : i]
    return None


def _extract_python_body(code: str, header_end: int) -> str | None:
    """Return the indented body of a Python function starting after the colon."""
    lines = code[header_end:].split("\n")
    if not lines:
        return None
    # skip the first (possibly empty) line after the colon
    body_lines: list[str] = []
    started = False
    base_indent: int | None = None
    for line in lines[1:]:
        stripped = line.lstrip()
        if not stripped:
            body_lines.append("")
            continue
        indent = len(line) - len(stripped)
        if base_indent is None:
            base_indent = indent
            started = True
        if started and indent < base_indent and stripped:
            break
        body_lines.append(line)
    return "\n".join(body_lines) if body_lines else None


# ---------------------------------------------------------------------------
# Pattern classification
# ---------------------------------------------------------------------------

def _classify_body(body: str) -> list[str]:
    """Return a list of detected decryption technique tags for the body."""
    patterns: list[str] = []
    bl = body.lower()

    # Reverse
    if ("split" in bl and "reverse" in bl and "join" in bl) or "[::-1]" in body:
        patterns.append("reverse")

    # ROT13 / Caesar
    if re.search(r"charCodeAt|ord\s*\(", body) and re.search(r"[+\-]\s*(?:13|0x0?d)\b", body):
        patterns.append("rot13")
    elif re.search(r"charCodeAt|ord\s*\(", body) and re.search(r"[+\-]\s*(?:0x[0-9a-fA-F]+|\d+)", body):
        # generic Caesar if there's a char code operation with an offset
        if "fromCharCode" in body or "chr" in bl:
            patterns.append("caesar")

    # XOR
    if _XOR_IN_BODY.search(body) and ("charCodeAt" in body or "ord" in bl or "chr" in bl):
        patterns.append("xor")

    # Base64
    if re.search(r"\batob\b|\bbtoa\b|\bb64decode\b|\bbase64\b", bl):
        patterns.append("base64")

    # String.fromCharCode array
    if "fromcharcode" in bl and re.search(r"split|map", bl):
        patterns.append("fromCharCode_array")

    # Replace chain
    if bl.count(".replace(") >= 2:
        patterns.append("replace_chain")
    elif ".replace(" in bl:
        patterns.append("replace")

    # Char code offset: String.fromCharCode(x - N) or chr(ord(x) - N)
    if re.search(r"fromCharCode\s*\([^)]*[+\-]\s*\d+", body):
        patterns.append("charcode_offset")
    if re.search(r"chr\s*\(\s*ord\s*\([^)]*\)\s*[+\-]\s*\d+", body):
        patterns.append("charcode_offset")

    # Array lookup
    if re.search(r"\[\s*\w+\s*\]", body) and re.search(r"return", body):
        # only add if nothing else was detected (avoid false positives)
        if not patterns:
            patterns.append("array_lookup")

    return patterns


# ---------------------------------------------------------------------------
# Static resolvers -- each takes (argument_value, body_text, params) and
# returns the resolved string or None.
# ---------------------------------------------------------------------------

def _resolve_reverse(arg: str, _body: str, _params: list[str]) -> str | None:
    """Resolve a simple string reverse."""
    return arg[::-1]


def _resolve_rot13(arg: str, _body: str, _params: list[str]) -> str | None:
    """Apply ROT13 to the argument."""
    out: list[str] = []
    for ch in arg:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _extract_caesar_offset(body: str) -> int | None:
    """Try to extract the shift offset from a Caesar/char-shift function body."""
    m = re.search(
        r"(?:charCodeAt\s*\(\s*\w*\s*\)|ord\s*\([^)]*\))\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)",
        body,
    )
    if m:
        offset = _parse_int(m.group(2))
        return offset if m.group(1) == "+" else -offset
    return None


def _resolve_caesar(arg: str, body: str, _params: list[str]) -> str | None:
    """Apply a Caesar shift with the offset extracted from the body."""
    offset = _extract_caesar_offset(body)
    if offset is None:
        return None
    try:
        return "".join(chr(ord(c) + offset) for c in arg)
    except (ValueError, OverflowError):
        return None


def _extract_xor_key(body: str) -> str | None:
    """Try to extract a fixed XOR key from the function body."""
    # Pattern: ^ "key" or ^ 'key'
    m = re.search(r'\^\s*["\']([^"\']+)["\']', body)
    if m:
        return m.group(1)
    # Pattern: ^ 0xNN (single byte)
    m = re.search(r'\^\s*(0x[0-9a-fA-F]+|\d+)\b', body)
    if m:
        val = _parse_int(m.group(1))
        if 0 < val < 256:
            return chr(val)
    return None


def _resolve_xor(arg: str, body: str, params: list[str]) -> str | None:
    """XOR the argument with the key found in the body."""
    key = _extract_xor_key(body)
    if key is None:
        return None
    try:
        out: list[str] = []
        for i, ch in enumerate(arg):
            out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
        return "".join(out)
    except (ValueError, OverflowError):
        return None


def _resolve_xor_two_args(arg: str, key: str, body: str) -> str | None:
    """XOR when the key is passed as the second argument."""
    try:
        out: list[str] = []
        for i, ch in enumerate(arg):
            out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
        return "".join(out)
    except (ValueError, OverflowError):
        return None


def _resolve_base64(arg: str, _body: str, _params: list[str]) -> str | None:
    """Decode a base64 argument."""
    try:
        decoded = base64.b64decode(arg).decode("utf-8", errors="replace")
        # sanity: reject if result has too many non-printable chars
        if sum(1 for c in decoded if not c.isprintable() and c not in "\n\r\t") > len(decoded) * 0.3:
            return None
        return decoded
    except Exception:
        return None


def _resolve_fromcharcode_array(arg: str, _body: str, _params: list[str]) -> str | None:
    """Resolve when the argument is a comma-separated list of char codes."""
    # The arg might be "72,101,108" or the call might pass individual numbers.
    nums = re.findall(r"0x[0-9a-fA-F]+|\d+", arg)
    if not nums:
        return None
    try:
        return "".join(chr(_parse_int(n)) for n in nums)
    except (ValueError, OverflowError):
        return None


def _resolve_charcode_offset(arg: str, body: str, _params: list[str]) -> str | None:
    """String.fromCharCode(charCodeAt(c) + offset) for each char."""
    offset = _extract_caesar_offset(body)
    if offset is None:
        return None
    try:
        return "".join(chr(ord(c) + offset) for c in arg)
    except (ValueError, OverflowError):
        return None


_RESOLVERS: dict[str, Any] = {
    "reverse": _resolve_reverse,
    "rot13": _resolve_rot13,
    "caesar": _resolve_caesar,
    "xor": _resolve_xor,
    "base64": _resolve_base64,
    "fromCharCode_array": _resolve_fromcharcode_array,
    "charcode_offset": _resolve_charcode_offset,
}


# ---------------------------------------------------------------------------
# Call-site detection
# ---------------------------------------------------------------------------

def _build_call_pattern(func_name: str) -> re.Pattern:
    """Build a regex that matches ``func_name(literal_arg)`` or
    ``func_name(literal_arg, literal_arg2)``."""
    return re.compile(
        r"\b"
        + re.escape(func_name)
        + r"""\(\s*("""
        + r""""(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|0x[0-9a-fA-F]+|\d+"""
        + r""")"""
        + r"""(?:\s*,\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|0x[0-9a-fA-F]+|\d+))*"""
        + r"""\s*\)"""
    )


def _unquote(s: str) -> str:
    """Remove surrounding quotes from a string literal."""
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def _extract_call_args(match_text: str, func_name: str) -> list[str]:
    """Extract the raw argument strings from a matched call expression."""
    # Strip the function name and parens
    inner = match_text[len(func_name) + 1 : -1].strip()
    # Split on commas (respecting quoted strings)
    args: list[str] = []
    current: list[str] = []
    in_quote: str | None = None
    escape = False
    for ch in inner:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            current.append(ch)
            escape = True
            continue
        if in_quote:
            current.append(ch)
            if ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
            current.append(ch)
            continue
        if ch == ",":
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


# ---------------------------------------------------------------------------
# Heuristic: count how many call sites a function has with literal args
# ---------------------------------------------------------------------------

def _count_literal_calls(code: str, func_name: str) -> int:
    """Return the number of call sites for *func_name* that pass literals."""
    pat = _build_call_pattern(func_name)
    return len(pat.findall(code))


# ---------------------------------------------------------------------------
# Main transform
# ---------------------------------------------------------------------------

# Quick pre-check pattern: code that has a function whose body contains
# decrypt-like operations AND is called multiple times.
_QUICK_CHECK = re.compile(
    r"(?:function\s+\w+\s*\([^)]*\)\s*\{[^}]*"
    r"(?:split|reverse|join|fromCharCode|charCodeAt|atob|btoa|chr|ord|\^)"
    r"[^}]*\})"
    r"|"
    r"(?:def\s+\w+\s*\([^)]*\)\s*:(?:\s*\n[ \t]+[^\n]*){0,8}"
    r"(?:split|reverse|join|chr|ord|b64decode|base64|\^))",
    re.DOTALL,
)


class StringDecryptor(BaseTransform):
    name = "StringDecryptor"
    description = "Detect and resolve custom string decryption/deobfuscation function calls."

    # ---- can_apply --------------------------------------------------

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        """Return True if the code has patterns suggesting a string decrypt
        function: a function with crypto/decode keywords in its body that
        is called multiple times with literal arguments."""
        if not _QUICK_CHECK.search(code):
            return False

        # Find candidate function names and check call frequency
        for m in re.finditer(r"(?:function\s+(\w+)|def\s+(\w+))", code):
            name = m.group(1) or m.group(2)
            if name and _count_literal_calls(code, name) > 0:
                return True
        return False

    # ---- apply ------------------------------------------------------

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        lang = (language or "").lower().strip()

        # Collect candidate functions
        candidates: list[dict[str, Any]] = []

        # --- JavaScript-style functions ---
        for pattern in (_JS_FUNC_DECL, _JS_VAR_FUNC):
            for m in pattern.finditer(code):
                func_name = m.group(1)
                params = [p.strip() for p in m.group(2).split(",")]
                body_start = m.end() - 1  # position of opening brace
                body = _extract_brace_body(code, body_start)
                if body is None:
                    continue
                candidates.append({
                    "name": func_name,
                    "params": params,
                    "body": body,
                    "lang": "js",
                })

        # --- Python-style functions ---
        for m in _PY_FUNC_DECL.finditer(code):
            func_name = m.group(1)
            params = [p.strip() for p in m.group(2).split(",")]
            body = _extract_python_body(code, m.end())
            if body is None:
                continue
            candidates.append({
                "name": func_name,
                "params": params,
                "body": body,
                "lang": "py",
            })

        # Filter to likely decryption functions with stricter false-positive prevention
        # Common utility function names that should NOT be treated as decryptors
        _UTILITY_NAMES = frozenset({
            "format", "replace", "trim", "strip", "join", "split", "concat",
            "toString", "valueOf", "stringify", "parse", "encode", "log",
            "print", "render", "display", "show", "hide", "toggle",
            "init", "setup", "configure", "validate", "sanitize", "escape",
            "serialize", "deserialize", "transform", "convert", "normalize",
            "sort", "filter", "reduce", "find", "indexOf", "includes",
            "startsWith", "endsWith", "slice", "splice", "push", "pop",
            "shift", "unshift", "map", "forEach", "keys", "values",
        })

        decrypt_funcs: list[dict[str, Any]] = []
        for cand in candidates:
            body_lower = cand["body"].lower()
            name_lower = cand["name"].lower()

            # Skip common utility function names
            if cand["name"] in _UTILITY_NAMES:
                continue

            keyword_count = sum(1 for kw in _DECRYPT_BODY_KEYWORDS if kw in body_lower)
            has_xor = bool(_XOR_IN_BODY.search(cand["body"]))
            call_count = _count_literal_calls(code, cand["name"])
            name_looks_obfuscated = bool(_OBFUSCATED_NAME.match(cand["name"]))
            name_has_decoder_word = any(
                token in name_lower
                for token in ("decrypt", "decode", "deobfusc", "unscramble", "unescape")
            )

            # Require MULTIPLE indicators to reduce false positives:
            # - At least 2 decrypt keywords, OR 1 keyword + XOR, OR obfuscated name + keyword
            indicators = 0
            if keyword_count >= 2:
                indicators += 1
            if has_xor:
                indicators += 1
            if name_looks_obfuscated:
                indicators += 1
            if keyword_count >= 1 and (has_xor or name_looks_obfuscated):
                indicators += 1

            if indicators < 1:
                continue

            # Single-use decrypt helpers are common in loaders. Allow them when
            # the name/body already provides a strong decode signal.
            if call_count <= 0:
                continue
            if call_count <= 3 and not (
                name_looks_obfuscated
                or name_has_decoder_word
                or keyword_count >= 2
                or has_xor
            ):
                continue

            patterns = _classify_body(cand["body"])
            if not patterns:
                # Body has keywords but we can't classify — only flag if
                # the function name is obfuscated (strong signal)
                if name_looks_obfuscated:
                    patterns = ["unknown"]
                else:
                    continue

            cand["patterns"] = patterns
            cand["call_count"] = call_count
            decrypt_funcs.append(cand)

        if not decrypt_funcs:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No custom string decryption functions detected.",
                details={
                    "decrypt_functions_found": 0,
                    "calls_resolved": 0,
                    "calls_unresolved": 0,
                    "patterns": [],
                    "detected_techniques": [],
                },
            )

        # Resolve call sites
        resolved_count = 0
        unresolved_count = 0
        all_patterns: set[str] = set()
        all_techniques: set[str] = set()
        resolved_strings: list[dict[str, str]] = []

        for func in decrypt_funcs:
            func_name: str = func["name"]
            func_params: list[str] = func["params"]
            func_body: str = func["body"]
            patterns: list[str] = func["patterns"]
            all_patterns.update(patterns)
            all_techniques.update(p for p in patterns if p != "unknown")

            call_pat = _build_call_pattern(func_name)

            def _make_replacer(
                fn: str,
                fp: list[str],
                fb: str,
                pats: list[str],
            ):
                """Create a closure for re.sub that resolves calls."""
                nonlocal resolved_count, unresolved_count

                def replacer(m: re.Match) -> str:
                    nonlocal resolved_count, unresolved_count
                    raw_args = _extract_call_args(m.group(0), fn)

                    # Try each detected pattern resolver
                    resolved_value: str | None = None
                    for pat in pats:
                        resolver = _RESOLVERS.get(pat)
                        if resolver is None:
                            continue

                        if pat == "xor" and len(raw_args) >= 2 and len(fp) >= 2:
                            # Two-argument XOR: func(cipher, key)
                            arg1 = _unquote(raw_args[0])
                            arg2 = _unquote(raw_args[1])
                            resolved_value = _resolve_xor_two_args(arg1, arg2, fb)
                            if resolved_value is not None:
                                break
                            # Also try with key from body
                            resolved_value = resolver(arg1, fb, fp)
                            if resolved_value is not None:
                                break
                        else:
                            arg = _unquote(raw_args[0]) if raw_args else ""
                            resolved_value = resolver(arg, fb, fp)
                            if resolved_value is not None:
                                break

                    if resolved_value is not None:
                        # Sanity check: result should be mostly printable
                        non_printable = sum(
                            1 for c in resolved_value
                            if not c.isprintable() and c not in "\n\r\t"
                        )
                        if non_printable > len(resolved_value) * 0.3 and len(resolved_value) > 0:
                            unresolved_count += 1
                            return f"/* encrypted string call: {fn}(...) */ {m.group(0)}"

                        # Escape quotes in the resolved value
                        escaped = resolved_value.replace("\\", "\\\\").replace('"', '\\"')
                        resolved_strings.append({
                            "function": fn,
                            "original": m.group(0)[:160],
                            "decrypted": resolved_value,
                        })
                        resolved_count += 1
                        return f'"{escaped}"'

                    # Could not resolve
                    unresolved_count += 1
                    return f"/* encrypted string call: {fn}(...) */ {m.group(0)}"

                return replacer

            replacer = _make_replacer(func_name, func_params, func_body, patterns)
            output = call_pat.sub(replacer, output)

        success = resolved_count > 0
        confidence = 0.70 + 0.03 * min(resolved_count, 10) if success else 0.0

        desc_parts: list[str] = []
        if resolved_count:
            desc_parts.append(f"Resolved {resolved_count} encrypted string call(s)")
        if unresolved_count:
            desc_parts.append(f"{unresolved_count} call(s) could not be resolved")
        desc_parts.append(
            f"across {len(decrypt_funcs)} decryption function(s)"
        )
        description = "; ".join(desc_parts) + "."

        state.setdefault("string_decryptor", []).append({
            "functions": [f["name"] for f in decrypt_funcs],
            "resolved": resolved_count,
            "unresolved": unresolved_count,
        })

        return TransformResult(
            success=success,
            output=output,
            confidence=confidence,
            description=description,
            details={
                "decrypt_functions_found": len(decrypt_funcs),
                "calls_resolved": resolved_count,
                "calls_unresolved": unresolved_count,
                "patterns": sorted(all_patterns),
                "detected_techniques": sorted(all_techniques),
                "decrypted_strings": resolved_strings[:50],
            },
        )
