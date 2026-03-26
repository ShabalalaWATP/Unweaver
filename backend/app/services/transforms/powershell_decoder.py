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
import gzip
import re
import zlib
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Encoded command
# ---------------------------------------------------------------------------

_ENCODED_CMD = re.compile(
    r"-(?:EncodedCommand|enc|ec)\s+['\"]?([A-Za-z0-9+/=\s]{20,})['\"]?",
    re.IGNORECASE,
)

_GETSTRING_FROM_B64 = re.compile(
    r"\[System\.Text\.Encoding\]::(Unicode|UTF8)\.GetString\(\s*"
    r"(?:\[System\.Convert\]::|\[Convert\]::|Convert\.)FromBase64String\(\s*['\"]([A-Za-z0-9+/=\s]+)['\"]\s*\)\s*\)",
    re.IGNORECASE,
)
_GETSTRING_START = re.compile(
    r"\[System\.Text\.Encoding\]::(Unicode|UTF8)\.GetString\s*\(",
    re.IGNORECASE,
)
_FROM_B64 = re.compile(
    r"(?:\[System\.Convert\]::|\[Convert\]::|Convert\.)FromBase64String\(\s*['\"]([A-Za-z0-9+/=\s]+)['\"]\s*\)",
    re.IGNORECASE,
)
_FROM_B64_EXPR = re.compile(
    r"(?:\[System\.Convert\]::|\[Convert\]::|Convert\.)FromBase64String\(\s*(.+?)\s*\)$",
    re.IGNORECASE,
)
_PS_STRING_ASSIGN = re.compile(
    r"""^\s*(\$\w+)\s*=\s*(?:"((?:[^"\\`]|`.|"")*)"|'((?:[^']|'')*)')\s*$""",
    re.IGNORECASE | re.MULTILINE,
)
_PS_FROM_B64_ASSIGN = re.compile(
    r"""^\s*(\$\w+)\s*=\s*((?:\[System\.Convert\]::|\[Convert\]::|Convert\.)FromBase64String\(\s*.+?\s*\))\s*$""",
    re.IGNORECASE | re.MULTILINE,
)
_PS_GETSTRING_ASSIGN = re.compile(
    r"""^\s*(\$\w+)\s*=\s*\[System\.Text\.Encoding\]::(Unicode|UTF8)\.GetString\(\s*(.+?)\s*\)\s*$""",
    re.IGNORECASE | re.MULTILINE,
)
_IEX_VAR = re.compile(r"""(?im)\b(?:Invoke-Expression|IEX)\s+(\$\w+)\b""")


def _decode_encoded_command(blob: str) -> str | None:
    """Decode a PowerShell -EncodedCommand payload (UTF-16LE base64)."""
    raw = _decode_base64_bytes(blob)
    if raw is None:
        return None
    try:
        return raw.decode("utf-16-le")
    except Exception:
        try:
            return raw.decode("utf-8")
        except Exception:
            return None


def _clean_base64(blob: str) -> str:
    return blob.replace(" ", "").replace("\n", "").replace("\r", "")


def _decode_base64_bytes(blob: str) -> bytes | None:
    cleaned = _clean_base64(blob)
    missing = len(cleaned) % 4
    if missing:
        cleaned += "=" * (4 - missing)
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception:
        try:
            return base64.b64decode(cleaned)
        except Exception:
            return None


def _decode_text_bytes(raw: bytes, encoding_name: str | None = None) -> str | None:
    candidates: list[str] = []
    if encoding_name:
        enc = "utf-16-le" if encoding_name.lower() == "unicode" else "utf-8"
        candidates.append(enc)
    candidates.extend(["utf-8", "utf-16-le", "latin-1"])
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            text = raw.decode(candidate)
        except Exception:
            continue
        printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t ")
        if printable / max(len(text), 1) >= 0.65:
            return text
    return None


def _decode_getstring_wrapper(encoding_name: str, blob: str) -> str | None:
    raw = _decode_base64_bytes(blob)
    if raw is None:
        return None
    return _decode_text_bytes(raw, encoding_name)


def _ps_string_literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _parse_ps_string_literal(expr: str) -> str | None:
    value = expr.strip()
    if len(value) < 2 or value[0] != value[-1] or value[0] not in {"'", '"'}:
        return None
    inner = value[1:-1]
    if value[0] == "'":
        return inner.replace("''", "'")
    return inner.replace('""', '"').replace("`\"", '"')


def _resolve_ps_string_expr(expr: str, string_bindings: dict[str, str]) -> str | None:
    literal = _parse_ps_string_literal(expr)
    if literal is not None:
        return literal
    return string_bindings.get(expr.strip())


def _resolve_ps_bytes_expr(
    expr: str,
    string_bindings: dict[str, str],
    byte_bindings: dict[str, bytes],
) -> bytes | None:
    value = expr.strip()
    if value in byte_bindings:
        return byte_bindings[value]

    from_b64 = _FROM_B64_EXPR.match(value)
    if from_b64 is None:
        return None

    blob = _resolve_ps_string_expr(from_b64.group(1), string_bindings)
    if blob is None:
        return None
    return _decode_base64_bytes(blob)


def _find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    in_single = False
    in_double = False
    i = open_idx
    while i < len(text):
        char = text[i]
        if in_single:
            if char == "'" and text[i + 1:i + 2] == "'":
                i += 2
                continue
            if char == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if char == "`" and i + 1 < len(text):
                i += 2
                continue
            if char == '"' and text[i + 1:i + 2] == '"':
                i += 2
                continue
            if char == '"':
                in_double = False
            i += 1
            continue
        if char == "'":
            in_single = True
        elif char == '"':
            in_double = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _iter_getstring_calls(code: str):
    for match in _GETSTRING_START.finditer(code):
        open_idx = code.find("(", match.end() - 1)
        if open_idx == -1:
            continue
        close_idx = _find_matching_paren(code, open_idx)
        if close_idx == -1:
            continue
        yield match.group(1), code[match.start():close_idx + 1]


def _decode_compressed_getstring_call(encoding_name: str, call_text: str) -> tuple[str, str] | None:
    if "frombase64string" not in call_text.lower():
        return None
    blob_match = _FROM_B64.search(call_text)
    if blob_match is None:
        return None
    raw = _decode_base64_bytes(blob_match.group(1))
    if raw is None:
        return None

    call_lower = call_text.lower()
    candidates: list[bytes] = []
    if "gzipstream" in call_lower:
        for decoder in (
            lambda b: gzip.decompress(b),
            lambda b: zlib.decompress(b, zlib.MAX_WBITS | 16),
        ):
            try:
                candidates.append(decoder(raw))
            except Exception:
                continue
    elif "deflatestream" in call_lower:
        for decoder in (
            lambda b: zlib.decompress(b),
            lambda b: zlib.decompress(b, -zlib.MAX_WBITS),
        ):
            try:
                candidates.append(decoder(raw))
            except Exception:
                continue
    else:
        return None

    for candidate in candidates:
        decoded = _decode_text_bytes(candidate, encoding_name)
        if decoded:
            return blob_match.group(1), decoded
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
_CHAR_ARRAY_JOIN = re.compile(
    r"\(\s*\[char\[\]\]\s*\(\s*([^)]+?)\s*\)\s*\)\s*-join\s*(['\"])(.*?)\2",
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


def _fold_char_array_join(m: re.Match) -> str | None:
    raw_values = [token.strip() for token in m.group(1).split(",") if token.strip()]
    if len(raw_values) < 2:
        return None

    chars: list[str] = []
    try:
        for token in raw_values:
            value = int(token, 16) if token.lower().startswith("0x") else int(token)
            chars.append(chr(value))
    except Exception:
        return None

    return m.group(3).join(chars)


class PowerShellDecoder(BaseTransform):
    name = "powershell_decoder"
    description = (
        "Decode PowerShell obfuscation: EncodedCommand, format strings, "
        "replacement chains, compressed wrappers, and backticks"
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
            r"\[(?:System\.)?Convert\]",
            r"(?:GzipStream|DeflateStream)",
            r"\[ScriptBlock\]",
            r"\[char\[\]\]",
            r"-(?:replace|creplace)\s",
            r"-join\s*['\"]",
            r"`[a-zA-Z]",  # backtick obfuscation
            r"\"\s*-f\s",  # format string
        ]
        return any(re.search(p, code, re.IGNORECASE) for p in ps_indicators)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        changes: list[dict[str, Any]] = []
        decoded_payloads: list[str] = []

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

        # --- [System.Text.Encoding]::*.GetString(New-Object ...GzipStream/DeflateStream...) ---
        for encoding_name, call_text in list(_iter_getstring_calls(output)):
            decoded_compressed = _decode_compressed_getstring_call(encoding_name, call_text)
            if decoded_compressed is None:
                continue
            encoded_blob, decoded = decoded_compressed
            changes.append({
                "type": "compressed_getstring",
                "encoding": encoding_name,
                "encoded": encoded_blob[:80],
                "decoded": decoded,
            })
            decoded_payloads.append(decoded)
            output = output.replace(call_text, _ps_string_literal(decoded), 1)

        # --- [System.Text.Encoding]::*.GetString([System.Convert]::FromBase64String(...)) ---
        for m in _GETSTRING_FROM_B64.finditer(output):
            decoded = _decode_getstring_wrapper(m.group(1), m.group(2))
            if decoded:
                changes.append({
                    "type": "encoding_getstring",
                    "encoding": m.group(1),
                    "encoded": m.group(2)[:80],
                    "decoded": decoded,
                })
                decoded_payloads.append(decoded)
                output = output.replace(
                    m.group(0),
                    _ps_string_literal(decoded),
                    1,
                )

        # --- Encoded command ---
        for m in _ENCODED_CMD.finditer(output):
            decoded = _decode_encoded_command(m.group(1))
            if decoded:
                changes.append({
                    "type": "encoded_command",
                    "encoded": m.group(1)[:80],
                    "decoded": decoded,
                })
                decoded_payloads.append(decoded)
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

        # --- ([char[]](73,69,88)) -join '' ---
        def _replace_char_array_join(m: re.Match) -> str:
            folded = _fold_char_array_join(m)
            if folded is not None:
                changes.append({
                    "type": "char_array_join",
                    "original": m.group(0)[:120],
                    "folded": folded,
                    "decoded": folded,
                })
                return f'"{folded}"'
            return m.group(0)

        output = _CHAR_ARRAY_JOIN.sub(_replace_char_array_join, output)

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
        output = re.sub(r"""(['"])\s*(\$\w+\s*=)""", r"\1\n\2", output)

        string_bindings: dict[str, str] = {}
        byte_bindings: dict[str, bytes] = {}
        for _ in range(3):
            bindings_changed = False

            for m in _PS_STRING_ASSIGN.finditer(output):
                var_name = m.group(1)
                literal = m.group(2) if m.group(2) is not None else m.group(3)
                value = (literal or "").replace("''", "'").replace('""', '"')
                if string_bindings.get(var_name) != value:
                    string_bindings[var_name] = value
                    bindings_changed = True

            for m in _PS_FROM_B64_ASSIGN.finditer(output):
                resolved = _resolve_ps_bytes_expr(m.group(2), string_bindings, byte_bindings)
                if resolved is not None and byte_bindings.get(m.group(1)) != resolved:
                    byte_bindings[m.group(1)] = resolved
                    bindings_changed = True

            for m in _PS_GETSTRING_ASSIGN.finditer(output):
                var_name = m.group(1)
                resolved_bytes = _resolve_ps_bytes_expr(m.group(3), string_bindings, byte_bindings)
                if resolved_bytes is None:
                    continue
                resolved = _decode_text_bytes(resolved_bytes, m.group(2))
                if resolved and string_bindings.get(var_name) != resolved:
                    string_bindings[var_name] = resolved
                    bindings_changed = True

            if not bindings_changed:
                break

        for m in list(_PS_GETSTRING_ASSIGN.finditer(output)):
            var_name = m.group(1)
            resolved = string_bindings.get(var_name)
            if not resolved:
                continue
            changes.append({
                "type": "binding_getstring",
                "variable": var_name,
                "decoded": resolved,
            })
            decoded_payloads.append(resolved)
            output = output.replace(
                m.group(0),
                f"{var_name} = {_ps_string_literal(resolved)}",
                1,
            )

        for m in list(_IEX_VAR.finditer(output)):
            variable = m.group(1)
            resolved = string_bindings.get(variable)
            if not resolved:
                continue
            changes.append({
                "type": "iex_inline",
                "variable": variable,
                "decoded": resolved,
            })
            decoded_payloads.append(resolved)
            output = output.replace(
                m.group(0),
                f"# DECODED (IEX):\n{resolved}",
                1,
            )

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
                "decoded_payloads": decoded_payloads,
                "decoded_strings": [
                    {
                        "encoded": change.get("encoded", change.get("type", "powershell_payload")),
                        "decoded": change.get("decoded", ""),
                    }
                    for change in changes
                    if change.get("decoded")
                ],
            },
        )
