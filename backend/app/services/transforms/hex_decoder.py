"""
HexDecoder transform -- detects hex-encoded strings in various formats
across languages and decodes them to readable text.

Supported formats:
  - \\x41\\x42  (C-style / Python / JS)
  - 0x41, 0x42  (comma-separated hex bytes)
  - \\u0041     (Unicode escapes)
  - %41%42      (URL-encoded)
  - Hex streams  (4142434445... -- long runs of hex pairs)
"""

from __future__ import annotations

import json
import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Hex sequence patterns
# ---------------------------------------------------------------------------

# \x41\x42\x43 ...
_BACKSLASH_X = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")

# 0x41,0x42  or  0x41, 0x42  (with optional whitespace and commas)
_ZERO_X_LIST = re.compile(
    r"(?:0x[0-9a-fA-F]{1,2}\s*,\s*){2,}0x[0-9a-fA-F]{1,2}"
)

# Unicode escapes: \u0041\u0042
_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}")

# URL-encoded: %41%42
_PERCENT_HEX = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")

# Raw hex stream (at least 8 hex chars = 4 bytes) -- very strict context
# We only grab these when they appear inside string delimiters or assignments.
_HEX_STREAM = re.compile(
    r"(?<=['\"\s=])([0-9a-fA-F]{8,})(?=['\"\s;,)])"
)

# PowerShell: 0x41,0x42 in @(0x41,0x42,...) or [byte[]](0x41,0x42,...)
_PS_BYTE_ARRAY = re.compile(
    r"(?:@\(|\[byte\[\]\]\s*\()\s*((?:0x[0-9a-fA-F]{1,2}\s*,?\s*)+)\)",
    re.IGNORECASE,
)


def _decode_backslash_x(text: str) -> str | None:
    """Decode \\x41\\x42... sequences."""
    try:
        hex_bytes = re.findall(r"\\x([0-9a-fA-F]{2})", text)
        raw = bytes(int(h, 16) for h in hex_bytes)
        return _try_text(raw)
    except Exception:
        return None


def _decode_0x_list(text: str) -> str | None:
    """Decode 0x41,0x42,... sequences."""
    try:
        hex_values = re.findall(r"0x([0-9a-fA-F]{1,2})", text)
        raw = bytes(int(h, 16) for h in hex_values)
        return _try_text(raw)
    except Exception:
        return None


def _decode_unicode_escape(text: str) -> str | None:
    """Decode \\u0041\\u0042... sequences."""
    try:
        codepoints = re.findall(r"\\u([0-9a-fA-F]{4})", text)
        return "".join(chr(int(cp, 16)) for cp in codepoints)
    except Exception:
        return None


def _decode_percent_hex(text: str) -> str | None:
    """Decode %41%42... sequences."""
    try:
        hex_bytes = re.findall(r"%([0-9a-fA-F]{2})", text)
        raw = bytes(int(h, 16) for h in hex_bytes)
        return _try_text(raw)
    except Exception:
        return None


def _decode_hex_stream(text: str) -> str | None:
    """Decode a raw hex stream (pairs of hex digits)."""
    cleaned = text.strip()
    if len(cleaned) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(cleaned)
        return _try_text(raw)
    except Exception:
        return None


def _try_text(raw: bytes) -> str | None:
    """Convert bytes to text if printable enough."""
    for enc in ("utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            printable = sum(
                1 for c in text if c.isprintable() or c in "\r\n\t "
            )
            if printable / max(len(text), 1) > 0.70:
                return text
        except Exception:
            continue
    return None


def _escape_for_quote(text: str, quote: str) -> str:
    escaped = text.replace("\\", "\\\\")
    escaped = escaped.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if quote == '"':
        return escaped.replace('"', '\\"')
    return escaped.replace("'", "\\'")


def _literal_for_language(text: str, language: str) -> str:
    lang = (language or "").lower().strip()
    if lang in ("python", "py"):
        return repr(text)
    if lang in ("powershell", "ps1", "ps"):
        return "'" + text.replace("'", "''") + "'"
    return json.dumps(text)


def _render_decoded_literal(
    text: str,
    code: str,
    start: int,
    end: int,
    language: str,
) -> str:
    if start > 0 and end < len(code):
        quote = code[start - 1]
        if quote in {'"', "'"} and code[end] == quote:
            return _escape_for_quote(text, quote)
    return _literal_for_language(text, language)


class HexDecoder(BaseTransform):
    name = "hex_decoder"
    description = "Detect and decode hex-encoded strings in various formats"

    # The decoders to apply, in order. Each entry is
    # (pattern, decoder_func, label).
    _DECODERS: list[tuple[re.Pattern, Any, str]] = [
        (_BACKSLASH_X, _decode_backslash_x, "backslash_x"),
        (_ZERO_X_LIST, _decode_0x_list, "0x_list"),
        (_PS_BYTE_ARRAY, _decode_0x_list, "ps_byte_array"),
        (_UNICODE_ESCAPE, _decode_unicode_escape, "unicode_escape"),
        (_PERCENT_HEX, _decode_percent_hex, "percent_hex"),
        (_HEX_STREAM, _decode_hex_stream, "hex_stream"),
    ]

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(
            _BACKSLASH_X.search(code)
            or _ZERO_X_LIST.search(code)
            or _UNICODE_ESCAPE.search(code)
            or _PERCENT_HEX.search(code)
            or _HEX_STREAM.search(code)
            or _PS_BYTE_ARRAY.search(code)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        decoded_items: list[dict[str, Any]] = []
        output = code

        for pattern, decoder, label in self._DECODERS:
            for m in pattern.finditer(output):
                # For PS_BYTE_ARRAY, the actual hex content is in group 1
                raw_match = m.group(1) if m.lastindex and m.lastindex >= 1 and label == "ps_byte_array" else m.group(0)
                decoded = decoder(raw_match)
                if decoded is not None:
                    decoded_items.append({
                        "format": label,
                        "encoded": m.group(0)[:120],
                        "decoded": decoded,
                        "start": m.start(),
                        "end": m.end(),
                    })
                    replacement = _render_decoded_literal(
                        decoded,
                        output,
                        m.start(),
                        m.end(),
                        language,
                    )
                    output = (
                        output[:m.start()]
                        + replacement
                        + output[m.end():]
                    )
                    # After replacement the offsets shift, so we break and
                    # re-scan to avoid stale positions. This is a simple
                    # approach; for very large files a position-tracking
                    # strategy would be better.
                    break
            else:
                continue
            # If we broke out of the inner loop (did a replacement),
            # restart scanning for this pattern from the top.
            # We limit iterations to prevent infinite loops.
            for _ in range(200):
                m2 = pattern.search(output)
                if m2 is None:
                    break
                raw_match = m2.group(1) if m2.lastindex and m2.lastindex >= 1 and label == "ps_byte_array" else m2.group(0)
                decoded = decoder(raw_match)
                if decoded is None:
                    break
                decoded_items.append({
                    "format": label,
                    "encoded": m2.group(0)[:120],
                    "decoded": decoded,
                    "start": m2.start(),
                    "end": m2.end(),
                })
                replacement = _render_decoded_literal(
                    decoded,
                    output,
                    m2.start(),
                    m2.end(),
                    language,
                )
                output = (
                    output[:m2.start()]
                    + replacement
                    + output[m2.end():]
                )

        if not decoded_items:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No decodable hex sequences found.",
            )

        state.setdefault("decoded_hex", []).extend(decoded_items)

        confidence = min(0.95, 0.75 + 0.03 * len(decoded_items))
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=f"Decoded {len(decoded_items)} hex sequence(s).",
            details={
                "decoded_count": len(decoded_items),
                "items": decoded_items,
                "decoded_strings": [
                    {
                        "encoded": item["encoded"],
                        "decoded": item["decoded"],
                    }
                    for item in decoded_items
                ],
            },
        )
