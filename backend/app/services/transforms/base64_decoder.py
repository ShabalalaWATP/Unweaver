"""
Base64Decoder transform -- detects base64-encoded strings in code, decodes
them (up to 3 nested layers), and recognises common obfuscation wrappers
such as ``[System.Convert]::FromBase64String``, ``atob()``, and
``base64.b64decode()``.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Wrapper patterns (language-specific calls that wrap base64 payloads)
# ---------------------------------------------------------------------------

_WRAPPER_PATTERNS: list[tuple[str, re.Pattern]] = [
    # PowerShell: [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('...'))
    (
        "powershell_getstring",
        re.compile(
            r"\[System\.Text\.Encoding\]::(?:Unicode|UTF8)\.GetString\(\s*"
            r"\[System\.Convert\]::FromBase64String\(\s*['\"]"
            r"([A-Za-z0-9+/\s=]+)['\"]\s*\)\s*\)",
            re.IGNORECASE,
        ),
    ),
    # C#: Encoding.UTF8.GetString(Convert.FromBase64String("..."))
    (
        "csharp_getstring",
        re.compile(
            r"(?:System\.Text\.)?Encoding\.(?:Unicode|UTF8)\.GetString\(\s*"
            r"Convert\.FromBase64String\(\s*['\"]([A-Za-z0-9+/\s=]+)['\"]\s*\)\s*\)",
            re.IGNORECASE,
        ),
    ),
    # PowerShell: [System.Convert]::FromBase64String('...')
    (
        "powershell_convert",
        re.compile(
            r"\[System\.Convert\]::FromBase64String\(\s*['\"]"
            r"([A-Za-z0-9+/\s=]+)['\"]"
            r"\s*\)",
            re.IGNORECASE,
        ),
    ),
    # PowerShell: -EncodedCommand / -enc  (handled mainly in powershell_decoder
    # but we catch standalone occurrences here too)
    (
        "powershell_enc",
        re.compile(
            r"-(?:EncodedCommand|enc)\s+['\"]?([A-Za-z0-9+/\s=]{20,})['\"]?",
            re.IGNORECASE,
        ),
    ),
    # JavaScript: atob('...')
    (
        "js_atob",
        re.compile(
            r"atob\(\s*['\"]([A-Za-z0-9+/\s=]+)['\"]\s*\)"
        ),
    ),
    # JavaScript: Buffer.from('...', 'base64')
    (
        "js_buffer",
        re.compile(
            r"Buffer\.from\(\s*['\"]([A-Za-z0-9+/\s=]+)['\"]"
            r"\s*,\s*['\"]base64['\"]\s*\)"
        ),
    ),
    # Python: base64.b64decode('...')
    (
        "py_b64decode",
        re.compile(
            r"base64\.b64decode\(\s*['\"]([A-Za-z0-9+/\s=]+)['\"]\s*\)"
        ),
    ),
    # Python: base64.decodebytes / decodestring (legacy)
    (
        "py_decodebytes",
        re.compile(
            r"base64\.(?:decodebytes|decodestring)\(\s*['\"]"
            r"([A-Za-z0-9+/\s=]+)['\"]\s*\)"
        ),
    ),
    # C#: Convert.FromBase64String("...")
    (
        "cs_convert",
        re.compile(
            r"Convert\.FromBase64String\(\s*\"([A-Za-z0-9+/\s=]+)\"\s*\)"
        ),
    ),
]

# Standalone base64 blobs (not inside a known wrapper). We require a minimum
# length of 16 to cut down on false positives.
_STANDALONE_B64 = re.compile(
    r"(?<![A-Za-z0-9+/=])"          # not preceded by b64 chars
    r"([A-Za-z0-9+/]{16,}={0,2})"   # the blob
    r"(?![A-Za-z0-9+/=])"           # not followed by b64 chars
)

MAX_NESTING = 8


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


def _is_plausible_b64(s: str) -> bool:
    """Quick check that a string looks like valid base64 (standard or URL-safe)."""
    stripped = s.replace(" ", "").replace("\n", "").replace("\r", "")
    if len(stripped) < 8:
        return False
    if len(stripped) % 4 not in (0, 2, 3):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/\-_]+={0,2}", stripped))


def _try_decode(blob: str) -> str | None:
    """Try to base64-decode a string. Return decoded text or None.

    Attempts standard base64 first, then URL-safe base64 (RFC 4648
    with ``-`` and ``_`` instead of ``+`` and ``/``).
    """
    cleaned = blob.replace(" ", "").replace("\n", "").replace("\r", "")
    # add padding if needed
    missing = len(cleaned) % 4
    if missing:
        cleaned += "=" * (4 - missing)

    # Try standard base64 first
    raw = None
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except Exception:
        pass

    # Try URL-safe base64 (RFC 4648: - and _ instead of + and /)
    if raw is None:
        try:
            raw = base64.urlsafe_b64decode(cleaned)
        except Exception:
            pass

    if raw is None:
        return None

    # Try UTF-8 first (most common)
    for enc in ("utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            printable_ratio = sum(
                1 for c in text if c.isprintable() or c in "\r\n\t "
            ) / max(len(text), 1)
            if printable_ratio > 0.75:
                return text
        except Exception:
            continue

    # Try UTF-16LE only if raw bytes contain null bytes (typical for
    # PowerShell -EncodedCommand which encodes ASCII as UTF-16LE, producing
    # \x00 after each ASCII char).  Without this guard, plain ASCII decoded
    # bytes are mis-interpreted as CJK characters.
    if b"\x00" in raw and len(raw) >= 4 and len(raw) % 2 == 0:
        try:
            text = raw.decode("utf-16-le")
            if text and all(
                c.isprintable() or c in "\r\n\t" for c in text
            ):
                return text
        except Exception:
            pass

    return None


def _decode_nested(blob: str, depth: int = 0) -> list[dict[str, Any]]:
    """Recursively decode base64 up to MAX_NESTING layers."""
    results: list[dict[str, Any]] = []
    decoded = _try_decode(blob)
    if decoded is None:
        return results

    entry: dict[str, Any] = {
        "encoded": blob[:120] + ("..." if len(blob) > 120 else ""),
        "decoded": decoded,
        "layer": depth + 1,
    }
    results.append(entry)

    if depth + 1 < MAX_NESTING and _is_plausible_b64(decoded.strip()):
        nested = _decode_nested(decoded.strip(), depth + 1)
        results.extend(nested)

    return results


class Base64Decoder(BaseTransform):
    name = "base64_decoder"
    description = "Detect and decode base64-encoded strings (up to 8 nested layers)"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        # Quick heuristic: must contain a longish run of base64-alphabet chars
        return bool(
            _STANDALONE_B64.search(code)
            or any(pat.search(code) for _, pat in _WRAPPER_PATTERNS)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        decoded_items: list[dict[str, Any]] = []
        output = code

        # --- wrapped calls ---
        for wrapper_name, pat in _WRAPPER_PATTERNS:
            for m in pat.finditer(code):
                blob = m.group(1)
                layers = _decode_nested(blob)
                if layers:
                    for layer in layers:
                        layer["wrapper"] = wrapper_name
                        layer["match_start"] = m.start()
                        layer["match_end"] = m.end()
                    decoded_items.extend(layers)
                    deepest = layers[-1]["decoded"]
                    replacement = _render_decoded_literal(
                        deepest,
                        code,
                        m.start(),
                        m.end(),
                        language,
                    )
                    output = output.replace(m.group(0), replacement, 1)

        # --- standalone blobs ---
        already_decoded_positions: set[tuple[int, int]] = {
            (d["match_start"], d["match_end"])
            for d in decoded_items
            if "match_start" in d
        }

        for m in _STANDALONE_B64.finditer(code):
            span = (m.start(), m.end())
            # skip if this region was already decoded as part of a wrapper
            if any(
                s <= span[0] and e >= span[1]
                for s, e in already_decoded_positions
            ):
                continue
            blob = m.group(1)
            if not _is_plausible_b64(blob):
                continue
            layers = _decode_nested(blob)
            if layers:
                for layer in layers:
                    layer["wrapper"] = "standalone"
                    layer["match_start"] = span[0]
                    layer["match_end"] = span[1]
                decoded_items.extend(layers)
                deepest = layers[-1]["decoded"]
                replacement = _render_decoded_literal(
                    deepest,
                    code,
                    span[0],
                    span[1],
                    language,
                )
                output = output.replace(m.group(0), replacement, 1)

        if not decoded_items:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No decodable base64 strings found.",
            )

        max_layer = max(d["layer"] for d in decoded_items)
        confidence = min(0.95, 0.7 + 0.05 * len(decoded_items))

        state.setdefault("decoded_base64", []).extend(decoded_items)

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=(
                f"Decoded {len(decoded_items)} base64 item(s), "
                f"max nesting depth {max_layer}."
            ),
            details={
                "decoded_count": len(decoded_items),
                "max_nesting": max_layer,
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
