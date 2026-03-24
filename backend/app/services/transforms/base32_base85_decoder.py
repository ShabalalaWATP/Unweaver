"""
Base32 and Base85 (Ascii85 / Z85) decoder.

Detects base32-encoded and base85-encoded strings in source code, decodes
them, and replaces inline where possible.  Handles both standard alphabets
and common variants.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Base32 patterns
# ---------------------------------------------------------------------------

# Standard Base32: A-Z, 2-7, = padding.  Minimum 16 chars to avoid FPs.
_BASE32_RE = re.compile(r"\b([A-Z2-7]{16,}={0,6})\b")

# Hex Base32 variant (0-9, A-V)
_BASE32_HEX_RE = re.compile(r"\b([0-9A-V]{16,}={0,6})\b")

# Base32 inside function calls: base32_decode("..."), b32decode("...")
_BASE32_CALL_RE = re.compile(
    r"(?:base32[_.]?decode|b32decode)\s*\(\s*['\"]([A-Z2-7=]{8,})['\"]",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Base85 / Ascii85 patterns
# ---------------------------------------------------------------------------

# Ascii85 (Adobe variant): <~ ... ~>
_ASCII85_RE = re.compile(r"<~([!-u\sz]{4,})~>")

# Python base85: b85decode("...") or a85decode("...")
_B85_CALL_RE = re.compile(
    r"(?:b85decode|a85decode|base85[_.]?decode)\s*\(\s*['\"]([!-~]{8,})['\"]",
    re.IGNORECASE,
)

# Raw base85 blobs (printable ASCII excluding quotes, 20+ chars, heuristic)
_B85_BLOB_RE = re.compile(r"['\"]([!-~]{20,})['\"]")


def _is_printable(text: str, threshold: float = 0.70) -> bool:
    """Check if decoded text is mostly printable."""
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return (printable / len(text)) >= threshold


def _try_base32(blob: str) -> str | None:
    """Attempt standard and hex base32 decoding."""
    for variant in ("standard", "hex"):
        try:
            padded = blob + "=" * (-len(blob) % 8)
            if variant == "hex":
                raw = base64.b32hexdecode(padded.encode())
            else:
                raw = base64.b32decode(padded.encode(), casefold=True)
            for enc in ("utf-8", "latin-1"):
                try:
                    text = raw.decode(enc)
                    if _is_printable(text):
                        return text
                except UnicodeDecodeError:
                    continue
        except Exception:
            continue
    return None


def _try_base85(blob: str) -> str | None:
    """Attempt base85 / ascii85 decoding."""
    for decoder in (base64.b85decode, base64.a85decode):
        try:
            raw = decoder(blob.encode())
            for enc in ("utf-8", "latin-1"):
                try:
                    text = raw.decode(enc)
                    if _is_printable(text):
                        return text
                except UnicodeDecodeError:
                    continue
        except Exception:
            continue
    return None


class Base32Base85Decoder(BaseTransform):
    """Detect and decode Base32 and Base85/Ascii85 encoded strings."""

    name = "base32_base85_decoder"
    description = "Decode Base32, Base85, and Ascii85 encoded strings."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        if not code or len(code) < 16:
            return False
        return bool(
            _BASE32_RE.search(code)
            or _BASE32_CALL_RE.search(code)
            or _ASCII85_RE.search(code)
            or _B85_CALL_RE.search(code)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        decoded_items: List[Dict[str, Any]] = []
        new_code = code

        # Base32 function calls
        for m in _BASE32_CALL_RE.finditer(new_code):
            blob = m.group(1)
            text = _try_base32(blob)
            if text:
                decoded_items.append({
                    "format": "base32_call",
                    "encoded": blob[:80],
                    "decoded": text[:500],
                })
                new_code = new_code.replace(m.group(0), f'"{text[:200]}"')

        # Ascii85 delimited blocks
        for m in _ASCII85_RE.finditer(new_code):
            blob = m.group(1)
            text = _try_base85(blob)
            if text:
                decoded_items.append({
                    "format": "ascii85",
                    "encoded": blob[:80],
                    "decoded": text[:500],
                })
                new_code = new_code.replace(m.group(0), f'"{text[:200]}"')

        # Base85 function calls
        for m in _B85_CALL_RE.finditer(new_code):
            blob = m.group(1)
            text = _try_base85(blob)
            if text:
                decoded_items.append({
                    "format": "base85_call",
                    "encoded": blob[:80],
                    "decoded": text[:500],
                })
                new_code = new_code.replace(m.group(0), f'"{text[:200]}"')

        # Standalone Base32 blobs
        for m in _BASE32_RE.finditer(new_code):
            blob = m.group(1)
            if any(d["encoded"] == blob[:80] for d in decoded_items):
                continue
            text = _try_base32(blob)
            if text and len(text) >= 4:
                decoded_items.append({
                    "format": "base32",
                    "encoded": blob[:80],
                    "decoded": text[:500],
                })
                new_code = new_code.replace(blob, text[:200])

        success = len(decoded_items) > 0
        confidence = min(len(decoded_items) * 0.15, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Decoded {len(decoded_items)} Base32/Base85 string(s)."
                if success else "No Base32/Base85 encoding found."
            ),
            details={
                "decoded_count": len(decoded_items),
                "items": decoded_items[:20],
                "decoded_strings": [
                    {"encoded": d["encoded"], "decoded": d["decoded"]}
                    for d in decoded_items[:10]
                ],
            },
        )
