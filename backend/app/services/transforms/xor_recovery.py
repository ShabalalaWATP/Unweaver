"""
XorRecovery transform -- detects XOR operations in code, performs single-byte
XOR brute-force on suspicious byte strings, and scores candidates by
printable-ASCII ratio.
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Patterns that indicate XOR usage in source code
# ---------------------------------------------------------------------------

_XOR_INDICATORS: list[re.Pattern] = [
    # Generic XOR operator usage  (a ^ b, a ^= b)
    re.compile(r"[\w\])\s]\s*\^=?\s*(?:0x[0-9a-fA-F]+|\d+)"),
    # JavaScript: charCodeAt ... ^ ...
    re.compile(r"\.charCodeAt\s*\(\s*\w*\s*\)\s*\^"),
    # Python: ord(...) ^ ...
    re.compile(r"ord\s*\(\s*.\s*\)\s*\^"),
    # PowerShell: -bxor
    re.compile(r"-bxor\b", re.IGNORECASE),
    # C#: explicit XOR in a loop pattern
    re.compile(r"\[\s*\w+\s*\]\s*\^=?\s*"),
    # Common XOR decrypt function names
    re.compile(r"(?:xor|decrypt|deobfuscate|decode)\s*\(", re.IGNORECASE),
]

# Patterns to extract the "ciphertext" blobs that might be XOR-encrypted.
# We look for byte arrays, hex strings, and suspicious-looking strings that
# appear near XOR operations.

# \x41\x42... strings
_HEX_ESCAPE_STR = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
# [0x41, 0x42, ...] byte arrays
_BYTE_ARRAY = re.compile(
    r"\[\s*(?:0x[0-9a-fA-F]{1,2}\s*,\s*){3,}0x[0-9a-fA-F]{1,2}\s*\]"
)
# Strings assigned near XOR ops (grab anything in quotes near ^)
_NEAR_XOR_STRING = re.compile(
    r"""['"]((?:[^'"\n\\]|\\.){{8,}})['"]""",
)


def _extract_bytes_from_hex_escape(text: str) -> bytes:
    """Extract bytes from \\x41\\x42... format."""
    pairs = re.findall(r"\\x([0-9a-fA-F]{2})", text)
    return bytes(int(h, 16) for h in pairs)


def _extract_bytes_from_array(text: str) -> bytes:
    """Extract bytes from [0x41, 0x42, ...] format."""
    values = re.findall(r"0x([0-9a-fA-F]{1,2})", text)
    return bytes(int(v, 16) for v in values)


def _extract_bytes_from_string(text: str) -> bytes:
    """Convert a regular string to bytes for XOR brute-forcing."""
    try:
        return text.encode("latin-1")
    except Exception:
        return text.encode("utf-8", errors="ignore")


def _printable_score(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (0x20-0x7E) or common
    whitespace."""
    if not data:
        return 0.0
    printable = sum(
        1 for b in data
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return printable / len(data)


def _xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR every byte of *data* with *key*."""
    return bytes(b ^ key for b in data)


def _brute_force_xor(
    data: bytes, min_score: float = 0.80
) -> list[dict[str, Any]]:
    """Try all 256 single-byte keys and return candidates above *min_score*."""
    candidates: list[dict[str, Any]] = []
    for key in range(1, 256):  # skip 0 (identity)
        result = _xor_single_byte(data, key)
        score = _printable_score(result)
        if score >= min_score:
            try:
                text = result.decode("utf-8", errors="replace")
            except Exception:
                text = result.decode("latin-1")
            candidates.append({
                "key": key,
                "key_hex": f"0x{key:02x}",
                "decoded": text,
                "score": round(score, 4),
            })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates


class XorRecovery(BaseTransform):
    name = "xor_recovery"
    description = (
        "Detect XOR operations and brute-force single-byte XOR on "
        "suspicious strings"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return any(pat.search(code) for pat in _XOR_INDICATORS)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        # Collect byte blobs to try brute-forcing
        blobs: list[tuple[str, bytes, int, int]] = []  # (label, data, start, end)

        for m in _HEX_ESCAPE_STR.finditer(code):
            data = _extract_bytes_from_hex_escape(m.group(0))
            if len(data) >= 4:
                blobs.append(("hex_escape", data, m.start(), m.end()))

        for m in _BYTE_ARRAY.finditer(code):
            data = _extract_bytes_from_array(m.group(0))
            if len(data) >= 4:
                blobs.append(("byte_array", data, m.start(), m.end()))

        # Also look for strings stored in state by the string extractor
        extracted_strings = state.get("extracted_strings", [])
        for s in extracted_strings:
            val = s.value if hasattr(s, "value") else s.get("value", "")
            if len(val) >= 8:
                data = _extract_bytes_from_string(val)
                # Only try if the string has low printable ratio (likely encoded)
                if _printable_score(data) < 0.60:
                    start = s.start if hasattr(s, "start") else s.get("start", 0)
                    end = s.end if hasattr(s, "end") else s.get("end", 0)
                    blobs.append(("string_literal", data, start, end))

        all_results: list[dict[str, Any]] = []
        output = code

        for label, data, start, end in blobs:
            candidates = _brute_force_xor(data)
            if candidates:
                best = candidates[0]
                entry = {
                    "source": label,
                    "position": {"start": start, "end": end},
                    "data_length": len(data),
                    "best_key": best["key_hex"],
                    "best_score": best["score"],
                    "best_decoded": best["decoded"],
                    "top_candidates": candidates[:5],
                }
                all_results.append(entry)

        if not all_results:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.1,
                description=(
                    "XOR operations detected but no decodable blobs found."
                ),
                details={"xor_indicators_found": True},
            )

        # Build annotated output
        for r in all_results:
            best_decoded = r["best_decoded"]
            best_key = r["best_key"]
            annotation = (
                f"/* XOR_DECODED(key={best_key}): {best_decoded!r} */"
            )
            # We append annotations rather than inline-replace to avoid
            # breaking code structure.
            output += f"\n// {r['source']} at {r['position']}: {annotation}"

        avg_score = sum(r["best_score"] for r in all_results) / len(all_results)
        confidence = min(0.95, avg_score)

        state.setdefault("xor_results", []).extend(all_results)

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=(
                f"XOR brute-forced {len(all_results)} blob(s); "
                f"best score {all_results[0]['best_score']:.2f}."
            ),
            details={
                "blob_count": len(all_results),
                "results": all_results,
            },
        )
