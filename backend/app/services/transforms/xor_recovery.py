"""
XorRecovery transform -- detects XOR operations in code, performs single-byte
and multi-byte XOR brute-force on suspicious byte strings, uses crib-dragging
known-plaintext attacks, and scores candidates by printable-ASCII ratio.
"""

from __future__ import annotations

import re
from math import gcd
from functools import reduce
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

# Pattern to match a full hex-escape string literal including quotes
_HEX_ESCAPE_LITERAL = re.compile(
    r'(["\'])(?:\\x[0-9a-fA-F]{2})+\1'
)
# Pattern to match a full byte-array literal including brackets
_BYTE_ARRAY_LITERAL = re.compile(
    r"\[\s*(?:0x[0-9a-fA-F]{1,2}\s*,\s*)*0x[0-9a-fA-F]{1,2}\s*\]"
)

# ---------------------------------------------------------------------------
# Default cribs for known-plaintext (crib-dragging) attacks
# ---------------------------------------------------------------------------

_DEFAULT_CRIBS: list[bytes] = [
    b"http://", b"https://", b"www.",
    b"function ", b"function(", b"var ", b"let ", b"const ",
    b"return ", b"return;", b"console.log",
    b".exe", b".dll", b".bat",
    b"import ", b"from ", b"def ", b"class ",
    b"<html", b"<script", b"</script>",
    b"window.", b"document.", b"eval(", b"this.", b"new ",
    b"null", b"true", b"false", b"undefined",
]


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
    """Score bytes for human-readability, supporting both ASCII and UTF-8.

    First tries to decode as UTF-8. If successful and the result contains
    printable Unicode characters (Latin, CJK, Cyrillic, Arabic, etc.),
    scores based on Unicode category. Falls back to ASCII-only scoring.
    """
    if not data:
        return 0.0

    # Try UTF-8 first for non-ASCII text (Chinese, Arabic, Cyrillic, etc.)
    try:
        text = data.decode("utf-8")
        import unicodedata
        printable = sum(
            1 for c in text
            if unicodedata.category(c)[0] in ("L", "N", "P", "S", "Z")
            or c in "\n\r\t"
        )
        utf8_score = printable / max(len(text), 1)
        if utf8_score > 0.5 and len(text) > 0:
            return utf8_score
    except (UnicodeDecodeError, ValueError):
        pass

    # Fallback: ASCII scoring
    printable = sum(
        1 for b in data
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return printable / len(data)


def _xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR every byte of *data* with *key*."""
    return bytes(b ^ key for b in data)


def _xor_multi_byte(data: bytes, key: bytes) -> bytes:
    """XOR *data* with a repeating multi-byte *key*."""
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


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
                "key_bytes": bytes([key]),
                "decoded": text,
                "score": round(score, 4),
                "method": "single_byte_bruteforce",
            })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates


# ---------------------------------------------------------------------------
# Kasiski-like analysis for guessing multi-byte key lengths
# ---------------------------------------------------------------------------

def _kasiski_key_lengths(data: bytes, max_key_len: int = 16) -> list[int]:
    """Find likely key lengths using Kasiski examination.

    Looks for repeated 3-byte sequences in *data* and computes the GCD of
    their spacing distances.  Returns candidate key lengths sorted by
    frequency (most likely first), limited to *max_key_len*.
    """
    if len(data) < 6:
        return list(range(2, min(max_key_len + 1, len(data))))

    trigram_positions: dict[bytes, list[int]] = {}
    for i in range(len(data) - 2):
        trigram = data[i:i + 3]
        trigram_positions.setdefault(trigram, []).append(i)

    distances: list[int] = []
    for _trigram, positions in trigram_positions.items():
        if len(positions) < 2:
            continue
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                d = positions[j] - positions[i]
                if d > 0:
                    distances.append(d)

    if not distances:
        return list(range(2, max_key_len + 1))

    # Count how often each small factor divides the distances
    factor_counts: dict[int, int] = {}
    for d in distances:
        for k in range(2, max_key_len + 1):
            if d % k == 0:
                factor_counts[k] = factor_counts.get(k, 0) + 1

    # Sort by count descending
    ranked = sorted(factor_counts.items(), key=lambda x: x[1], reverse=True)
    result = [k for k, _count in ranked]

    # Ensure all key lengths from 2..max_key_len appear (append any missing)
    seen = set(result)
    for k in range(2, max_key_len + 1):
        if k not in seen:
            result.append(k)

    return result


# ---------------------------------------------------------------------------
# Multi-byte XOR brute force
# ---------------------------------------------------------------------------

def _brute_force_multi_byte_xor(
    data: bytes,
    min_score: float = 0.80,
    max_key_len: int = 16,
) -> list[dict[str, Any]]:
    """Determine each byte of a multi-byte XOR key independently.

    For a given key length *k*, byte *i* of the key is chosen to maximise the
    printable-ASCII score of every *k*-th byte starting at offset *i*.
    Kasiski analysis is used to prioritise likely key lengths.
    """
    if len(data) < 4:
        return []

    candidate_lengths = _kasiski_key_lengths(data, max_key_len)
    candidates: list[dict[str, Any]] = []

    for key_len in candidate_lengths:
        if key_len >= len(data):
            continue

        key_bytes = bytearray(key_len)
        per_byte_scores: list[float] = []

        for i in range(key_len):
            # Extract every key_len-th byte starting at position i
            stripe = bytes(data[j] for j in range(i, len(data), key_len))
            best_k = 0
            best_score = -1.0
            for k in range(1, 256):
                decrypted_stripe = _xor_single_byte(stripe, k)
                s = _printable_score(decrypted_stripe)
                if s > best_score:
                    best_score = s
                    best_k = k
            key_bytes[i] = best_k
            per_byte_scores.append(best_score)

        # Decrypt with the recovered key
        key = bytes(key_bytes)
        result = _xor_multi_byte(data, key)
        overall_score = _printable_score(result)

        if overall_score >= min_score:
            try:
                text = result.decode("utf-8", errors="replace")
            except Exception:
                text = result.decode("latin-1")
            candidates.append({
                "key": list(key_bytes),
                "key_hex": key.hex(),
                "key_bytes": key,
                "decoded": text,
                "score": round(overall_score, 4),
                "key_length": key_len,
                "method": "multi_byte_bruteforce",
            })

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates


# ---------------------------------------------------------------------------
# Known-plaintext (crib dragging) attack
# ---------------------------------------------------------------------------

def _crib_drag(
    data: bytes,
    cribs: list[bytes] | None = None,
) -> list[dict]:
    """Slide known-plaintext cribs across *data* to recover key fragments.

    At each position the crib is XOR-ed with the ciphertext to derive a
    candidate key fragment.  If the same fragment appears at multiple
    positions that share a common period, we infer the key.  Returns a list
    of results sorted by score.
    """
    if cribs is None:
        cribs = _DEFAULT_CRIBS

    if len(data) < 4:
        return []

    # Collect (key_fragment, period, crib) hits
    # key_fragment -> list of (position, crib)
    fragment_hits: dict[bytes, list[tuple[int, bytes]]] = {}

    for crib in cribs:
        if len(crib) > len(data):
            continue
        for pos in range(len(data) - len(crib) + 1):
            fragment = bytes(data[pos + i] ^ crib[i] for i in range(len(crib)))
            fragment_hits.setdefault(fragment, []).append((pos, crib))

    results: list[dict] = []

    for fragment, hits in fragment_hits.items():
        if len(hits) < 1:
            continue

        # Try to find a repeating period among hit positions
        positions = sorted(set(h[0] for h in hits))

        # For fragments that appear at only one position, try using the
        # fragment as a repeating key directly
        candidate_periods: list[int] = []
        if len(positions) >= 2:
            diffs = [positions[j] - positions[i]
                     for i in range(len(positions))
                     for j in range(i + 1, len(positions))
                     if positions[j] - positions[i] > 0]
            if diffs:
                common_period = reduce(gcd, diffs)
                if 1 <= common_period <= 64:
                    candidate_periods.append(common_period)

        # Also try the fragment length itself as the period
        candidate_periods.append(len(fragment))

        for period in candidate_periods:
            # Build the full key by tiling the fragment at the correct offset
            if period < len(fragment):
                # The fragment must be consistent with itself when tiled
                consistent = True
                for i in range(len(fragment)):
                    if fragment[i] != fragment[i % period]:
                        consistent = False
                        break
                if not consistent:
                    continue
                full_key = bytes(fragment[:period])
            else:
                # Period >= fragment length: we only know part of the key.
                # Place the fragment at offset = first_hit_pos % period
                full_key_arr = bytearray(period)
                offset = positions[0] % period
                for i in range(len(fragment)):
                    idx = (offset + i) % period
                    full_key_arr[idx] = fragment[i]
                # The bytes we didn't set are still 0 -- check if decryption
                # is good enough despite unknown bytes
                full_key = bytes(full_key_arr)

            decrypted = _xor_multi_byte(data, full_key)
            score = _printable_score(decrypted)

            if score >= 0.75:
                try:
                    text = decrypted.decode("utf-8", errors="replace")
                except Exception:
                    text = decrypted.decode("latin-1")

                crib_names = list(set(h[1] for h in hits))
                results.append({
                    "key": list(full_key),
                    "key_hex": full_key.hex(),
                    "key_bytes": full_key,
                    "decoded": text,
                    "score": round(score, 4),
                    "key_length": len(full_key),
                    "method": "crib_drag",
                    "cribs_matched": [c.decode("latin-1", errors="replace")
                                      for c in crib_names[:5]],
                    "hit_positions": positions[:10],
                })

    # Deduplicate by decoded text, keeping highest score
    seen_decoded: dict[str, dict] = {}
    for r in results:
        d = r["decoded"]
        if d not in seen_decoded or r["score"] > seen_decoded[d]["score"]:
            seen_decoded[d] = r
    results = list(seen_decoded.values())

    results.sort(key=lambda c: c["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Inline replacement helpers
# ---------------------------------------------------------------------------

def _make_string_literal(decoded: str) -> str:
    """Create an escaped string literal suitable for inline replacement."""
    # Use double quotes, escape internal quotes and backslashes
    escaped = decoded.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def _inline_replace(
    code: str,
    blobs: list[tuple[str, bytes, int, int]],
    results_map: dict[int, dict],
    min_replace_score: float = 0.85,
) -> str:
    """Replace XOR-encrypted blobs inline with their decoded values.

    Only replaces when the best candidate score exceeds *min_replace_score*.
    Works backwards through the string to preserve earlier offsets.
    """
    # Build a list of (start, end, replacement) sorted by start descending
    replacements: list[tuple[int, int, str]] = []

    for idx, (label, _data, start, end) in enumerate(blobs):
        if idx not in results_map:
            continue
        best = results_map[idx]
        if best["score"] < min_replace_score:
            continue

        decoded_literal = _make_string_literal(best["decoded"])

        if label == "hex_escape":
            # Find the full string literal surrounding this hex escape
            # Search backwards for opening quote and forwards for closing quote
            literal_start = start
            literal_end = end
            # Look for enclosing quotes
            if literal_start > 0 and code[literal_start - 1] in ('"', "'"):
                quote = code[literal_start - 1]
                # Find matching closing quote
                close = code.find(quote, end)
                if close != -1 and close == end:
                    literal_start -= 1
                    literal_end = close + 1
                    replacements.append((literal_start, literal_end, decoded_literal))
                    continue
            # Fallback: replace just the hex escapes, wrapping in quotes
            replacements.append((start, end, decoded_literal))

        elif label == "byte_array":
            replacements.append((start, end, decoded_literal))

        elif label == "string_literal":
            replacements.append((start, end, decoded_literal))

    # Sort by start position descending so replacements don't shift offsets
    replacements.sort(key=lambda r: r[0], reverse=True)

    output = code
    for rstart, rend, replacement in replacements:
        output = output[:rstart] + replacement + output[rend:]

    return output


# ---------------------------------------------------------------------------
# Rolling / rotating XOR recovery
# ---------------------------------------------------------------------------

def _rolling_xor_variants(data: bytes, min_score: float = 0.75) -> list[dict[str, Any]]:
    """Try common rolling XOR patterns where the key changes per byte.

    Patterns tested:
    1. key[i] = base_key ^ i  (position-dependent XOR)
    2. key[i] = base_key + i  (incrementing key)
    3. key[i] = base_key ^ (i & 0xFF)  (position XOR with wrap)
    4. key[i] = data[i-1] ^ base_key  (CBC-like chaining)
    """
    candidates: list[dict[str, Any]] = []

    for base_key in range(1, 256):
        # Pattern 1: key XOR position
        result1 = bytes(data[i] ^ ((base_key ^ i) & 0xFF) for i in range(len(data)))
        score1 = _printable_score(result1)
        if score1 >= min_score:
            try:
                text = result1.decode("utf-8", errors="replace")
            except Exception:
                text = result1.decode("latin-1")
            candidates.append({
                "key": base_key,
                "key_hex": f"0x{base_key:02x}",
                "key_bytes": bytes([base_key]),
                "decoded": text,
                "score": round(score1, 4),
                "method": "rolling_xor_position",
            })

        # Pattern 2: incrementing key
        result2 = bytes(data[i] ^ ((base_key + i) & 0xFF) for i in range(len(data)))
        score2 = _printable_score(result2)
        if score2 >= min_score:
            try:
                text = result2.decode("utf-8", errors="replace")
            except Exception:
                text = result2.decode("latin-1")
            candidates.append({
                "key": base_key,
                "key_hex": f"0x{base_key:02x}",
                "key_bytes": bytes([base_key]),
                "decoded": text,
                "score": round(score2, 4),
                "method": "rolling_xor_increment",
            })

    # Pattern 4: CBC-like chaining (key[i] = prev_ciphertext ^ base)
    for base_key in range(1, 256):
        result = bytearray(len(data))
        result[0] = data[0] ^ base_key
        for i in range(1, len(data)):
            result[i] = data[i] ^ ((data[i - 1] ^ base_key) & 0xFF)
        score = _printable_score(bytes(result))
        if score >= min_score:
            try:
                text = bytes(result).decode("utf-8", errors="replace")
            except Exception:
                text = bytes(result).decode("latin-1")
            candidates.append({
                "key": base_key,
                "key_hex": f"0x{base_key:02x}",
                "key_bytes": bytes([base_key]),
                "decoded": text,
                "score": round(score, 4),
                "method": "rolling_xor_cbc",
            })

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[:10]


class XorRecovery(BaseTransform):
    name = "xor_recovery"
    description = (
        "Detect XOR operations and recover plaintext using single-byte "
        "brute-force, multi-byte key recovery, rolling/rotating XOR, "
        "and known-plaintext crib-dragging attacks"
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
        # Map from blob index -> best result for that blob
        best_per_blob: dict[int, dict] = {}

        for idx, (label, data, start, end) in enumerate(blobs):
            blob_candidates: list[dict[str, Any]] = []

            # ---- Step 1: single-byte brute force (fast) ----
            single_candidates = _brute_force_xor(data)
            blob_candidates.extend(single_candidates)

            # ---- Step 2: multi-byte brute force (if single-byte weak) ----
            best_single_score = single_candidates[0]["score"] if single_candidates else 0.0
            if best_single_score < 0.90:
                multi_candidates = _brute_force_multi_byte_xor(data)
                blob_candidates.extend(multi_candidates)

            # ---- Step 2.5: rolling/rotating XOR (if static keys weak) ----
            best_so_far = max((c["score"] for c in blob_candidates), default=0.0)
            if best_so_far < 0.90:
                rolling_candidates = _rolling_xor_variants(data)
                blob_candidates.extend(rolling_candidates)

            # ---- Step 3: crib dragging ----
            crib_candidates = _crib_drag(data)
            blob_candidates.extend(crib_candidates)

            # ---- Step 4: pick the best result for this blob ----
            if blob_candidates:
                blob_candidates.sort(key=lambda c: c["score"], reverse=True)
                best = blob_candidates[0]

                # Remove non-serialisable key_bytes before storing in results
                best_clean = {k: v for k, v in best.items() if k != "key_bytes"}
                best_clean["source"] = label
                best_clean["position"] = {"start": start, "end": end}
                best_clean["data_length"] = len(data)
                best_clean["top_candidates"] = [
                    {k: v for k, v in c.items() if k != "key_bytes"}
                    for c in blob_candidates[:5]
                ]

                all_results.append(best_clean)
                best_per_blob[idx] = best

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

        # ---- Step 5: inline replacement for high-confidence results ----
        output = _inline_replace(code, blobs, best_per_blob, min_replace_score=0.85)

        # Also add annotations for results that were NOT replaced inline
        # (i.e. score below 0.85 but still above the detection threshold)
        for r in all_results:
            if r["score"] < 0.85:
                best_decoded = r.get("decoded", "")
                best_key = r.get("key_hex", "?")
                method = r.get("method", "unknown")
                annotation = (
                    f"/* XOR_DECODED({method}, key={best_key}): "
                    f"{best_decoded!r} */"
                )
                output += (
                    f"\n// {r['source']} at {r['position']}: {annotation}"
                )

        avg_score = sum(r["score"] for r in all_results) / len(all_results)
        confidence = min(0.95, avg_score)

        # Collect method summary
        methods_used = list(set(r.get("method", "unknown") for r in all_results))

        state.setdefault("xor_results", []).extend(all_results)

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=(
                f"XOR recovered {len(all_results)} blob(s) via "
                f"{', '.join(methods_used)}; "
                f"best score {all_results[0]['score']:.2f}."
            ),
            details={
                "blob_count": len(all_results),
                "methods_used": methods_used,
                "results": all_results,
            },
        )
