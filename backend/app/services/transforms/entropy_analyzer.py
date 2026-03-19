"""
EntropyAnalyzer transform -- measures Shannon entropy across code to identify
encrypted, packed, or heavily-obfuscated sections.  High-entropy regions are
flagged as likely base64 blobs, hex streams, or encrypted payloads.

This is a non-destructive analysis transform: the source code is returned
unchanged, and all findings are reported in the ``TransformResult.details``
dictionary.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

_SNIPPET_MAX_LEN = 80  # max characters shown in a region snippet


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy in bits (0.0 -- 8.0) for *data*."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Detectors for specific high-entropy techniques
# ---------------------------------------------------------------------------

# Matches long runs of base64 characters (at least 40 chars, optional padding)
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Matches continuous hex streams (at least 32 hex chars, no spaces)
_HEX_STREAM = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")

# Matches hex with consistent delimiters  (e.g. \x41\x42 or 0x41,0x42)
_ESCAPED_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")

# Long stretches of printable ASCII with very uniform distribution -- often
# encrypted ciphertext encoded as printable characters.
_DENSE_PRINTABLE = re.compile(r"[\x21-\x7e]{80,}")


def _detect_techniques(region_text: str) -> list[str]:
    """Return technique tags that match the given *region_text*."""
    techniques: list[str] = []
    if _BASE64_BLOB.search(region_text):
        techniques.append("base64_blob")
    if _HEX_STREAM.search(region_text):
        techniques.append("hex_stream")
    if _ESCAPED_HEX.search(region_text):
        techniques.append("escaped_hex")
    if _DENSE_PRINTABLE.search(region_text):
        entropy = _shannon_entropy(region_text)
        if entropy > 5.8:
            techniques.append("suspected_encryption")
    return techniques


# ---------------------------------------------------------------------------
# Entropy profile classification
# ---------------------------------------------------------------------------

def _classify_profile(avg_entropy: float) -> str:
    """Map average window entropy to a human-readable profile label."""
    if avg_entropy < 4.0:
        return "clean"
    if avg_entropy < 5.0:
        return "partially_obfuscated"
    if avg_entropy < 6.0:
        return "heavily_obfuscated"
    return "encrypted"


def _profile_to_confidence(profile: str) -> float:
    """Confidence that the code is *clean* -- inverse of obfuscation level.

    High overall entropy means LOW confidence that the code is readable /
    unobfuscated.
    """
    return {
        "clean": 0.95,
        "partially_obfuscated": 0.65,
        "heavily_obfuscated": 0.35,
        "encrypted": 0.10,
    }.get(profile, 0.5)


# ---------------------------------------------------------------------------
# Transform
# ---------------------------------------------------------------------------

class EntropyAnalyzer(BaseTransform):
    """Measure Shannon entropy to identify encrypted/packed sections."""

    name = "EntropyAnalyzer"
    description = "Measure Shannon entropy to identify encrypted/packed sections."

    # Sliding-window parameters
    _window_size: int = 256
    _step_size: int = 128
    _high_threshold: float = 5.5
    _low_threshold: float = 3.0

    # ------------------------------------------------------------------
    # BaseTransform interface
    # ------------------------------------------------------------------

    def can_apply(self, code: str, language: str, state: dict) -> bool:  # noqa: D401
        return bool(code)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        overall_entropy = _shannon_entropy(code)

        # ---- sliding-window analysis ----
        window_entropies: list[tuple[int, int, float]] = []
        code_len = len(code)

        if code_len <= self._window_size:
            # Code is shorter than one window -- treat the whole thing as one.
            window_entropies.append((0, code_len, overall_entropy))
        else:
            offset = 0
            while offset + self._window_size <= code_len:
                window_text = code[offset : offset + self._window_size]
                ent = _shannon_entropy(window_text)
                window_entropies.append((offset, offset + self._window_size, ent))
                offset += self._step_size
            # Handle trailing partial window if there's remaining text
            if offset < code_len and code_len - offset >= self._step_size:
                window_text = code[offset:code_len]
                ent = _shannon_entropy(window_text)
                window_entropies.append((offset, code_len, ent))

        # ---- aggregate stats ----
        entropies = [e for _, _, e in window_entropies]
        max_entropy = max(entropies) if entropies else 0.0
        min_entropy = min(entropies) if entropies else 0.0
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

        # ---- identify high / low regions ----
        high_entropy_regions: list[dict[str, Any]] = []
        low_entropy_regions: list[dict[str, Any]] = []

        for start, end, ent in window_entropies:
            snippet = code[start:end]
            truncated = (
                snippet[:_SNIPPET_MAX_LEN] + "..."
                if len(snippet) > _SNIPPET_MAX_LEN
                else snippet
            )
            # Replace newlines in snippet for clean single-line display
            truncated = truncated.replace("\n", "\\n").replace("\r", "")

            if ent > self._high_threshold:
                high_entropy_regions.append(
                    {
                        "start": start,
                        "end": end,
                        "entropy": round(ent, 4),
                        "snippet": truncated,
                    }
                )
            elif ent < self._low_threshold:
                low_entropy_regions.append(
                    {
                        "start": start,
                        "end": end,
                        "entropy": round(ent, 4),
                        "snippet": truncated,
                    }
                )

        # ---- detect specific obfuscation techniques ----
        all_techniques: list[str] = []
        for region in high_entropy_regions:
            region_text = code[region["start"] : region["end"]]
            techniques = _detect_techniques(region_text)
            if techniques:
                region["techniques"] = techniques
                all_techniques.extend(techniques)

        # Overall flagging based on full code
        full_techniques = _detect_techniques(code)
        for t in full_techniques:
            if t not in all_techniques:
                all_techniques.append(t)

        # Add a general flag if many high-entropy windows exist
        if len(high_entropy_regions) > len(window_entropies) * 0.5 and len(window_entropies) > 1:
            if "high_entropy_blob" not in all_techniques:
                all_techniques.append("high_entropy_blob")

        # ---- classify profile ----
        profile = _classify_profile(avg_entropy)
        confidence = _profile_to_confidence(profile)

        # ---- store in shared state for downstream transforms ----
        state["entropy_profile"] = profile
        state["overall_entropy"] = round(overall_entropy, 4)

        # ---- build description ----
        desc_parts = [
            f"Overall entropy: {overall_entropy:.2f} bits",
            f"profile: {profile}",
        ]
        if high_entropy_regions:
            desc_parts.append(
                f"{len(high_entropy_regions)} high-entropy region(s) detected"
            )
        if all_techniques:
            desc_parts.append(
                f"techniques: {', '.join(sorted(set(all_techniques)))}"
            )

        description = ". ".join(desc_parts) + "."

        details: dict[str, Any] = {
            "overall_entropy": round(overall_entropy, 4),
            "max_entropy": round(max_entropy, 4),
            "min_entropy": round(min_entropy, 4),
            "avg_entropy": round(avg_entropy, 4),
            "high_entropy_regions": high_entropy_regions,
            "low_entropy_regions": low_entropy_regions,
            "entropy_profile": profile,
            "detected_techniques": sorted(set(all_techniques)),
            "window_count": len(window_entropies),
        }

        return TransformResult(
            success=True,
            output=code,  # non-destructive analysis
            confidence=confidence,
            description=description,
            details=details,
        )
