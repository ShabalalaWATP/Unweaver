"""
ReadabilityScorer -- scores code readability on a 0-100 scale, using
factors like identifier meaningfulness, comment density, nesting depth,
line length, string-literal ratio, and obfuscation markers.

Can compare before/after scores to measure deobfuscation effectiveness.
"""

from __future__ import annotations

import re
import math
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Scoring factors (each produces a 0-100 sub-score)
# ---------------------------------------------------------------------------


def _score_identifier_meaningfulness(code: str) -> tuple[float, dict[str, Any]]:
    """Score how meaningful the identifiers in the code are.

    Obfuscated names (_0xHEX, single chars, Il-confusion) drag the score
    down; natural English-word identifiers push it up.
    """
    # Extract identifiers (simplified)
    idents = re.findall(r"\b([a-zA-Z_]\w{0,60})\b", code)
    if not idents:
        return 50.0, {"total_identifiers": 0}

    # Deduplicate
    unique = set(idents)

    # Count bad names
    bad_patterns = [
        re.compile(r"^_0x[0-9a-fA-F]{4,}$"),
        re.compile(r"^[a-zA-Z]$"),             # single char (excluding loop vars)
        re.compile(r"^[Il1]{4,}$"),             # Il confusion
        re.compile(r"^_{4,}\w*$"),              # underscore gibberish
        re.compile(r"^[bcdfghjklmnpqrstvwxyz]{4,}$"),  # consonant soup
    ]
    # Common legitimate single-char: i, j, k, x, y, n, e, _, etc.
    legit_single = {"i", "j", "k", "n", "x", "y", "e", "f", "_", "m", "s", "t", "p"}
    # Common keywords to exclude
    keywords = {
        "var", "let", "const", "function", "return", "if", "else", "for",
        "while", "class", "def", "import", "from", "self", "this", "new",
        "true", "false", "null", "None", "True", "False", "undefined",
        "int", "str", "string", "bool", "float", "void", "public",
        "private", "static", "async", "await",
    }

    bad_count = 0
    for ident in unique:
        if ident in keywords or ident in legit_single:
            continue
        for pat in bad_patterns:
            if pat.match(ident):
                bad_count += 1
                break

    meaningful_ratio = 1.0 - (bad_count / max(len(unique), 1))
    score = max(0, min(100, meaningful_ratio * 100))

    return score, {
        "total_identifiers": len(unique),
        "bad_identifiers": bad_count,
        "meaningful_ratio": round(meaningful_ratio, 3),
    }


def _score_comment_density(code: str) -> tuple[float, dict[str, Any]]:
    """Score comment density. Some comments = good, none or excessive = meh."""
    lines = code.split("\n")
    total_lines = len(lines)
    if total_lines == 0:
        return 50.0, {"total_lines": 0, "comment_lines": 0}

    comment_lines = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            comment_lines += 1
        elif stripped.startswith("/*") or stripped.startswith("*"):
            comment_lines += 1

    ratio = comment_lines / total_lines

    # Ideal ratio: ~10-30%
    if ratio < 0.01:
        score = 20.0  # no comments at all
    elif ratio < 0.05:
        score = 50.0
    elif ratio <= 0.30:
        score = 90.0  # good
    elif ratio <= 0.50:
        score = 70.0  # a bit much
    else:
        score = 40.0  # mostly comments

    return score, {
        "total_lines": total_lines,
        "comment_lines": comment_lines,
        "ratio": round(ratio, 3),
    }


def _score_nesting_depth(code: str) -> tuple[float, dict[str, Any]]:
    """Score based on maximum nesting depth. Deep nesting = harder to read."""
    max_depth = 0
    current = 0
    depths: list[int] = []

    for char in code:
        if char in ("{", "(", "["):
            current += 1
            if current > max_depth:
                max_depth = current
        elif char in ("}", ")", "]"):
            current = max(0, current - 1)
        elif char == "\n":
            depths.append(current)

    # Also consider indentation depth for Python
    indent_depths: list[int] = []
    for line in code.split("\n"):
        if line.strip():
            indent = len(line) - len(line.lstrip())
            indent_depths.append(indent)

    max_indent = max(indent_depths) if indent_depths else 0
    avg_indent = sum(indent_depths) / max(len(indent_depths), 1)

    # Score: low depth = good (100), very deep = bad (0)
    if max_depth <= 3:
        brace_score = 100.0
    elif max_depth <= 6:
        brace_score = 80.0
    elif max_depth <= 10:
        brace_score = 50.0
    else:
        brace_score = max(0, 30.0 - (max_depth - 10) * 3)

    # Indent-based penalty
    indent_score = max(0, 100 - avg_indent * 3)

    score = (brace_score + indent_score) / 2

    return score, {
        "max_brace_depth": max_depth,
        "max_indent": max_indent,
        "avg_indent": round(avg_indent, 1),
    }


def _score_line_length(code: str) -> tuple[float, dict[str, Any]]:
    """Score based on line lengths. Very long lines indicate minified or
    obfuscated code."""
    lines = code.split("\n")
    if not lines:
        return 50.0, {}

    lengths = [len(line) for line in lines]
    max_len = max(lengths) if lengths else 0
    avg_len = sum(lengths) / max(len(lengths), 1)
    long_lines = sum(1 for l in lengths if l > 120)

    # Minified code has very few lines but they're extremely long
    if max_len > 1000:
        score = 10.0
    elif max_len > 500:
        score = 30.0
    elif avg_len > 120:
        score = 40.0
    elif avg_len > 80:
        score = 70.0
    else:
        score = 95.0

    # Penalty for having many long lines
    long_ratio = long_lines / max(len(lines), 1)
    score -= long_ratio * 30

    return max(0, min(100, score)), {
        "max_length": max_len,
        "avg_length": round(avg_len, 1),
        "long_lines": long_lines,
        "total_lines": len(lines),
    }


def _score_string_literal_ratio(code: str) -> tuple[float, dict[str, Any]]:
    """Score based on string literal density. Heavily string-based code is
    often obfuscated (e.g., string arrays, concatenated chars)."""
    string_chars = 0
    in_string = False
    quote_char = ""
    escape = False

    for ch in code:
        if escape:
            if in_string:
                string_chars += 1
            escape = False
            continue
        if ch == "\\":
            escape = True
            if in_string:
                string_chars += 1
            continue
        if not in_string:
            if ch in ('"', "'", "`"):
                in_string = True
                quote_char = ch
                string_chars += 1
        else:
            string_chars += 1
            if ch == quote_char:
                in_string = False

    total = max(len(code), 1)
    ratio = string_chars / total

    # Normal code: ~10-30% strings. Obfuscated can be 60%+
    if ratio < 0.10:
        score = 90.0
    elif ratio < 0.30:
        score = 85.0
    elif ratio < 0.50:
        score = 60.0
    elif ratio < 0.70:
        score = 30.0
    else:
        score = 10.0

    return score, {
        "string_chars": string_chars,
        "total_chars": total,
        "ratio": round(ratio, 3),
    }


def _score_obfuscation_markers(code: str) -> tuple[float, dict[str, Any]]:
    """Penalize for the presence of known obfuscation markers."""
    markers: list[tuple[str, re.Pattern, float]] = [
        ("eval_exec", re.compile(r"\beval\s*\(|\bexec\s*\("), 15),
        ("hex_vars", re.compile(r"\b_0x[0-9a-fA-F]{4,}\b"), 20),
        ("base64_blob", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), 10),
        ("charcode_build", re.compile(r"(?:fromCharCode|chr\(|\\x[0-9a-f]{2}){3,}", re.IGNORECASE), 15),
        ("encoded_command", re.compile(r"-(?:EncodedCommand|enc)\b", re.IGNORECASE), 20),
        ("jsfuck_like", re.compile(r"[\[\]()!+]{20,}"), 25),
        ("string_array_obf", re.compile(r"var\s+_0x\w+\s*=\s*\["), 15),
    ]

    total_penalty = 0.0
    found_markers: list[str] = []

    for name, pat, penalty in markers:
        hits = len(pat.findall(code))
        if hits > 0:
            # Diminishing penalty for repeated hits
            actual_penalty = penalty * min(hits, 3)
            total_penalty += actual_penalty
            found_markers.append(f"{name} (x{hits})")

    score = max(0, 100 - total_penalty)

    return score, {
        "markers_found": found_markers,
        "total_penalty": round(total_penalty, 1),
    }


# Factor weights (must sum to 1.0)
_FACTOR_WEIGHTS = {
    "identifier_meaningfulness": 0.25,
    "comment_density": 0.10,
    "nesting_depth": 0.10,
    "line_length": 0.15,
    "string_literal_ratio": 0.15,
    "obfuscation_markers": 0.25,
}

_FACTOR_FUNCS = {
    "identifier_meaningfulness": _score_identifier_meaningfulness,
    "comment_density": _score_comment_density,
    "nesting_depth": _score_nesting_depth,
    "line_length": _score_line_length,
    "string_literal_ratio": _score_string_literal_ratio,
    "obfuscation_markers": _score_obfuscation_markers,
}


def compute_readability_score(code: str) -> tuple[float, dict[str, Any]]:
    """Compute a composite readability score (0-100) for the given code.

    Returns (score, factor_details).
    """
    factor_scores: dict[str, float] = {}
    factor_details: dict[str, Any] = {}

    for name, func in _FACTOR_FUNCS.items():
        score, details = func(code)
        factor_scores[name] = score
        factor_details[name] = {"score": round(score, 1), **details}

    weighted_sum = sum(
        factor_scores[name] * _FACTOR_WEIGHTS[name]
        for name in _FACTOR_WEIGHTS
    )
    overall = max(0, min(100, round(weighted_sum, 1)))

    return overall, factor_details


class ReadabilityScorer(BaseTransform):
    name = "readability_scorer"
    description = "Score code readability 0-100 with detailed factor breakdown"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(code and len(code.strip()) > 10)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        score, factor_details = compute_readability_score(code)

        # Compare with a previous score if available
        prev_score = state.get("readability_score")
        improvement = None
        if prev_score is not None:
            improvement = score - prev_score

        state["readability_score"] = score

        # Classify
        if score >= 80:
            classification = "good"
        elif score >= 60:
            classification = "moderate"
        elif score >= 40:
            classification = "poor"
        elif score >= 20:
            classification = "heavily obfuscated"
        else:
            classification = "extremely obfuscated"

        desc_parts = [
            f"Readability score: {score}/100 ({classification})"
        ]
        if improvement is not None:
            direction = "improved" if improvement > 0 else "decreased"
            desc_parts.append(
                f"{direction} by {abs(improvement):.1f} points"
            )

        return TransformResult(
            success=True,
            output=code,
            confidence=0.90,
            description=". ".join(desc_parts) + ".",
            details={
                "score": score,
                "classification": classification,
                "previous_score": prev_score,
                "improvement": improvement,
                "factors": factor_details,
                "weights": _FACTOR_WEIGHTS,
            },
        )
