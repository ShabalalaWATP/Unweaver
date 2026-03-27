"""
Source preprocessing for anomaly cleanup and minified-code beautification.

This module is intentionally conservative:
  - only normalises anomalous whitespace / invisible characters outside
    strings and comments;
  - only beautifies when the source strongly resembles minified code;
  - keeps a pure-Python dependency profile for Ubuntu deployments.
"""

from __future__ import annotations

import ast
import json
import re
import tokenize
from io import StringIO
from typing import Any, Dict, List, Tuple

from .base import BaseTransform, TransformResult
from .binary_analysis import looks_like_binary_blob_text

try:  # pragma: no cover - exercised through transform behaviour
    import black
except ImportError:  # pragma: no cover - graceful fallback
    black = None

try:  # pragma: no cover - exercised through transform behaviour
    import jsbeautifier
except ImportError:  # pragma: no cover - graceful fallback
    jsbeautifier = None

_WORKSPACE_BUNDLE_HEADER = "UNWEAVER_WORKSPACE_BUNDLE v1"

_SPACE_EQUIVALENTS = {
    "\u00a0",
    "\u1680",
    "\u180e",
    "\u2000",
    "\u2001",
    "\u2002",
    "\u2003",
    "\u2004",
    "\u2005",
    "\u2006",
    "\u2007",
    "\u2008",
    "\u2009",
    "\u200a",
    "\u202f",
    "\u205f",
    "\u3000",
}
_NEWLINE_EQUIVALENTS = {"\u0085", "\u2028", "\u2029"}
_REMOVE_EQUIVALENTS = {
    "\u0000",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}
_PUNCTUATION_EQUIVALENTS = {
    "“": '"',
    "”": '"',
    "„": '"',
    "‟": '"',
    "‘": "'",
    "’": "'",
    "‚": "'",
    "‛": "'",
    "（": "(",
    "）": ")",
    "｛": "{",
    "｝": "}",
    "［": "[",
    "］": "]",
    "；": ";",
    "，": ",",
}
_CONTROL_EXCEPTIONS = {"\n", "\t"}
_JS_LIKE_LANGUAGES = {"javascript", "js", "typescript", "ts", "json"}
_PYTHON_LIKE_LANGUAGES = {"python", "py"}
_SEMICOLON_SPLIT_LANGUAGES = {"javascript", "js", "typescript", "ts", "python", "py", "powershell", "ps", "ps1"}


def _is_workspace_bundle(code: str) -> bool:
    return code.lstrip().startswith(_WORKSPACE_BUNDLE_HEADER)


def _is_hash_comment_start(code: str, index: int) -> bool:
    if index < 0 or index >= len(code) or code[index] != "#":
        return False
    if index == 0:
        return True
    prev = code[index - 1]
    return prev.isspace()


def _is_minified_javascript_hint(code: str) -> bool:
    return bool(
        re.search(
            r"\b(?:function|const|let|var|if|while|for|switch)\b.*?[{;].*?[)};]",
            code[:12000],
            re.DOTALL,
        )
    )


def normalize_source_anomalies(code: str) -> Tuple[str, Dict[str, int]]:
    """Normalise parse-hostile whitespace and invisible characters.

    The transformation is only applied outside strings and comments so we do
    not silently alter payload strings or analyst-visible indicators.
    """
    if looks_like_binary_blob_text(code):
        return code, {
            "spaces_normalized": 0,
            "newlines_normalized": 0,
            "characters_removed": 0,
            "punctuation_normalized": 0,
        }
    if not code:
        return code, {
            "spaces_normalized": 0,
            "newlines_normalized": 0,
            "characters_removed": 0,
            "punctuation_normalized": 0,
        }

    counts = {
        "spaces_normalized": 0,
        "newlines_normalized": 0,
        "characters_removed": 0,
        "punctuation_normalized": 0,
    }
    result: List[str] = []
    quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    escape = False
    i = 0

    while i < len(code):
        ch = code[i]
        nxt = code[i + 1] if i + 1 < len(code) else ""

        if ch == "\r":
            result.append("\n")
            if nxt == "\n":
                i += 2
            else:
                i += 1
            if not quote and not in_line_comment and not in_block_comment:
                counts["newlines_normalized"] += 1
            else:
                in_line_comment = False
            continue

        if in_line_comment:
            result.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            result.append(ch)
            if ch == "*" and nxt == "/":
                result.append(nxt)
                i += 2
                in_block_comment = False
            else:
                i += 1
            continue

        if quote is not None:
            result.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif quote == ch:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            result.append(ch)
            result.append(nxt)
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            result.append(ch)
            result.append(nxt)
            in_block_comment = True
            i += 2
            continue
        if ch == "#" and _is_hash_comment_start(code, i):
            result.append(ch)
            in_line_comment = True
            i += 1
            continue
        if ch in {'"', "'", "`"}:
            result.append(ch)
            quote = ch
            i += 1
            continue

        if ch in _SPACE_EQUIVALENTS:
            result.append(" ")
            counts["spaces_normalized"] += 1
            i += 1
            continue
        if ch in _NEWLINE_EQUIVALENTS:
            result.append("\n")
            counts["newlines_normalized"] += 1
            i += 1
            continue
        if ch in _REMOVE_EQUIVALENTS or (ord(ch) < 32 and ch not in _CONTROL_EXCEPTIONS):
            counts["characters_removed"] += 1
            i += 1
            continue
        if ch in _PUNCTUATION_EQUIVALENTS:
            result.append(_PUNCTUATION_EQUIVALENTS[ch])
            counts["punctuation_normalized"] += 1
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result), counts


def detect_minified_source(code: str, language: str) -> Dict[str, Any]:
    """Return a minification profile with score and reasons."""
    cleaned = code.strip()
    if not cleaned or _is_workspace_bundle(cleaned):
        return {"likely": False, "score": 0.0, "reasons": []}

    lines = cleaned.splitlines() or [cleaned]
    non_empty_lines = [line for line in lines if line.strip()]
    total_lines = max(len(non_empty_lines), 1)
    total_chars = len(cleaned)
    avg_line_length = total_chars / total_lines
    max_line_length = max((len(line) for line in non_empty_lines), default=0)
    semicolon_density = cleaned.count(";") / total_lines
    whitespace_ratio = sum(1 for ch in cleaned if ch.isspace()) / max(total_chars, 1)
    indentation_ratio = sum(
        1 for line in non_empty_lines
        if line[:1].isspace() and line.strip()
    ) / total_lines
    punctuation_density = sum(
        1 for ch in cleaned if ch in "{}[]();,:"
    ) / max(total_chars, 1)

    lang = (language or "").lower().strip()
    js_like = lang in _JS_LIKE_LANGUAGES or (not lang and _is_minified_javascript_hint(cleaned))
    python_like = lang in _PYTHON_LIKE_LANGUAGES

    score = 0.0
    reasons: List[str] = []

    if total_chars >= 180 and total_lines <= 3:
        score += 0.22
        reasons.append("few_lines_large_payload")
    if avg_line_length >= 180:
        score += min(0.25, (avg_line_length - 180.0) / 1200.0 + 0.08)
        reasons.append("high_average_line_length")
    if max_line_length >= 420:
        score += min(0.2, (max_line_length - 420.0) / 2000.0 + 0.08)
        reasons.append("extreme_line_length")
    if semicolon_density >= 4.0:
        score += min(0.16, semicolon_density / 40.0)
        reasons.append("dense_statement_delimiters")
    if punctuation_density >= 0.16 and whitespace_ratio <= 0.18:
        score += 0.14
        reasons.append("dense_punctuation_low_whitespace")
    if indentation_ratio <= 0.08 and avg_line_length >= 120:
        score += 0.08
        reasons.append("low_indentation")
    if js_like and "dense_statement_delimiters" in reasons:
        score += 0.06
        reasons.append("javascript_like_structure")
    if python_like and total_lines <= 4 and semicolon_density >= 1.5:
        score += 0.18
        reasons.append("python_compound_statements")
    if python_like and avg_line_length >= 120 and indentation_ratio <= 0.05:
        score += 0.12
        reasons.append("python_flat_layout")

    score = max(0.0, min(1.0, score))
    return {
        "likely": score >= 0.45,
        "score": score,
        "reasons": reasons,
        "avg_line_length": avg_line_length,
        "max_line_length": max_line_length,
        "non_empty_lines": total_lines,
    }


def source_needs_preprocessing(code: str, language: str) -> bool:
    if looks_like_binary_blob_text(code):
        return False
    normalized, counts = normalize_source_anomalies(code)
    if normalized != code:
        return True
    lang = (language or "").lower().strip()
    if lang in _PYTHON_LIKE_LANGUAGES:
        beautified, _ = _beautify_python(normalized, detect_minified_source(normalized, language))
        if beautified != normalized:
            return True
    profile = detect_minified_source(normalized, language)
    return bool(profile.get("likely"))


def _split_dense_statements(code: str, language: str) -> str:
    lang = (language or "").lower().strip()
    if lang not in _SEMICOLON_SPLIT_LANGUAGES:
        return code

    result: List[str] = []
    quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    escape = False
    i = 0
    while i < len(code):
        ch = code[i]
        nxt = code[i + 1] if i + 1 < len(code) else ""

        result.append(ch)

        if ch == "\r":
            i += 1
            continue

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                result.append(nxt)
                i += 2
                in_block_comment = False
            else:
                i += 1
            continue

        if quote is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            result.append(nxt)
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            result.append(nxt)
            in_block_comment = True
            i += 2
            continue
        if ch == "#" and _is_hash_comment_start(code, i):
            in_line_comment = True
            i += 1
            continue
        if ch in {'"', "'", "`"}:
            quote = ch
            i += 1
            continue

        if ch == ";":
            while result and len(result) >= 2 and result[-2] == "\n":
                break
            if not nxt.startswith("\n"):
                result.append("\n")

        i += 1

    return "".join(result)


def _layout_quality_score(code: str) -> float:
    cleaned = code.strip()
    if not cleaned:
        return 0.0
    lines = [line for line in cleaned.splitlines() if line.strip()]
    total_lines = max(len(lines), 1)
    total_chars = len(cleaned)
    avg_line_length = total_chars / total_lines
    max_line_length = max((len(line) for line in lines), default=0)
    indentation_ratio = sum(
        1 for line in lines
        if line[:1].isspace()
    ) / total_lines
    semicolon_density = cleaned.count(";") / total_lines

    if avg_line_length <= 90:
        avg_score = 1.0
    elif avg_line_length <= 180:
        avg_score = 0.75
    elif avg_line_length <= 320:
        avg_score = 0.45
    else:
        avg_score = 0.15

    if max_line_length <= 140:
        max_score = 1.0
    elif max_line_length <= 260:
        max_score = 0.7
    elif max_line_length <= 480:
        max_score = 0.35
    else:
        max_score = 0.1

    semicolon_score = max(0.0, 1.0 - min(semicolon_density / 6.0, 1.0))
    return max(
        0.0,
        min(
            1.0,
            0.45 * avg_score
            + 0.25 * max_score
            + 0.15 * min(indentation_ratio / 0.2, 1.0)
            + 0.15 * semicolon_score,
        ),
    )


def _python_has_comment_tokens(code: str) -> bool:
    try:
        for token in tokenize.generate_tokens(StringIO(code).readline):
            if token.type == tokenize.COMMENT:
                return True
    except Exception:
        return bool(re.search(r"(^|\s)#", code))
    return False


def _python_prefix_comments(code: str) -> tuple[str, str]:
    lines = code.splitlines(keepends=True)
    prefix: List[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if stripped.startswith("#!") or stripped.startswith("# -*-") or stripped.startswith("# coding") or stripped.startswith("# vim:"):
            prefix.append(lines[index])
            index += 1
            continue
        break
    return "".join(prefix), "".join(lines[index:])


def _try_black_format(code: str) -> Tuple[str, str]:
    if black is None:
        return code, "none"
    try:
        mode = black.FileMode(
            line_length=88,
            string_normalization=False,
        )
        formatted = black.format_str(code, mode=mode)
        return formatted, "python_black"
    except getattr(black, "NothingChanged", Exception):
        return code, "none"
    except Exception:
        return code, "none"


def _beautify_python(code: str, profile: Dict[str, Any]) -> Tuple[str, str]:
    try:
        original_tree = ast.parse(code)
    except SyntaxError:
        return code, "none"

    before_score = _layout_quality_score(code)
    strongly_needed = (
        profile.get("likely")
        or "python_compound_statements" in profile.get("reasons", [])
        or profile.get("max_line_length", 0) >= 140
    )
    if not strongly_needed:
        return code, "none"

    candidate, engine = _try_black_format(code)
    if candidate != code:
        try:
            candidate_tree = ast.parse(candidate)
        except SyntaxError:
            candidate_tree = None
        if (
            candidate_tree is not None
            and ast.dump(original_tree, include_attributes=False)
            == ast.dump(candidate_tree, include_attributes=False)
        ):
            improvement = _layout_quality_score(candidate) - before_score
            if improvement >= 0.05:
                return candidate, engine

    if _python_has_comment_tokens(code):
        split = _split_dense_statements(code, "python")
        return (split, "semicolon_split") if split != code else (code, "none")

    prefix, _ = _python_prefix_comments(code)
    try:
        candidate_body = ast.unparse(original_tree)
    except Exception:
        split = _split_dense_statements(code, "python")
        return (split, "semicolon_split") if split != code else (code, "none")

    candidate = prefix + candidate_body
    if code.endswith("\n") and not candidate.endswith("\n"):
        candidate += "\n"
    if candidate == code:
        return code, "none"

    try:
        candidate_tree = ast.parse(candidate)
    except SyntaxError:
        return code, "none"

    if ast.dump(original_tree, include_attributes=False) != ast.dump(candidate_tree, include_attributes=False):
        return code, "none"

    improvement = _layout_quality_score(candidate) - before_score
    if improvement < 0.08:
        return code, "none"

    return candidate, "python_ast_unparse"


def beautify_source(code: str, language: str) -> Tuple[str, str]:
    """Beautify source using the best available pure-Python strategy."""
    lang = (language or "").lower().strip()
    if lang in {"json"}:
        try:
            parsed = json.loads(code)
            return json.dumps(parsed, indent=2, ensure_ascii=False) + "\n", "json_pretty"
        except Exception:
            return code, "none"

    if lang in _PYTHON_LIKE_LANGUAGES:
        profile = detect_minified_source(code, language)
        beautified, engine = _beautify_python(code, profile)
        if beautified != code:
            return beautified, engine
        split = _split_dense_statements(code, lang)
        if split != code and profile.get("likely"):
            return split, "semicolon_split"
        return code, "none"

    if lang in _JS_LIKE_LANGUAGES or (not lang and _is_minified_javascript_hint(code)):
        if jsbeautifier is not None:
            try:
                options = jsbeautifier.default_options()
                options.indent_size = 2
                options.preserve_newlines = True
                options.max_preserve_newlines = 2
                options.end_with_newline = True
                options.space_in_empty_paren = False
                options.space_before_conditional = True
                return jsbeautifier.beautify(code, options), "jsbeautifier"
            except Exception:
                pass
        return _split_dense_statements(code, "javascript"), "semicolon_split"

    split = _split_dense_statements(code, lang)
    if split != code:
        return split, "semicolon_split"
    return code, "none"


class SourcePreprocessor(BaseTransform):
    name = "SourcePreprocessor"
    description = "Normalise parser-hostile source anomalies and beautify likely minified code."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        if not code or _is_workspace_bundle(code) or looks_like_binary_blob_text(code):
            return False
        return source_needs_preprocessing(code, language)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        if not code or _is_workspace_bundle(code) or looks_like_binary_blob_text(code):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description=(
                    "Workspace bundles and binary payloads are not source-preprocessed "
                    "as flat text."
                ),
                details={},
            )

        normalized, anomaly_counts = normalize_source_anomalies(code)
        profile = detect_minified_source(normalized, language)
        output = normalized
        beautifier = "none"
        lang = (language or "").lower().strip()

        if profile.get("likely") or lang in _PYTHON_LIKE_LANGUAGES:
            beautified, beautifier = beautify_source(normalized, language)
            if beautified and beautified.strip():
                output = beautified

        if output == code:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No preprocessing changes were necessary.",
                details={},
            )

        techniques: List[str] = []
        if normalized != code:
            techniques.append("source_anomaly_normalization")
        if output != normalized:
            techniques.append("minified_code_beautification")

        lines_before = max(len(code.splitlines()), 1)
        lines_after = max(len(output.splitlines()), 1)
        confidence = 0.72
        if normalized != code:
            confidence += 0.08
        if output != normalized:
            confidence += min(0.12, float(profile.get("score", 0.0)) * 0.2)
        confidence = min(0.92, confidence)

        description_parts: List[str] = []
        if normalized != code:
            description_parts.append("normalised parser-hostile source anomalies")
        if output != normalized:
            description_parts.append(
                f"beautified likely minified code via {beautifier}"
            )
        description = (
            " and ".join(description_parts).capitalize() + "."
            if description_parts else
            "No preprocessing changes were necessary."
        )

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=description,
            details={
                "detected_techniques": techniques,
                "preprocessing": {
                    "anomaly_counts": anomaly_counts,
                    "minified_profile": profile,
                    "beautifier": beautifier,
                    "lines_before": lines_before,
                    "lines_after": lines_after,
                },
                "evidence_references": [
                    f"preprocess:{name}"
                    for name, count in anomaly_counts.items()
                    if count
                ][:12],
            },
        )
