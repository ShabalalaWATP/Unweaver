"""
RenameSuggester -- detects meaningless variable/function names that are
typical of obfuscated code and suggests semantic replacements based on
usage-context heuristics.
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Patterns that indicate a name is meaningless / obfuscated
# ---------------------------------------------------------------------------

_OBFUSCATED_PATTERNS: list[tuple[str, re.Pattern]] = [
    # _0x prefixed hex names (javascript-obfuscator)
    ("hex_prefix", re.compile(r"\b_0x[0-9a-fA-F]{4,}\b")),
    # Single character identifiers (excluding common loop vars and math)
    ("single_char", re.compile(r"\b(?<![.\[])([a-zA-Z])\b(?!\s*[:\.\[({])")),
    # Double-underscore prefixed gibberish
    ("dunder_gibberish", re.compile(r"\b__[a-zA-Z0-9]{8,}__\b")),
    # Il1-style confusing names (mix of I, l, 1)
    ("Il_confusion", re.compile(r"\b[Il1]{4,}\b")),
    # Very long underscore-separated hex or random
    ("long_underscore", re.compile(r"\b_[a-zA-Z0-9]{10,}\b")),
    # Random-looking short names (2-3 consonants, no vowels)
    ("consonant_soup", re.compile(r"\b[bcdfghjklmnpqrstvwxyz]{3,5}\b")),
]

# ---------------------------------------------------------------------------
# Usage-context heuristics to suggest better names
# ---------------------------------------------------------------------------

# Patterns that suggest what a variable is used for
_CONTEXT_HINTS: list[tuple[re.Pattern, str, str]] = [
    # URL / HTTP
    (re.compile(r"https?://|\.(?:get|post|fetch|request|ajax)\b", re.IGNORECASE), "url", "target_url"),
    (re.compile(r"XMLHttpRequest|fetch\(|\.open\s*\(\s*['\"](?:GET|POST)", re.IGNORECASE), "request", "http_request"),

    # File / Path
    (re.compile(r"\\\\|[A-Z]:\\|/tmp/|/etc/|\.(?:exe|dll|ps1|bat|sh|py)\b", re.IGNORECASE), "path", "file_path"),
    (re.compile(r"\.(?:read|write|open|close)\s*\(", re.IGNORECASE), "file", "file_handle"),

    # Base64 / Encoding
    (re.compile(r"base64|btoa|atob|b64decode|FromBase64", re.IGNORECASE), "encoded", "encoded_data"),

    # Command / Shell
    (re.compile(r"cmd\.exe|powershell|/bin/sh|exec\(|system\(|Process\.Start", re.IGNORECASE), "command", "shell_command"),

    # Key / Password / Secret
    (re.compile(r"password|passwd|secret|key|token|credential", re.IGNORECASE), "secret", "secret_value"),

    # IP / Network
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "ip", "target_ip"),
    (re.compile(r"socket|connect|bind|listen|port", re.IGNORECASE), "network", "connection"),

    # Registry
    (re.compile(r"HKLM|HKCU|Registry|RegKey", re.IGNORECASE), "regkey", "registry_key"),

    # Loop / Iterator
    (re.compile(r"\bfor\s*\(\s*(?:var|let)?\s*$NAME", re.IGNORECASE), "index", "loop_index"),
    (re.compile(r"\.(?:forEach|map|filter|reduce)\s*\("), "item", "current_item"),

    # Array / List / Collection
    (re.compile(r"\[.*\]|\bArray\b|\blist\b", re.IGNORECASE), "items", "data_array"),

    # Counter / Number
    (re.compile(r"\+\+|--|\+=\s*1|count|length|size", re.IGNORECASE), "counter", "count"),

    # String / Text
    (re.compile(r"\.(?:split|replace|substring|substr|slice|trim|concat)\s*\("), "text", "text_value"),
    (re.compile(r"\.(?:join|toString|charAt)\s*\("), "str", "string_value"),

    # Result / Output
    (re.compile(r"\breturn\s+$NAME\b"), "result", "result"),
    (re.compile(r"\.(?:innerHTML|textContent|innerText)\s*="), "output", "rendered_output"),

    # Function / Callback
    (re.compile(r"function\s+$NAME\s*\(|$NAME\s*=\s*function"), "func", "handler_func"),

    # Decode / Decrypt
    (re.compile(r"decode|decrypt|deobfuscate|unescape", re.IGNORECASE), "decoded", "decoded_value"),

    # XOR
    (re.compile(r"\^|xor|bxor", re.IGNORECASE), "xor_key", "xor_key"),
]


def _get_assignment_context(code: str, var_name: str) -> str:
    """Get the right-hand side of assignments to this variable."""
    # Match: var_name = <something>
    escaped = re.escape(var_name)
    pattern = re.compile(
        rf"(?:var|let|const|my|local)?\s*{escaped}\s*=\s*([^\n;]+)",
        re.IGNORECASE,
    )
    contexts: list[str] = []
    for m in pattern.finditer(code):
        contexts.append(m.group(1).strip())
    return " ".join(contexts)


def _get_usage_context(code: str, var_name: str) -> str:
    """Get surrounding code where the variable is used."""
    escaped = re.escape(var_name)
    pattern = re.compile(rf".{{0,60}}{escaped}.{{0,60}}")
    usages: list[str] = []
    for m in pattern.finditer(code):
        usages.append(m.group(0))
    return " ".join(usages[:10])  # limit to prevent huge strings


def _suggest_name(
    code: str, var_name: str, var_type: str
) -> tuple[str, float]:
    """Suggest a semantic name for a variable based on context.

    Returns (suggested_name, confidence).
    """
    assign_ctx = _get_assignment_context(code, var_name)
    usage_ctx = _get_usage_context(code, var_name)
    combined_ctx = assign_ctx + " " + usage_ctx

    best_suggestion = ""
    best_confidence = 0.0

    for hint_pat, short_name, long_name in _CONTEXT_HINTS:
        # Replace $NAME placeholder with the actual variable name
        adjusted_pattern = re.compile(
            hint_pat.pattern.replace("$NAME", re.escape(var_name)),
            hint_pat.flags,
        )
        matches = adjusted_pattern.findall(combined_ctx)
        if matches:
            confidence = min(0.85, 0.40 + 0.10 * len(matches))
            if confidence > best_confidence:
                best_confidence = confidence
                best_suggestion = long_name

    if not best_suggestion:
        # Fallback: generate a positional name
        if var_type == "single_char":
            best_suggestion = f"var_{var_name}"
            best_confidence = 0.20
        elif var_type == "hex_prefix":
            best_suggestion = f"obf_{var_name[-4:]}"
            best_confidence = 0.25
        else:
            best_suggestion = f"renamed_{var_name[:8]}"
            best_confidence = 0.15

    return best_suggestion, best_confidence


class RenameSuggester(BaseTransform):
    name = "rename_suggester"
    description = (
        "Detect meaningless variable/function names and suggest "
        "semantic replacements"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        for _, pat in _OBFUSCATED_PATTERNS:
            if pat.search(code):
                return True
        return False

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        # Collect all obfuscated-looking identifiers
        candidates: dict[str, str] = {}  # name -> pattern_type

        for ptype, pat in _OBFUSCATED_PATTERNS:
            for m in pat.finditer(code):
                name = m.group(0)
                # Skip very common single-char names in loops
                if ptype == "single_char" and name in ("i", "j", "k", "n", "x", "y", "e", "f", "m", "s"):
                    continue
                # Skip language keywords
                if name in _KEYWORDS:
                    continue
                if name not in candidates:
                    candidates[name] = ptype

        if not candidates:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No obfuscated identifiers detected.",
            )

        # Generate suggestions
        suggestions: list[dict[str, Any]] = []
        seen_suggestions: dict[str, int] = {}  # to disambiguate duplicates

        for name, ptype in candidates.items():
            suggested, confidence = _suggest_name(code, name, ptype)

            # Disambiguate duplicate suggestions
            if suggested in seen_suggestions:
                seen_suggestions[suggested] += 1
                suggested = f"{suggested}_{seen_suggestions[suggested]}"
            else:
                seen_suggestions[suggested] = 0

            # Count occurrences
            escaped = re.escape(name)
            occurrences = len(re.findall(rf"\b{escaped}\b", code))

            suggestions.append({
                "original": name,
                "suggested": suggested,
                "confidence": round(confidence, 2),
                "pattern_type": ptype,
                "occurrences": occurrences,
            })

        # Sort by confidence descending, then by occurrences
        suggestions.sort(
            key=lambda s: (s["confidence"], s["occurrences"]),
            reverse=True,
        )

        # Build the rename mapping
        rename_map = {
            s["original"]: s["suggested"] for s in suggestions
        }

        state.setdefault("rename_suggestions", []).extend(suggestions)
        state["rename_map"] = rename_map

        high_confidence = sum(
            1 for s in suggestions if s["confidence"] >= 0.50
        )
        overall_confidence = min(
            0.85,
            0.30 + 0.05 * high_confidence
        )

        type_counts: dict[str, int] = {}
        for s in suggestions:
            t = s["pattern_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        summary = ", ".join(f"{v} {k}" for k, v in type_counts.items())

        return TransformResult(
            success=True,
            output=code,  # suggestions only, no auto-rename
            confidence=overall_confidence,
            description=(
                f"Found {len(suggestions)} obfuscated name(s) ({summary}); "
                f"{high_confidence} with high-confidence suggestions."
            ),
            details={
                "suggestion_count": len(suggestions),
                "high_confidence_count": high_confidence,
                "type_counts": type_counts,
                "suggestions": suggestions,
                "rename_map": rename_map,
            },
        )


# Common keywords to exclude from rename suggestions
_KEYWORDS = frozenset({
    # JavaScript
    "var", "let", "const", "function", "return", "if", "else", "for",
    "while", "do", "switch", "case", "break", "continue", "new", "this",
    "true", "false", "null", "undefined", "typeof", "instanceof", "void",
    "delete", "throw", "try", "catch", "finally", "class", "extends",
    "super", "import", "export", "default", "from", "as", "of", "in",
    "async", "await", "yield", "with", "debugger",
    # Python
    "def", "class", "import", "from", "as", "if", "elif", "else",
    "for", "while", "break", "continue", "return", "yield", "try",
    "except", "finally", "raise", "with", "assert", "pass", "del",
    "lambda", "True", "False", "None", "and", "or", "not", "is", "in",
    "global", "nonlocal", "self", "cls",
    # PowerShell
    "function", "param", "begin", "process", "end", "if", "else",
    "elseif", "switch", "for", "foreach", "while", "do", "until",
    "break", "continue", "return", "throw", "try", "catch", "finally",
    "trap", "exit",
    # C#
    "using", "namespace", "class", "struct", "interface", "enum",
    "public", "private", "protected", "internal", "static", "void",
    "int", "string", "bool", "float", "double", "var", "new", "return",
    "if", "else", "for", "foreach", "while", "do", "switch", "case",
    "break", "continue", "try", "catch", "finally", "throw", "async",
    "await", "true", "false", "null", "this", "base", "ref", "out",
})
