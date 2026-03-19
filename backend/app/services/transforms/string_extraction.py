"""
StringExtractor transform -- pulls every string literal out of source code,
records its position, and flags suspicious patterns (URLs, IPs, paths,
registry keys, base64-looking content).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Language-aware string-literal patterns
# ---------------------------------------------------------------------------

# JavaScript / TypeScript
_JS_PATTERNS = [
    # template literals  (backtick strings -- simplified, no nested ${} matching)
    re.compile(r"`(?:[^`\\]|\\.)*`", re.DOTALL),
    # double-quoted
    re.compile(r'"(?:[^"\\]|\\.)*"'),
    # single-quoted
    re.compile(r"'(?:[^'\\]|\\.)*'"),
]

# Python
_PY_PATTERNS = [
    # triple-double
    re.compile(r'"""(?:[^\\]|\\.)*?"""', re.DOTALL),
    # triple-single
    re.compile(r"'''(?:[^\\]|\\.)*?'''", re.DOTALL),
    # f-strings (triple)
    re.compile(r'f"""(?:[^\\]|\\.)*?"""', re.DOTALL),
    re.compile(r"f'''(?:[^\\]|\\.)*?'''", re.DOTALL),
    # regular f-strings
    re.compile(r'f"(?:[^"\\]|\\.)*"'),
    re.compile(r"f'(?:[^'\\]|\\.)*'"),
    # raw strings
    re.compile(r'r"(?:[^"\\]|\\.)*"'),
    re.compile(r"r'(?:[^'\\]|\\.)*'"),
    # byte strings
    re.compile(r'b"(?:[^"\\]|\\.)*"'),
    re.compile(r"b'(?:[^'\\]|\\.)*'"),
    # plain strings
    re.compile(r'"(?:[^"\\]|\\.)*"'),
    re.compile(r"'(?:[^'\\]|\\.)*'"),
]

# PowerShell
_PS_PATTERNS = [
    # here-strings
    re.compile(r"@\"\s*\n.*?\n\"@", re.DOTALL),
    re.compile(r"@'\s*\n.*?\n'@", re.DOTALL),
    # double-quoted (expandable)
    re.compile(r'"(?:[^"\\`]|`.|"")*"'),
    # single-quoted (literal)
    re.compile(r"'(?:[^']|'')*'"),
]

# C#
_CS_PATTERNS = [
    # verbatim strings
    re.compile(r'@"(?:[^"]|"")*"'),
    # interpolated verbatim
    re.compile(r'\$@"(?:[^"]|"")*"'),
    # interpolated
    re.compile(r'\$"(?:[^"\\]|\\.)*"'),
    # regular
    re.compile(r'"(?:[^"\\]|\\.)*"'),
    # char literal
    re.compile(r"'(?:[^'\\]|\\.)'"),
]

_LANGUAGE_PATTERNS: dict[str, list[re.Pattern]] = {
    "javascript": _JS_PATTERNS,
    "typescript": _JS_PATTERNS,
    "js": _JS_PATTERNS,
    "ts": _JS_PATTERNS,
    "python": _PY_PATTERNS,
    "py": _PY_PATTERNS,
    "powershell": _PS_PATTERNS,
    "ps1": _PS_PATTERNS,
    "ps": _PS_PATTERNS,
    "csharp": _CS_PATTERNS,
    "cs": _CS_PATTERNS,
    "c#": _CS_PATTERNS,
}

# Fallback: a union of common patterns
_GENERIC_PATTERNS = [
    re.compile(r'"""(?:[^\\]|\\.)*?"""', re.DOTALL),
    re.compile(r"'''(?:[^\\]|\\.)*?'''", re.DOTALL),
    re.compile(r"`(?:[^`\\]|\\.)*`", re.DOTALL),
    re.compile(r'"(?:[^"\\]|\\.)*"'),
    re.compile(r"'(?:[^'\\]|\\.)*'"),
]

# ---------------------------------------------------------------------------
# Suspicious-content detectors
# ---------------------------------------------------------------------------

_SUSPICIOUS: list[tuple[str, re.Pattern]] = [
    ("url", re.compile(
        r"https?://[^\s\"'`\]})>]{4,}", re.IGNORECASE
    )),
    ("defanged_url", re.compile(
        r"hxxps?://[^\s\"'`\]})>]{4,}", re.IGNORECASE
    )),
    ("ip_v4", re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )),
    ("ip_v6", re.compile(
        r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    )),
    ("windows_path", re.compile(
        r"[A-Za-z]:\\(?:[^\s\\\"']+\\)*[^\s\\\"']*"
    )),
    ("unix_path", re.compile(
        r"(?:/[a-zA-Z0-9_.@-]+){2,}"
    )),
    ("registry_key", re.compile(
        r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s\"']+",
        re.IGNORECASE,
    )),
    ("base64_candidate", re.compile(
        r"^[A-Za-z0-9+/]{20,}={0,2}$"
    )),
    ("email", re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    )),
    ("hash_sha256", re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    )),
    ("hash_sha1", re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    )),
    ("hash_md5", re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    )),
]


@dataclass
class ExtractedString:
    """One string literal pulled from source code."""

    value: str
    raw: str  # the full matched text including quotes
    start: int
    end: int
    flags: list[str] = field(default_factory=list)


def _strip_quotes(raw: str) -> str:
    """Best-effort removal of surrounding quote characters."""
    # triple-quoted
    for q in ('"""', "'''"):
        if raw.startswith(q) and raw.endswith(q):
            return raw[3:-3]
    # prefixed strings  (f", b", r", $@", @")
    prefixes = ("f'", 'f"', "b'", 'b"', "r'", 'r"', '$@"', '@"', '$"')
    for p in prefixes:
        if raw.startswith(p):
            return raw[len(p):-1]
    # template / backtick
    if raw.startswith("`") and raw.endswith("`"):
        return raw[1:-1]
    # here-string
    if raw.startswith("@\"") and raw.endswith("\"@"):
        return raw[2:-2].strip("\r\n")
    if raw.startswith("@'") and raw.endswith("'@"):
        return raw[2:-2].strip("\r\n")
    # normal single/double
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        return raw[1:-1]
    return raw


def _flag_string(value: str) -> list[str]:
    """Return list of suspicious-pattern tags for a string value."""
    tags: list[str] = []
    for tag, pat in _SUSPICIOUS:
        if pat.search(value):
            tags.append(tag)
    return tags


class StringExtractor(BaseTransform):
    name = "string_extraction"
    description = "Extract all string literals and flag suspicious content"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        # Strings exist in virtually all code, so just check there's something.
        return bool(code and code.strip())

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        lang = language.lower().strip() if language else ""
        patterns = _LANGUAGE_PATTERNS.get(lang, _GENERIC_PATTERNS)

        extracted: list[ExtractedString] = []
        seen_spans: set[tuple[int, int]] = set()

        for pat in patterns:
            for m in pat.finditer(code):
                span = (m.start(), m.end())
                # skip if already covered by a longer match
                if any(s <= span[0] and e >= span[1] for s, e in seen_spans):
                    continue
                raw = m.group(0)
                value = _strip_quotes(raw)
                flags = _flag_string(value)
                extracted.append(ExtractedString(
                    value=value,
                    raw=raw,
                    start=span[0],
                    end=span[1],
                    flags=flags,
                ))
                seen_spans.add(span)

        # sort by position
        extracted.sort(key=lambda s: s.start)

        suspicious = [s for s in extracted if s.flags]

        # Store in state for downstream transforms
        state["extracted_strings"] = extracted

        details: dict[str, Any] = {
            "total_strings": len(extracted),
            "suspicious_count": len(suspicious),
            "strings": [
                {
                    "value": s.value,
                    "start": s.start,
                    "end": s.end,
                    "flags": s.flags,
                }
                for s in extracted
            ],
        }

        description_parts = [f"Extracted {len(extracted)} string literal(s)"]
        if suspicious:
            description_parts.append(
                f"{len(suspicious)} flagged as suspicious"
            )

        return TransformResult(
            success=True,
            output=code,  # extraction is non-destructive
            confidence=0.95 if extracted else 0.5,
            description=". ".join(description_parts) + ".",
            details=details,
        )
