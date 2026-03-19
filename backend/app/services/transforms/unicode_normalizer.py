"""
UnicodeNormalizer transform -- decodes and normalizes all common escape
sequences found in obfuscated code, converting them to readable characters.

Supported formats:
  - \\uXXXX         (4-digit Unicode escapes)
  - \\UXXXXXXXX     (8-digit Unicode escapes)
  - \\xXX           (hex escapes)
  - \\NNN           (3-digit octal escapes)
  - &#72; / &#x48;  (HTML numeric entities)
  - &amp; &lt; etc. (HTML named entities)
  - %XX             (URL percent-encoding)
  - String.fromCharCode(72,101,108)  (JavaScript charcode patterns)
  - [char]72        (PowerShell char cast patterns)

Safety:
  - Only decodes printable characters (U+0020 .. U+FFFF).
  - Preserves control-character escapes (\\n, \\t, \\r, \\0, etc.).
  - Skips content inside comments (// ..., /* ... */, # ...).
"""

from __future__ import annotations

import html
import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Comment patterns -- lines or regions we should NOT touch.
# For '#' comments we require that the '#' is either at the start of the line
# or preceded by whitespace, so that HTML entities like &#72; are not treated
# as comments.
_LINE_COMMENT = re.compile(r"(//[^\n]*|(?:^|(?<=\s))#[^\n]*)", re.MULTILINE)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _is_printable_safe(cp: int) -> bool:
    """Return True if codepoint is in the safe-to-decode range.

    We decode printable ASCII (0x20..0x7E) and common Unicode above that
    up to U+FFFF, but reject control characters (< 0x20) except nothing --
    we simply keep those as their original escape form.
    """
    return 0x0020 <= cp <= 0xFFFF and (cp >= 0x20)


def _build_comment_mask(code: str) -> list[bool]:
    """Return a boolean list where True means the character is inside a comment."""
    mask = [False] * len(code)
    for pattern in (_BLOCK_COMMENT, _LINE_COMMENT):
        for m in pattern.finditer(code):
            for i in range(m.start(), m.end()):
                mask[i] = True
    return mask


def _safe_replace(
    code: str,
    pattern: re.Pattern,
    replacer,
    mask: list[bool],
) -> tuple[str, int]:
    """Apply *replacer* to every non-comment match of *pattern* in *code*.

    Returns (new_code, replacement_count).  We collect all matches first,
    filter out those in comments or that cannot be decoded, then apply
    replacements from right to left so earlier offsets stay valid.
    """
    # Collect all matches.
    matches = list(pattern.finditer(code))
    if not matches:
        return code, 0

    # Build list of (start, end, replacement) from right to left.
    replacements: list[tuple[int, int, str]] = []
    for m in matches:
        # Skip if inside a comment.
        if m.start() < len(mask) and mask[m.start()]:
            continue
        replacement = replacer(m)
        if replacement is None:
            continue
        replacements.append((m.start(), m.end(), replacement))

    if not replacements:
        return code, 0

    # Apply from right to left so indices remain stable.
    result = code
    for start, end, repl in reversed(replacements):
        result = result[:start] + repl + result[end:]

    # Rebuild the mask for subsequent pipeline stages.
    # Since we process pipeline steps sequentially, we rebuild the mask
    # based on the new code length.  We do a simple resize: the mask
    # is extended or truncated to match the new length, with new positions
    # marked as non-comment (False).
    new_len = len(result)
    if new_len > len(mask):
        mask.extend([False] * (new_len - len(mask)))
    elif new_len < len(mask):
        del mask[new_len:]

    return result, len(replacements)


# ---------------------------------------------------------------------------
# Individual decoders (each returns a replacement string or None)
# ---------------------------------------------------------------------------

# 1. \uXXXX  (4-digit Unicode escape)
_RE_UNICODE4 = re.compile(r"\\u([0-9a-fA-F]{4})")


def _replace_unicode4(m: re.Match) -> str | None:
    cp = int(m.group(1), 16)
    if _is_printable_safe(cp):
        return chr(cp)
    return None


# 2. \UXXXXXXXX  (8-digit Unicode escape)
_RE_UNICODE8 = re.compile(r"\\U([0-9a-fA-F]{8})")


def _replace_unicode8(m: re.Match) -> str | None:
    cp = int(m.group(1), 16)
    if _is_printable_safe(cp):
        return chr(cp)
    return None


# 3. \xXX  (hex escape)
_RE_HEX = re.compile(r"\\x([0-9a-fA-F]{2})")


def _replace_hex(m: re.Match) -> str | None:
    cp = int(m.group(1), 16)
    if _is_printable_safe(cp):
        return chr(cp)
    return None


# 4. Octal escapes: \NNN  (exactly 3 octal digits, value 0-377)
# We require 3 digits to avoid false positives with backreferences like \1.
_RE_OCTAL = re.compile(r"\\([0-3][0-7]{2})")


def _replace_octal(m: re.Match) -> str | None:
    cp = int(m.group(1), 8)
    if _is_printable_safe(cp):
        return chr(cp)
    return None


# 5a. HTML numeric entities: &#72; or &#x48;
_RE_HTML_NUMERIC = re.compile(r"&#(x[0-9a-fA-F]{1,6}|[0-9]{1,7});")


def _replace_html_numeric(m: re.Match) -> str | None:
    val = m.group(1)
    try:
        if val.startswith("x") or val.startswith("X"):
            cp = int(val[1:], 16)
        else:
            cp = int(val, 10)
    except ValueError:
        return None
    if _is_printable_safe(cp):
        return chr(cp)
    return None


# 5b. HTML named entities: &amp; &lt; &gt; &quot;
_NAMED_ENTITIES: dict[str, str] = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&nbsp;": " ",
}
_RE_HTML_NAMED = re.compile(
    r"&(amp|lt|gt|quot|apos|nbsp);", re.IGNORECASE
)


def _replace_html_named(m: re.Match) -> str | None:
    full = m.group(0).lower()
    return _NAMED_ENTITIES.get(full)


# 6. URL percent-encoding: %XX
_RE_PERCENT = re.compile(r"%([0-9a-fA-F]{2})")


def _replace_percent(m: re.Match) -> str | None:
    cp = int(m.group(1), 16)
    if _is_printable_safe(cp):
        return chr(cp)
    return None


# 7. JavaScript String.fromCharCode(72, 101, 108, ...)
_RE_FROMCHARCODE = re.compile(
    r"String\.fromCharCode\(\s*((?:\d{1,5}\s*,\s*)*\d{1,5})\s*\)",
    re.IGNORECASE,
)


def _replace_fromcharcode(m: re.Match) -> str | None:
    try:
        codes = [int(c.strip()) for c in m.group(1).split(",")]
        chars = []
        for cp in codes:
            if not _is_printable_safe(cp):
                return None
            chars.append(chr(cp))
        return '"' + "".join(chars) + '"'
    except (ValueError, OverflowError):
        return None


# 8. PowerShell [char]NN  (decimal codepoint)
_RE_PS_CHAR = re.compile(r"\[char\]\s*(\d{1,5})", re.IGNORECASE)


def _replace_ps_char(m: re.Match) -> str | None:
    try:
        cp = int(m.group(1))
    except ValueError:
        return None
    if _is_printable_safe(cp):
        return f"'{chr(cp)}'"
    return None


# ---------------------------------------------------------------------------
# Ordered decode pipeline
# ---------------------------------------------------------------------------

# (pattern, replacer_func, counter_key)
_DECODE_PIPELINE: list[tuple[re.Pattern, Any, str]] = [
    (_RE_UNICODE4, _replace_unicode4, "unicode_count"),
    (_RE_UNICODE8, _replace_unicode8, "unicode_count"),
    (_RE_HEX, _replace_hex, "hex_count"),
    (_RE_OCTAL, _replace_octal, "octal_count"),
    (_RE_HTML_NUMERIC, _replace_html_numeric, "html_entity_count"),
    (_RE_HTML_NAMED, _replace_html_named, "html_entity_count"),
    (_RE_PERCENT, _replace_percent, "url_encode_count"),
    (_RE_FROMCHARCODE, _replace_fromcharcode, "charcode_count"),
    (_RE_PS_CHAR, _replace_ps_char, "charcode_count"),
]

# Quick-check pattern: does the code contain *anything* we might decode?
_QUICK_CHECK = re.compile(
    r"\\u[0-9a-fA-F]{4}"
    r"|\\U[0-9a-fA-F]{8}"
    r"|\\x[0-9a-fA-F]{2}"
    r"|\\[0-3][0-7]{2}"
    r"|&#[xX]?[0-9a-fA-F]+;"
    r"|&(amp|lt|gt|quot|apos|nbsp);"
    r"|%[0-9a-fA-F]{2}"
    r"|String\.fromCharCode\s*\("
    r"|\[char\]\s*\d",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Transform class
# ---------------------------------------------------------------------------


class UnicodeNormalizer(BaseTransform):
    name = "UnicodeNormalizer"
    description = (
        "Decode Unicode escapes, hex escapes, and octal escapes "
        "to readable characters."
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(_QUICK_CHECK.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        mask = _build_comment_mask(code)

        counters: dict[str, int] = {
            "unicode_count": 0,
            "hex_count": 0,
            "octal_count": 0,
            "html_entity_count": 0,
            "url_encode_count": 0,
            "charcode_count": 0,
        }

        output = code

        for pattern, replacer, counter_key in _DECODE_PIPELINE:
            output, n = _safe_replace(output, pattern, replacer, mask)
            counters[counter_key] += n

        total = sum(counters.values())

        if total == 0:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No decodable escape sequences found.",
            )

        confidence = 0.85 + 0.01 * min(total, 15)
        confidence = min(confidence, 1.0)

        # Build a human-readable summary of what was decoded.
        parts: list[str] = []
        label_map = {
            "unicode_count": "Unicode escape",
            "hex_count": "hex escape",
            "octal_count": "octal escape",
            "html_entity_count": "HTML entity",
            "url_encode_count": "URL-encoded",
            "charcode_count": "charcode pattern",
        }
        for key, label in label_map.items():
            n = counters[key]
            if n > 0:
                parts.append(f"{n} {label}{'s' if n != 1 else ''}")

        description = f"Decoded {total} escape sequence(s): {', '.join(parts)}."

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=description,
            details={
                "total_replacements": total,
                **counters,
            },
        )
