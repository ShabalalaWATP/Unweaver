"""
IOCExtractor -- extracts Indicators of Compromise from source code:

  - IP addresses (v4, v6)
  - URLs and domains
  - Email addresses
  - File paths (Windows, Unix)
  - Registry keys
  - Hashes (MD5, SHA1, SHA256)
  - Defanged indicators (hxxp, [.], etc.)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .base import BaseTransform, TransformResult


@dataclass
class IOC:
    """A single Indicator of Compromise."""

    type: str
    value: str
    defanged: bool = False
    original: str = ""  # original text before refanging
    context: str = ""   # surrounding code snippet
    start: int = 0
    end: int = 0


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# IPv4
_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|1?\d\d?)){3})\b"
)

# IPv4 defanged:  1[.]2[.]3[.]4  or  1(.)2(.)3(.)4
_IPV4_DEFANGED = re.compile(
    r"\b(\d{1,3}\s*[\[\(]\.[\]\)]\s*\d{1,3}\s*[\[\(]\.[\]\)]\s*"
    r"\d{1,3}\s*[\[\(]\.[\]\)]\s*\d{1,3})\b"
)

# IPv6 (simplified -- captures common forms)
_IPV6 = re.compile(
    r"\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b"
)

# URLs (http, https, ftp)
_URL = re.compile(
    r"((?:https?|ftp)://[^\s\"'<>(){}\[\]|\\^`,;]{4,})",
    re.IGNORECASE,
)

# Defanged URLs: hxxp(s)://  or  http[s]://  or  http[:]//
_URL_DEFANGED = re.compile(
    r"(hxxps?://[^\s\"'<>(){}\[\]|\\^`,;]{4,})",
    re.IGNORECASE,
)

_URL_DEFANGED2 = re.compile(
    r"(https?\[:\]//[^\s\"'<>(){}\[\]|\\^`,;]{4,})",
    re.IGNORECASE,
)

# Domains (basic -- requires at least one dot)
_DOMAIN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.(?:com|net|org|info|io|co|me|xyz|top|biz|ru|cn|tk|ml|ga|cf|gq"
    r"|pw|onion|bit|cc|ws|su|de|uk|fr|it|br|in|au|ca|nl|pl|es|cz"
    r"|edu|gov|mil|int))\b",
    re.IGNORECASE,
)

# Defanged domains: evil[.]com  or  evil(.)com
_DOMAIN_DEFANGED = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\s*[\[\(]\.[\]\)]\s*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
    r"\s*[\[\(]\.[\]\)]\s*(?:com|net|org|info|io|co|me|xyz|top|biz|ru|cn|tk"
    r"|onion|edu|gov))\b",
    re.IGNORECASE,
)

# Email
_EMAIL = re.compile(
    r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)

# Defanged email: user[@]domain[.]com  or  user[at]domain[dot]com
_EMAIL_DEFANGED = re.compile(
    r"\b([a-zA-Z0-9_.+-]+\s*[\[\(](?:@|at)[\]\)]\s*"
    r"[a-zA-Z0-9-]+\s*[\[\(](?:\.|dot)[\]\)]\s*[a-zA-Z0-9-.]+)\b",
    re.IGNORECASE,
)

# Windows file paths
_WIN_PATH = re.compile(
    r"([A-Za-z]:\\(?:[^\s\\:*?\"<>|]+\\)*[^\s\\:*?\"<>|]*)"
)

# UNC paths
_UNC_PATH = re.compile(
    r"(\\\\[^\s\\:*?\"<>|]+(?:\\[^\s\\:*?\"<>|]+)*)"
)

# Unix paths (at least 2 components to reduce false positives)
_UNIX_PATH = re.compile(
    r"((?:/[a-zA-Z0-9_.@-]+){2,})"
)

# Registry keys
_REGISTRY = re.compile(
    r"((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER"
    r"|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
    r"\\[^\s\"']+)",
    re.IGNORECASE,
)

# Hashes
_SHA256 = re.compile(r"\b([a-fA-F0-9]{64})\b")
_SHA1 = re.compile(r"\b([a-fA-F0-9]{40})\b")
_MD5 = re.compile(r"\b([a-fA-F0-9]{32})\b")


def _refang(text: str) -> str:
    """Convert defanged indicators back to their real form."""
    result = text
    result = re.sub(r"\[\.?\]", ".", result)
    result = re.sub(r"\(\.?\)", ".", result)
    result = re.sub(r"\[:\]", ":", result)
    result = re.sub(r"\[at\]", "@", result, flags=re.IGNORECASE)
    result = re.sub(r"\(at\)", "@", result, flags=re.IGNORECASE)
    result = re.sub(r"\[dot\]", ".", result, flags=re.IGNORECASE)
    result = re.sub(r"\(dot\)", ".", result, flags=re.IGNORECASE)
    result = re.sub(r"^hxxp", "http", result, flags=re.IGNORECASE)
    result = result.replace(" ", "")
    return result


def _get_context(code: str, start: int, end: int, width: int = 40) -> str:
    """Get surrounding context for an IOC match."""
    ctx_start = max(0, start - width)
    ctx_end = min(len(code), end + width)
    return code[ctx_start:ctx_end].replace("\n", " ").strip()


def _is_false_positive_ip(ip: str) -> bool:
    """Check for common false-positive IPs (version numbers, etc.)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return True
    # Version-number-like: 0.0.0.0, 127.0.0.1 are valid IOCs
    # but things like 1.0.0 or values > 255 are not IPs
    if any(n > 255 for n in nums):
        return True
    # Skip broadcast / unspecified
    if ip in ("0.0.0.0", "255.255.255.255"):
        return False  # These are still IOCs
    return False


def _is_likely_hash(candidate: str, length: int) -> bool:
    """Check if a hex string is likely a hash vs. just hex data."""
    # Must be exactly the right length and all hex
    if len(candidate) != length:
        return False
    # Should contain a mix of digits and letters (pure digits = likely a number)
    has_alpha = any(c in "abcdefABCDEF" for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    return has_alpha and has_digit


class IOCExtractor(BaseTransform):
    name = "ioc_extractor"
    description = "Extract Indicators of Compromise (IPs, URLs, domains, hashes, paths, etc.)"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(code and len(code.strip()) > 10)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        iocs: list[IOC] = []
        seen_values: set[str] = set()

        def _add(ioc: IOC) -> None:
            key = f"{ioc.type}:{ioc.value}"
            if key not in seen_values:
                seen_values.add(key)
                iocs.append(ioc)

        # --- IPv4 ---
        for m in _IPV4.finditer(code):
            ip = m.group(1)
            if not _is_false_positive_ip(ip):
                _add(IOC(
                    type="ipv4", value=ip,
                    context=_get_context(code, m.start(), m.end()),
                    start=m.start(), end=m.end(),
                ))

        # --- IPv4 defanged ---
        for m in _IPV4_DEFANGED.finditer(code):
            original = m.group(1)
            refanged = _refang(original)
            if not _is_false_positive_ip(refanged):
                _add(IOC(
                    type="ipv4", value=refanged, defanged=True,
                    original=original,
                    context=_get_context(code, m.start(), m.end()),
                    start=m.start(), end=m.end(),
                ))

        # --- IPv6 ---
        for m in _IPV6.finditer(code):
            _add(IOC(
                type="ipv6", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- URLs ---
        for m in _URL.finditer(code):
            _add(IOC(
                type="url", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- Defanged URLs ---
        for pat in (_URL_DEFANGED, _URL_DEFANGED2):
            for m in pat.finditer(code):
                original = m.group(1)
                refanged = _refang(original)
                _add(IOC(
                    type="url", value=refanged, defanged=True,
                    original=original,
                    context=_get_context(code, m.start(), m.end()),
                    start=m.start(), end=m.end(),
                ))

        # --- Domains ---
        for m in _DOMAIN.finditer(code):
            _add(IOC(
                type="domain", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- Defanged domains ---
        for m in _DOMAIN_DEFANGED.finditer(code):
            original = m.group(1)
            refanged = _refang(original)
            _add(IOC(
                type="domain", value=refanged, defanged=True,
                original=original,
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- Emails ---
        for m in _EMAIL.finditer(code):
            _add(IOC(
                type="email", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        for m in _EMAIL_DEFANGED.finditer(code):
            original = m.group(1)
            refanged = _refang(original)
            _add(IOC(
                type="email", value=refanged, defanged=True,
                original=original,
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- File paths ---
        for m in _WIN_PATH.finditer(code):
            _add(IOC(
                type="windows_path", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        for m in _UNC_PATH.finditer(code):
            _add(IOC(
                type="unc_path", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        for m in _UNIX_PATH.finditer(code):
            path = m.group(1)
            # Skip common false positives
            if path.startswith("/usr/bin") or path.startswith("/etc"):
                pass  # These are valid IOCs
            _add(IOC(
                type="unix_path", value=path,
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- Registry keys ---
        for m in _REGISTRY.finditer(code):
            _add(IOC(
                type="registry_key", value=m.group(1),
                context=_get_context(code, m.start(), m.end()),
                start=m.start(), end=m.end(),
            ))

        # --- Hashes (check SHA256 before SHA1 before MD5 to avoid subsets) ---
        sha256_positions: set[tuple[int, int]] = set()
        for m in _SHA256.finditer(code):
            if _is_likely_hash(m.group(1), 64):
                sha256_positions.add((m.start(), m.end()))
                _add(IOC(
                    type="sha256", value=m.group(1).lower(),
                    context=_get_context(code, m.start(), m.end()),
                    start=m.start(), end=m.end(),
                ))

        sha1_positions: set[tuple[int, int]] = set()
        for m in _SHA1.finditer(code):
            # Skip if this is part of a SHA256 match
            if any(s <= m.start() and m.end() <= e for s, e in sha256_positions):
                continue
            if _is_likely_hash(m.group(1), 40):
                sha1_positions.add((m.start(), m.end()))
                _add(IOC(
                    type="sha1", value=m.group(1).lower(),
                    context=_get_context(code, m.start(), m.end()),
                    start=m.start(), end=m.end(),
                ))

        for m in _MD5.finditer(code):
            # Skip if part of SHA256 or SHA1
            if any(s <= m.start() and m.end() <= e for s, e in sha256_positions):
                continue
            if any(s <= m.start() and m.end() <= e for s, e in sha1_positions):
                continue
            if _is_likely_hash(m.group(1), 32):
                _add(IOC(
                    type="md5", value=m.group(1).lower(),
                    context=_get_context(code, m.start(), m.end()),
                    start=m.start(), end=m.end(),
                ))

        if not iocs:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No IOCs extracted.",
            )

        # Group by type
        type_counts: dict[str, int] = {}
        for ioc in iocs:
            type_counts[ioc.type] = type_counts.get(ioc.type, 0) + 1

        defanged_count = sum(1 for i in iocs if i.defanged)

        state.setdefault("iocs", []).extend([
            {
                "type": i.type,
                "value": i.value,
                "defanged": i.defanged,
                "original": i.original,
                "context": i.context,
                "start": i.start,
                "end": i.end,
            }
            for i in iocs
        ])

        summary = ", ".join(f"{v} {k}" for k, v in type_counts.items())
        confidence = min(0.95, 0.60 + 0.05 * len(iocs))

        return TransformResult(
            success=True,
            output=code,
            confidence=confidence,
            description=(
                f"Extracted {len(iocs)} IOC(s): {summary}."
                + (f" ({defanged_count} defanged)" if defanged_count else "")
            ),
            details={
                "ioc_count": len(iocs),
                "type_counts": type_counts,
                "defanged_count": defanged_count,
                "iocs": [
                    {
                        "type": i.type,
                        "value": i.value,
                        "defanged": i.defanged,
                        "original": i.original,
                        "context": i.context,
                    }
                    for i in iocs
                ],
            },
        )
