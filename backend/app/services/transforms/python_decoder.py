"""
PythonDecoder transform -- handles Python-specific obfuscation techniques:

  - exec(base64.b64decode(...))
  - zlib.decompress + base64
  - marshal.loads
  - Reversed strings
  - String rotation / ROT13
  - codecs.decode with rot_13
  - Layered encoding combinations
"""

from __future__ import annotations

import base64
import codecs
import re
import zlib
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# exec(base64.b64decode('...'))
# ---------------------------------------------------------------------------

_EXEC_B64 = re.compile(
    r"\bexec\s*\(\s*"
    r"(?:base64\.b64decode|b64decode)\s*\(\s*"
    r"""['"]([\s\S]*?)['"]\s*\)\s*"""
    r"(?:\.decode\s*\(\s*['\"][\w-]+['\"]\s*\))?\s*\)",
)

_STANDALONE_B64DECODE = re.compile(
    r"(?:base64\.b64decode|b64decode)\s*\(\s*"
    r"""['"]([\s\S]*?)['"]\s*\)"""
)

# ---------------------------------------------------------------------------
# zlib.decompress(base64.b64decode('...'))
# ---------------------------------------------------------------------------

_ZLIB_B64 = re.compile(
    r"\bzlib\.decompress\s*\(\s*"
    r"(?:base64\.b64decode|b64decode)\s*\(\s*"
    r"""['"]([\s\S]*?)['"]\s*\)\s*\)""",
)

# exec(zlib.decompress(base64.b64decode('...')))
_EXEC_ZLIB_B64 = re.compile(
    r"\bexec\s*\(\s*"
    r"zlib\.decompress\s*\(\s*"
    r"(?:base64\.b64decode|b64decode)\s*\(\s*"
    r"""['"]([\s\S]*?)['"]\s*\)\s*\)"""
    r"(?:\.decode\s*\(\s*['\"][\w-]+['\"]\s*\))?\s*\)",
)

# ---------------------------------------------------------------------------
# marshal.loads(...)
# ---------------------------------------------------------------------------

_MARSHAL_LOADS = re.compile(
    r"\bmarshal\.loads\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
)

# ---------------------------------------------------------------------------
# Reversed strings:  exec("".join(reversed("..."))  or  "..."[::-1]
# ---------------------------------------------------------------------------

_REVERSED_JOIN = re.compile(
    r"""(?:""|'')\s*\.join\s*\(\s*reversed\s*\(\s*['"]([\s\S]*?)['"]\s*\)\s*\)"""
)

_SLICE_REVERSE = re.compile(
    r"""['"]([\s\S]*?)['"]\s*\[\s*:\s*:\s*-1\s*\]"""
)

# ---------------------------------------------------------------------------
# ROT13:  codecs.decode('...', 'rot_13')  or  codecs.decode('...', 'rot13')
# ---------------------------------------------------------------------------

_CODECS_ROT13 = re.compile(
    r"""\bcodecs\.decode\s*\(\s*['"]([\s\S]*?)['"]\s*,\s*['"]rot[_-]?13['"]\s*\)"""
)

# exec(codecs.decode('...', 'rot_13'))
_EXEC_ROT13 = re.compile(
    r"""\bexec\s*\(\s*codecs\.decode\s*\(\s*['"]([\s\S]*?)['"]\s*,\s*['"]rot[_-]?13['"]\s*\)\s*\)"""
)

# ---------------------------------------------------------------------------
# Generic chr() building:  exec("".join([chr(x) for x in [72, 101, ...]]))
# ---------------------------------------------------------------------------

_CHR_LIST = re.compile(
    r"""(?:""|'')\s*\.join\s*\(\s*\[\s*chr\s*\(\s*\w+\s*\)\s+for\s+\w+\s+in\s+\[([\d,\s]+)\]\s*\]\s*\)"""
)

# exec("".join(map(chr, [72, 101, ...])))
_CHR_MAP = re.compile(
    r"""(?:""|'')\s*\.join\s*\(\s*map\s*\(\s*chr\s*,\s*\[([\d,\s]+)\]\s*\)\s*\)"""
)


def _try_b64_decode(blob: str) -> str | None:
    """Decode base64, return string or None."""
    cleaned = blob.replace(" ", "").replace("\n", "").replace("\r", "")
    missing = len(cleaned) % 4
    if missing:
        cleaned += "=" * (4 - missing)
    try:
        raw = base64.b64decode(cleaned, validate=True)
        text = raw.decode("utf-8")
        return text
    except Exception:
        try:
            raw = base64.b64decode(cleaned)
            return raw.decode("latin-1")
        except Exception:
            return None


def _try_zlib_b64_decode(blob: str) -> str | None:
    """Decode base64 then decompress with zlib."""
    cleaned = blob.replace(" ", "").replace("\n", "").replace("\r", "")
    missing = len(cleaned) % 4
    if missing:
        cleaned += "=" * (4 - missing)
    try:
        raw = base64.b64decode(cleaned, validate=True)
        decompressed = zlib.decompress(raw)
        return decompressed.decode("utf-8")
    except Exception:
        try:
            raw = base64.b64decode(cleaned)
            decompressed = zlib.decompress(raw)
            return decompressed.decode("latin-1")
        except Exception:
            return None


def _rot13(text: str) -> str:
    """Apply ROT13 transformation."""
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        # Manual fallback
        result = []
        for c in text:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)


def _chr_from_list(nums_str: str) -> str | None:
    """Convert a comma-separated list of ints to a string via chr()."""
    try:
        nums = [int(n.strip()) for n in nums_str.split(",") if n.strip()]
        return "".join(chr(n) for n in nums)
    except Exception:
        return None


class PythonDecoder(BaseTransform):
    name = "python_decoder"
    description = (
        "Decode Python obfuscation: exec+base64, zlib, marshal, "
        "reversed strings, ROT13, codecs"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang and lang not in ("python", "py", ""):
            return False
        indicators = [
            r"\bexec\s*\(",
            r"\bbase64\.",
            r"\bzlib\.",
            r"\bmarshal\.loads",
            r"\bcodecs\.decode",
            r"\[::-1\]",
            r"\breversed\s*\(",
        ]
        return any(re.search(p, code) for p in indicators)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        changes: list[dict[str, Any]] = []

        # --- exec(zlib.decompress(base64.b64decode('...'))) ---
        for m in _EXEC_ZLIB_B64.finditer(output):
            decoded = _try_zlib_b64_decode(m.group(1))
            if decoded:
                changes.append({
                    "type": "exec_zlib_b64",
                    "encoded": m.group(1)[:80],
                    "decoded": decoded[:2000],
                })
                output = output.replace(
                    m.group(0),
                    f"# DECODED (exec+zlib+b64):\n{decoded}",
                    1,
                )

        # --- zlib + base64 (non-exec) ---
        for m in _ZLIB_B64.finditer(output):
            # Skip if already handled above
            if f"# DECODED (exec+zlib+b64):" in output and m.group(1)[:40] in output:
                continue
            decoded = _try_zlib_b64_decode(m.group(1))
            if decoded:
                changes.append({
                    "type": "zlib_b64",
                    "encoded": m.group(1)[:80],
                    "decoded": decoded[:2000],
                })
                output = output.replace(
                    m.group(0),
                    f'"""DECODED (zlib+b64): {decoded}"""',
                    1,
                )

        # --- exec(base64.b64decode('...')) ---
        for m in _EXEC_B64.finditer(output):
            decoded = _try_b64_decode(m.group(1))
            if decoded:
                changes.append({
                    "type": "exec_b64",
                    "encoded": m.group(1)[:80],
                    "decoded": decoded[:2000],
                })
                output = output.replace(
                    m.group(0),
                    f"# DECODED (exec+b64):\n{decoded}",
                    1,
                )

        # --- exec(codecs.decode('...', 'rot_13')) ---
        for m in _EXEC_ROT13.finditer(output):
            decoded = _rot13(m.group(1))
            changes.append({
                "type": "exec_rot13",
                "encoded": m.group(1)[:200],
                "decoded": decoded[:2000],
            })
            output = output.replace(
                m.group(0),
                f"# DECODED (exec+rot13):\n{decoded}",
                1,
            )

        # --- codecs.decode('...', 'rot_13') standalone ---
        for m in _CODECS_ROT13.finditer(output):
            decoded = _rot13(m.group(1))
            changes.append({
                "type": "rot13",
                "encoded": m.group(1)[:200],
                "decoded": decoded[:2000],
            })
            output = output.replace(
                m.group(0),
                f'"{decoded}"',
                1,
            )

        # --- Reversed strings ---
        for m in _REVERSED_JOIN.finditer(output):
            decoded = m.group(1)[::-1]
            changes.append({
                "type": "reversed_join",
                "encoded": m.group(1)[:200],
                "decoded": decoded,
            })
            output = output.replace(m.group(0), f'"{decoded}"', 1)

        for m in _SLICE_REVERSE.finditer(output):
            decoded = m.group(1)[::-1]
            changes.append({
                "type": "slice_reverse",
                "encoded": m.group(1)[:200],
                "decoded": decoded,
            })
            output = output.replace(m.group(0), f'"{decoded}"', 1)

        # --- chr() list building ---
        for pat in (_CHR_LIST, _CHR_MAP):
            for m in pat.finditer(output):
                decoded = _chr_from_list(m.group(1))
                if decoded:
                    changes.append({
                        "type": "chr_list",
                        "encoded": m.group(0)[:120],
                        "decoded": decoded,
                    })
                    output = output.replace(m.group(0), f'"{decoded}"', 1)

        # --- marshal.loads detection (flag only, can't safely decode) ---
        for m in _MARSHAL_LOADS.finditer(output):
            changes.append({
                "type": "marshal_loads",
                "expression": m.group(0)[:200],
                "note": "marshal.loads found -- contains serialized code objects",
            })

        # --- standalone base64.b64decode ---
        for m in _STANDALONE_B64DECODE.finditer(output):
            # Only process if not already handled
            if m.group(1)[:40] not in str(changes):
                decoded = _try_b64_decode(m.group(1))
                if decoded:
                    changes.append({
                        "type": "b64decode",
                        "encoded": m.group(1)[:80],
                        "decoded": decoded[:2000],
                    })
                    output = output.replace(
                        m.group(0),
                        f'"""DECODED (b64): {decoded}"""',
                        1,
                    )

        if not changes:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No Python obfuscation patterns decoded.",
            )

        state.setdefault("py_decoded", []).extend(changes)

        type_counts: dict[str, int] = {}
        for c in changes:
            t = c["type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        confidence = min(0.95, 0.70 + 0.05 * len(changes))
        summary = ", ".join(f"{v} {k}" for k, v in type_counts.items())

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=f"Decoded Python obfuscation: {summary}.",
            details={
                "change_count": len(changes),
                "type_counts": type_counts,
                "changes": changes,
            },
        )
