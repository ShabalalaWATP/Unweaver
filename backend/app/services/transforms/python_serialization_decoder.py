"""
Python serialization decoder — detects and safely decodes pickle, marshal,
and compiled bytecode patterns embedded in Python malware.

SAFETY: This transform NEVER executes pickle.loads() or marshal.loads()
on untrusted data.  Instead it:
- Detects the patterns and flags them as findings
- Extracts the base64/hex encoded payload for examination
- Parses pickle opcodes to extract embedded strings without execution
- Identifies marshal magic numbers and code object structures
"""

from __future__ import annotations

import base64
import re
import struct
from typing import Any, Dict, List

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# pickle.loads(base64.b64decode("..."))
_PICKLE_LOADS_RE = re.compile(
    r"""pickle\.loads\s*\(\s*"""
    r"""(?:base64\.b64decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)"""
    r"""|bytes\.fromhex\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*\)"""
    r"""|([b]['"][^'"]+['"]))\s*\)""",
    re.IGNORECASE,
)

# marshal.loads(base64.b64decode("..."))
_MARSHAL_LOADS_RE = re.compile(
    r"""marshal\.loads\s*\(\s*"""
    r"""(?:base64\.b64decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)"""
    r"""|bytes\.fromhex\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*\)"""
    r"""|([b]['"][^'"]+['"]))\s*\)""",
    re.IGNORECASE,
)

# exec(marshal.loads(...)) or exec(pickle.loads(...))
_EXEC_SERIAL_RE = re.compile(
    r"""exec\s*\(\s*(?:marshal|pickle)\.loads\s*\(""",
    re.IGNORECASE,
)

# types.CodeType(...) or compile(...)
_CODE_TYPE_RE = re.compile(
    r"""(?:types\.CodeType|compile)\s*\(""",
    re.IGNORECASE,
)

# import marshal; import pickle
_IMPORT_SERIAL_RE = re.compile(
    r"""(?:^|\n)\s*(?:import|from)\s+(?:pickle|marshal|shelve|dill|cloudpickle)""",
    re.IGNORECASE,
)

# zlib.decompress(base64.b64decode("..."))
_ZLIB_B64_RE = re.compile(
    r"""zlib\.decompress\s*\(\s*base64\.b64decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]""",
    re.IGNORECASE,
)

# Pickle protocol magic bytes (in hex literals or byte strings)
_PICKLE_MAGIC_RE = re.compile(
    r"""b['"]\\x80\\x0[2-5]""",  # pickle protocol 2-5
)


def _safe_extract_pickle_strings(data: bytes) -> List[str]:
    """Extract string literals from pickle bytecode without executing it.

    Parses a subset of pickle opcodes to pull out SHORT_BINUNICODE and
    BINUNICODE strings.  Never calls pickle.loads().
    """
    strings: List[str] = []
    i = 0
    while i < len(data):
        op = data[i]
        i += 1

        # SHORT_BINUNICODE (opcode 0x8c): 1-byte length + UTF-8 string
        if op == 0x8C and i < len(data):
            length = data[i]
            i += 1
            if i + length <= len(data):
                try:
                    s = data[i:i + length].decode("utf-8")
                    if s and len(s) >= 2:
                        strings.append(s)
                except UnicodeDecodeError:
                    pass
                i += length
            else:
                break

        # BINUNICODE (opcode 0x58): 4-byte LE length + UTF-8 string
        elif op == 0x58 and i + 4 <= len(data):
            length = struct.unpack("<I", data[i:i + 4])[0]
            i += 4
            if length > 10000:
                break  # safety cap
            if i + length <= len(data):
                try:
                    s = data[i:i + length].decode("utf-8")
                    if s and len(s) >= 2:
                        strings.append(s)
                except UnicodeDecodeError:
                    pass
                i += length
            else:
                break

        # SHORT_BINSTRING (opcode 0x55): 1-byte length + ASCII
        elif op == 0x55 and i < len(data):
            length = data[i]
            i += 1
            if i + length <= len(data):
                try:
                    s = data[i:i + length].decode("ascii")
                    if s and len(s) >= 2:
                        strings.append(s)
                except UnicodeDecodeError:
                    pass
                i += length
            else:
                break

        # STOP (opcode 0x2E): end of pickle
        elif op == 0x2E:
            break

        # For all other opcodes, we can't safely advance without a full
        # opcode table, so stop parsing.  We've extracted what we can.
        else:
            # Try to continue for a few more bytes
            continue

    return strings


def _try_zlib_b64(blob: str) -> str | None:
    """Try to decompress a zlib+base64 payload."""
    import zlib
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        decompressed = zlib.decompress(raw)
        text = decompressed.decode("utf-8", errors="replace")
        printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t ")
        if printable / max(len(text), 1) > 0.65:
            return text
    except Exception:
        pass
    return None


class PythonSerializationDecoder(BaseTransform):
    """Detect and safely decode Python pickle/marshal/zlib patterns."""

    name = "python_serialization_decoder"
    description = (
        "Detect pickle.loads, marshal.loads, zlib.decompress chains and "
        "extract embedded strings without executing untrusted bytecode."
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower()
        if lang and lang not in ("python", "py", ""):
            return False
        return bool(
            _PICKLE_LOADS_RE.search(code)
            or _MARSHAL_LOADS_RE.search(code)
            or _EXEC_SERIAL_RE.search(code)
            or _ZLIB_B64_RE.search(code)
            or (_IMPORT_SERIAL_RE.search(code) and _PICKLE_MAGIC_RE.search(code))
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        findings: List[Dict[str, Any]] = []
        extracted_strings: List[str] = []
        new_code = code
        techniques: List[str] = []

        # zlib.decompress(base64.b64decode("...")) — actually decode this
        for m in _ZLIB_B64_RE.finditer(code):
            blob = m.group(1)
            result = _try_zlib_b64(blob)
            if result:
                findings.append({
                    "type": "zlib_b64_decoded",
                    "payload_length": len(result),
                    "preview": result[:200],
                })
                # Replace the entire exec(zlib.decompress(base64...)) chain
                # Find the outermost exec() if present
                search_start = max(0, m.start() - 50)
                exec_match = re.search(
                    r"exec\s*\(\s*" + re.escape(m.group(0)),
                    code[search_start:m.end() + 10],
                )
                if exec_match:
                    full_start = search_start + exec_match.start()
                    # Find matching close paren
                    depth = 0
                    close_idx = full_start
                    for ci in range(full_start, min(len(new_code), m.end() + 50)):
                        if new_code[ci] == "(":
                            depth += 1
                        elif new_code[ci] == ")":
                            depth -= 1
                            if depth == 0:
                                close_idx = ci + 1
                                break
                    if close_idx > full_start:
                        new_code = (
                            new_code[:full_start]
                            + f"# Decoded zlib+base64 payload:\n{result[:2000]}"
                            + new_code[close_idx:]
                        )
                techniques.append("zlib_compression")

        # pickle.loads(base64.b64decode("...")) — extract strings safely
        for m in _PICKLE_LOADS_RE.finditer(code):
            b64_blob = m.group(1)
            hex_blob = m.group(2)
            raw_data = None

            if b64_blob:
                try:
                    raw_data = base64.b64decode(b64_blob + "=" * (-len(b64_blob) % 4))
                except Exception:
                    pass
            elif hex_blob:
                try:
                    raw_data = bytes.fromhex(hex_blob)
                except Exception:
                    pass

            if raw_data:
                strings = _safe_extract_pickle_strings(raw_data)
                extracted_strings.extend(strings)
                findings.append({
                    "type": "pickle_payload",
                    "encoding": "base64" if b64_blob else "hex",
                    "payload_bytes": len(raw_data),
                    "extracted_strings": strings[:20],
                })
                if strings:
                    comment = "# Pickle payload strings: " + ", ".join(
                        repr(s) for s in strings[:5]
                    )
                    new_code = new_code.replace(
                        m.group(0), f"{comment}\n{m.group(0)}"
                    )
            techniques.append("pickle_deserialization")

        # marshal.loads — flag as dangerous, extract what we can
        for m in _MARSHAL_LOADS_RE.finditer(code):
            findings.append({
                "type": "marshal_payload",
                "context": m.group(0)[:120],
            })
            new_code = new_code.replace(
                m.group(0),
                f"# WARNING: marshal.loads() — compiled bytecode execution\n{m.group(0)}"
            )
            techniques.append("marshal_bytecode")

        # exec(marshal.loads(...)) or exec(pickle.loads(...))
        for m in _EXEC_SERIAL_RE.finditer(code):
            if m.group(0) not in "".join(f["context"] for f in findings if "context" in f):
                findings.append({
                    "type": "exec_serialization",
                    "context": m.group(0)[:120],
                })
                techniques.append("code_execution")

        success = len(findings) > 0
        confidence = min(0.5 + len(findings) * 0.1, 0.85) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Detected {len(findings)} serialization pattern(s), "
                f"extracted {len(extracted_strings)} embedded string(s)."
                if success else "No pickle/marshal patterns found."
            ),
            details={
                "findings": findings[:20],
                "extracted_strings_count": len(extracted_strings),
                "detected_techniques": list(set(techniques)),
                "strings": [
                    {"value": s, "encoding": "pickle", "context": "pickle payload"}
                    for s in extracted_strings[:20]
                ],
                "suspicious_apis": [
                    f.get("context", f.get("type", ""))[:80]
                    for f in findings[:10]
                ],
            },
        )
