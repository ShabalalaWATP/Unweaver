"""
Python serialization decoder — detects and safely decodes pickle, marshal,
and compiled bytecode patterns embedded in Python malware.

SAFETY:
- The main process never executes pickle.loads() or marshal.loads().
- Pickle handling remains non-executing and string-focused.
- Marshal payloads are analysed in a short-lived isolated helper process
  using only the local Python stdlib, then converted into metadata,
  strings, imports, function names, and disassembly previews.
"""

from __future__ import annotations

import base64
import ast
import json
import subprocess
import re
import struct
import sys
from pathlib import Path
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

_URL_FRAGMENT_RE = re.compile(
    r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?",
    re.IGNORECASE,
)
_IDENTIFIER_FRAGMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,63}")
_ANGLE_NAME_FRAGMENT_RE = re.compile(r"<[A-Za-z_][A-Za-z0-9_]{0,63}>")
_MARSHAL_WORKER_PATH = Path(__file__).with_name("_marshal_worker.py")
_MARSHAL_WORKER_TIMEOUT_SECONDS = 3.0
_MAX_MARSHAL_ANALYSIS_BYTES = 1024 * 1024


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


def _unique_strings(values: List[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _extract_printable_strings(data: bytes, min_length: int = 3) -> List[str]:
    strings: List[str] = []
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)

    for match in ascii_pattern.finditer(data):
        try:
            strings.append(match.group(0).decode("ascii"))
        except Exception:
            continue

    for match in utf16_pattern.finditer(data):
        try:
            strings.append(match.group(0).decode("utf-16-le"))
        except Exception:
            continue

    return _unique_strings(strings)


def _refine_serialized_strings(values: List[str]) -> List[str]:
    refined: List[str] = []
    for value in values:
        cleaned = value.strip(" \t\r\n\x00")
        if not cleaned:
            continue

        urls = _URL_FRAGMENT_RE.findall(cleaned)
        if urls:
            refined.extend(
                re.sub(r"(?<=[a-z])[A-Z]{1,2}$", "", url)
                for url in urls
            )
            continue

        angle_names = _ANGLE_NAME_FRAGMENT_RE.findall(cleaned)
        if angle_names:
            refined.extend(angle_names)
            continue

        identifiers = [m.group(0) for m in _IDENTIFIER_FRAGMENT_RE.finditer(cleaned)]
        if cleaned.isidentifier():
            refined.append(cleaned)
        elif identifiers and len(cleaned) > 12:
            refined.extend(identifiers[:8])
            continue
        elif len(cleaned) >= 4:
            refined.append(cleaned)

    return _suppress_near_duplicate_strings(_unique_strings(refined))


def _string_priority(value: str) -> tuple[int, int]:
    if _URL_FRAGMENT_RE.fullmatch(value):
        return (0, len(value))
    if _ANGLE_NAME_FRAGMENT_RE.fullmatch(value):
        return (1, len(value))
    if value.isidentifier():
        return (2, len(value))
    return (3, len(value))


def _suppress_near_duplicate_strings(values: List[str]) -> List[str]:
    accepted: List[str] = []
    for candidate in sorted(_unique_strings(values), key=_string_priority):
        if any(
            (
                accepted_value in candidate or candidate in accepted_value
            ) and abs(len(candidate) - len(accepted_value)) <= 2
            for accepted_value in accepted
        ):
            continue
        accepted.append(candidate)
    return accepted


def _decode_inline_bytes_literal(blob: str | None) -> bytes | None:
    if not blob:
        return None
    try:
        value = ast.literal_eval(blob)
    except Exception:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _load_serialized_bytes(
    b64_blob: str | None,
    hex_blob: str | None,
    bytes_blob: str | None,
) -> bytes | None:
    if b64_blob:
        try:
            return base64.b64decode(b64_blob + "=" * (-len(b64_blob) % 4))
        except Exception:
            return None
    if hex_blob:
        try:
            return bytes.fromhex(hex_blob)
        except Exception:
            return None
    return _decode_inline_bytes_literal(bytes_blob)


def _run_marshal_worker(raw_data: bytes) -> Dict[str, Any] | None:
    if not raw_data or len(raw_data) > _MAX_MARSHAL_ANALYSIS_BYTES:
        return None
    if not _MARSHAL_WORKER_PATH.exists():
        return None

    payload = json.dumps(
        {"payload_b64": base64.b64encode(raw_data).decode("ascii")}
    )
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(_MARSHAL_WORKER_PATH)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=_MARSHAL_WORKER_TIMEOUT_SECONDS,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "error_type": "TimeoutExpired"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "error_type": type(exc).__name__}

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()

    if not stdout:
        return {
            "ok": False,
            "error": stderr or f"worker_exit_{completed.returncode}",
            "error_type": "WorkerFailure",
        }

    try:
        data = json.loads(stdout)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"invalid_worker_output: {exc}",
            "error_type": "WorkerProtocolError",
            "raw_output": stdout[:400],
        }

    if completed.returncode != 0 and data.get("ok") is not True:
        data.setdefault("error", stderr or f"worker_exit_{completed.returncode}")
    return data


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


def _build_marshal_annotation_lines(
    marshal_strings: List[str],
    worker_analysis: Dict[str, Any] | None,
) -> List[str]:
    lines = ["# WARNING: marshal.loads() — compiled bytecode execution"]
    if marshal_strings:
        lines.append(
            "# Marshal payload strings: " + ", ".join(repr(s) for s in marshal_strings[:5])
        )

    if worker_analysis and worker_analysis.get("ok") and isinstance(worker_analysis.get("analysis"), dict):
        analysis = worker_analysis["analysis"]
        imports = analysis.get("imports", [])
        functions = analysis.get("function_names", [])
        python_version = worker_analysis.get("python_version")
        code_object_count = analysis.get("code_object_count", 0)
        if python_version:
            lines.append(
                f"# Marshal worker: isolated stdlib subprocess (python {python_version}, code objects={code_object_count})"
            )
        if imports:
            lines.append("# Marshal imports: " + ", ".join(repr(item) for item in imports[:8]))
        if functions:
            lines.append("# Marshal functions: " + ", ".join(repr(item) for item in functions[:8]))
        preview = analysis.get("disassembly_preview", [])
        if preview:
            lines.append("# Marshal disassembly preview:")
            lines.extend(f"#   {line}" for line in preview[:12])
    elif worker_analysis and worker_analysis.get("error"):
        lines.append(
            "# Marshal worker note: " + repr(worker_analysis.get("error"))[1:-1]
        )

    return lines


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
        annotation_lines: List[str] = []
        recovered_imports: List[str] = []
        recovered_functions: List[str] = []
        marshal_worker_reports: List[Dict[str, Any]] = []
        disassembly_previews: List[str] = []

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
            raw_data = _load_serialized_bytes(m.group(1), m.group(2), m.group(3))

            if raw_data:
                strings = _safe_extract_pickle_strings(raw_data)
                strings.extend(_extract_printable_strings(raw_data))
                strings = _refine_serialized_strings(strings)
                extracted_strings.extend(strings)
                findings.append({
                    "type": "pickle_payload",
                    "encoding": (
                        "base64" if m.group(1)
                        else "hex" if m.group(2)
                        else "bytes"
                    ),
                    "payload_bytes": len(raw_data),
                    "extracted_strings": strings[:20],
                })
                if strings:
                    annotation_lines.append(
                        "# Pickle payload strings: " + ", ".join(
                            repr(s) for s in strings[:5]
                        )
                    )
            techniques.append("pickle_deserialization")

        # marshal.loads — flag as dangerous, extract what we can
        for m in _MARSHAL_LOADS_RE.finditer(code):
            raw_data = _load_serialized_bytes(m.group(1), m.group(2), m.group(3))
            marshal_strings = []
            worker_report: Dict[str, Any] | None = None
            if raw_data:
                marshal_strings = _refine_serialized_strings(
                    _extract_printable_strings(raw_data)
                )
                worker_report = _run_marshal_worker(raw_data)
                if worker_report:
                    marshal_worker_reports.append(worker_report)
                if worker_report and worker_report.get("ok") and isinstance(worker_report.get("analysis"), dict):
                    analysis = worker_report["analysis"]
                    marshal_strings.extend(analysis.get("strings", []))
                    recovered_imports.extend(analysis.get("imports", []))
                    recovered_functions.extend(analysis.get("function_names", []))
                    disassembly_previews.extend(analysis.get("disassembly_preview", [])[:24])
                    for code_summary in analysis.get("code_objects", []):
                        if not isinstance(code_summary, dict):
                            continue
                        marshal_strings.extend(code_summary.get("names", []))
                        marshal_strings.extend(code_summary.get("varnames", []))

                marshal_strings = _refine_serialized_strings(marshal_strings)
            extracted_strings.extend(marshal_strings)
            findings.append({
                "type": "marshal_payload",
                "context": m.group(0)[:120],
                "payload_bytes": len(raw_data) if raw_data else 0,
                "extracted_strings": marshal_strings[:20],
                "imports": _unique_strings(recovered_imports)[:10],
                "function_names": _unique_strings(recovered_functions)[:10],
                "worker_ok": bool(worker_report and worker_report.get("ok")),
                "worker_error": (worker_report or {}).get("error"),
            })
            annotation_lines.extend(
                _build_marshal_annotation_lines(marshal_strings, worker_report)
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
        extracted_strings = _unique_strings(extracted_strings)
        recovered_imports = _unique_strings(recovered_imports)
        recovered_functions = _unique_strings(recovered_functions)
        disassembly_previews = _unique_strings(disassembly_previews)
        if annotation_lines:
            header = "\n".join(_unique_strings(annotation_lines))
            if header not in new_code:
                new_code = header + "\n" + new_code
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
                "imports": recovered_imports[:30],
                "functions": recovered_functions[:30],
                "strings": [
                    {"value": s, "encoding": "serialized_payload", "context": "serialized payload"}
                    for s in extracted_strings[:20]
                ],
                "decoded_strings": [
                    {"encoded": "serialized_payload", "decoded": s}
                    for s in extracted_strings[:20]
                ],
                "decoded_artifacts": extracted_strings[:20],
                "marshal_analysis": marshal_worker_reports[:10],
                "disassembly_preview": disassembly_previews[:40],
                "suspicious_apis": [
                    f.get("context", f.get("type", ""))[:80]
                    for f in findings[:10]
                ],
            },
        )
