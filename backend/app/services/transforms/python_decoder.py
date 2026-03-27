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

import ast
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

_EXEC_START = re.compile(r"\bexec\s*\(")
_EXEC_COMPILE_START = re.compile(r"\bexec\s*\(\s*compile\s*\(")

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


def _decode_bytes(raw: bytes, encoding: str | None = None) -> str | None:
    encodings = [encoding] if encoding else []
    encodings.extend(["utf-8", "utf-16-le", "latin-1"])
    seen: set[str] = set()
    for candidate in encodings:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            return raw.decode(candidate)
        except Exception:
            continue
    return None


def _normalise_embedded_source(text: str) -> str:
    value = text.replace("\r\n", "\n").strip()
    prefixes = (
        "DECODED (b64):",
        "DECODED (zlib+b64):",
    )
    for prefix in prefixes:
        if value.startswith(prefix):
            return value[len(prefix):].lstrip()
    return value


def _skip_python_string(code: str, start: int) -> int:
    quote = code[start]
    triple = code[start:start + 3] == quote * 3
    if triple:
        idx = start + 3
        while idx < len(code) - 2:
            if code[idx] == "\\":
                idx += 2
                continue
            if code[idx:idx + 3] == quote * 3:
                return idx + 3
            idx += 1
        return len(code)

    idx = start + 1
    while idx < len(code):
        if code[idx] == "\\":
            idx += 2
            continue
        if code[idx] == quote:
            return idx + 1
        idx += 1
    return len(code)


def _find_matching_paren(code: str, start: int) -> int | None:
    if start >= len(code) or code[start] != "(":
        return None
    depth = 0
    idx = start
    while idx < len(code):
        char = code[idx]
        if char == "#":
            newline = code.find("\n", idx)
            if newline == -1:
                return None
            idx = newline + 1
            continue
        if char in {"'", '"'}:
            idx = _skip_python_string(code, idx)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return None


def _simple_callable_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
    ):
        return f"{node.value.value.id}.{node.value.attr}.{node.attr}"
    return None


def _resolve_python_value(
    node: ast.AST,
    bindings: dict[str, str | bytes],
) -> str | bytes | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, bytes)):
            return node.value
        return None

    if isinstance(node, ast.Name):
        return bindings.get(node.id)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_python_value(node.left, bindings)
        right = _resolve_python_value(node.right, bindings)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, bytes) and isinstance(right, bytes):
            return left + right
        return None

    if isinstance(node, ast.Call):
        callable_name = _simple_callable_name(node.func)

        if callable_name in {"base64.b64decode", "b64decode"} and node.args:
            blob = _resolve_python_value(node.args[0], bindings)
            try:
                if isinstance(blob, str):
                    return base64.b64decode(blob)
                if isinstance(blob, bytes):
                    return base64.b64decode(blob)
            except Exception:
                return None
            return None

        if callable_name == "zlib.decompress" and node.args:
            raw = _resolve_python_value(node.args[0], bindings)
            if isinstance(raw, bytes):
                try:
                    return zlib.decompress(raw)
                except Exception:
                    return None
            return None

        if callable_name == "bytes.fromhex" and node.args:
            blob = _resolve_python_value(node.args[0], bindings)
            if isinstance(blob, str):
                try:
                    return bytes.fromhex(blob)
                except Exception:
                    return None
            return None

        if callable_name == "codecs.decode" and len(node.args) >= 2:
            text_value = _resolve_python_value(node.args[0], bindings)
            codec_value = _resolve_python_value(node.args[1], bindings)
            if isinstance(text_value, str) and isinstance(codec_value, str):
                if codec_value.lower().replace("-", "_") == "rot_13":
                    return _rot13(text_value)
            return None

        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            raw = _resolve_python_value(node.func.value, bindings)
            encoding = None
            if node.args:
                enc_value = _resolve_python_value(node.args[0], bindings)
                if isinstance(enc_value, str):
                    encoding = enc_value
            if isinstance(raw, bytes):
                return _decode_bytes(raw, encoding)
            return None

    return None


def _collect_string_bindings(code: str) -> dict[str, str | bytes]:
    try:
        tree = ast.parse(code)
    except Exception:
        return {}

    bindings: dict[str, str | bytes] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _resolve_python_value(node.value, bindings)
            if isinstance(value, (str, bytes)):
                bindings[node.targets[0].id] = value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            value = _resolve_python_value(node.value, bindings)
            if isinstance(value, (str, bytes)):
                bindings[node.target.id] = value
    return bindings


def _iter_exec_compile_blocks(code: str) -> list[tuple[int, int, str]]:
    blocks: list[tuple[int, int, str]] = []
    for match in _EXEC_COMPILE_START.finditer(code):
        open_index = code.find("(", match.start())
        if open_index == -1:
            continue
        close_index = _find_matching_paren(code, open_index)
        if close_index is None:
            continue
        blocks.append((match.start(), close_index + 1, code[match.start():close_index + 1]))
    return blocks


def _iter_exec_blocks(code: str) -> list[tuple[int, int, str]]:
    blocks: list[tuple[int, int, str]] = []
    for match in _EXEC_START.finditer(code):
        open_index = code.find("(", match.start())
        if open_index == -1:
            continue
        close_index = _find_matching_paren(code, open_index)
        if close_index is None:
            continue
        blocks.append((match.start(), close_index + 1, code[match.start():close_index + 1]))
    return blocks


def _extract_exec_source(
    expression: str,
    bindings: dict[str, str | bytes],
) -> str | None:
    try:
        tree = ast.parse(expression, mode="eval")
    except Exception:
        return None

    call = tree.body
    if not isinstance(call, ast.Call):
        return None
    if _simple_callable_name(call.func) != "exec" or not call.args:
        return None

    source_value = _resolve_python_value(call.args[0], bindings)
    if isinstance(source_value, bytes):
        text = _decode_bytes(source_value)
    elif isinstance(source_value, str):
        text = source_value
    else:
        return None

    if not text:
        return None
    return _normalise_embedded_source(text)


def _extract_compile_source(
    expression: str,
    bindings: dict[str, str | bytes],
) -> str | None:
    try:
        tree = ast.parse(expression, mode="eval")
    except Exception:
        return None

    call = tree.body
    if not isinstance(call, ast.Call):
        return None
    if _simple_callable_name(call.func) != "exec" or not call.args:
        return None

    compile_call = call.args[0]
    if not isinstance(compile_call, ast.Call):
        return None
    if _simple_callable_name(compile_call.func) != "compile":
        return None
    if len(compile_call.args) < 3:
        return None

    mode_value = _resolve_python_value(compile_call.args[2], bindings)
    if mode_value != "exec":
        return None

    source_value = _resolve_python_value(compile_call.args[0], bindings)
    if isinstance(source_value, bytes):
        text = _decode_bytes(source_value)
    elif isinstance(source_value, str):
        text = source_value
    else:
        return None

    if not text:
        return None
    return _normalise_embedded_source(text)


def _render_exec_compile_replacement(code: str, start: int, decoded: str) -> str:
    line_start = code.rfind("\n", 0, start) + 1
    prefix = code[line_start:start]
    indent = prefix if prefix.strip() == "" else ""
    body = decoded.replace("\r\n", "\n").strip()
    if not body:
        return decoded
    rendered_body = "\n".join(
        f"{indent}{line}" if line else ""
        for line in body.splitlines()
    )
    return f"# DECODED (exec+compile):\n{rendered_body}"


def _render_exec_replacement(code: str, start: int, label: str, decoded: str) -> str:
    line_start = code.rfind("\n", 0, start) + 1
    prefix = code[line_start:start]
    indent = prefix if prefix.strip() == "" else ""
    body = decoded.replace("\r\n", "\n").strip()
    if not body:
        return decoded
    rendered_body = "\n".join(
        f"{indent}{line}" if line else ""
        for line in body.splitlines()
    )
    return f"# DECODED ({label}):\n{rendered_body}"


class PythonDecoder(BaseTransform):
    name = "python_decoder"
    description = (
        "Decode Python obfuscation: exec+base64, zlib, exec+compile, marshal, "
        "reversed strings, ROT13, codecs"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang and lang not in ("python", "py", ""):
            return False
        indicators = [
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
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

        # --- exec(...) wrappers backed by variable/layered decode chains ---
        bindings = _collect_string_bindings(output)
        for start, end, expression in reversed(_iter_exec_blocks(output)):
            decoded = _extract_exec_source(expression, bindings)
            if not decoded:
                continue
            changes.append({
                "type": "exec_resolved",
                "encoded": expression[:120],
                "decoded": decoded[:2000],
            })
            replacement = _render_exec_replacement(output, start, "exec", decoded)
            output = output[:start] + replacement + output[end:]
            bindings = _collect_string_bindings(output)

        # --- exec(compile(..., 'exec')) wrappers ---
        bindings = _collect_string_bindings(output)
        for start, end, expression in reversed(_iter_exec_compile_blocks(output)):
            decoded = _extract_compile_source(expression, bindings)
            if not decoded:
                continue
            changes.append({
                "type": "exec_compile",
                "encoded": expression[:120],
                "decoded": decoded[:2000],
            })
            replacement = _render_exec_compile_replacement(output, start, decoded)
            output = output[:start] + replacement + output[end:]
            bindings = _collect_string_bindings(output)

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
