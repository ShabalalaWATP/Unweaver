"""
Isolated marshal-analysis worker.

This script is executed in a separate Python process with ``-I -S`` so the
main app can inspect hostile marshal payloads without unmarshalling them in the
primary process.
"""

from __future__ import annotations

import base64
import dis
import json
import marshal
import sys
import types
from typing import Any

MAX_CODE_OBJECTS = 64
MAX_DIS_LINES = 160
MAX_CONTAINER_ITEMS = 64
MAX_STRING_LENGTH = 200


def _trim_text(value: str, limit: int = MAX_STRING_LENGTH) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _stringify_bytes(value: bytes) -> str | None:
    for encoding in ("utf-8", "latin-1", "utf-16-le"):
        try:
            decoded = value.decode(encoding)
        except Exception:
            continue
        printable = sum(1 for char in decoded if char.isprintable() or char in "\r\n\t ")
        if printable / max(len(decoded), 1) >= 0.7:
            return _trim_text(decoded.replace("\x00", ""))
    return None


def _record_string(target: list[str], seen: set[str], value: str) -> None:
    cleaned = value.strip()
    if not cleaned or cleaned in seen:
        return
    seen.add(cleaned)
    target.append(_trim_text(cleaned))


def _safe_json_value(value: Any) -> str:
    try:
        rendered = repr(value)
    except Exception:
        rendered = f"<unreprable {type(value).__name__}>"
    return _trim_text(rendered, 160)


def _walk_marshaled_object(
    obj: Any,
    strings: list[str],
    string_seen: set[str],
    *,
    depth: int = 0,
) -> None:
    if depth > 4:
        return
    if isinstance(obj, str):
        _record_string(strings, string_seen, obj)
        return
    if isinstance(obj, (bytes, bytearray)):
        decoded = _stringify_bytes(bytes(obj))
        if decoded:
            _record_string(strings, string_seen, decoded)
        return
    if isinstance(obj, types.CodeType):
        return
    if isinstance(obj, dict):
        for idx, (key, value) in enumerate(obj.items()):
            if idx >= MAX_CONTAINER_ITEMS:
                break
            _walk_marshaled_object(key, strings, string_seen, depth=depth + 1)
            _walk_marshaled_object(value, strings, string_seen, depth=depth + 1)
        return
    if isinstance(obj, (list, tuple, set, frozenset)):
        for idx, item in enumerate(obj):
            if idx >= MAX_CONTAINER_ITEMS:
                break
            _walk_marshaled_object(item, strings, string_seen, depth=depth + 1)


def _analyze_code_object(root: types.CodeType) -> dict[str, Any]:
    queue: list[types.CodeType] = [root]
    visited: set[int] = set()
    strings: list[str] = []
    string_seen: set[str] = set()
    function_names: list[str] = []
    function_seen: set[str] = set()
    imports: list[str] = []
    import_seen: set[str] = set()
    disassembly_preview: list[str] = []
    code_summaries: list[dict[str, Any]] = []

    while queue and len(code_summaries) < MAX_CODE_OBJECTS:
        code_obj = queue.pop(0)
        if id(code_obj) in visited:
            continue
        visited.add(id(code_obj))

        if code_obj.co_name and code_obj.co_name not in {"<module>", "<lambda>"}:
            if code_obj.co_name not in function_seen:
                function_seen.add(code_obj.co_name)
                function_names.append(code_obj.co_name)

        const_strings: list[str] = []
        for const in code_obj.co_consts:
            if isinstance(const, str):
                trimmed = _trim_text(const)
                const_strings.append(trimmed)
                _record_string(strings, string_seen, trimmed)
            elif isinstance(const, (bytes, bytearray)):
                decoded = _stringify_bytes(bytes(const))
                if decoded:
                    const_strings.append(decoded)
                    _record_string(strings, string_seen, decoded)
            elif isinstance(const, types.CodeType):
                queue.append(const)
            else:
                _walk_marshaled_object(const, strings, string_seen, depth=1)

        names = [_trim_text(name, 80) for name in code_obj.co_names[:40]]
        varnames = [_trim_text(name, 80) for name in code_obj.co_varnames[:20]]

        for instruction in dis.get_instructions(code_obj):
            if instruction.opname == "IMPORT_NAME" and isinstance(instruction.argval, str):
                if instruction.argval not in import_seen:
                    import_seen.add(instruction.argval)
                    imports.append(instruction.argval)
            if len(disassembly_preview) < MAX_DIS_LINES:
                arg_repr = ""
                if instruction.argval is not None:
                    arg_repr = " " + _safe_json_value(instruction.argval)
                prefix = code_obj.co_name or "<code>"
                disassembly_preview.append(
                    f"{prefix}:{instruction.offset:04d} {instruction.opname}{arg_repr}"
                )

        code_summaries.append(
            {
                "name": code_obj.co_name,
                "filename": _trim_text(code_obj.co_filename, 120),
                "firstlineno": code_obj.co_firstlineno,
                "argcount": code_obj.co_argcount,
                "names": names,
                "varnames": varnames,
                "const_strings": const_strings[:20],
            }
        )

    return {
        "top_level_type": "code",
        "code_object_count": len(code_summaries),
        "code_objects": code_summaries,
        "function_names": function_names[:40],
        "imports": imports[:40],
        "strings": strings[:120],
        "disassembly_preview": disassembly_preview,
    }


def main() -> int:
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        print(json.dumps({"ok": False, "error": "no_input"}))
        return 1

    try:
        request = json.loads(raw_input)
        payload_b64 = request["payload_b64"]
        payload = base64.b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"decode_failed: {exc}"}))
        return 1

    try:
        obj = marshal.loads(payload)
    except BaseException as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "python_version": sys.version.split()[0],
                }
            )
        )
        return 0

    analysis: dict[str, Any]
    if isinstance(obj, types.CodeType):
        analysis = _analyze_code_object(obj)
    else:
        strings: list[str] = []
        _walk_marshaled_object(obj, strings, set())
        analysis = {
            "top_level_type": type(obj).__name__,
            "code_object_count": 0,
            "code_objects": [],
            "function_names": [],
            "imports": [],
            "strings": strings[:120],
            "disassembly_preview": [],
        }

    print(
        json.dumps(
            {
                "ok": True,
                "python_version": sys.version.split()[0],
                "analysis": analysis,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
