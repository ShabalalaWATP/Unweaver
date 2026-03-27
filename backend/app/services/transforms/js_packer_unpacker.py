"""
JavaScript packer unpacker.

Supports the standard Dean Edwards Packer family:
    eval(function(p,a,c,k,e,d){...}('payload',62,123,'symtab'.split('|'),0,{}))

The transform never executes the packed code. It only parses the static
payload, symbol table, and radix/count parameters, then performs the
deterministic token substitution locally.
"""

from __future__ import annotations

import ast
import re
from typing import Any, List

from .base import BaseTransform, TransformResult

_PACKER_HEAD = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)",
    re.IGNORECASE,
)

_SYMTAB_SPLIT_RE = re.compile(
    r"^(?P<literal>(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"))"
    r"\s*\.split\(\s*(?P<sep>(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"))\s*\)$",
    re.DOTALL,
)

_WORD_RE = re.compile(r"\b\w+\b")
_BASE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _skip_js_string(code: str, start: int) -> int:
    quote = code[start]
    idx = start + 1
    while idx < len(code):
        if code[idx] == "\\":
            idx += 2
            continue
        if code[idx] == quote:
            return idx + 1
        idx += 1
    return len(code)


def _skip_js_comment(code: str, start: int) -> int:
    if code.startswith("//", start):
        newline = code.find("\n", start)
        return len(code) if newline == -1 else newline + 1
    if code.startswith("/*", start):
        end = code.find("*/", start + 2)
        return len(code) if end == -1 else end + 2
    return start


def _find_matching(code: str, start: int, open_char: str, close_char: str) -> int | None:
    if start >= len(code) or code[start] != open_char:
        return None
    depth = 0
    idx = start
    while idx < len(code):
        if code[idx] in {"'", '"', "`"}:
            idx = _skip_js_string(code, idx)
            continue
        if code.startswith("//", idx) or code.startswith("/*", idx):
            idx = _skip_js_comment(code, idx)
            continue
        if code[idx] == open_char:
            depth += 1
        elif code[idx] == close_char:
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return None


def _split_top_level_args(text: str) -> List[str]:
    parts: List[str] = []
    start = 0
    depth_paren = 0
    depth_brace = 0
    depth_bracket = 0
    idx = 0
    while idx < len(text):
        char = text[idx]
        if char in {"'", '"', "`"}:
            idx = _skip_js_string(text, idx)
            continue
        if text.startswith("//", idx) or text.startswith("/*", idx):
            idx = _skip_js_comment(text, idx)
            continue
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren -= 1
        elif char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace -= 1
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket -= 1
        elif char == "," and depth_paren == 0 and depth_brace == 0 and depth_bracket == 0:
            parts.append(text[start:idx].strip())
            start = idx + 1
        idx += 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_js_literal(token: str) -> str | None:
    try:
        value = ast.literal_eval(token)
    except Exception:
        return None
    return value if isinstance(value, str) else None


def _parse_symbol_table(token: str) -> list[str] | None:
    match = _SYMTAB_SPLIT_RE.match(token.strip())
    if match:
        literal = _parse_js_literal(match.group("literal"))
        separator = _parse_js_literal(match.group("sep"))
        if literal is None or separator is None:
            return None
        return literal.split(separator)

    try:
        value = ast.literal_eval(token)
    except Exception:
        return None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _decode_base_token(token: str, base: int) -> int | None:
    if not token or base < 2 or base > len(_BASE_ALPHABET):
        return None
    value = 0
    for char in token:
        index = _BASE_ALPHABET.find(char)
        if index < 0 or index >= base:
            return None
        value = value * base + index
    return value


def _unpack_payload(payload: str, base: int, count: int, symtab: list[str]) -> str:
    def replace_word(match: re.Match[str]) -> str:
        token = match.group(0)
        index = _decode_base_token(token, base)
        if index is None or index >= count or index >= len(symtab):
            return token
        replacement = symtab[index]
        return replacement or token

    return _WORD_RE.sub(replace_word, payload)


class JavaScriptPackerUnpacker(BaseTransform):
    name = "js_packer_unpacker"
    description = "Unpack standard Dean Edwards Packer JavaScript payloads"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang and lang not in ("javascript", "js", "jsx", "typescript", "ts", "tsx", ""):
            return False
        return bool(_PACKER_HEAD.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        changes: list[dict[str, Any]] = []

        for match in reversed(list(_PACKER_HEAD.finditer(code))):
            brace_open = code.find("{", match.end())
            if brace_open == -1:
                continue
            brace_close = _find_matching(code, brace_open, "{", "}")
            if brace_close is None:
                continue

            invoke_open = brace_close + 1
            while invoke_open < len(code) and code[invoke_open].isspace():
                invoke_open += 1
            if invoke_open >= len(code) or code[invoke_open] != "(":
                continue

            invoke_close = _find_matching(code, invoke_open, "(", ")")
            if invoke_close is None:
                continue

            args = _split_top_level_args(code[invoke_open + 1:invoke_close])
            if len(args) < 4:
                continue

            payload = _parse_js_literal(args[0])
            symtab = _parse_symbol_table(args[3])
            if payload is None or symtab is None:
                continue

            try:
                base = int(args[1].strip(), 10)
                count = int(args[2].strip(), 10)
            except Exception:
                continue

            unpacked = _unpack_payload(payload, base, count, symtab)
            if unpacked == payload:
                continue

            replace_end = invoke_close + 1
            while replace_end < len(code) and code[replace_end].isspace():
                replace_end += 1
            if replace_end < len(code) and code[replace_end] == ")":
                replace_end += 1

            output = output[:match.start()] + unpacked + output[replace_end:]
            changes.append(
                {
                    "type": "dean_edwards_packer",
                    "radix": base,
                    "symbol_count": len(symtab),
                    "decoded": unpacked[:2000],
                }
            )

        if not changes:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No Dean Edwards Packer payloads could be unpacked.",
            )

        return TransformResult(
            success=True,
            output=output,
            confidence=min(0.95, 0.8 + 0.05 * len(changes)),
            description=f"Unpacked {len(changes)} Dean Edwards Packer payload(s).",
            details={
                "change_count": len(changes),
                "changes": changes,
                "decoded_strings": [{"encoded": "dean_edwards_packer", "decoded": item["decoded"]} for item in changes],
                "detected_techniques": ["dean_edwards_packer"],
            },
        )
