"""
DeterministicRenamer -- identifies obfuscated variable names using pattern
analysis and usage-context heuristics, then *applies* the renames directly
to the source code.

For JavaScript-like inputs the transform now aims for JSNice-style
readability: idiomatic camelCase names, string-table/resolver recovery,
boolean prefixes, plural collection names, and optional post-rename
beautification when the source still looks compressed.
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult
from .source_preprocessor import beautify_source, detect_minified_source

# ---------------------------------------------------------------------------
# Reserved words -- never rename these
# ---------------------------------------------------------------------------

KEYWORDS: frozenset[str] = frozenset({
    # JavaScript
    "var", "let", "const", "function", "return", "if", "else", "for",
    "while", "do", "switch", "case", "break", "continue", "new", "this",
    "true", "false", "null", "undefined", "typeof", "instanceof", "void",
    "delete", "throw", "try", "catch", "finally", "class", "extends",
    "super", "import", "export", "default", "from", "as", "of", "in",
    "async", "await", "yield", "with", "debugger", "arguments",
    "constructor", "prototype", "get", "set", "static", "enum",
    "implements", "interface", "package", "private", "protected", "public",
    # Python
    "def", "class", "import", "from", "as", "if", "elif", "else",
    "for", "while", "break", "continue", "return", "yield", "try",
    "except", "finally", "raise", "with", "assert", "pass", "del",
    "lambda", "True", "False", "None", "and", "or", "not", "is", "in",
    "global", "nonlocal", "self", "cls", "print", "range", "len",
    "type", "int", "str", "float", "bool", "list", "dict", "set",
    "tuple", "bytes", "object", "property", "classmethod", "staticmethod",
    # PowerShell
    "param", "begin", "process", "end", "elseif", "foreach", "until",
    "trap", "exit",
    # C#
    "using", "namespace", "struct", "enum", "public", "private",
    "protected", "internal", "static", "void", "int", "string", "bool",
    "float", "double", "var", "new", "return", "foreach", "do",
    "switch", "case", "break", "continue", "try", "catch", "finally",
    "throw", "async", "await", "true", "false", "null", "this", "base",
    "ref", "out", "abstract", "sealed", "virtual", "override", "readonly",
    "volatile", "extern", "event", "delegate", "operator", "implicit",
    "explicit", "checked", "unchecked", "fixed", "lock", "stackalloc",
})

# ---------------------------------------------------------------------------
# Conventional short identifiers that should NOT be renamed
# ---------------------------------------------------------------------------

_CONVENTIONAL_SHORT: frozenset[str] = frozenset({
    "i", "j", "k", "x", "y", "z", "n", "e", "f", "m", "s", "t", "w", "h",
    "a", "b", "c", "d", "p", "q", "r", "v",
    "_",
})

# ---------------------------------------------------------------------------
# Common abbreviations that should NOT be renamed
# ---------------------------------------------------------------------------

_COMMON_ABBREVIATIONS: frozenset[str] = frozenset({
    # Standard library / builtins
    "str", "int", "len", "max", "min", "abs", "sum", "map", "err",
    "buf", "ptr", "idx", "ctx", "obj", "arg", "val", "key", "src",
    "dst", "tmp", "msg", "cmd", "req", "res", "ret", "ref", "fmt",
    "cfg", "env", "pos", "dir", "fn", "cb", "fd", "fs", "db", "io",
    # Common C/system names
    "strlen", "strcmp", "strcpy", "strcat", "memcpy", "malloc", "free",
    "printf", "sprintf", "fprintf", "scanf", "fopen", "fclose", "fread",
    # Common web / JS names
    "xhr", "dom", "url", "uri", "api", "img", "svg", "div", "btn",
    "nav", "css", "html", "jsx", "tsx", "doc", "win", "nav",
    # Common Python names
    "cls", "pkg", "sys", "pid", "uid", "gid", "cwd",
    # PowerShell
    "wmi", "adsi", "cli",
})

_JS_LIKE_LANGUAGES = {"javascript", "js", "typescript", "ts"}
_WORKSPACE_BUNDLE_HEADER = "UNWEAVER_WORKSPACE_BUNDLE v1"

# ---------------------------------------------------------------------------
# Obfuscation detection patterns
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hex_prefix", re.compile(r"\b_0x[a-fA-F0-9]{4,8}\b")),
    ("il_confusion", re.compile(r"\b(?=[Il1]*[I])(?=[Il1]*[l1])[Il1]{4,}\b")),
    ("consonant_soup", re.compile(r"\b[bcdfghjkmnpqrstvwxzBCDFGHJKMNPQRSTVWXZ]{4,}\b")),
    ("hash_name", re.compile(r"\b_[a-fA-F0-9]{8}\b")),
    ("generic_numbered", re.compile(r"\bvar\d+\b")),
    ("single_char", re.compile(r"\b([a-zA-Z])\b")),
]

# ---------------------------------------------------------------------------
# Context heuristics -- (pattern, semantic_prefix)
# ---------------------------------------------------------------------------

_CONTEXT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""https?://|['"]https?:""", re.IGNORECASE), "url"),
    (re.compile(
        r"XMLHttpRequest|fetch\s*\(|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE)|axios\.",
        re.IGNORECASE,
    ), "request"),
    (re.compile(
        r"""[A-Z]:\\|/tmp/|/etc/|/home/|\\\\|['"][./][\w/\\]+\.\w{1,5}['"]""",
        re.IGNORECASE,
    ), "filepath"),
    (re.compile(r"re\.compile|RegExp\s*\(|/[^/]+/[gimsuy]*", re.IGNORECASE), "pattern"),
    (re.compile(
        r"document\.\w+|\.getElementById|\.querySelector|\.innerHTML|\.appendChild|HTMLElement",
        re.IGNORECASE,
    ), "element"),
    (re.compile(
        r"crypto|encrypt|decrypt|cipher|base64|btoa|atob|encode|decode|hash|md5|sha|rc4",
        re.IGNORECASE,
    ), "cipher"),
    (re.compile(
        r"addEventListener|\.on\w+\s*=|callback|handler|\.then\s*\(|\.catch\s*\(|setTimeout|setInterval",
        re.IGNORECASE,
    ), "handler"),
    (re.compile(r"function\s+\$NAME|def\s+\$NAME|\$NAME\s*=\s*function"), "func"),
    (re.compile(
        r"\$NAME\s*=\s*\[|Array\s*\(|new\s+Array|\.push\s*\(|\.pop\s*\(|\.concat\s*\(|\.map\s*\(",
        re.IGNORECASE,
    ), "items"),
    (re.compile(
        r"\$NAME\s*\+\+|\$NAME\s*--|for\s*\(.*\$NAME.*\+\+|for\s.*\$NAME\s+in\s+range",
        re.IGNORECASE,
    ), "counter"),
]

_FALLBACK_PREFIX = "var"

_JS_PREFIX_BASES: dict[str, str] = {
    "url": "requestUrl",
    "request": "requestData",
    "filepath": "filePath",
    "pattern": "matchPattern",
    "element": "targetElement",
    "cipher": "decodedPayload",
    "handler": "callback",
    "func": "helperFunction",
    "items": "items",
    "counter": "index",
    "var": "value",
}

_BOOLEAN_NAME_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bready\b", re.IGNORECASE), "isReady"),
    (re.compile(r"\bloaded?\b", re.IGNORECASE), "isLoaded"),
    (re.compile(r"\bvalid\b", re.IGNORECASE), "isValid"),
    (re.compile(r"\benabled?\b", re.IGNORECASE), "isEnabled"),
    (re.compile(r"\bvisible\b", re.IGNORECASE), "isVisible"),
    (re.compile(r"\btoken\b", re.IGNORECASE), "hasToken"),
    (re.compile(r"\bpayload\b", re.IGNORECASE), "hasPayload"),
    (re.compile(r"\bvalue\b", re.IGNORECASE), "hasValue"),
    (re.compile(r"\bretry\b", re.IGNORECASE), "shouldRetry"),
    (re.compile(r"\bcontinue\b", re.IGNORECASE), "shouldContinue"),
]

_COLLECTION_NAME_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsplit\s*\(", re.IGNORECASE), "segments"),
    (re.compile(r"\bhandler\b|addEventListener", re.IGNORECASE), "handlers"),
    (re.compile(r"\btoken\b", re.IGNORECASE), "tokens"),
    (re.compile(r"\bstring\b|\bliteral\b", re.IGNORECASE), "strings"),
]


# ===================================================================
# Helper utilities
# ===================================================================

def _is_js_like(language: str) -> bool:
    return (language or "").lower().strip() in _JS_LIKE_LANGUAGES


def _collect_existing_identifiers(code: str) -> set[str]:
    return set(re.findall(r"\b[a-zA-Z_]\w*\b", code))


def _count_occurrences(code: str, name: str) -> int:
    return len(re.findall(r"\b" + re.escape(name) + r"\b", code))


def _get_assignment_rhs(code: str, name: str) -> str:
    escaped = re.escape(name)
    pat = re.compile(
        rf"(?:var|let|const|my|local)?\s*{escaped}\s*=\s*([^\n;]+)",
        re.IGNORECASE,
    )
    return " ".join(m.group(1).strip() for m in pat.finditer(code))


def _get_usage_context(code: str, name: str, window: int = 100) -> str:
    escaped = re.escape(name)
    pat = re.compile(rf".{{0,{window}}}{escaped}.{{0,{window}}}")
    return " ".join(m.group(0) for m in pat.finditer(code))[:5000]


def _get_function_snippets(code: str, name: str) -> str:
    escaped = re.escape(name)
    patterns = [
        re.compile(
            rf"function\s+{escaped}\s*\(([^)]*)\)\s*\{{([\s\S]{{0,1400}}?)\}}",
            re.IGNORECASE,
        ),
        re.compile(
            rf"(?:var|let|const)\s+{escaped}\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)\s*\{{([\s\S]{{0,1400}}?)\}}",
            re.IGNORECASE,
        ),
        re.compile(
            rf"(?:var|let|const)\s+{escaped}\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{{([\s\S]{{0,1400}}?)\}}",
            re.IGNORECASE,
        ),
        re.compile(
            rf"(?:var|let|const)\s+{escaped}\s*=\s*(?:async\s*)?([a-zA-Z_]\w*)\s*=>\s*\{{([\s\S]{{0,1400}}?)\}}",
            re.IGNORECASE,
        ),
        re.compile(
            rf"(?:var|let|const)\s+{escaped}\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*([^\n;]+)",
            re.IGNORECASE,
        ),
        re.compile(
            rf"(?:var|let|const)\s+{escaped}\s*=\s*(?:async\s*)?([a-zA-Z_]\w*)\s*=>\s*([^\n;]+)",
            re.IGNORECASE,
        ),
    ]
    snippets: list[str] = []
    for pattern in patterns:
        for match in pattern.finditer(code):
            snippets.extend(
                str(group).strip()
                for group in match.groups()
                if group and str(group).strip()
            )
    return " ".join(snippets)[:5000]


def _infer_semantic_prefix(code: str, name: str) -> str:
    assign_rhs = _get_assignment_rhs(code, name)
    usage_ctx = _get_usage_context(code, name)
    combined = assign_rhs + " " + usage_ctx

    best_prefix = ""
    best_score = 0

    for rule_pat, prefix in _CONTEXT_RULES:
        adjusted_src = rule_pat.pattern.replace("$NAME", re.escape(name))
        adjusted = re.compile(adjusted_src, rule_pat.flags)
        hits = len(adjusted.findall(combined))
        if hits and hits > best_score:
            best_score = hits
            best_prefix = prefix

    return best_prefix or _FALLBACK_PREFIX


def _build_string_mask(code: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    pattern = re.compile(
        r'(?:'
        r'"""[\s\S]*?"""|'
        r"'''[\s\S]*?'''|"
        r'`(?:[^`\\]|\\.)*`|'
        r'"(?:[^"\\]|\\.)*"|'
        r"'(?:[^'\\]|\\.)*'|"
        r'//[^\n]*|'
        r'#[^\n]*|'
        r'/\*[\s\S]*?\*/'
        r')'
    )
    for match in pattern.finditer(code):
        spans.append((match.start(), match.end()))
    return spans


def _position_in_string_or_comment(
    pos: int, spans: list[tuple[int, int]]
) -> bool:
    for start, end in spans:
        if start <= pos < end:
            return True
        if start > pos:
            break
    return False


def _safe_rename(
    code: str,
    old_name: str,
    new_name: str,
    protected_spans: list[tuple[int, int]],
) -> str:
    pat = re.compile(r"\b" + re.escape(old_name) + r"\b")
    matches = list(pat.finditer(code))
    for match in reversed(matches):
        if _position_in_string_or_comment(match.start(), protected_spans):
            continue
        code = code[:match.start()] + new_name + code[match.end():]
    return code


def _to_camel_case(value: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) and any(ch.isupper() for ch in value[1:]):
        candidate = value[0].lower() + value[1:]
        if not candidate[0].isalpha() and candidate[0] != "_":
            candidate = f"value{candidate}"
        return candidate

    parts = [part for part in re.split(r"[^a-zA-Z0-9]+", value) if part]
    if not parts:
        return "value"
    first = parts[0].lower()
    rest = [part[:1].upper() + part[1:].lower() for part in parts[1:]]
    candidate = first + "".join(rest)
    if not candidate[0].isalpha() and candidate[0] != "_":
        candidate = f"value{candidate}"
    return candidate


def _allocate_identifier(base: str, existing_ids: set[str]) -> str:
    candidate = _to_camel_case(base)
    if candidate not in existing_ids and candidate not in KEYWORDS:
        existing_ids.add(candidate)
        return candidate

    index = 2
    while True:
        numbered = f"{candidate}{index}"
        if numbered not in existing_ids and numbered not in KEYWORDS:
            existing_ids.add(numbered)
            return numbered
        index += 1


def _looks_like_string_table(rhs: str, combined: str) -> bool:
    quoted_entries = len(
        re.findall(r"""(['"])(?:(?=(\\?))\2.)*?\1""", rhs)
    )
    return (
        (
            bool(re.search(r"^\s*\[", rhs))
            and (
                quoted_entries >= 2
                or bool(
                    re.search(
                        r"(?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){3,}",
                        rhs,
                    )
                )
            )
        )
        or bool(
            re.search(
                r"""\.push\s*\(\s*\w+\.shift\s*\(""",
                combined,
                re.IGNORECASE,
            )
        )
    )


def _looks_like_string_resolver(function_src: str, combined: str) -> bool:
    return bool(
        re.search(
            r"""\breturn\s+\w+\s*\[\s*(?:0x[0-9a-fA-F]+|\d+|\w+)\s*\]""",
            function_src,
            re.IGNORECASE,
        )
        or re.search(r"\bparseInt\s*\(", function_src, re.IGNORECASE)
        or re.search(r"""\w+\s*\(\s*['"]0x[0-9a-fA-F]+['"]\s*\)""", combined)
    )


def _looks_like_decoder(function_src: str, combined: str) -> bool:
    return bool(
        re.search(
            r"\b(?:atob|btoa|decodeURIComponent|fromCharCode|charCodeAt|CryptoJS|RC4|rc4|decrypt|decode)\b",
            function_src + " " + combined,
            re.IGNORECASE,
        )
        or re.search(r"\.split\(\s*['\"]{0,1}\s*['\"]{0,1}\s*\)\.reverse\(\)\.join", function_src)
        or "^" in function_src
    )


def _looks_like_callback(combined: str) -> bool:
    return bool(
        re.search(
            r"\b(?:addEventListener|callback|handler|setTimeout|setInterval)\b|\.then\s*\(|\.catch\s*\(",
            combined,
            re.IGNORECASE,
        )
    )


def _looks_like_dom_element(combined: str) -> bool:
    return bool(
        re.search(
            r"\b(?:document|window)\b|getElementById|querySelector|createElement|HTMLElement",
            combined,
            re.IGNORECASE,
        )
    )


def _looks_like_collection(rhs: str, combined: str) -> bool:
    return bool(
        re.search(r"^\s*\[", rhs)
        or re.search(r"\bnew\s+Array\b|\bArray\s*\(", rhs, re.IGNORECASE)
        or re.search(r"\.(?:push|pop|map|filter|reduce|forEach|join|concat|slice)\s*\(", combined)
    )


def _looks_like_boolean(rhs: str, combined: str, name: str) -> bool:
    escaped = re.escape(name)
    strong_rhs = bool(
        re.search(r"\b(?:true|false)\b|!0\b|!1\b|!!\[\]|!\[\]", rhs, re.IGNORECASE)
    )
    comparison_usage = bool(
        re.search(
            rf"\b(?:if|while)\s*\(\s*!?\s*{escaped}\b|"
            rf"\b{escaped}\b\s*(?:===|!==|==|!=)\s*(?:true|false)|"
            rf"(?:true|false)\s*(?:===|!==|==|!=)\s*{escaped}\b",
            combined,
            re.IGNORECASE,
        )
    )
    return strong_rhs or comparison_usage


def _looks_like_index(combined: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(
            rf"\[\s*{escaped}\s*\]|\b{escaped}\s*\+\+|\b{escaped}\s*--|for\s*\([^)]*\b{escaped}\b[^)]*(?:\+\+|--)",
            combined,
            re.IGNORECASE,
        )
    )


def _looks_like_function(code: str, name: str, function_src: str) -> bool:
    if function_src:
        return True
    escaped = re.escape(name)
    return bool(
        re.search(rf"\bfunction\s+{escaped}\b", code)
        or re.search(rf"\b(?:var|let|const)\s+{escaped}\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>|[A-Za-z_]\w*\s*=>)", code)
    )


def _infer_boolean_name(combined: str) -> str:
    for pattern, candidate in _BOOLEAN_NAME_RULES:
        if pattern.search(combined):
            return candidate
    return "isEnabled"


def _infer_collection_name(combined: str) -> str:
    for pattern, candidate in _COLLECTION_NAME_RULES:
        if pattern.search(combined):
            return candidate
    return "items"


def _map_prefix_to_base(prefix: str, *, is_function: bool) -> str:
    base = _JS_PREFIX_BASES.get(prefix, _JS_PREFIX_BASES["var"])
    if is_function:
        if prefix == "url":
            return "resolveUrl"
        if prefix == "request":
            return "sendRequest"
        if prefix == "filepath":
            return "resolveFilePath"
        if prefix == "pattern":
            return "matchValue"
        if prefix == "element":
            return "resolveElement"
        if prefix == "cipher":
            return "decodeValue"
        if prefix == "handler":
            return "handleEvent"
        if prefix == "items":
            return "collectItems"
        if prefix == "counter":
            return "nextIndex"
        return "helperFunction"
    return base


def _infer_semantic_name(
    code: str,
    name: str,
    language: str,
    ptype: str,
) -> str:
    rhs = _get_assignment_rhs(code, name)
    usage_ctx = _get_usage_context(code, name)
    function_src = _get_function_snippets(code, name)
    combined = " ".join(part for part in (rhs, usage_ctx, function_src) if part)
    js_like = _is_js_like(language)
    is_function = _looks_like_function(code, name, function_src)

    if js_like:
        if _looks_like_string_table(rhs, combined):
            return "stringTable"
        if _looks_like_string_resolver(function_src, combined):
            return "resolveString"
        if _looks_like_decoder(function_src, combined):
            if re.search(r"\b(?:decrypt|rc4|xor|cipher|crypto)\b|\^", combined, re.IGNORECASE):
                return "decryptString" if is_function else "decryptedValue"
            return "decodeString" if is_function else "decodedValue"
        if _looks_like_dom_element(combined):
            return "targetElement"
        if _looks_like_callback(combined):
            return "handleEvent" if is_function else "callback"
        if _looks_like_boolean(rhs, combined, name):
            return _infer_boolean_name(combined)
        if _looks_like_index(combined, name):
            return "index"
        if re.search(r"\bfetch\s*\(", combined, re.IGNORECASE):
            return "fetchData" if is_function else "responsePromise"
        if re.search(r"\b(?:response|json\s*\(|text\s*\(|status)\b", combined, re.IGNORECASE):
            return "response"
        if _looks_like_collection(rhs, combined):
            return _infer_collection_name(combined)
        if ptype == "single_char" and re.search(r"\^", combined):
            return "byteValue"
        if ptype == "single_char" and re.search(r"\b(?:charCodeAt|fromCharCode)\b", combined, re.IGNORECASE):
            return "charCode"

    prefix = _infer_semantic_prefix(code, name)
    return _map_prefix_to_base(prefix, is_function=is_function) if js_like else prefix


def _maybe_beautify_renamed_code(code: str, language: str) -> tuple[str, str]:
    if not _is_js_like(language):
        return code, "none"
    if code.lstrip().startswith(_WORKSPACE_BUNDLE_HEADER):
        return code, "none"

    profile = detect_minified_source(code, language)
    if not profile.get("likely") and profile.get("max_line_length", 0) < 140:
        return code, "none"

    beautified, engine = beautify_source(code, language)
    if beautified and beautified != code:
        return beautified, engine
    return code, "none"


# ===================================================================
# Transform class
# ===================================================================


class DeterministicRenamer(BaseTransform):
    name = "DeterministicRenamer"
    description = (
        "Rename obfuscated identifiers with meaningful names based on "
        "usage context."
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        for ptype, pat in _OBFUSCATION_PATTERNS:
            if ptype == "single_char":
                for match in pat.finditer(code):
                    candidate = match.group(0)
                    if candidate in _CONVENTIONAL_SHORT or candidate in KEYWORDS:
                        continue
                    if _count_occurrences(code, candidate) >= 5:
                        return True
            else:
                if pat.search(code):
                    return True
        return False

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        candidates: dict[str, str] = {}

        for ptype, pat in _OBFUSCATION_PATTERNS:
            for match in pat.finditer(code):
                name = match.group(0)

                if ptype == "single_char":
                    if name in _CONVENTIONAL_SHORT:
                        continue
                    if _count_occurrences(code, name) < 5:
                        continue

                if name in KEYWORDS:
                    continue
                if name.lower() in _COMMON_ABBREVIATIONS:
                    continue
                if _count_occurrences(code, name) < 2:
                    continue

                candidates.setdefault(name, ptype)

        if not candidates:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No obfuscated identifiers detected.",
            )

        existing_ids = _collect_existing_identifiers(code)
        rename_map: dict[str, str] = {}
        patterns_detected: set[str] = set()

        for name, ptype in sorted(candidates.items(), key=lambda item: (-len(item[0]), item[0])):
            patterns_detected.add(ptype)
            semantic_name = _infer_semantic_name(code, name, language, ptype)
            rename_map[name] = _allocate_identifier(semantic_name, existing_ids)

        renamed_code = code
        renames_applied = 0

        for old_name in sorted(rename_map, key=len, reverse=True):
            new_name = rename_map[old_name]
            protected = _build_string_mask(renamed_code)
            before = renamed_code
            renamed_code = _safe_rename(renamed_code, old_name, new_name, protected)
            if renamed_code != before:
                renames_applied += 1

        if renames_applied == 0:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Obfuscated names found but no safe renames could be applied.",
                details={
                    "renames_applied": 0,
                    "rename_map": rename_map,
                    "patterns_detected": sorted(patterns_detected),
                },
            )

        beautifier = "none"
        beautified_code, beautifier = _maybe_beautify_renamed_code(renamed_code, language)
        renamed_code = beautified_code

        confidence = 0.60 + 0.02 * min(renames_applied, 20)
        if beautifier != "none":
            confidence += 0.03
        confidence = min(confidence, 0.95)

        state.setdefault("applied_renames", {}).update(rename_map)

        return TransformResult(
            success=True,
            output=renamed_code,
            confidence=round(confidence, 2),
            description=(
                f"Renamed {renames_applied} obfuscated identifier(s) "
                f"across {len(patterns_detected)} pattern type(s)."
            ),
            details={
                "renames_applied": renames_applied,
                "rename_map": rename_map,
                "patterns_detected": sorted(patterns_detected),
                "rename_style": "jsnice-inspired" if _is_js_like(language) else "semantic-prefix",
                "beautifier": beautifier,
            },
        )
