"""
DeterministicRenamer -- identifies obfuscated variable names using pattern
analysis and usage-context heuristics, then *applies* the renames directly
to the source code.  Unlike RenameSuggester (which only proposes names),
this transform rewrites every matched identifier in-place and returns the
modified source.
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

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
# These are legitimate short variable/function names used by real developers
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

# ---------------------------------------------------------------------------
# Obfuscation detection patterns
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # _0x-prefixed hex identifiers (e.g. _0x3a8f, _0x1eabc7d2)
    ("hex_prefix", re.compile(r"\b_0x[a-fA-F0-9]{4,8}\b")),
    # Il1-confusion identifiers (mix of uppercase-I, lowercase-l, digit-1)
    ("il_confusion", re.compile(r"\b(?=[Il1]*[I])(?=[Il1]*[l1])[Il1]{4,}\b")),
    # Random consonant soup (4+ consecutive consonants, no vowels)
    ("consonant_soup", re.compile(r"\b[bcdfghjkmnpqrstvwxzBCDFGHJKMNPQRSTVWXZ]{4,}\b")),
    # Hash-style names: _<8+ hex chars>
    ("hash_name", re.compile(r"\b_[a-fA-F0-9]{8}\b")),
    # Generic numbered variables: var1, var2, ...
    ("generic_numbered", re.compile(r"\bvar\d+\b")),
    # Single-character variables (filtered later by frequency & convention)
    ("single_char", re.compile(r"\b([a-zA-Z])\b")),
]

# ---------------------------------------------------------------------------
# Context heuristics -- (pattern, semantic_prefix)
# ---------------------------------------------------------------------------

_CONTEXT_RULES: list[tuple[re.Pattern[str], str]] = [
    # URL / endpoint
    (re.compile(r"""https?://|['"]https?:""", re.IGNORECASE), "url"),
    # Fetch / XHR / request
    (re.compile(
        r"XMLHttpRequest|fetch\s*\(|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE)",
        re.IGNORECASE,
    ), "request"),
    # File path
    (re.compile(
        r"""[A-Z]:\\|/tmp/|/etc/|/home/|\\\\|['"][./][\w/\\]+\.\w{1,5}['"]""",
        re.IGNORECASE,
    ), "filepath"),
    # Regex / pattern
    (re.compile(r"re\.compile|RegExp\s*\(|/[^/]+/[gimsuy]*", re.IGNORECASE), "pattern"),
    # DOM / document
    (re.compile(
        r"document\.\w+|\.getElementById|\.querySelector|\.innerHTML|\.appendChild",
        re.IGNORECASE,
    ), "element"),
    # Crypto / encode / decode
    (re.compile(
        r"crypto|encrypt|decrypt|cipher|base64|btoa|atob|encode|decode|hash|md5|sha",
        re.IGNORECASE,
    ), "cipher"),
    # Callback / handler (function passed as arg or assigned)
    (re.compile(
        r"addEventListener|\.on\w+\s*=|callback|handler|\.then\s*\(|\.catch\s*\(",
        re.IGNORECASE,
    ), "handler"),
    # Function definition
    (re.compile(r"function\s+\$NAME|def\s+\$NAME|\$NAME\s*=\s*function"), "func"),
    # Array / list
    (re.compile(
        r"\$NAME\s*=\s*\[|Array\s*\(|new\s+Array|\.push\s*\(|\.pop\s*\(|\.concat\s*\(",
        re.IGNORECASE,
    ), "items"),
    # Counter / number in loop
    (re.compile(
        r"\$NAME\s*\+\+|\$NAME\s*--|for\s*\(.*\$NAME.*\+\+|for\s.*\$NAME\s+in\s+range",
        re.IGNORECASE,
    ), "counter"),
]

# Fallback label when no context rule matches
_FALLBACK_PREFIX = "var"


# ===================================================================
# Helper utilities
# ===================================================================

def _collect_existing_identifiers(code: str) -> set[str]:
    """Return every word-like token in *code* so we can check for collisions."""
    return set(re.findall(r"\b[a-zA-Z_]\w*\b", code))


def _count_occurrences(code: str, name: str) -> int:
    return len(re.findall(r"\b" + re.escape(name) + r"\b", code))


def _get_assignment_rhs(code: str, name: str) -> str:
    """Return the concatenated right-hand sides of all assignments to *name*."""
    escaped = re.escape(name)
    pat = re.compile(
        rf"(?:var|let|const|my|local)?\s*{escaped}\s*=\s*([^\n;]+)",
        re.IGNORECASE,
    )
    return " ".join(m.group(1).strip() for m in pat.finditer(code))


def _get_usage_context(code: str, name: str, window: int = 80) -> str:
    """Return snippets surrounding every use of *name*."""
    escaped = re.escape(name)
    pat = re.compile(rf".{{0,{window}}}{escaped}.{{0,{window}}}")
    return " ".join(m.group(0) for m in pat.finditer(code))[:4000]


def _infer_semantic_prefix(code: str, name: str) -> str:
    """Run context rules against the usage neighbourhood of *name*.

    Returns the best semantic prefix (e.g. "url", "request", "filepath").
    Falls back to ``_FALLBACK_PREFIX``.
    """
    assign_rhs = _get_assignment_rhs(code, name)
    usage_ctx = _get_usage_context(code, name)
    combined = assign_rhs + " " + usage_ctx

    best_prefix = ""
    best_score = 0

    for rule_pat, prefix in _CONTEXT_RULES:
        # Replace the $NAME placeholder so rules can reference the identifier
        adjusted_src = rule_pat.pattern.replace("$NAME", re.escape(name))
        adjusted = re.compile(adjusted_src, rule_pat.flags)
        hits = len(adjusted.findall(combined))
        if hits and hits > best_score:
            best_score = hits
            best_prefix = prefix

    return best_prefix or _FALLBACK_PREFIX


def _build_string_mask(code: str) -> list[tuple[int, int]]:
    """Return (start, end) spans of string literals and comments.

    Covers:
      - single-quoted strings (with escaped quote handling)
      - double-quoted strings
      - template literals (backtick)
      - single-line comments (// and #)
      - multi-line comments (/* ... */)
    """
    spans: list[tuple[int, int]] = []
    # Order matters: longer patterns first to avoid partial matches
    pattern = re.compile(
        r'(?:'
        r'"""[\s\S]*?"""|'          # Python triple-double
        r"'''[\s\S]*?'''|"          # Python triple-single
        r'`(?:[^`\\]|\\.)*`|'       # JS template literal
        r'"(?:[^"\\]|\\.)*"|'       # double-quoted string
        r"'(?:[^'\\]|\\.)*'|"       # single-quoted string
        r'//[^\n]*|'                # single-line comment (//)
        r'#[^\n]*|'                 # single-line comment (#)
        r'/\*[\s\S]*?\*/'           # multi-line comment
        r')'
    )
    for m in pattern.finditer(code):
        spans.append((m.start(), m.end()))
    return spans


def _position_in_string_or_comment(
    pos: int, spans: list[tuple[int, int]]
) -> bool:
    """Return True if *pos* falls inside any of the protected spans."""
    for start, end in spans:
        if start <= pos < end:
            return True
        if start > pos:
            break  # spans are sorted by start
    return False


def _safe_rename(
    code: str,
    old_name: str,
    new_name: str,
    protected_spans: list[tuple[int, int]],
) -> str:
    """Replace *old_name* with *new_name* at word boundaries, skipping
    positions that fall inside string literals or comments.

    Returns the modified code; protected_spans are **not** updated (the
    caller must rebuild them if doing multiple passes -- or process
    names longest-first to avoid offset drift issues by rebuilding between
    renames).
    """
    pat = re.compile(r"\b" + re.escape(old_name) + r"\b")
    # We process from right-to-left so earlier offsets stay valid.
    matches = list(pat.finditer(code))
    for m in reversed(matches):
        if _position_in_string_or_comment(m.start(), protected_spans):
            continue
        code = code[:m.start()] + new_name + code[m.end():]
    return code


# ===================================================================
# Transform class
# ===================================================================

class DeterministicRenamer(BaseTransform):
    name = "DeterministicRenamer"
    description = (
        "Rename obfuscated identifiers with meaningful names based on "
        "usage context."
    )

    # ---------------------------------------------------------------
    # can_apply
    # ---------------------------------------------------------------
    def can_apply(self, code: str, language: str, state: dict) -> bool:
        """Return True if the code contains identifiers that match known
        obfuscation patterns."""
        for ptype, pat in _OBFUSCATION_PATTERNS:
            if ptype == "single_char":
                # Only flag single-char vars if they appear many times and
                # are not conventional short names.
                for m in pat.finditer(code):
                    ch = m.group(0)
                    if ch in _CONVENTIONAL_SHORT or ch in KEYWORDS:
                        continue
                    if _count_occurrences(code, ch) >= 5:
                        return True
            else:
                if pat.search(code):
                    return True
        return False

    # ---------------------------------------------------------------
    # apply
    # ---------------------------------------------------------------
    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        # ----- Step 1: collect obfuscated candidates -----
        candidates: dict[str, str] = {}  # name -> pattern_type

        for ptype, pat in _OBFUSCATION_PATTERNS:
            for m in pat.finditer(code):
                name = m.group(0)

                # Skip conventional short names
                if ptype == "single_char":
                    if name in _CONVENTIONAL_SHORT:
                        continue
                    # Only rename single-char vars appearing many times
                    if _count_occurrences(code, name) < 5:
                        continue

                if name in KEYWORDS:
                    continue

                # Skip common abbreviations (legitimate short names)
                if name.lower() in _COMMON_ABBREVIATIONS:
                    continue

                # Minimum-occurrence gate (applies to all patterns)
                if _count_occurrences(code, name) < 2:
                    continue

                if name not in candidates:
                    candidates[name] = ptype

        if not candidates:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No obfuscated identifiers detected.",
            )

        # ----- Step 2: build rename map -----
        existing_ids = _collect_existing_identifiers(code)
        rename_map: dict[str, str] = {}
        prefix_counters: dict[str, int] = {}
        patterns_detected: set[str] = set()

        for name, ptype in candidates.items():
            patterns_detected.add(ptype)
            prefix = _infer_semantic_prefix(code, name)

            # Allocate a unique suffix
            n = prefix_counters.get(prefix, 0) + 1
            prefix_counters[prefix] = n
            proposed = f"{prefix}_{n}"

            # Collision check -- bump until unique
            while proposed in existing_ids or proposed in KEYWORDS:
                n += 1
                prefix_counters[prefix] = n
                proposed = f"{prefix}_{n}"

            rename_map[name] = proposed
            existing_ids.add(proposed)  # reserve

        # ----- Step 3: apply renames (longest names first) -----
        sorted_names = sorted(rename_map, key=len, reverse=True)

        renamed_code = code
        renames_applied = 0

        for old_name in sorted_names:
            new_name = rename_map[old_name]
            # Rebuild protected spans for every pass so offsets stay accurate
            protected = _build_string_mask(renamed_code)
            before = renamed_code
            renamed_code = _safe_rename(
                renamed_code, old_name, new_name, protected
            )
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

        # ----- Step 4: result -----
        confidence = 0.60 + 0.02 * min(renames_applied, 20)
        confidence = min(confidence, 0.95)

        # Store mapping in pipeline state for downstream transforms
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
            },
        )
