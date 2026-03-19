"""
JunkCodeRemover transform -- detects and removes (or flags) dead code,
opaque predicates, and other junk that obfuscators insert.

Detection categories:
  - Unreachable code after return/break/continue/throw
  - Opaque predicates: if(true), if(1==1), if(false){...}
  - Unused variable assignments that are immediately overwritten
  - No-op statements (e.g. void 0, pass, ;)
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Opaque predicate patterns
# ---------------------------------------------------------------------------

# Always-true predicates
_OPAQUE_TRUE: list[re.Pattern] = [
    re.compile(r"\bif\s*\(\s*true\s*\)", re.IGNORECASE),
    re.compile(r"\bif\s*\(\s*1\s*===?\s*1\s*\)"),
    re.compile(r"\bif\s*\(\s*0\s*===?\s*0\s*\)"),
    re.compile(r"\bif\s*\(\s*1\s*\)"),
    re.compile(r"\bif\s*\(\s*!\s*0\s*\)"),
    re.compile(r"\bif\s*\(\s*!!\s*1\s*\)"),
    re.compile(r"\bif\s*\(\s*!!\s*\[\]\s*\)"),  # JS: !![] is true
    re.compile(r"\bif\s*\(\s*True\s*\)"),         # Python
    re.compile(r"\bif\s+True\s*:"),               # Python
    re.compile(r"\bif\s*\(\s*\$true\s*\)", re.IGNORECASE),  # PowerShell
]

# Always-false predicates (the entire block is dead code)
_OPAQUE_FALSE: list[re.Pattern] = [
    re.compile(r"\bif\s*\(\s*false\s*\)", re.IGNORECASE),
    re.compile(r"\bif\s*\(\s*1\s*===?\s*2\s*\)"),
    re.compile(r"\bif\s*\(\s*0\s*\)"),
    re.compile(r"\bif\s*\(\s*!\s*1\s*\)"),
    re.compile(r"\bif\s*\(\s*null\s*\)"),
    re.compile(r"\bif\s*\(\s*undefined\s*\)"),
    re.compile(r"\bif\s*\(\s*False\s*\)"),        # Python
    re.compile(r"\bif\s+False\s*:"),              # Python
    re.compile(r"\bif\s*\(\s*\$false\s*\)", re.IGNORECASE),  # PowerShell
]

# ---------------------------------------------------------------------------
# Unreachable code after control flow
# ---------------------------------------------------------------------------

# Lines after return / break / continue / throw (JS / C#)
_UNREACHABLE_JS = re.compile(
    r"^([ \t]*(?:return|break|continue|throw)\b[^;\n]*;)\s*\n"
    r"((?:[ \t]+[^\n]+\n?)+)",
    re.MULTILINE,
)

# Python: code after return / break / continue / raise (indented same or more)
_UNREACHABLE_PY = re.compile(
    r"^([ \t]*(?:return|break|continue|raise)\b[^\n]*)\n"
    r"((?:[ \t]+[^\n]+\n?)+)",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# No-op / junk statements
# ---------------------------------------------------------------------------

_NOOP_PATTERNS: list[re.Pattern] = [
    # void 0; or void(0);
    re.compile(r"^\s*void\s*\(?\s*0\s*\)?\s*;?\s*$", re.MULTILINE),
    # standalone semicolons
    re.compile(r"^\s*;\s*$", re.MULTILINE),
    # empty blocks  { }
    re.compile(r"\{\s*\}"),
    # Python pass
    re.compile(r"^\s*pass\s*$", re.MULTILINE),
]

# ---------------------------------------------------------------------------
# Variable overwrite detection
#   var x = <expr>;  (possibly followed by other code)
#   var x = <other>;  (x is assigned and never read in between)
# ---------------------------------------------------------------------------

_VAR_ASSIGN = re.compile(
    r"^([ \t]*(?:var|let|const|my|local)?\s*(\$?[a-zA-Z_]\w*)\s*=\s*[^;\n]+;?)\s*$",
    re.MULTILINE,
)


def _detect_overwrites(code: str) -> list[dict[str, Any]]:
    """Find variables that are assigned and then immediately reassigned
    without being used in between."""
    findings: list[dict[str, Any]] = []
    lines = code.split("\n")
    prev_var: str | None = None
    prev_line_idx: int = -1
    prev_line_text: str = ""

    for idx, line in enumerate(lines):
        m = _VAR_ASSIGN.match(line)
        if m:
            var_name = m.group(2)
            if var_name == prev_var and idx == prev_line_idx + 1:
                findings.append({
                    "type": "overwritten_variable",
                    "variable": var_name,
                    "dead_line": prev_line_idx + 1,
                    "dead_text": prev_line_text.strip(),
                })
            prev_var = var_name
            prev_line_idx = idx
            prev_line_text = line
        else:
            # If the line references prev_var, it's used -- reset tracking.
            if prev_var and re.search(r"\b" + re.escape(prev_var) + r"\b", line):
                prev_var = None

    return findings


class JunkCodeRemover(BaseTransform):
    name = "junk_code_remover"
    description = (
        "Detect dead code, opaque predicates, and junk statements"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        # Quick scan for any indicator
        for pat in _OPAQUE_TRUE + _OPAQUE_FALSE:
            if pat.search(code):
                return True
        for pat in _NOOP_PATTERNS:
            if pat.search(code):
                return True
        if _UNREACHABLE_JS.search(code) or _UNREACHABLE_PY.search(code):
            return True
        return False

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        findings: list[dict[str, Any]] = []
        lang = (language or "").lower().strip()

        # --- Opaque always-true predicates ---
        for pat in _OPAQUE_TRUE:
            for m in pat.finditer(output):
                findings.append({
                    "type": "opaque_true",
                    "text": m.group(0),
                    "position": m.start(),
                    "action": "simplify (condition is always true)",
                })
                # Simplify: remove the condition, keep the body.
                # We mark it rather than blindly removing to be conservative.
                output = output.replace(
                    m.group(0),
                    f"/* ALWAYS TRUE */ {m.group(0)}",
                    1,
                )

        # --- Opaque always-false predicates ---
        for pat in _OPAQUE_FALSE:
            for m in pat.finditer(output):
                findings.append({
                    "type": "opaque_false",
                    "text": m.group(0),
                    "position": m.start(),
                    "action": "remove (block is dead code)",
                })
                output = output.replace(
                    m.group(0),
                    f"/* DEAD CODE - ALWAYS FALSE */ {m.group(0)}",
                    1,
                )

        # --- Unreachable code ---
        unreachable_pat = (
            _UNREACHABLE_PY
            if lang in ("python", "py")
            else _UNREACHABLE_JS
        )
        for m in unreachable_pat.finditer(output):
            dead_block = m.group(2)
            # Only flag if the dead block is non-trivial
            stripped = dead_block.strip()
            if stripped and stripped not in ("}", ""):
                findings.append({
                    "type": "unreachable",
                    "after": m.group(1).strip(),
                    "dead_code": stripped[:200],
                    "position": m.start(2),
                })
                # Annotate
                annotated = "/* UNREACHABLE */ " + dead_block
                output = output.replace(dead_block, annotated, 1)

        # --- No-op statements ---
        for pat in _NOOP_PATTERNS:
            for m in pat.finditer(output):
                text = m.group(0).strip()
                if text and text not in ("{}", ""):
                    findings.append({
                        "type": "noop",
                        "text": text,
                        "position": m.start(),
                    })

        # --- Variable overwrites ---
        overwrites = _detect_overwrites(code)
        findings.extend(overwrites)

        if not findings:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No junk code patterns detected.",
            )

        # Confidence is conservative -- we don't want to break real code
        confidence = min(0.80, 0.40 + 0.05 * len(findings))

        state.setdefault("junk_code", []).extend(findings)

        type_counts: dict[str, int] = {}
        for f in findings:
            t = f["type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        summary_parts = [
            f"{count} {typ.replace('_', ' ')}"
            for typ, count in type_counts.items()
        ]

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=f"Detected junk code: {', '.join(summary_parts)}.",
            details={
                "finding_count": len(findings),
                "type_counts": type_counts,
                "findings": findings,
            },
        )
