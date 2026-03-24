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


# ---------------------------------------------------------------------------
# Helper: extract a balanced-brace block starting at a given position
# ---------------------------------------------------------------------------

def _extract_brace_block(code: str, start: int) -> tuple[str, int] | None:
    """Starting from *start* (which should point at an opening '{'),
    return (contents_between_braces, end_index_after_closing_brace).

    String-aware: skips braces inside string literals to prevent
    ``if(false) { var s = "}"; }`` from terminating on the wrong brace.

    Returns None if no balanced block is found.
    """
    if start >= len(code) or code[start] != "{":
        return None
    depth = 1
    i = start + 1
    in_string: str | None = None
    while i < len(code) and depth > 0:
        ch = code[i]
        if in_string:
            # Inside a string — skip escaped characters
            if ch == "\\" and i + 1 < len(code):
                i += 2
                continue
            if ch == in_string:
                in_string = None
        else:
            if ch in ('"', "'", "`"):
                in_string = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1
    if depth == 0:
        return code[start + 1 : i - 1], i
    return None


def _find_brace_block_after(code: str, pos: int) -> tuple[str, int, int] | None:
    """Find the next '{' at or after *pos*, skipping whitespace, then extract
    the balanced brace block.

    Returns (body_text, block_start_index, block_end_index) or None.
    block_start_index points at the '{', block_end_index is one past the '}'.
    """
    i = pos
    while i < len(code) and code[i] in " \t\r\n":
        i += 1
    if i >= len(code) or code[i] != "{":
        return None
    result = _extract_brace_block(code, i)
    if result is None:
        return None
    body, end = result
    return body, i, end


def _detect_else_after(code: str, pos: int) -> tuple[str | None, int]:
    """Check whether an 'else' clause follows at *pos* (skipping whitespace).

    For JS-style brace blocks: ``else { body }`` or ``else if(...){ body }``
    Returns (else_body_or_None, end_position_after_else_block).
    If there is an ``else if``, we return None for the body (don't unwrap --
    let the next pass handle the inner if).
    """
    rest = code[pos:]
    m = re.match(r"\s*else\b", rest)
    if not m:
        return None, pos

    after_else = pos + m.end()
    # else if(...) -- don't unwrap, just report end so caller can remove it
    m_elif = re.match(r"\s*if\s*\(", code[after_else:])
    if m_elif:
        # Find the brace block after the if(...)
        paren_start = after_else + m_elif.end() - 1  # points at '('
        # skip past the parenthesized condition
        depth = 0
        j = paren_start
        while j < len(code):
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        block = _find_brace_block_after(code, j)
        if block:
            _, _, end = block
            return None, end
        return None, pos

    # plain else { body }
    block = _find_brace_block_after(code, after_else)
    if block:
        body, _, end = block
        return body, end
    return None, pos


def _get_indentation(line: str) -> int:
    """Return the number of leading whitespace characters."""
    return len(line) - len(line.lstrip())


def _extract_python_block(lines: list[str], start_idx: int) -> tuple[list[str], int]:
    """Extract the indented block starting after the line at *start_idx*.

    Returns (block_lines, next_line_index_after_block).
    """
    if start_idx + 1 >= len(lines):
        return [], start_idx + 1
    base_indent = _get_indentation(lines[start_idx])
    block_lines: list[str] = []
    i = start_idx + 1
    while i < len(lines):
        line = lines[i]
        # blank lines belong to the block
        if line.strip() == "":
            block_lines.append(line)
            i += 1
            continue
        if _get_indentation(line) > base_indent:
            block_lines.append(line)
            i += 1
        else:
            break
    # trim trailing blank lines
    while block_lines and block_lines[-1].strip() == "":
        block_lines.pop()
    return block_lines, i


def _dedent_lines(lines: list[str], amount: int) -> list[str]:
    """Remove up to *amount* leading whitespace characters from each line."""
    result: list[str] = []
    for line in lines:
        if line.strip() == "":
            result.append("")
        else:
            removed = 0
            tmp = line
            while removed < amount and tmp and tmp[0] in " \t":
                tmp = tmp[1:]
                removed += 1
            result.append(tmp)
    return result


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
        is_python = lang in ("python", "py")

        # ---------------------------------------------------------------
        # Pass 1: Always-false predicates -> remove entire block
        #         (if there is an else, keep and unwrap the else body)
        # ---------------------------------------------------------------
        output, p1_findings = self._remove_always_false(output, is_python)
        findings.extend(p1_findings)

        # ---------------------------------------------------------------
        # Pass 2: Always-true predicates -> unwrap the body
        #         (if there is an else, discard the else block)
        # ---------------------------------------------------------------
        output, p2_findings = self._remove_always_true(output, is_python)
        findings.extend(p2_findings)

        # ---------------------------------------------------------------
        # Pass 3: Unreachable code after return/break/continue/throw
        # ---------------------------------------------------------------
        output, p3_findings = self._remove_unreachable(output, is_python)
        findings.extend(p3_findings)

        # ---------------------------------------------------------------
        # Pass 4: No-op removal
        # ---------------------------------------------------------------
        output, p4_findings = self._remove_noops(output)
        findings.extend(p4_findings)

        # ---------------------------------------------------------------
        # Pass 5: Variable overwrite removal
        # ---------------------------------------------------------------
        output, p5_findings = self._remove_overwrites(output)
        findings.extend(p5_findings)

        # Clean up excessive blank lines left by removals (3+ -> 2)
        output = re.sub(r"\n{3,}", "\n\n", output)

        if not findings:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No junk code patterns detected.",
            )

        # Confidence scales with number of findings
        confidence = min(0.85, 0.45 + 0.05 * len(findings))

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
            description=f"Removed junk code: {', '.join(summary_parts)}.",
            details={
                "finding_count": len(findings),
                "type_counts": type_counts,
                "findings": findings,
            },
        )

    # ===================================================================
    # Pass helpers
    # ===================================================================

    @staticmethod
    def _remove_always_false(
        code: str, is_python: bool
    ) -> tuple[str, list[dict[str, Any]]]:
        """Remove always-false if-blocks. Keep else body if present."""
        findings: list[dict[str, Any]] = []

        if is_python:
            code, f = _remove_always_false_python(code)
            findings.extend(f)
        else:
            code, f = _remove_always_false_js(code)
            findings.extend(f)

        return code, findings

    @staticmethod
    def _remove_always_true(
        code: str, is_python: bool
    ) -> tuple[str, list[dict[str, Any]]]:
        """Unwrap always-true if-blocks. Discard else body if present."""
        findings: list[dict[str, Any]] = []

        if is_python:
            code, f = _remove_always_true_python(code)
            findings.extend(f)
        else:
            code, f = _remove_always_true_js(code)
            findings.extend(f)

        return code, findings

    @staticmethod
    def _remove_unreachable(
        code: str, is_python: bool
    ) -> tuple[str, list[dict[str, Any]]]:
        """Remove unreachable code after return/break/continue/throw."""
        findings: list[dict[str, Any]] = []

        if is_python:
            code, f = _remove_unreachable_python(code)
        else:
            code, f = _remove_unreachable_js(code)
        findings.extend(f)

        return code, findings

    @staticmethod
    def _remove_noops(code: str) -> tuple[str, list[dict[str, Any]]]:
        """Remove no-op statements."""
        findings: list[dict[str, Any]] = []

        for pat in _NOOP_PATTERNS:
            for m in pat.finditer(code):
                text = m.group(0).strip()
                if text:
                    findings.append({
                        "type": "noop",
                        "text": text,
                        "action": "removed",
                    })

        if findings:
            for pat in _NOOP_PATTERNS:
                code = pat.sub("", code)

        return code, findings

    @staticmethod
    def _remove_overwrites(code: str) -> tuple[str, list[dict[str, Any]]]:
        """Remove variable assignments that are immediately overwritten."""
        findings: list[dict[str, Any]] = []
        lines = code.split("\n")
        removal_indices: set[int] = set()

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
                        "action": "removed",
                    })
                    removal_indices.add(prev_line_idx)
                prev_var = var_name
                prev_line_idx = idx
                prev_line_text = line
            else:
                if prev_var and re.search(
                    r"\b" + re.escape(prev_var) + r"\b", line
                ):
                    prev_var = None

        if removal_indices:
            lines = [
                line for idx, line in enumerate(lines)
                if idx not in removal_indices
            ]
            code = "\n".join(lines)

        return code, findings


# -----------------------------------------------------------------------
# Always-false removal (JS / brace-delimited)
# -----------------------------------------------------------------------

def _remove_always_false_js(code: str) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    changed = True
    while changed:
        changed = False
        for pat in _OPAQUE_FALSE:
            m = pat.search(code)
            if not m:
                continue
            match_text = m.group(0)

            # Find the brace block that forms the if-body
            block = _find_brace_block_after(code, m.end())
            if block is None:
                continue
            body, blk_start, blk_end = block

            # Check for else clause after the if-block
            else_body, final_end = _detect_else_after(code, blk_end)

            # The full span to replace: from the start of the if-match to
            # final_end (which covers else if present)
            full_span_start = m.start()
            full_span_end = final_end

            # Also capture any leading whitespace on the same line
            line_start = code.rfind("\n", 0, full_span_start)
            line_start = line_start + 1 if line_start != -1 else 0
            leading = code[line_start:full_span_start]
            if leading.strip() == "":
                full_span_start = line_start

            findings.append({
                "type": "opaque_false",
                "text": match_text,
                "action": "removed block (dead code)",
            })

            if else_body is not None:
                # Keep the else body, unwrapped
                replacement = else_body.strip() + "\n"
            else:
                replacement = ""

            code = code[:full_span_start] + replacement + code[full_span_end:]
            changed = True
            break  # restart scan after mutation
    return code, findings


# -----------------------------------------------------------------------
# Always-false removal (Python / indentation-based)
# -----------------------------------------------------------------------

def _remove_always_false_python(code: str) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    lines = code.split("\n")
    changed = True
    while changed:
        changed = False
        for idx, line in enumerate(lines):
            is_false = False
            for pat in _OPAQUE_FALSE:
                if pat.search(line):
                    is_false = True
                    break
            if not is_false:
                continue

            base_indent = _get_indentation(line)
            block_lines, after_idx = _extract_python_block(lines, idx)

            # Check for else/elif
            has_else = False
            else_body: list[str] = []
            else_end = after_idx
            if after_idx < len(lines):
                next_line = lines[after_idx]
                else_m = re.match(r"^(\s*)(else\s*:|elif\s+)", next_line)
                if else_m and _get_indentation(next_line) == base_indent:
                    has_else = True
                    else_body, else_end = _extract_python_block(lines, after_idx)

            findings.append({
                "type": "opaque_false",
                "text": line.strip(),
                "action": "removed block (dead code)",
            })

            if has_else and else_body:
                # Unwrap else body: dedent by one level
                dedent_amount = _get_indentation(else_body[0]) - base_indent
                unwrapped = _dedent_lines(else_body, dedent_amount)
                lines[idx:else_end] = unwrapped
            else:
                # Remove the if-block (and else if present)
                lines[idx:else_end] = []

            changed = True
            break  # restart

    return "\n".join(lines), findings


# -----------------------------------------------------------------------
# Always-true removal (JS / brace-delimited)
# -----------------------------------------------------------------------

def _remove_always_true_js(code: str) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    changed = True
    while changed:
        changed = False
        for pat in _OPAQUE_TRUE:
            m = pat.search(code)
            if not m:
                continue
            match_text = m.group(0)

            block = _find_brace_block_after(code, m.end())
            if block is None:
                continue
            body, blk_start, blk_end = block

            # Check for else clause -- discard it
            _else_body, final_end = _detect_else_after(code, blk_end)

            full_span_start = m.start()
            full_span_end = final_end

            # Capture leading whitespace on the line
            line_start = code.rfind("\n", 0, full_span_start)
            line_start = line_start + 1 if line_start != -1 else 0
            leading = code[line_start:full_span_start]
            if leading.strip() == "":
                full_span_start = line_start

            findings.append({
                "type": "opaque_true",
                "text": match_text,
                "action": "unwrapped body (condition always true)",
            })

            replacement = body.strip() + "\n"
            code = code[:full_span_start] + replacement + code[full_span_end:]
            changed = True
            break
    return code, findings


# -----------------------------------------------------------------------
# Always-true removal (Python / indentation-based)
# -----------------------------------------------------------------------

def _remove_always_true_python(code: str) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    lines = code.split("\n")
    changed = True
    while changed:
        changed = False
        for idx, line in enumerate(lines):
            is_true = False
            for pat in _OPAQUE_TRUE:
                if pat.search(line):
                    is_true = True
                    break
            if not is_true:
                continue

            base_indent = _get_indentation(line)
            block_lines, after_idx = _extract_python_block(lines, idx)

            # Check for else/elif and discard it
            else_end = after_idx
            if after_idx < len(lines):
                next_line = lines[after_idx]
                else_m = re.match(r"^(\s*)(else\s*:|elif\s+)", next_line)
                if else_m and _get_indentation(next_line) == base_indent:
                    _else_body, else_end = _extract_python_block(lines, after_idx)

            findings.append({
                "type": "opaque_true",
                "text": line.strip(),
                "action": "unwrapped body (condition always true)",
            })

            if block_lines:
                dedent_amount = _get_indentation(block_lines[0]) - base_indent
                unwrapped = _dedent_lines(block_lines, dedent_amount)
                lines[idx:else_end] = unwrapped
            else:
                lines[idx:else_end] = []

            changed = True
            break

    return "\n".join(lines), findings


# -----------------------------------------------------------------------
# Unreachable code removal (JS)
# -----------------------------------------------------------------------

def _remove_unreachable_js(code: str) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    changed = True
    while changed:
        changed = False
        m = _UNREACHABLE_JS.search(code)
        if m:
            dead_block = m.group(2)
            stripped = dead_block.strip()
            if stripped and stripped not in ("}", ""):
                findings.append({
                    "type": "unreachable",
                    "after": m.group(1).strip(),
                    "dead_code": stripped[:200],
                    "action": "removed",
                })
                # Remove the dead block, keep the control-flow statement
                code = code[: m.start(2)] + code[m.end(2) :]
                changed = True
    return code, findings


# -----------------------------------------------------------------------
# Unreachable code removal (Python)
# -----------------------------------------------------------------------

def _remove_unreachable_python(code: str) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    changed = True
    while changed:
        changed = False
        m = _UNREACHABLE_PY.search(code)
        if m:
            dead_block = m.group(2)
            stripped = dead_block.strip()
            if stripped and stripped not in ("}", ""):
                findings.append({
                    "type": "unreachable",
                    "after": m.group(1).strip(),
                    "dead_code": stripped[:200],
                    "action": "removed",
                })
                code = code[: m.start(2)] + code[m.end(2) :]
                changed = True
    return code, findings
