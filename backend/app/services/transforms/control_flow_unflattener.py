"""
ControlFlowUnflattener transform -- recovers readable control flow from
switch-case dispatcher patterns inserted by control flow flattening (CFF)
obfuscators.

Common CFF patterns handled:
  - while(true) { switch(state) { case 0: ... case 1: ... } }
  - for(;;) { switch(state) { case 0: ... } }
  - String-split dispatch: "3|1|4|2".split("|") index-based switches
  - Hex literal case labels: case 0x1: case 0xa:
  - Conditional state transitions: state = cond ? A : B
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# while(true), while(!0), while(1)
_WHILE_TRUE = re.compile(
    r"\bwhile\s*\(\s*(?:true|!0|!\s*false|1|!!\s*1|!!\[\])\s*\)",
    re.IGNORECASE,
)

# for(;;)
_FOR_INFINITE = re.compile(r"\bfor\s*\(\s*;\s*;\s*\)")

# switch(<identifier>) inside a loop body
_SWITCH_IN_LOOP = re.compile(
    r"(?:while\s*\(\s*(?:true|!0|!\s*false|1)\s*\)|for\s*\(\s*;\s*;\s*\))"
    r"\s*\{[^{}]*?\bswitch\s*\(",
    re.IGNORECASE | re.DOTALL,
)

# String-split dispatch: var <x> = "<digits|...>".split("|")
_STRING_SPLIT_DISPATCH = re.compile(
    r"""(?:var|let|const)\s+(\w+)\s*=\s*["']([\d|]+)["']\s*\.\s*split\s*\(\s*["']\|["']\s*\)""",
)

# State variable numeric assignment: _state = 5; or state = 0x3;
_STATE_ASSIGN = re.compile(
    r"\b(\w*(?:state|_s|_st|_next|_step|_idx|_pos)\w*)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
    re.IGNORECASE,
)

# Generic: any variable assigned to a number inside a while(true)/for(;;)+switch
# Used as a fallback to identify state variables
_GENERIC_STATE_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
)

# ---------------------------------------------------------------------------
# Dispatcher extraction patterns
# ---------------------------------------------------------------------------

# Full dispatcher block: while(true/1)/for(;;) { switch(var) { ... } }
# We use a custom brace-matching approach instead of a single regex.

_LOOP_HEAD = re.compile(
    r"(while\s*\(\s*(?:true|!0|!\s*false|1|!!\s*1|!!\[\])\s*\)"
    r"|for\s*\(\s*;\s*;\s*\))\s*\{",
    re.IGNORECASE,
)

_SWITCH_HEAD = re.compile(
    r"\bswitch\s*\(\s*(\w+(?:\[\w+(?:\+\+)?\])?)\s*\)\s*\{",
)

# Case label: case 0: or case 0x1: or case "0": or case '0':
_CASE_LABEL = re.compile(
    r"""case\s+(?:(0x[0-9a-fA-F]+|\d+)|["'](\d+)["'])\s*:""",
)

# Conditional state transition: stateVar = cond ? A : B
_COND_TRANSITION = re.compile(
    r"(\w+)\s*=\s*(.+?)\s*\?\s*(0x[0-9a-fA-F]+|\d+)\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*;",
)

# Direct state assignment: stateVar = N;
_DIRECT_TRANSITION = re.compile(
    r"(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
)

# String-split loop pattern:
#   var order = "3|1|0|4|2".split("|"); var i = 0;
#   while(i < order.length) { switch(order[i++]) { ... } }
_STRING_SPLIT_FULL = re.compile(
    r"""(?:var|let|const)\s+(\w+)\s*=\s*["']([\d|]+)["']\s*\.\s*split\s*\(\s*["']\|["']\s*\)\s*;?\s*"""
    r"""(?:var|let|const)?\s*(\w+)\s*=\s*0\s*;?\s*"""
    r"""while\s*\(\s*\3\s*<\s*\1\s*\.\s*length\s*\)\s*\{""",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_int(s: str) -> int:
    """Parse a numeric string, supporting hex literals."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def _find_matching_brace(code: str, open_pos: int) -> int:
    """Find the position of the closing brace that matches the opening brace
    at *open_pos*.  Returns -1 if not found."""
    if open_pos >= len(code) or code[open_pos] != "{":
        return -1
    depth = 1
    i = open_pos + 1
    in_string: str | None = None
    while i < len(code) and depth > 0:
        ch = code[i]
        if in_string:
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
    return i - 1 if depth == 0 else -1


def _extract_case_blocks(switch_body: str) -> dict[int, str]:
    """Extract the body of each case block from the interior of a switch
    statement.  Returns a dict mapping case number -> body text."""
    cases: dict[int, str] = {}
    # Find all case label positions
    labels: list[tuple[int, int]] = []
    for m in _CASE_LABEL.finditer(switch_body):
        case_num = _parse_int(m.group(1) or m.group(2))
        labels.append((m.end(), case_num))

    # Also look for a default: label
    default_m = re.search(r"\bdefault\s*:", switch_body)

    for idx, (body_start, case_num) in enumerate(labels):
        # The body extends until the next case/default label or the end
        if idx + 1 < len(labels):
            body_end = switch_body.rfind("case", body_start, labels[idx + 1][0])
            if body_end == -1:
                body_end = labels[idx + 1][0] - 1
                # Walk back past the "case N:" text
                temp = switch_body[:body_end]
                last_case = temp.rfind("case")
                if last_case > body_start:
                    body_end = last_case
        elif default_m and default_m.start() > body_start:
            body_end = default_m.start()
        else:
            body_end = len(switch_body)

        body = switch_body[body_start:body_end].strip()
        # Remove trailing break;
        body = re.sub(r"\bbreak\s*;\s*$", "", body).strip()
        # Remove trailing continue;
        body = re.sub(r"\bcontinue\s*;\s*$", "", body).strip()
        cases[case_num] = body

    return cases


def _identify_state_var(switch_head: str, case_blocks: dict[int, str]) -> str | None:
    """Identify the state variable from the switch expression and case bodies."""
    m = _SWITCH_HEAD.search(switch_head)
    if not m:
        return None
    switch_expr = m.group(1)
    # If the switch expression is a simple identifier, that's the state var
    if re.fullmatch(r"\w+", switch_expr):
        return switch_expr
    # If it's array-indexed (e.g. order[i++]), return the index var
    arr_m = re.match(r"(\w+)\[(\w+)", switch_expr)
    if arr_m:
        return arr_m.group(2)
    return switch_expr


def _trace_execution_order(
    cases: dict[int, str],
    state_var: str,
    initial_state: int,
    max_steps: int = 500,
) -> tuple[list[int], bool]:
    """Follow state transitions starting from *initial_state*.

    Returns (ordered_case_list, complete).
    *complete* is True if we reached a terminal state (no further transition)
    without hitting a cycle or the step limit.
    """
    order: list[int] = []
    visited: set[int] = set()
    current = initial_state

    for _ in range(max_steps):
        if current in visited:
            # Cycle detected -- stop but keep what we have
            return order, False
        if current not in cases:
            # Terminal or unknown state -- we're done
            return order, True

        visited.add(current)
        order.append(current)
        body = cases[current]

        # Check for conditional transition -- don't follow, just record
        cond_m = _COND_TRANSITION.search(body)
        if cond_m and cond_m.group(1) == state_var:
            # This is a branch point -- we stop linear tracing here
            order.append(current)  # remove duplicate
            order.pop()
            order.append(current)
            return order, True

        # Look for direct state assignment
        # Find the LAST assignment to the state var (the effective one)
        last_assign: int | None = None
        for m in _DIRECT_TRANSITION.finditer(body):
            if m.group(1) == state_var:
                last_assign = _parse_int(m.group(2))

        if last_assign is not None:
            current = last_assign
        else:
            # No transition found -- terminal block
            return order, True

    # Hit max steps
    return order, False


def _reconstruct_block(
    cases: dict[int, str],
    order: list[int],
    state_var: str,
) -> str:
    """Reconstruct linear code from the ordered case blocks."""
    lines: list[str] = []
    for case_num in order:
        body = cases.get(case_num, "")
        if not body:
            continue

        # Check for conditional transition
        cond_m = _COND_TRANSITION.search(body)
        if cond_m and cond_m.group(1) == state_var:
            # Remove the conditional assignment line from body
            condition = cond_m.group(2).strip()
            target_a = _parse_int(cond_m.group(3))
            target_b = _parse_int(cond_m.group(4))
            clean_body = body[:cond_m.start()].strip()
            # Remove any trailing state assignments before the conditional
            clean_body = re.sub(
                r"\b" + re.escape(state_var) + r"\s*=\s*(?:0x[0-9a-fA-F]+|\d+)\s*;\s*$",
                "",
                clean_body,
            ).strip()
            if clean_body:
                lines.append(clean_body)

            # Build if/else from the two branches
            block_a = _reconstruct_branch(cases, target_a, state_var)
            block_b = _reconstruct_branch(cases, target_b, state_var)
            if block_a or block_b:
                lines.append(f"if ({condition}) {{")
                if block_a:
                    lines.append(_indent(block_a))
                lines.append("} else {")
                if block_b:
                    lines.append(_indent(block_b))
                lines.append("}")
        else:
            # Strip state variable assignments from the body
            clean = _strip_state_assignments(body, state_var)
            if clean:
                lines.append(clean)

    return "\n".join(lines)


def _reconstruct_branch(
    cases: dict[int, str],
    start_state: int,
    state_var: str,
    max_depth: int = 50,
) -> str:
    """Reconstruct a single branch (used for if/else arms)."""
    lines: list[str] = []
    visited: set[int] = set()
    current = start_state

    for _ in range(max_depth):
        if current in visited or current not in cases:
            break
        visited.add(current)
        body = cases[current]

        # Check for nested conditional
        cond_m = _COND_TRANSITION.search(body)
        if cond_m and cond_m.group(1) == state_var:
            clean_body = body[:cond_m.start()].strip()
            clean_body = _strip_state_assignments(clean_body, state_var)
            if clean_body:
                lines.append(clean_body)
            # Don't recurse further to avoid explosion
            condition = cond_m.group(2).strip()
            target_a = _parse_int(cond_m.group(3))
            target_b = _parse_int(cond_m.group(4))
            lines.append(f"if ({condition}) {{ /* -> case {target_a} */ }} else {{ /* -> case {target_b} */ }}")
            break

        clean = _strip_state_assignments(body, state_var)
        if clean:
            lines.append(clean)

        # Follow transition
        last_assign: int | None = None
        for m in _DIRECT_TRANSITION.finditer(body):
            if m.group(1) == state_var:
                last_assign = _parse_int(m.group(2))
        if last_assign is not None:
            current = last_assign
        else:
            break

    return "\n".join(lines)


def _strip_state_assignments(body: str, state_var: str) -> str:
    """Remove state variable assignments from a case body."""
    # Remove lines like: stateVar = N;
    pattern = re.compile(
        r"^\s*" + re.escape(state_var) + r"\s*=\s*(?:0x[0-9a-fA-F]+|\d+)\s*;\s*$",
        re.MULTILINE,
    )
    cleaned = pattern.sub("", body)
    # Also remove inline state assignments
    inline_pattern = re.compile(
        r"\b" + re.escape(state_var) + r"\s*=\s*(?:0x[0-9a-fA-F]+|\d+)\s*;?\s*",
    )
    cleaned = inline_pattern.sub("", cleaned)
    # Clean up blank lines
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned


def _indent(text: str, spaces: int = 4) -> str:
    """Indent every line of *text* by *spaces* spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.split("\n"))


# ---------------------------------------------------------------------------
# String-split dispatch handling
# ---------------------------------------------------------------------------

def _handle_string_split_dispatch(code: str) -> tuple[str, list[dict[str, Any]]]:
    """Detect and unflatten string-split dispatch patterns.

    Pattern:
        var order = "3|1|4|0|2".split("|"); var i = 0;
        while (i < order.length) { switch(order[i++]) { ... } }

    Returns (transformed_code, list_of_detail_dicts).
    """
    changes: list[dict[str, Any]] = []

    # Find the string-split variable declarations
    split_decls = list(_STRING_SPLIT_DISPATCH.finditer(code))
    if not split_decls:
        return code, changes

    output = code
    for decl in reversed(split_decls):  # reverse to preserve positions
        order_var = decl.group(1)
        order_str = decl.group(2)
        execution_order = [int(x) for x in order_str.split("|")]

        # Find the associated while loop + switch
        # Look after the declaration for a while loop referencing this var
        search_start = decl.end()
        loop_pattern = re.compile(
            r"(?:(?:var|let|const)?\s*\w+\s*=\s*0\s*;?\s*)?"
            r"while\s*\(\s*\w+\s*<\s*" + re.escape(order_var)
            + r"\s*\.\s*length\s*\)\s*\{",
            re.DOTALL,
        )
        loop_m = loop_pattern.search(output, search_start)
        if not loop_m:
            # Try alternate pattern: for loop
            loop_pattern2 = re.compile(
                r"for\s*\(\s*(?:var|let|const)?\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*"
                + re.escape(order_var)
                + r"\s*\.\s*length\s*;\s*\w+\+\+\s*\)\s*\{",
            )
            loop_m = loop_pattern2.search(output, search_start)
            if not loop_m:
                continue

        # Find the matching closing brace
        brace_start = loop_m.end() - 1
        brace_end = _find_matching_brace(output, brace_start)
        if brace_end == -1:
            continue

        loop_body = output[brace_start + 1:brace_end]

        # Find switch inside
        switch_m = _SWITCH_HEAD.search(loop_body)
        if not switch_m:
            continue

        switch_brace = loop_body.find("{", switch_m.end() - 1)
        if switch_brace == -1:
            continue
        switch_end = _find_matching_brace(loop_body, switch_brace)
        if switch_end == -1:
            continue

        switch_interior = loop_body[switch_brace + 1:switch_end]
        cases = _extract_case_blocks(switch_interior)

        if not cases:
            continue

        # Reconstruct in execution order
        reconstructed_lines: list[str] = []
        for case_num in execution_order:
            if case_num in cases:
                body = cases[case_num]
                # Strip break/continue at end
                body = re.sub(r"\bbreak\s*;\s*$", "", body).strip()
                body = re.sub(r"\bcontinue\s*;\s*$", "", body).strip()
                if body:
                    reconstructed_lines.append(body)

        if not reconstructed_lines:
            continue

        reconstructed = "\n".join(reconstructed_lines)

        # Replace the entire block (declaration + loop) with reconstructed code
        full_start = decl.start()
        full_end = brace_end + 1
        # Also consume any stray index variable declaration between decl and loop
        between = output[decl.end():loop_m.start()]
        # Adjust full_end to include the loop closing brace
        output = output[:full_start] + reconstructed + output[full_end:]

        changes.append({
            "type": "string_split_dispatch",
            "order": execution_order,
            "cases_count": len(cases),
            "cases_resolved": len([c for c in execution_order if c in cases]),
        })

    return output, changes


# ---------------------------------------------------------------------------
# Main dispatcher detection and unflattening
# ---------------------------------------------------------------------------

def _find_dispatchers(code: str) -> list[dict[str, Any]]:
    """Find all while(true)/for(;;)+switch dispatcher blocks in the code.

    Returns a list of dicts with keys:
        full_start, full_end: span of the entire dispatcher in the source
        switch_var: the variable used in the switch expression
        cases: dict[int, str] mapping case number to body
        initial_state: the initial value of the state variable (if found)
    """
    dispatchers: list[dict[str, Any]] = []

    for loop_m in _LOOP_HEAD.finditer(code):
        brace_pos = code.index("{", loop_m.start() + len(loop_m.group(1)))
        brace_end = _find_matching_brace(code, brace_pos)
        if brace_end == -1:
            continue

        loop_body = code[brace_pos + 1:brace_end]
        switch_m = _SWITCH_HEAD.search(loop_body)
        if not switch_m:
            continue

        switch_var = switch_m.group(1)
        # Simple identifier state var
        if re.fullmatch(r"\w+", switch_var):
            state_var = switch_var
        else:
            # array-indexed -- handled by string-split path
            continue

        switch_brace_rel = loop_body.find("{", switch_m.end() - 1)
        if switch_brace_rel == -1:
            continue
        switch_end_rel = _find_matching_brace(loop_body, switch_brace_rel)
        if switch_end_rel == -1:
            continue

        switch_interior = loop_body[switch_brace_rel + 1:switch_end_rel]
        cases = _extract_case_blocks(switch_interior)

        if len(cases) < 2:
            continue

        # Find initial state: look backwards from the loop for `stateVar = N;`
        lookback_start = max(0, loop_m.start() - 500)
        lookback = code[lookback_start:loop_m.start()]
        init_pattern = re.compile(
            r"(?:var|let|const)?\s*" + re.escape(state_var)
            + r"\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
        )
        init_matches = list(init_pattern.finditer(lookback))
        initial_state = _parse_int(init_matches[-1].group(1)) if init_matches else None

        # If we couldn't find an explicit init, try to infer: the lowest-numbered
        # case is often the entry point
        if initial_state is None:
            initial_state = min(cases.keys())

        # Determine the full span to replace: include the variable init if found
        full_start = loop_m.start()
        if init_matches:
            # Include from the init assignment
            init_abs_start = lookback_start + init_matches[-1].start()
            # Walk back to include any 'var'/'let'/'const' keyword
            pre = code[max(0, init_abs_start - 20):init_abs_start]
            decl_m = re.search(r"(?:var|let|const)\s+$", pre)
            if decl_m:
                full_start = max(0, init_abs_start - 20) + decl_m.start()
            else:
                full_start = init_abs_start

        dispatchers.append({
            "full_start": full_start,
            "full_end": brace_end + 1,
            "state_var": state_var,
            "cases": cases,
            "initial_state": initial_state,
            "case_count": len(cases),
        })

    return dispatchers


# ---------------------------------------------------------------------------
# Transform class
# ---------------------------------------------------------------------------

class ControlFlowUnflattener(BaseTransform):
    name = "ControlFlowUnflattener"
    description = "Recover readable control flow from switch-case dispatcher patterns."

    # Max number of dispatchers to process in a single pass (safety limit)
    _MAX_DISPATCHERS = 50

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        # Quick checks: must have a loop + switch pattern or string-split dispatch
        has_infinite_loop = bool(_WHILE_TRUE.search(code) or _FOR_INFINITE.search(code))
        has_switch = "switch" in code

        if has_infinite_loop and has_switch:
            return True

        if _STRING_SPLIT_DISPATCH.search(code):
            return True

        # Check for state-variable patterns even without obvious infinite loop
        if has_switch and _STATE_ASSIGN.search(code):
            return True

        return False

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        output = code
        dispatchers_found = 0
        dispatchers_resolved = 0
        cases_reordered = 0
        detected_techniques: list[str] = []
        all_changes: list[dict[str, Any]] = []
        confidence_scores: list[float] = []

        # --- Phase 1: String-split dispatch ---
        output, split_changes = _handle_string_split_dispatch(output)
        if split_changes:
            dispatchers_found += len(split_changes)
            dispatchers_resolved += len(split_changes)
            detected_techniques.append("string_split_dispatch")
            for ch in split_changes:
                cases_reordered += ch.get("cases_resolved", 0)
                confidence_scores.append(0.85)
            all_changes.extend(split_changes)

        # --- Phase 2: while(true)/for(;;) + switch(stateVar) dispatchers ---
        dispatchers = _find_dispatchers(output)
        dispatchers_found += len(dispatchers)

        if len(dispatchers) > self._MAX_DISPATCHERS:
            dispatchers = dispatchers[:self._MAX_DISPATCHERS]

        # Process in reverse order to preserve source positions
        for disp in reversed(dispatchers):
            state_var = disp["state_var"]
            cases_map = disp["cases"]
            initial_state = disp["initial_state"]

            # Trace execution order
            order, complete = _trace_execution_order(
                cases_map, state_var, initial_state,
            )

            if not order:
                # Could not determine any order -- leave unchanged, add comment
                comment = (
                    f"/* [Unweaver] CFF dispatcher detected (state var: {state_var}, "
                    f"{len(cases_map)} cases) but execution order could not be determined */\n"
                )
                output = (
                    output[:disp["full_start"]]
                    + comment
                    + output[disp["full_start"]:disp["full_end"]]
                    + output[disp["full_end"]:]
                )
                all_changes.append({
                    "type": "state_dispatch_unresolved",
                    "state_var": state_var,
                    "cases_count": len(cases_map),
                    "reason": "empty_trace",
                })
                continue

            # Reconstruct linear code
            reconstructed = _reconstruct_block(cases_map, order, state_var)

            if not reconstructed.strip():
                # Reconstruction produced nothing meaningful
                all_changes.append({
                    "type": "state_dispatch_unresolved",
                    "state_var": state_var,
                    "cases_count": len(cases_map),
                    "reason": "empty_reconstruction",
                })
                continue

            # Determine confidence based on trace quality
            total_cases = len(cases_map)
            traced_cases = len(order)
            trace_ratio = traced_cases / total_cases if total_cases > 0 else 0

            if complete and trace_ratio >= 0.8:
                conf = 0.85
            elif complete and trace_ratio >= 0.5:
                conf = 0.75
            elif complete:
                conf = 0.70
            else:
                conf = 0.65

            confidence_scores.append(conf)
            dispatchers_resolved += 1
            cases_reordered += traced_cases

            if "state_variable_dispatch" not in detected_techniques:
                detected_techniques.append("state_variable_dispatch")

            # Add a header comment
            header = (
                f"/* [Unweaver] CFF unflattened: {traced_cases}/{total_cases} cases "
                f"from state var '{state_var}' "
                f"(order: {' -> '.join(str(c) for c in order)}) */\n"
            )

            output = (
                output[:disp["full_start"]]
                + header
                + reconstructed
                + "\n"
                + output[disp["full_end"]:]
            )

            all_changes.append({
                "type": "state_dispatch_resolved",
                "state_var": state_var,
                "cases_count": total_cases,
                "traced_cases": traced_cases,
                "execution_order": order,
                "complete": complete,
            })

        # --- Build result ---
        if dispatchers_resolved == 0:
            # Nothing was successfully unflattened
            if dispatchers_found > 0:
                return TransformResult(
                    success=False,
                    output=output,
                    confidence=0.0,
                    description=(
                        f"Found {dispatchers_found} potential CFF dispatcher(s) "
                        f"but could not resolve execution order."
                    ),
                    details={
                        "dispatchers_found": dispatchers_found,
                        "dispatchers_resolved": 0,
                        "cases_reordered": 0,
                        "detected_techniques": detected_techniques,
                        "changes": all_changes,
                    },
                )
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No control flow flattening patterns detected.",
            )

        # Aggregate confidence: average of per-dispatcher scores
        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores)
            if confidence_scores
            else 0.70
        )

        state.setdefault("cff_unflattened", []).extend(all_changes)

        return TransformResult(
            success=True,
            output=output,
            confidence=round(avg_confidence, 2),
            description=(
                f"Unflattened {dispatchers_resolved}/{dispatchers_found} "
                f"CFF dispatcher(s), reordered {cases_reordered} case block(s)."
            ),
            details={
                "dispatchers_found": dispatchers_found,
                "dispatchers_resolved": dispatchers_resolved,
                "cases_reordered": cases_reordered,
                "detected_techniques": detected_techniques,
                "changes": all_changes,
            },
        )
