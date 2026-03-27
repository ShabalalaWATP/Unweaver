"""
Literal propagation and dead-branch pruning.

This transform focuses on deterministic "post-decoder" cleanup:
  - inline safe literal aliases
  - propagate resolved literals into later expressions
  - prune trivially dead branches once conditions become constant

Python uses a real AST rewrite. JavaScript / TypeScript uses an ESTree
parser when available and falls back to guarded token-aware heuristics.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .base import BaseTransform, TransformResult
from .js_tooling import parse_javascript_ast
from .source_preprocessor import normalize_source_anomalies

_UNKNOWN = object()
_SIMPLE_LITERAL_TYPES = (str, int, float, bool, type(None))
_JS_CONST_DECL = re.compile(
    r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+);?",
    re.MULTILINE,
)
_JS_IF_TOKEN = re.compile(r"\bif\b")
_JS_EXPORT_CONST_DECL = re.compile(
    r"\bexport\s+const\s+([A-Za-z_$][\w$]*)\s*=",
    re.MULTILINE,
)
_JS_EXPORT_NAMED_BLOCK = re.compile(
    r"\bexport\s*{\s*([^}]+)\s*}",
    re.MULTILINE,
)
_JS_EXPORT_MEMBER_ASSIGN = re.compile(
    r"\b(?:exports|module\.exports)\.([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+);?",
    re.MULTILINE,
)
_JS_EXPORT_DEFAULT = re.compile(
    r"\bexport\s+default\s+([^;\n]+);?",
    re.MULTILINE,
)
_JS_MODULE_EXPORT_DEFAULT = re.compile(
    r"\bmodule\.exports\s*=\s*([^;\n]+);?",
    re.MULTILINE,
)


def _is_simple_literal(value: Any) -> bool:
    return isinstance(value, _SIMPLE_LITERAL_TYPES)


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


def _build_protected_spans(code: str) -> List[Tuple[int, int]]:
    """Return string/comment spans for token-aware JS rewriting."""
    spans: List[Tuple[int, int]] = []
    pattern = re.compile(
        r"(?:"
        r"'''[\s\S]*?'''|"
        r'"""[\s\S]*?"""|'
        r"`(?:[^`\\]|\\.)*`|"
        r'"(?:[^"\\]|\\.)*"|'
        r"'(?:[^'\\]|\\.)*'|"
        r"//[^\n]*|"
        r"#[^\n]*|"
        r"/\*[\s\S]*?\*/"
        r")"
    )
    for match in pattern.finditer(code):
        spans.append((match.start(), match.end()))
    return spans


def _position_in_spans(pos: int, spans: Sequence[Tuple[int, int]]) -> bool:
    for start, end in spans:
        if start <= pos < end:
            return True
        if start > pos:
            break
    return False


def _skip_protected_forward(
    code: str,
    pos: int,
    spans: Sequence[Tuple[int, int]],
) -> int:
    for start, end in spans:
        if start <= pos < end:
            return end
        if start > pos:
            break
    return pos


def _prev_non_space(code: str, pos: int) -> str:
    idx = pos - 1
    while idx >= 0 and code[idx].isspace():
        idx -= 1
    return code[idx] if idx >= 0 else ""


def _next_non_space(code: str, pos: int) -> str:
    idx = pos
    while idx < len(code) and code[idx].isspace():
        idx += 1
    return code[idx] if idx < len(code) else ""


def _line_slice(code: str, pos: int) -> str:
    line_start = code.rfind("\n", 0, pos) + 1
    line_end = code.find("\n", pos)
    if line_end == -1:
        line_end = len(code)
    return code[line_start:line_end]


def _line_is_import_statement(code: str, pos: int) -> bool:
    stripped = _line_slice(code, pos).lstrip()
    return stripped.startswith("import ")


def _line_is_export_statement(code: str, pos: int) -> bool:
    stripped = _line_slice(code, pos).lstrip()
    return stripped.startswith("export ")


def _identifier_occurrences(code: str, name: str) -> int:
    spans = _build_protected_spans(code)
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    count = 0
    for match in pattern.finditer(code):
        if _position_in_spans(match.start(), spans):
            continue
        count += 1
    return count


def _find_matching_delimiter(
    code: str,
    start: int,
    open_char: str,
    close_char: str,
    spans: Sequence[Tuple[int, int]],
) -> Optional[int]:
    if start >= len(code) or code[start] != open_char:
        return None
    depth = 0
    idx = start
    while idx < len(code):
        skipped = _skip_protected_forward(code, idx, spans)
        if skipped != idx:
            idx = skipped
            continue
        if code[idx] == open_char:
            depth += 1
        elif code[idx] == close_char:
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return None


def _python_literal_repr(value: Any) -> str:
    return repr(value)


def _js_literal_repr(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    return str(value)


def _js_template_to_literal(expr: str) -> Optional[str]:
    stripped = expr.strip()
    if not (stripped.startswith("`") and stripped.endswith("`")):
        return None
    inner = stripped[1:-1]
    if "${" in inner:
        return None
    return json.dumps(inner)


def _js_expr_to_python(expr: str, constants: Dict[str, Any]) -> Optional[str]:
    candidate = expr.strip()
    if not candidate:
        return None
    if any(token in candidate for token in ("=>", "function", "new ", "[", "{", "?.", "??")):
        return None

    template_literal = _js_template_to_literal(candidate)
    if template_literal is not None:
        candidate = template_literal

    candidate = candidate.replace("!==", " != ").replace("===", " == ")
    candidate = re.sub(r"(?<![=!])!(?!=)", " not ", candidate)
    candidate = candidate.replace("&&", " and ").replace("||", " or ")
    candidate = re.sub(r"\btrue\b", "True", candidate)
    candidate = re.sub(r"\bfalse\b", "False", candidate)
    candidate = re.sub(r"\bnull\b", "None", candidate)

    protected = _build_protected_spans(candidate)
    pattern = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    pieces: List[str] = []
    cursor = 0
    for match in pattern.finditer(candidate):
        if _position_in_spans(match.start(), protected):
            continue
        pieces.append(candidate[cursor:match.start()])
        name = match.group(0)
        if name in {"True", "False", "None", "and", "or", "not"}:
            pieces.append(name)
        elif name in constants and _is_simple_literal(constants[name]):
            pieces.append(_python_literal_repr(constants[name]))
        else:
            return None
        cursor = match.end()
    pieces.append(candidate[cursor:])
    converted = "".join(pieces).strip()
    if not converted:
        return None
    return converted


_PY_SAFE_EXPR_NODES = (
    ast.Expression,
    ast.Constant,
    ast.UnaryOp,
    ast.BinOp,
    ast.BoolOp,
    ast.Compare,
    ast.operator,
    ast.unaryop,
    ast.boolop,
    ast.cmpop,
    ast.Load,
)


def _evaluate_python_source(expr: str) -> Any:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return _UNKNOWN
    for node in ast.walk(tree):
        if not isinstance(node, _PY_SAFE_EXPR_NODES):
            return _UNKNOWN
    try:
        return eval(compile(tree, "<literal-propagator>", "eval"), {"__builtins__": {}}, {})
    except Exception:
        return _UNKNOWN


def _evaluate_js_literal(expr: str, constants: Dict[str, Any]) -> Any:
    converted = _js_expr_to_python(expr, constants)
    if converted is None:
        return _UNKNOWN
    value = _evaluate_python_source(converted)
    if value is _UNKNOWN or not _is_simple_literal(value):
        return _UNKNOWN
    return value


def _evaluate_python_expr(node: ast.AST, env: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value if _is_simple_literal(node.value) else _UNKNOWN
    if isinstance(node, ast.Name):
        return env.get(node.id, _UNKNOWN)
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if isinstance(value, ast.FormattedValue):
                rendered = _evaluate_python_expr(value.value, env)
                if rendered is _UNKNOWN:
                    return _UNKNOWN
                parts.append(str(rendered))
                continue
            return _UNKNOWN
        return "".join(parts)
    if isinstance(node, ast.UnaryOp):
        operand = _evaluate_python_expr(node.operand, env)
        if operand is _UNKNOWN:
            return _UNKNOWN
        try:
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.Invert) and isinstance(operand, int):
                return ~operand
        except Exception:
            return _UNKNOWN
        return _UNKNOWN
    if isinstance(node, ast.BinOp):
        left = _evaluate_python_expr(node.left, env)
        right = _evaluate_python_expr(node.right, env)
        if left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        try:
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.FloorDiv):
                return left // right
            if isinstance(node.op, ast.Mod):
                return left % right
            if isinstance(node.op, ast.Pow):
                return left ** right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.RShift):
                return left >> right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
        except Exception:
            return _UNKNOWN
        return _UNKNOWN
    if isinstance(node, ast.BoolOp):
        values = [_evaluate_python_expr(value, env) for value in node.values]
        if any(value is _UNKNOWN for value in values):
            return _UNKNOWN
        if isinstance(node.op, ast.And) and all(isinstance(value, bool) for value in values):
            return all(values)
        if isinstance(node.op, ast.Or) and all(isinstance(value, bool) for value in values):
            return any(values)
        return _UNKNOWN
    if isinstance(node, ast.Compare):
        left = _evaluate_python_expr(node.left, env)
        if left is _UNKNOWN:
            return _UNKNOWN
        current = left
        for operator, comparator_node in zip(node.ops, node.comparators):
            comparator = _evaluate_python_expr(comparator_node, env)
            if comparator is _UNKNOWN:
                return _UNKNOWN
            try:
                if isinstance(operator, ast.Eq):
                    ok = current == comparator
                elif isinstance(operator, ast.NotEq):
                    ok = current != comparator
                elif isinstance(operator, ast.Lt):
                    ok = current < comparator
                elif isinstance(operator, ast.LtE):
                    ok = current <= comparator
                elif isinstance(operator, ast.Gt):
                    ok = current > comparator
                elif isinstance(operator, ast.GtE):
                    ok = current >= comparator
                elif isinstance(operator, ast.Is):
                    ok = current is comparator
                elif isinstance(operator, ast.IsNot):
                    ok = current is not comparator
                elif isinstance(operator, ast.In):
                    ok = current in comparator
                elif isinstance(operator, ast.NotIn):
                    ok = current not in comparator
                else:
                    return _UNKNOWN
            except Exception:
                return _UNKNOWN
            if not ok:
                return False
            current = comparator
        return True
    if isinstance(node, ast.IfExp):
        test_value = _evaluate_python_expr(node.test, env)
        if not isinstance(test_value, bool):
            return _UNKNOWN
        return _evaluate_python_expr(node.body if test_value else node.orelse, env)
    return _UNKNOWN


def _assignment_target_names(target: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            names.update(_assignment_target_names(item))
    return names


def _assigned_names_from_statements(statements: Sequence[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for stmt in statements:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                names.update(_assignment_target_names(target))
        elif isinstance(stmt, ast.AnnAssign):
            names.update(_assignment_target_names(stmt.target))
        elif isinstance(stmt, ast.AugAssign):
            names.update(_assignment_target_names(stmt.target))
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            names.update(_assignment_target_names(stmt.target))
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(stmt.name)
    return names


@dataclass
class _PythonRewriteStats:
    propagated: int = 0
    pruned_branches: int = 0
    simplified_assignments: int = 0
    removed_assignments: int = 0
    recovered_literals: List[str] = None

    def __post_init__(self) -> None:
        if self.recovered_literals is None:
            self.recovered_literals = []


class _PythonLiteralSimplifier:
    def __init__(self) -> None:
        self.stats = _PythonRewriteStats()

    def simplify(self, tree: ast.Module) -> ast.Module:
        tree.body = self._simplify_body(tree.body, {})
        return ast.fix_missing_locations(tree)

    def simplify_with_seed(
        self,
        tree: ast.Module,
        seed_env: Optional[Dict[str, Any]] = None,
    ) -> ast.Module:
        initial_env = {
            key: value
            for key, value in (seed_env or {}).items()
            if _is_simple_literal(value)
        }
        tree.body = self._simplify_body(tree.body, initial_env)
        return ast.fix_missing_locations(tree)

    def _record_literal(self, value: Any) -> None:
        if isinstance(value, str) and value:
            self.stats.recovered_literals.append(value[:500])

    def _rewrite_expr(self, node: ast.AST | None, env: Dict[str, Any]) -> ast.AST | None:
        if node is None:
            return None

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in env:
            value = env[node.id]
            if _is_simple_literal(value):
                self.stats.propagated += 1
                self._record_literal(value)
                return ast.copy_location(ast.Constant(value=value), node)

        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                rewritten = self._rewrite_expr(value, env)
                if rewritten is not None:
                    setattr(node, field, rewritten)
            elif isinstance(value, list):
                rewritten_items = [
                    self._rewrite_expr(item, env) if isinstance(item, ast.AST) else item
                    for item in value
                ]
                setattr(node, field, rewritten_items)

        evaluated = _evaluate_python_expr(node, env)
        if _is_simple_literal(evaluated) and not isinstance(node, ast.Constant):
            self._record_literal(evaluated)
            return ast.copy_location(ast.Constant(value=evaluated), node)
        return node

    def _simplify_body(
        self,
        statements: Sequence[ast.stmt],
        inherited_env: Dict[str, Any],
    ) -> List[ast.stmt]:
        env = dict(inherited_env)
        output: List[ast.stmt] = []
        for stmt in statements:
            rewritten, env = self._simplify_stmt(stmt, env)
            output.extend(rewritten)
        return output

    def _simplify_stmt(
        self,
        stmt: ast.stmt,
        env: Dict[str, Any],
    ) -> Tuple[List[ast.stmt], Dict[str, Any]]:
        if isinstance(stmt, ast.Assign):
            stmt.value = self._rewrite_expr(stmt.value, env)
            if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name = stmt.targets[0].id
                value = _evaluate_python_expr(stmt.value, env)
                if _is_simple_literal(value):
                    env[name] = value
                    self.stats.simplified_assignments += 1
                    self._record_literal(value)
                else:
                    env.pop(name, None)
            else:
                for target in stmt.targets:
                    for name in _assignment_target_names(target):
                        env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, ast.AnnAssign):
            stmt.value = self._rewrite_expr(stmt.value, env) if stmt.value is not None else None
            for name in _assignment_target_names(stmt.target):
                value = _evaluate_python_expr(stmt.value, env) if stmt.value is not None else _UNKNOWN
                if _is_simple_literal(value):
                    env[name] = value
                    self.stats.simplified_assignments += 1
                    self._record_literal(value)
                else:
                    env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, ast.AugAssign):
            stmt.value = self._rewrite_expr(stmt.value, env)
            for name in _assignment_target_names(stmt.target):
                env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, ast.If):
            stmt.test = self._rewrite_expr(stmt.test, env)
            test_value = _evaluate_python_expr(stmt.test, env)
            if isinstance(test_value, bool):
                self.stats.pruned_branches += 1
                chosen = stmt.body if test_value else stmt.orelse
                chosen_env = dict(env)
                return self._simplify_body(chosen, chosen_env), chosen_env
            body = self._simplify_body(stmt.body, dict(env))
            orelse = self._simplify_body(stmt.orelse, dict(env))
            stmt.body = body
            stmt.orelse = orelse
            for name in _assigned_names_from_statements(body + orelse):
                env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            blocked = {
                arg.arg for arg in (
                    list(stmt.args.posonlyargs)
                    + list(stmt.args.args)
                    + list(stmt.args.kwonlyargs)
                )
            }
            if stmt.args.vararg is not None:
                blocked.add(stmt.args.vararg.arg)
            if stmt.args.kwarg is not None:
                blocked.add(stmt.args.kwarg.arg)
            inherited = {key: value for key, value in env.items() if key not in blocked}
            stmt.decorator_list = [
                self._rewrite_expr(item, env) for item in stmt.decorator_list
            ]
            stmt.returns = self._rewrite_expr(stmt.returns, env)
            stmt.args.defaults = [
                self._rewrite_expr(item, env) for item in stmt.args.defaults
            ]
            stmt.args.kw_defaults = [
                self._rewrite_expr(item, env) if item is not None else None
                for item in stmt.args.kw_defaults
            ]
            stmt.body = self._simplify_body(stmt.body, inherited)
            env.pop(stmt.name, None)
            return [stmt], env

        if isinstance(stmt, ast.ClassDef):
            stmt.decorator_list = [
                self._rewrite_expr(item, env) for item in stmt.decorator_list
            ]
            stmt.bases = [self._rewrite_expr(item, env) for item in stmt.bases]
            stmt.keywords = [
                ast.keyword(arg=item.arg, value=self._rewrite_expr(item.value, env))
                for item in stmt.keywords
            ]
            stmt.body = self._simplify_body(stmt.body, {})
            env.pop(stmt.name, None)
            return [stmt], env

        if isinstance(stmt, ast.Return):
            stmt.value = self._rewrite_expr(stmt.value, env)
            return [stmt], env

        if isinstance(stmt, ast.Expr):
            stmt.value = self._rewrite_expr(stmt.value, env)
            return [stmt], env

        if isinstance(stmt, ast.Assert):
            stmt.test = self._rewrite_expr(stmt.test, env)
            stmt.msg = self._rewrite_expr(stmt.msg, env)
            return [stmt], env

        if isinstance(stmt, ast.While):
            stmt.test = self._rewrite_expr(stmt.test, env)
            test_value = _evaluate_python_expr(stmt.test, env)
            if test_value is False:
                self.stats.pruned_branches += 1
                return self._simplify_body(stmt.orelse, dict(env)), env
            stmt.body = self._simplify_body(stmt.body, dict(env))
            stmt.orelse = self._simplify_body(stmt.orelse, dict(env))
            for name in _assigned_names_from_statements(stmt.body + stmt.orelse):
                env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            stmt.iter = self._rewrite_expr(stmt.iter, env)
            stmt.body = self._simplify_body(stmt.body, dict(env))
            stmt.orelse = self._simplify_body(stmt.orelse, dict(env))
            for name in _assignment_target_names(stmt.target):
                env.pop(name, None)
            for name in _assigned_names_from_statements(stmt.body + stmt.orelse):
                env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, ast.Try):
            stmt.body = self._simplify_body(stmt.body, dict(env))
            for handler in stmt.handlers:
                if handler.type is not None:
                    handler.type = self._rewrite_expr(handler.type, env)
                handler.body = self._simplify_body(handler.body, dict(env))
            stmt.orelse = self._simplify_body(stmt.orelse, dict(env))
            stmt.finalbody = self._simplify_body(stmt.finalbody, dict(env))
            for name in _assigned_names_from_statements(
                stmt.body + stmt.orelse + stmt.finalbody
            ):
                env.pop(name, None)
            return [stmt], env

        if isinstance(stmt, ast.With):
            rewritten_items: List[ast.withitem] = []
            for item in stmt.items:
                rewritten_items.append(
                    ast.withitem(
                        context_expr=self._rewrite_expr(item.context_expr, env),
                        optional_vars=item.optional_vars,
                    )
                )
            stmt.items = rewritten_items
            stmt.body = self._simplify_body(stmt.body, dict(env))
            for name in _assigned_names_from_statements(stmt.body):
                env.pop(name, None)
            return [stmt], env

        for field, value in ast.iter_fields(stmt):
            if isinstance(value, ast.AST):
                rewritten = self._rewrite_expr(value, env)
                if rewritten is not None:
                    setattr(stmt, field, rewritten)
            elif isinstance(value, list):
                rewritten_items = [
                    self._rewrite_expr(item, env) if isinstance(item, ast.AST) else item
                    for item in value
                ]
                setattr(stmt, field, rewritten_items)
        return [stmt], env


@dataclass(frozen=True)
class _TextEdit:
    start: int
    end: int
    replacement: str


@dataclass
class _JavaScriptAstStats:
    normalized_declarations: int = 0
    propagated_uses: int = 0
    pruned_branches: int = 0
    removed_declarations: int = 0
    recovered_literals: List[str] = None

    def __post_init__(self) -> None:
        if self.recovered_literals is None:
            self.recovered_literals = []


def _apply_text_edits(text: str, edits: Sequence[_TextEdit]) -> str:
    output = text
    cursor = len(output) + 1
    for edit in sorted(edits, key=lambda item: (item.start, item.end), reverse=True):
        if edit.start < 0 or edit.end < edit.start:
            continue
        if edit.end > cursor:
            continue
        output = output[:edit.start] + edit.replacement + output[edit.end:]
        cursor = edit.start
    return output


def _js_node_range(node: Any) -> Optional[Tuple[int, int]]:
    value = getattr(node, "range", None)
    if (
        isinstance(value, (list, tuple))
        and len(value) == 2
        and all(isinstance(item, int) for item in value)
    ):
        return value[0], value[1]
    return None


def _js_node_source(code: str, node: Any) -> str:
    span = _js_node_range(node)
    if span is None:
        return ""
    start, end = span
    return code[start:end]


def _iter_js_child_nodes(node: Any) -> Iterable[Tuple[str, Any]]:
    for field, value in vars(node).items():
        if field in {"type", "range", "errors", "sourceType", "start", "end", "loc"}:
            continue
        if hasattr(value, "type"):
            yield field, value
            continue
        if isinstance(value, list):
            for item in value:
                if hasattr(item, "type"):
                    yield field, item


def _pattern_identifier_names(node: Any) -> set[str]:
    names: set[str] = set()
    node_type = getattr(node, "type", "")
    if node_type == "Identifier":
        value = str(getattr(node, "name", "")).strip()
        if value:
            names.add(value)
        return names
    if node_type == "AssignmentPattern":
        return _pattern_identifier_names(getattr(node, "left", None))
    if node_type == "RestElement":
        return _pattern_identifier_names(getattr(node, "argument", None))
    if node_type == "ArrayPattern":
        for element in getattr(node, "elements", []) or []:
            names.update(_pattern_identifier_names(element))
        return names
    if node_type == "ObjectPattern":
        for prop in getattr(node, "properties", []) or []:
            prop_type = getattr(prop, "type", "")
            if prop_type == "Property":
                names.update(_pattern_identifier_names(getattr(prop, "value", None)))
            elif prop_type == "RestElement":
                names.update(_pattern_identifier_names(getattr(prop, "argument", None)))
        return names
    return names


def _js_assigned_names(node: Any) -> set[str]:
    names: set[str] = set()
    node_type = getattr(node, "type", "")
    if node_type == "VariableDeclaration":
        for declaration in getattr(node, "declarations", []) or []:
            names.update(_pattern_identifier_names(getattr(declaration, "id", None)))
    elif node_type == "AssignmentExpression":
        names.update(_pattern_identifier_names(getattr(node, "left", None)))
    elif node_type == "UpdateExpression":
        names.update(_pattern_identifier_names(getattr(node, "argument", None)))
    elif node_type in {"FunctionDeclaration", "ClassDeclaration"}:
        identifier = getattr(node, "id", None)
        if getattr(identifier, "type", "") == "Identifier":
            names.add(str(identifier.name))
    elif node_type == "CatchClause":
        names.update(_pattern_identifier_names(getattr(node, "param", None)))

    for _, child in _iter_js_child_nodes(node):
        names.update(_js_assigned_names(child))
    return names


def _function_parameter_names(node: Any) -> set[str]:
    names: set[str] = set()
    for param in getattr(node, "params", []) or []:
        names.update(_pattern_identifier_names(param))
    return names


def _js_identifier_is_replaceable(node: Any, parent: Any, field: str) -> bool:
    if getattr(node, "type", "") != "Identifier" or parent is None:
        return False

    parent_type = getattr(parent, "type", "")
    if parent_type == "VariableDeclarator" and field == "id":
        return False
    if parent_type in {
        "FunctionDeclaration",
        "FunctionExpression",
        "ArrowFunctionExpression",
        "ClassDeclaration",
        "ClassExpression",
    } and field in {"id", "params"}:
        return False
    if parent_type in {
        "ImportSpecifier",
        "ImportDefaultSpecifier",
        "ImportNamespaceSpecifier",
        "ExportSpecifier",
        "LabeledStatement",
        "BreakStatement",
        "ContinueStatement",
        "CatchClause",
        "RestElement",
        "AssignmentPattern",
        "ArrayPattern",
        "ObjectPattern",
    }:
        return False
    if parent_type == "MemberExpression" and field == "property" and not getattr(parent, "computed", False):
        return False
    if parent_type == "Property":
        if field == "key" and not getattr(parent, "computed", False):
            return False
        if field == "value" and getattr(parent, "shorthand", False):
            return False
    if parent_type == "MethodDefinition" and field == "key" and not getattr(parent, "computed", False):
        return False
    if parent_type == "AssignmentExpression" and field == "left":
        return False
    if parent_type == "UpdateExpression" and field == "argument":
        return False
    if parent_type == "CallExpression" and field == "callee":
        return False
    if parent_type == "NewExpression" and field == "callee":
        return False
    if parent_type == "TaggedTemplateExpression" and field == "tag":
        return False
    if parent_type == "UnaryExpression" and getattr(parent, "operator", "") == "delete":
        return False
    return True


def _evaluate_js_ast_expr(node: Any, env: Dict[str, Any]) -> Any:
    node_type = getattr(node, "type", "")
    if node_type == "Literal":
        value = getattr(node, "value", _UNKNOWN)
        return value if _is_simple_literal(value) else _UNKNOWN
    if node_type == "Identifier":
        return env.get(str(getattr(node, "name", "")), _UNKNOWN)
    if node_type == "TemplateLiteral":
        parts: List[str] = []
        quasis = getattr(node, "quasis", []) or []
        expressions = getattr(node, "expressions", []) or []
        for index, quasi in enumerate(quasis):
            cooked = getattr(getattr(quasi, "value", None), "cooked", None)
            if not isinstance(cooked, str):
                return _UNKNOWN
            parts.append(cooked)
            if index < len(expressions):
                rendered = _evaluate_js_ast_expr(expressions[index], env)
                if rendered is _UNKNOWN:
                    return _UNKNOWN
                parts.append(str(rendered))
        return "".join(parts)
    if node_type == "UnaryExpression":
        operator = str(getattr(node, "operator", ""))
        argument = _evaluate_js_ast_expr(getattr(node, "argument", None), env)
        if argument is _UNKNOWN:
            return _UNKNOWN
        try:
            if operator == "!":
                return not bool(argument)
            if operator == "+":
                return +argument
            if operator == "-":
                return -argument
            if operator == "~" and isinstance(argument, int):
                return ~argument
            if operator == "void":
                return None
        except Exception:
            return _UNKNOWN
        return _UNKNOWN
    if node_type == "BinaryExpression":
        left = _evaluate_js_ast_expr(getattr(node, "left", None), env)
        right = _evaluate_js_ast_expr(getattr(node, "right", None), env)
        if left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        operator = str(getattr(node, "operator", ""))
        try:
            if operator == "+":
                return left + right
            if operator == "-":
                return left - right
            if operator == "*":
                return left * right
            if operator == "/":
                return left / right
            if operator == "%":
                return left % right
            if operator == "**":
                return left ** right
            if operator == "<<":
                return left << right
            if operator == ">>":
                return left >> right
            if operator == ">>>":
                return (int(left) % (1 << 32)) >> int(right)
            if operator == "&":
                return left & right
            if operator == "|":
                return left | right
            if operator == "^":
                return left ^ right
            if operator in {"==", "==="}:
                return left == right
            if operator in {"!=", "!=="}:
                return left != right
            if operator == "<":
                return left < right
            if operator == "<=":
                return left <= right
            if operator == ">":
                return left > right
            if operator == ">=":
                return left >= right
        except Exception:
            return _UNKNOWN
        return _UNKNOWN
    if node_type == "LogicalExpression":
        left = _evaluate_js_ast_expr(getattr(node, "left", None), env)
        right_node = getattr(node, "right", None)
        operator = str(getattr(node, "operator", ""))
        if left is _UNKNOWN:
            return _UNKNOWN
        if operator == "&&":
            return _evaluate_js_ast_expr(right_node, env) if bool(left) else left
        if operator == "||":
            return left if bool(left) else _evaluate_js_ast_expr(right_node, env)
        if operator == "??":
            return left if left is not None else _evaluate_js_ast_expr(right_node, env)
        return _UNKNOWN
    if node_type == "ConditionalExpression":
        test = _evaluate_js_ast_expr(getattr(node, "test", None), env)
        if not isinstance(test, bool):
            return _UNKNOWN
        branch = getattr(node, "consequent", None) if test else getattr(node, "alternate", None)
        return _evaluate_js_ast_expr(branch, env)
    if node_type == "SequenceExpression":
        expressions = getattr(node, "expressions", []) or []
        if not expressions:
            return _UNKNOWN
        return _evaluate_js_ast_expr(expressions[-1], env)
    return _UNKNOWN


class _JavaScriptAstSimplifier:
    def __init__(
        self,
        code: str,
        imported_literals: Dict[str, Any],
        *,
        language: str = "javascript",
    ) -> None:
        cleaned, _ = normalize_source_anomalies(code)
        self.code = cleaned
        self.language = language
        self.imported_literals = {
            key: value
            for key, value in imported_literals.items()
            if _is_simple_literal(value)
        }
        self.stats = _JavaScriptAstStats()

    def simplify(self) -> Optional[TransformResult]:
        program = parse_javascript_ast(self.code, language=self.language)
        if program is None:
            return None

        edits, _ = self._simplify_statement_list(
            getattr(program, "body", []) or [],
            dict(self.imported_literals),
        )
        if not edits:
            return TransformResult(
                success=False,
                output=self.code,
                confidence=0.0,
                description="No AST-safe JavaScript literal propagation opportunities found.",
                details={},
            )

        output = _apply_text_edits(self.code, edits)
        if output == self.code:
            return TransformResult(
                success=False,
                output=self.code,
                confidence=0.0,
                description="No AST-safe JavaScript literal propagation opportunities found.",
                details={},
            )

        recovered = [
            {"decoded": value}
            for value in _unique_preserve_order(self.stats.recovered_literals[:20])
        ]
        techniques = ["literal_propagation", "javascript_ast_literal_propagation"]
        if self.imported_literals:
            techniques.append("cross_file_literal_propagation")
        if self.stats.pruned_branches:
            techniques.append("dead_branch_pruning")

        confidence = min(
            0.93,
            0.72
            + self.stats.normalized_declarations * 0.025
            + self.stats.propagated_uses * 0.02
            + self.stats.pruned_branches * 0.05,
        )
        description = (
            f"AST-normalised {self.stats.normalized_declarations} declaration(s), "
            f"propagated {self.stats.propagated_uses} literal reference(s), "
            f"and pruned {self.stats.pruned_branches} dead branch(es)."
        )
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=description,
            details={
                "recovered": recovered,
                "detected_techniques": techniques,
                "literal_propagation": {
                    "engine": "javascript_ast",
                    "normalized_declarations": self.stats.normalized_declarations,
                    "propagated_uses": self.stats.propagated_uses,
                    "pruned_branches": self.stats.pruned_branches,
                    "removed_declarations": self.stats.removed_declarations,
                    "imported_literal_count": len(self.imported_literals),
                },
            },
        )

    def _record_literal(self, value: Any) -> None:
        if isinstance(value, str) and value:
            self.stats.recovered_literals.append(value[:500])

    def _localise_edits(
        self,
        edits: Sequence[_TextEdit],
        start: int,
        end: int,
    ) -> List[_TextEdit]:
        localised: List[_TextEdit] = []
        for edit in edits:
            if start <= edit.start and edit.end <= end:
                localised.append(
                    _TextEdit(
                        start=edit.start - start,
                        end=edit.end - start,
                        replacement=edit.replacement,
                    )
                )
        return localised

    def _render_statement(self, statement: Any, env: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        edits, updated_env = self._simplify_statement(statement, dict(env))
        span = _js_node_range(statement)
        if span is None:
            return "", updated_env
        start, end = span
        text = self.code[start:end]
        return _apply_text_edits(text, self._localise_edits(edits, start, end)), updated_env

    def _render_block_contents(self, block: Any, env: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        span = _js_node_range(block)
        if span is None or getattr(block, "type", "") != "BlockStatement":
            return self._render_statement(block, env)
        child_edits, updated_env = self._simplify_statement_list(
            getattr(block, "body", []) or [],
            dict(env),
        )
        start, end = span
        inner_start = start + 1
        inner_end = max(inner_start, end - 1)
        text = self.code[inner_start:inner_end]
        return _apply_text_edits(text, self._localise_edits(child_edits, inner_start, inner_end)), updated_env

    def _simplify_statement_list(
        self,
        statements: Sequence[Any],
        env: Dict[str, Any],
    ) -> Tuple[List[_TextEdit], Dict[str, Any]]:
        current_env = dict(env)
        edits: List[_TextEdit] = []
        for statement in statements:
            statement_edits, current_env = self._simplify_statement(statement, current_env)
            edits.extend(statement_edits)
        return edits, current_env

    def _function_child_env(self, node: Any, env: Dict[str, Any]) -> Dict[str, Any]:
        blocked = _function_parameter_names(node)
        identifier = getattr(node, "id", None)
        if getattr(identifier, "type", "") == "Identifier":
            blocked.add(str(identifier.name))
        return {
            key: value
            for key, value in env.items()
            if key not in blocked
        }

    def _collect_expression_edits(
        self,
        node: Any,
        env: Dict[str, Any],
        parent: Any = None,
        field: str = "",
    ) -> List[_TextEdit]:
        if node is None or not hasattr(node, "type"):
            return []

        node_type = getattr(node, "type", "")
        if node_type == "Identifier" and _js_identifier_is_replaceable(node, parent, field):
            name = str(getattr(node, "name", "")).strip()
            value = env.get(name, _UNKNOWN)
            if _is_simple_literal(value):
                replacement = _js_literal_repr(value)
                source = _js_node_source(self.code, node)
                if replacement != source:
                    span = _js_node_range(node)
                    if span is not None:
                        self.stats.propagated_uses += 1
                        self._record_literal(value)
                        return [_TextEdit(span[0], span[1], replacement)]
            return []

        if node_type in {"FunctionExpression", "ArrowFunctionExpression"}:
            body = getattr(node, "body", None)
            child_env = self._function_child_env(node, env)
            if getattr(body, "type", "") == "BlockStatement":
                edits, _ = self._simplify_statement_list(getattr(body, "body", []) or [], child_env)
                return edits
            return self._collect_expression_edits(body, child_env, node, "body")

        edits: List[_TextEdit] = []
        for child_field, child in _iter_js_child_nodes(node):
            edits.extend(self._collect_expression_edits(child, env, node, child_field))
        return edits

    def _simplify_statement(
        self,
        statement: Any,
        env: Dict[str, Any],
    ) -> Tuple[List[_TextEdit], Dict[str, Any]]:
        if statement is None or not hasattr(statement, "type"):
            return [], env

        statement_type = getattr(statement, "type", "")
        current_env = dict(env)

        if statement_type == "VariableDeclaration":
            edits: List[_TextEdit] = []
            declaration_kind = str(getattr(statement, "kind", ""))
            for declaration in getattr(statement, "declarations", []) or []:
                initializer = getattr(declaration, "init", None)
                identifier_names = _pattern_identifier_names(getattr(declaration, "id", None))
                if initializer is None:
                    for name in identifier_names:
                        current_env.pop(name, None)
                    continue

                if declaration_kind == "const" and len(identifier_names) == 1:
                    value = _evaluate_js_ast_expr(initializer, current_env)
                    name = next(iter(identifier_names))
                    if _is_simple_literal(value):
                        rendered = _js_literal_repr(value)
                        source = _js_node_source(self.code, initializer)
                        span = _js_node_range(initializer)
                        if span is not None and rendered != source:
                            edits.append(_TextEdit(span[0], span[1], rendered))
                            self.stats.normalized_declarations += 1
                        current_env[name] = value
                        self._record_literal(value)
                        continue
                    current_env.pop(name, None)

                edits.extend(self._collect_expression_edits(initializer, current_env, declaration, "init"))
                for name in identifier_names:
                    current_env.pop(name, None)
            return edits, current_env

        if statement_type == "ExpressionStatement":
            expression = getattr(statement, "expression", None)
            return self._collect_expression_edits(expression, current_env, statement, "expression"), current_env

        if statement_type in {"ReturnStatement", "ThrowStatement"}:
            argument = getattr(statement, "argument", None)
            return self._collect_expression_edits(argument, current_env, statement, "argument"), current_env

        if statement_type == "IfStatement":
            test = getattr(statement, "test", None)
            test_value = _evaluate_js_ast_expr(test, current_env)
            if isinstance(test_value, bool):
                chosen = getattr(statement, "consequent", None) if test_value else getattr(statement, "alternate", None)
                replacement = ""
                updated_env = dict(current_env)
                if chosen is not None:
                    if getattr(chosen, "type", "") == "BlockStatement":
                        replacement, _ = self._render_block_contents(chosen, updated_env)
                    else:
                        replacement, _ = self._render_statement(chosen, updated_env)
                    for name in _js_assigned_names(chosen):
                        updated_env.pop(name, None)
                span = _js_node_range(statement)
                if span is not None:
                    self.stats.pruned_branches += 1
                    return [_TextEdit(span[0], span[1], replacement)], updated_env

            edits = self._collect_expression_edits(test, current_env, statement, "test")
            consequent_edits, _ = self._simplify_statement(getattr(statement, "consequent", None), dict(current_env))
            edits.extend(consequent_edits)
            alternate = getattr(statement, "alternate", None)
            if alternate is not None:
                alternate_edits, _ = self._simplify_statement(alternate, dict(current_env))
                edits.extend(alternate_edits)
            for name in _js_assigned_names(getattr(statement, "consequent", None)):
                current_env.pop(name, None)
            for name in _js_assigned_names(alternate):
                current_env.pop(name, None)
            return edits, current_env

        if statement_type == "BlockStatement":
            block_edits, _ = self._simplify_statement_list(getattr(statement, "body", []) or [], dict(current_env))
            return block_edits, current_env

        if statement_type in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            body = getattr(statement, "body", None)
            if getattr(body, "type", "") == "BlockStatement":
                child_env = self._function_child_env(statement, current_env)
                block_edits, _ = self._simplify_statement_list(getattr(body, "body", []) or [], child_env)
            else:
                block_edits = self._collect_expression_edits(body, self._function_child_env(statement, current_env), statement, "body")
            identifier = getattr(statement, "id", None)
            if getattr(identifier, "type", "") == "Identifier":
                current_env.pop(str(identifier.name), None)
            return block_edits, current_env

        if statement_type == "ExportNamedDeclaration":
            declaration = getattr(statement, "declaration", None)
            if declaration is not None:
                return self._simplify_statement(declaration, current_env)
            return [], current_env

        if statement_type == "ExportDefaultDeclaration":
            declaration = getattr(statement, "declaration", None)
            if getattr(declaration, "type", "") in {
                "FunctionDeclaration",
                "FunctionExpression",
                "ArrowFunctionExpression",
            }:
                return self._simplify_statement(declaration, current_env)
            return self._collect_expression_edits(declaration, current_env, statement, "declaration"), current_env

        if statement_type in {"ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement"}:
            edits: List[_TextEdit] = []
            for field_name in ("init", "test", "update", "left", "right"):
                edits.extend(
                    self._collect_expression_edits(
                        getattr(statement, field_name, None),
                        current_env,
                        statement,
                        field_name,
                    )
                )
            body = getattr(statement, "body", None)
            body_edits, _ = self._simplify_statement(body, dict(current_env))
            edits.extend(body_edits)
            for name in _js_assigned_names(statement):
                current_env.pop(name, None)
            return edits, current_env

        if statement_type == "SwitchStatement":
            edits = self._collect_expression_edits(getattr(statement, "discriminant", None), current_env, statement, "discriminant")
            for case in getattr(statement, "cases", []) or []:
                test = getattr(case, "test", None)
                edits.extend(self._collect_expression_edits(test, current_env, case, "test"))
                consequent_edits, _ = self._simplify_statement_list(getattr(case, "consequent", []) or [], dict(current_env))
                edits.extend(consequent_edits)
            for name in _js_assigned_names(statement):
                current_env.pop(name, None)
            return edits, current_env

        if statement_type == "TryStatement":
            edits: List[_TextEdit] = []
            block_edits, _ = self._simplify_statement(getattr(statement, "block", None), dict(current_env))
            edits.extend(block_edits)
            handler = getattr(statement, "handler", None)
            if handler is not None:
                body = getattr(handler, "body", None)
                handler_env = dict(current_env)
                for name in _pattern_identifier_names(getattr(handler, "param", None)):
                    handler_env.pop(name, None)
                handler_edits, _ = self._simplify_statement(body, handler_env)
                edits.extend(handler_edits)
            finalizer_edits, _ = self._simplify_statement(getattr(statement, "finalizer", None), dict(current_env))
            edits.extend(finalizer_edits)
            for name in _js_assigned_names(statement):
                current_env.pop(name, None)
            return edits, current_env

        edits: List[_TextEdit] = []
        for field_name, child in _iter_js_child_nodes(statement):
            if field_name in {"body", "consequent", "alternate", "block", "handler", "finalizer"}:
                continue
            edits.extend(self._collect_expression_edits(child, current_env, statement, field_name))
        return edits, current_env


def _collect_js_constants(
    code: str,
    seed_constants: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Tuple[int, int, str, str]], Dict[str, Any]]:
    spans = _build_protected_spans(code)
    declarations: List[Tuple[int, int, str, str]] = []
    for match in _JS_CONST_DECL.finditer(code):
        if _position_in_spans(match.start(), spans):
            continue
        declarations.append((match.start(), match.end(), match.group(1), match.group(2).strip()))

    constants: Dict[str, Any] = {
        key: value
        for key, value in (seed_constants or {}).items()
        if _is_simple_literal(value)
    }
    unresolved = declarations[:]
    progress = True
    while progress:
        progress = False
        for _, _, name, expr in unresolved:
            if name in constants:
                continue
            value = _evaluate_js_literal(expr, constants)
            if _is_simple_literal(value):
                constants[name] = value
                progress = True
    return declarations, constants


def _normalize_js_declarations(
    code: str,
    declarations: Sequence[Tuple[int, int, str, str]],
    constants: Dict[str, Any],
) -> Tuple[str, int]:
    changes = 0
    output = code
    for start, end, name, expr in reversed(declarations):
        if name not in constants:
            continue
        rendered = _js_literal_repr(constants[name])
        if expr.strip() == rendered:
            continue
        replacement = f"const {name} = {rendered};"
        output = output[:start] + replacement + output[end:]
        changes += 1
    return output, changes


def _replace_js_identifier_uses(code: str, constants: Dict[str, Any]) -> Tuple[str, int]:
    output = code
    total = 0
    for name, value in sorted(constants.items(), key=lambda item: (-len(item[0]), item[0])):
        rendered = _js_literal_repr(value)
        spans = _build_protected_spans(output)
        declaration_spans = [
            (match.start(), match.end())
            for match in _JS_CONST_DECL.finditer(output)
            if not _position_in_spans(match.start(), spans)
        ]
        pattern = re.compile(r"\b" + re.escape(name) + r"\b")
        matches = list(pattern.finditer(output))
        for match in reversed(matches):
            start, end = match.span()
            if _position_in_spans(start, spans):
                continue
            if _line_is_import_statement(output, start):
                continue
            if any(span_start <= start < span_end for span_start, span_end in declaration_spans):
                continue
            prev_non_space = _prev_non_space(output, start)
            next_non_space = _next_non_space(output, end)
            if prev_non_space == ".":
                continue
            if next_non_space == ":":
                continue
            if prev_non_space in "{," and next_non_space in ",}":
                continue
            tail = output[end:].lstrip()
            if tail.startswith(("=", "+=", "-=", "*=", "/=", "%=", "++", "--")):
                continue
            output = output[:start] + rendered + output[end:]
            total += 1
    return output, total


def _prune_js_dead_branches(code: str, constants: Dict[str, Any]) -> Tuple[str, int]:
    output = code
    pruned = 0
    search_pos = 0

    while search_pos < len(output):
        spans = _build_protected_spans(output)
        match = None
        for candidate in _JS_IF_TOKEN.finditer(output, search_pos):
            if _position_in_spans(candidate.start(), spans):
                continue
            match = candidate
            break
        if match is None:
            break

        cond_start = match.end()
        while cond_start < len(output) and output[cond_start].isspace():
            cond_start += 1
        if cond_start >= len(output) or output[cond_start] != "(":
            search_pos = match.end()
            continue

        cond_end = _find_matching_delimiter(output, cond_start, "(", ")", spans)
        if cond_end is None:
            search_pos = match.end()
            continue

        condition = output[cond_start + 1:cond_end]
        cond_value = _evaluate_js_literal(condition, constants)
        if not isinstance(cond_value, bool):
            search_pos = cond_end + 1
            continue

        body_start = cond_end + 1
        while body_start < len(output) and output[body_start].isspace():
            body_start += 1
        if body_start >= len(output) or output[body_start] != "{":
            search_pos = cond_end + 1
            continue

        body_end = _find_matching_delimiter(output, body_start, "{", "}", spans)
        if body_end is None:
            search_pos = cond_end + 1
            continue
        true_body = output[body_start + 1:body_end]

        else_start = body_end + 1
        while else_start < len(output) and output[else_start].isspace():
            else_start += 1
        false_body = ""
        segment_end = body_end + 1
        if output.startswith("else", else_start):
            else_block_start = else_start + 4
            while else_block_start < len(output) and output[else_block_start].isspace():
                else_block_start += 1
            if else_block_start < len(output) and output[else_block_start] == "{":
                else_block_end = _find_matching_delimiter(
                    output,
                    else_block_start,
                    "{",
                    "}",
                    spans,
                )
                if else_block_end is None:
                    search_pos = body_end + 1
                    continue
                false_body = output[else_block_start + 1:else_block_end]
                segment_end = else_block_end + 1

        replacement = true_body if cond_value else false_body
        output = output[:match.start()] + replacement + output[segment_end:]
        pruned += 1
        search_pos = max(match.start(), 0)

    return output, pruned


def _remove_unused_js_declarations(code: str, constants: Dict[str, Any]) -> Tuple[str, int]:
    output = code
    removed = 0
    while True:
        spans = _build_protected_spans(output)
        removed_this_round = False
        for match in reversed(list(_JS_CONST_DECL.finditer(output))):
            if _position_in_spans(match.start(), spans):
                continue
            name = match.group(1)
            if name not in constants:
                continue
            if _line_is_export_statement(output, match.start()):
                continue
            if _identifier_occurrences(output, name) > 1:
                continue
            start, end = match.span()
            while end < len(output) and output[end] in " \t":
                end += 1
            if end < len(output) and output[end] == "\n":
                end += 1
            output = output[:start] + output[end:]
            removed += 1
            removed_this_round = True
        if not removed_this_round:
            break
    return output, removed


def _parse_export_bindings(raw: str) -> List[Tuple[str, str]]:
    bindings: List[Tuple[str, str]] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        if " as " in value:
            local_name, exported_name = [item.strip() for item in value.split(" as ", 1)]
        else:
            local_name = value
            exported_name = value
        if local_name and exported_name:
            bindings.append((local_name, exported_name))
    return bindings


def _extract_js_literal_bindings(
    code: str,
    *,
    imported_literals: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _, constants = _collect_js_constants(code, imported_literals)
    exported: Dict[str, Any] = {}

    for match in _JS_EXPORT_CONST_DECL.finditer(code):
        name = match.group(1)
        if name in constants:
            exported[name] = constants[name]

    for match in _JS_EXPORT_NAMED_BLOCK.finditer(code):
        for local_name, exported_name in _parse_export_bindings(match.group(1)):
            if local_name in constants:
                exported[exported_name] = constants[local_name]

    for match in _JS_EXPORT_MEMBER_ASSIGN.finditer(code):
        export_name = match.group(1)
        value = _evaluate_js_literal(match.group(2), constants)
        if _is_simple_literal(value):
            exported[export_name] = value

    for pattern in (_JS_EXPORT_DEFAULT, _JS_MODULE_EXPORT_DEFAULT):
        match = pattern.search(code)
        if match:
            value = _evaluate_js_literal(match.group(1), constants)
            if _is_simple_literal(value):
                exported["default"] = value
                break

    return exported


def _extract_python_literal_bindings(
    code: str,
    *,
    imported_literals: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {}

    env: Dict[str, Any] = {
        key: value
        for key, value in (imported_literals or {}).items()
        if _is_simple_literal(value)
    }
    exported: Dict[str, Any] = {}

    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            value = _evaluate_python_expr(stmt.value, env)
            if not _is_simple_literal(value):
                for target in stmt.targets:
                    for name in _assignment_target_names(target):
                        env.pop(name, None)
                continue
            for target in stmt.targets:
                for name in _assignment_target_names(target):
                    env[name] = value
                    if not name.startswith("_"):
                        exported[name] = value
        elif isinstance(stmt, ast.AnnAssign):
            value = _evaluate_python_expr(stmt.value, env) if stmt.value is not None else _UNKNOWN
            for name in _assignment_target_names(stmt.target):
                if _is_simple_literal(value):
                    env[name] = value
                    if not name.startswith("_"):
                        exported[name] = value
                else:
                    env.pop(name, None)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

    return exported


def extract_literal_bindings(
    code: str,
    language: str,
    *,
    imported_literals: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    lang = (language or "").lower().strip()
    if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx", ""}:
        return _extract_js_literal_bindings(
            code,
            imported_literals=imported_literals,
        )
    if lang in {"python", "py"}:
        return _extract_python_literal_bindings(
            code,
            imported_literals=imported_literals,
        )
    return {}


class LiteralPropagator(BaseTransform):
    name = "LiteralPropagator"
    description = "Propagate resolved literals and prune trivially dead branches."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx", ""}:
            return bool(re.search(r"\bconst\s+[A-Za-z_$][\w$]*\s*=|\bif\s*\(", code))
        if lang in {"python", "py"}:
            return bool(re.search(r"^\s*[A-Za-z_]\w*\s*=|\bif\b|\bwhile\b", code, re.MULTILINE))
        return False

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        lang = (language or "").lower().strip()
        imported_literals = state.get("imported_literals", {})
        if not isinstance(imported_literals, dict):
            imported_literals = {}
        if lang in {"javascript", "js", "typescript", "ts", "tsx", "jsx", ""}:
            return self._apply_javascript(
                code,
                imported_literals,
                language=lang or "javascript",
            )
        if lang in {"python", "py"}:
            return self._apply_python(code, imported_literals)
        return TransformResult(
            success=False,
            output=code,
            confidence=0.0,
            description="Literal propagation is only supported for JavaScript/TypeScript and Python.",
            details={},
        )

    def _apply_javascript(
        self,
        code: str,
        imported_literals: Dict[str, Any],
        *,
        language: str = "javascript",
    ) -> TransformResult:
        ast_result = self._apply_javascript_ast(
            code,
            imported_literals,
            language=language,
        )
        if ast_result and ast_result.success:
            _, constants = _collect_js_constants(ast_result.output, imported_literals)
            cleaned, removed = _remove_unused_js_declarations(ast_result.output, constants)
            if removed and cleaned != ast_result.output:
                details = dict(ast_result.details)
                techniques = list(details.get("detected_techniques", []))
                if "unused_literal_cleanup" not in techniques:
                    techniques.append("unused_literal_cleanup")
                propagation_details = dict(details.get("literal_propagation", {}))
                propagation_details["removed_declarations"] = (
                    int(propagation_details.get("removed_declarations", 0)) + removed
                )
                details["detected_techniques"] = techniques
                details["literal_propagation"] = propagation_details
                details["recovered"] = details.get("recovered", [])
                description = ast_result.description.rstrip(".")
                return TransformResult(
                    success=True,
                    output=cleaned,
                    confidence=min(0.94, ast_result.confidence + removed * 0.015),
                    description=f"{description}, and removed {removed} unused declaration(s).",
                    details=details,
                )
            return ast_result
        return self._apply_javascript_heuristic(code, imported_literals)

    def _apply_javascript_ast(
        self,
        code: str,
        imported_literals: Dict[str, Any],
        *,
        language: str = "javascript",
    ) -> Optional[TransformResult]:
        if not code.strip():
            return None
        simplifier = _JavaScriptAstSimplifier(
            code,
            imported_literals,
            language=language,
        )
        return simplifier.simplify()

    def _apply_javascript_heuristic(
        self,
        code: str,
        imported_literals: Dict[str, Any],
    ) -> TransformResult:
        original = code
        declarations, constants = _collect_js_constants(code, imported_literals)
        output, normalized = _normalize_js_declarations(code, declarations, constants)
        output, propagated = _replace_js_identifier_uses(output, constants)
        output, pruned = _prune_js_dead_branches(output, constants)
        output, propagated_second = _replace_js_identifier_uses(output, constants)
        output, removed = _remove_unused_js_declarations(output, constants)
        propagated += propagated_second

        if output == original:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No safe literal propagation opportunities found.",
                details={},
            )

        recovered = []
        for name, value in list(constants.items())[:20]:
            if isinstance(value, str) and value:
                recovered.append({"name": name, "decoded": value[:500]})

        techniques = ["literal_propagation"]
        if imported_literals:
            techniques.append("cross_file_literal_propagation")
        if pruned:
            techniques.append("dead_branch_pruning")

        confidence = min(
            0.9,
            0.68 + normalized * 0.02 + propagated * 0.025 + pruned * 0.05 + removed * 0.02,
        )
        description = (
            f"Normalised {normalized} declaration(s), propagated {propagated} literal use(s), "
            f"pruned {pruned} dead branch(es), and removed {removed} unused declaration(s)."
        )
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=description,
            details={
                "recovered": recovered,
                "detected_techniques": techniques,
                "literal_propagation": {
                    "normalized_declarations": normalized,
                    "propagated_uses": propagated,
                    "pruned_branches": pruned,
                    "removed_declarations": removed,
                    "imported_literal_count": len(imported_literals),
                },
            },
        )

    def _apply_python(self, code: str, imported_literals: Dict[str, Any]) -> TransformResult:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            cleaned, counts = normalize_source_anomalies(code)
            if cleaned == code:
                return TransformResult(
                    success=False,
                    output=code,
                    confidence=0.0,
                    description="Python source is not parseable for AST literal propagation.",
                    details={},
                )
            try:
                tree = ast.parse(cleaned)
                code = cleaned
            except SyntaxError:
                return TransformResult(
                    success=False,
                    output=code,
                    confidence=0.0,
                    description="Python source is not parseable for AST literal propagation.",
                    details={
                        "preprocessing": {
                            "anomaly_counts": counts,
                        }
                    },
                )

        simplifier = _PythonLiteralSimplifier()
        simplified_tree = simplifier.simplify_with_seed(tree, imported_literals)
        output = ast.unparse(simplified_tree)
        if code.endswith("\n") and not output.endswith("\n"):
            output += "\n"

        if output == code:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No safe Python literal propagation opportunities found.",
                details={},
            )

        recovered = [
            {"decoded": value}
            for value in _unique_preserve_order(simplifier.stats.recovered_literals[:20])
        ]
        techniques = ["literal_propagation"]
        if imported_literals:
            techniques.append("cross_file_literal_propagation")
        if simplifier.stats.pruned_branches:
            techniques.append("dead_branch_pruning")

        confidence = min(
            0.92,
            0.7
            + simplifier.stats.simplified_assignments * 0.02
            + simplifier.stats.propagated * 0.02
            + simplifier.stats.pruned_branches * 0.05,
        )
        description = (
            f"Simplified {simplifier.stats.simplified_assignments} assignment(s), "
            f"propagated {simplifier.stats.propagated} literal reference(s), "
            f"and pruned {simplifier.stats.pruned_branches} dead branch(es)."
        )
        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=description,
            details={
                "recovered": recovered,
                "detected_techniques": techniques,
                "literal_propagation": {
                    "simplified_assignments": simplifier.stats.simplified_assignments,
                    "propagated_uses": simplifier.stats.propagated,
                    "pruned_branches": simplifier.stats.pruned_branches,
                    "imported_literal_count": len(imported_literals),
                },
            },
        )
