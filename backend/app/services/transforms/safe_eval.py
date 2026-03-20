"""
Sandboxed expression evaluator for JavaScript and Python expressions found in
obfuscated code.

Used by the constant folder and string decryptor transforms to safely evaluate
expressions without using Python's ``eval()`` with unrestricted access.

**Design goals**:

1.  Evaluate arithmetic, bitwise, string, and common builtin expressions that
    obfuscators produce (e.g. ``0x41 ^ 0x13``, ``String.fromCharCode(72,101)``).
2.  Never execute arbitrary code -- the evaluator walks an AST (Python's ``ast``
    module for Python expressions; a token-based JS-to-Python translator for JS)
    and only allows a tightly-scoped set of operations.
3.  Enforce hard limits on expression length, evaluation time, recursion depth,
    and result size.
4.  Return ``None`` on *any* error or timeout so callers can simply skip
    non-evaluable expressions.
"""

from __future__ import annotations

import ast
import base64
import logging
import math
import operator
import re
import sys
import threading
from typing import Any, Callable, Union
from urllib.parse import quote as _uri_encode
from urllib.parse import unquote as _uri_decode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------

MAX_EXPR_LENGTH: int = 10_000
"""Maximum character length of an expression accepted for evaluation."""

MAX_RESULT_LENGTH: int = 100_000
"""Maximum character length of a string result before we discard it."""

MAX_RECURSION_DEPTH: int = 50
"""Maximum AST recursion depth during evaluation."""

EVAL_TIMEOUT_SECONDS: float = 0.1
"""Wall-clock timeout (100 ms) for a single evaluation."""

# ---------------------------------------------------------------------------
# Allowed operators
# ---------------------------------------------------------------------------

_UNARY_OPS: dict[type, Callable] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Invert: operator.invert,
    ast.Not: operator.not_,
}

_BIN_OPS: dict[type, Callable] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
}

_CMP_OPS: dict[type, Callable] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}

# ---------------------------------------------------------------------------
# JS-to-Python preprocessing
# ---------------------------------------------------------------------------

# ``>>>`` (unsigned right shift) -- approximate with Python's ``>>``
_JS_UNSIGNED_RSHIFT = re.compile(r">>>")

# Template literal: `...${expr}...`
_JS_TEMPLATE_LITERAL = re.compile(
    r"`([^`]*?)`"
)
_JS_TEMPLATE_EXPR = re.compile(r"\$\{([^}]+)\}")

# String.fromCharCode(n, ...)
_JS_FROM_CHAR_CODE = re.compile(
    r"String\s*\.\s*fromCharCode\s*\("
)

# parseInt / parseFloat
_JS_PARSE_INT = re.compile(r"\bparseInt\s*\(")
_JS_PARSE_FLOAT = re.compile(r"\bparseFloat\s*\(")

# Math.* functions
_JS_MATH_CALL = re.compile(
    r"\bMath\s*\.\s*(floor|ceil|abs|round|pow|min|max|sqrt|log|random)\s*\("
)

# atob / btoa / unescape / decodeURIComponent / encodeURIComponent
_JS_ATOB = re.compile(r"\batob\s*\(")
_JS_BTOA = re.compile(r"\bbtoa\s*\(")
_JS_UNESCAPE = re.compile(r"\bunescape\s*\(")
_JS_DECODE_URI = re.compile(r"\bdecodeURIComponent\s*\(")
_JS_ENCODE_URI = re.compile(r"\bencodeURIComponent\s*\(")

# Hex literals: 0xFF
_HEX_LITERAL = re.compile(r"\b0x([0-9a-fA-F]+)\b")


def _js_to_python_source(expr: str) -> str:
    """Best-effort token-level transformation of a JS expression into an
    equivalent Python expression that can be parsed by ``ast.parse``.

    This is intentionally conservative -- it only translates patterns that
    appear frequently in obfuscated JS.  Anything we cannot translate safely
    is left as-is (which will cause ``ast.parse`` to fail, making
    ``safe_eval`` return ``None``).
    """
    s = expr

    # >>> -> >>
    s = _JS_UNSIGNED_RSHIFT.sub(">>", s)

    # Template literals -- only handles simple cases without nesting
    def _expand_template(m: re.Match) -> str:
        body = m.group(1)
        parts: list[str] = []
        last = 0
        for inner in _JS_TEMPLATE_EXPR.finditer(body):
            if inner.start() > last:
                parts.append(repr(body[last:inner.start()]))
            parts.append(f"str({inner.group(1)})")
            last = inner.end()
        if last < len(body):
            parts.append(repr(body[last:]))
        return " + ".join(parts) if parts else "''"

    s = _JS_TEMPLATE_LITERAL.sub(_expand_template, s)

    # String.fromCharCode(...) -> __fromCharCode(...)
    s = _JS_FROM_CHAR_CODE.sub("__fromCharCode(", s)

    # parseInt / parseFloat -> __parseInt / __parseFloat
    s = _JS_PARSE_INT.sub("__parseInt(", s)
    s = _JS_PARSE_FLOAT.sub("__parseFloat(", s)

    # Math.fn(...) -> __math_fn(...)
    def _replace_math(m: re.Match) -> str:
        return f"__math_{m.group(1)}("
    s = _JS_MATH_CALL.sub(_replace_math, s)

    # atob / btoa / unescape / decodeURIComponent / encodeURIComponent
    s = _JS_ATOB.sub("__atob(", s)
    s = _JS_BTOA.sub("__btoa(", s)
    s = _JS_UNESCAPE.sub("__unescape(", s)
    s = _JS_DECODE_URI.sub("__decodeURIComponent(", s)
    s = _JS_ENCODE_URI.sub("__encodeURIComponent(", s)

    # Replace JS boolean / null / undefined
    s = re.sub(r"\btrue\b", "True", s)
    s = re.sub(r"\bfalse\b", "False", s)
    s = re.sub(r"\bnull\b", "None", s)
    s = re.sub(r"\bundefined\b", "None", s)

    return s


# ---------------------------------------------------------------------------
# Safe namespace for ast-based evaluation
# ---------------------------------------------------------------------------

def _safe_fromCharCode(*codes: Any) -> str:
    """Emulate ``String.fromCharCode(n, ...)``."""
    return "".join(chr(int(c)) for c in codes)


def _safe_parseInt(value: Any, radix: int = 10) -> int:
    """Emulate JS ``parseInt``."""
    s = str(value).strip()
    if not s:
        return 0
    # JS parseInt stops at first non-digit character
    if radix == 16 or s.lower().startswith("0x"):
        m = re.match(r"[+-]?(?:0x)?([0-9a-fA-F]+)", s, re.IGNORECASE)
        if m:
            return int(m.group(0).replace("0x", "").replace("0X", ""), 16)
    m = re.match(r"[+-]?\d+", s)
    return int(m.group(0)) if m else 0


def _safe_parseFloat(value: Any) -> float:
    """Emulate JS ``parseFloat``."""
    s = str(value).strip()
    m = re.match(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", s)
    return float(m.group(0)) if m else 0.0


def _safe_atob(data: Any) -> str:
    """Emulate JS ``atob`` (base64 decode)."""
    s = str(data)
    # JS atob is lenient with padding
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s).decode("latin-1")


def _safe_btoa(data: Any) -> str:
    """Emulate JS ``btoa`` (base64 encode)."""
    return base64.b64encode(str(data).encode("latin-1")).decode("ascii")


def _safe_unescape(s: Any) -> str:
    """Emulate JS ``unescape`` -- handles ``%uXXXX`` and ``%XX`` sequences."""
    text = str(s)

    def _replace_u(m: re.Match) -> str:
        return chr(int(m.group(1), 16))

    text = re.sub(r"%u([0-9a-fA-F]{4})", _replace_u, text)

    def _replace_hex(m: re.Match) -> str:
        return chr(int(m.group(1), 16))

    text = re.sub(r"%([0-9a-fA-F]{2})", _replace_hex, text)
    return text


def _safe_decodeURIComponent(s: Any) -> str:
    """Emulate JS ``decodeURIComponent``."""
    return _uri_decode(str(s))


def _safe_encodeURIComponent(s: Any) -> str:
    """Emulate JS ``encodeURIComponent``."""
    return _uri_encode(str(s), safe="")


# Math helpers -- Math.random() always returns 0 for determinism.
_MATH_FUNCTIONS: dict[str, Callable] = {
    "floor": math.floor,
    "ceil": math.ceil,
    "abs": abs,
    "round": round,
    "pow": pow,
    "min": min,
    "max": max,
    "sqrt": math.sqrt,
    "log": math.log,
    "random": lambda: 0,
}


def _build_safe_namespace() -> dict[str, Any]:
    """Construct the restricted namespace available during evaluation."""
    ns: dict[str, Any] = {
        # JS builtins
        "__fromCharCode": _safe_fromCharCode,
        "__parseInt": _safe_parseInt,
        "__parseFloat": _safe_parseFloat,
        "__atob": _safe_atob,
        "__btoa": _safe_btoa,
        "__unescape": _safe_unescape,
        "__decodeURIComponent": _safe_decodeURIComponent,
        "__encodeURIComponent": _safe_encodeURIComponent,
        # Python builtins
        "chr": chr,
        "ord": ord,
        "int": int,
        "float": float,
        "str": str,
        "len": len,
        "abs": abs,
        "round": round,
        "bool": bool,
        # base64 helpers (for Python expressions)
        "__b64decode": lambda s: base64.b64decode(s).decode("utf-8", errors="replace"),
        "__b64encode": lambda s: base64.b64encode(
            s.encode("utf-8") if isinstance(s, str) else s
        ).decode("ascii"),
    }
    # Math.* helpers
    for fname, fn in _MATH_FUNCTIONS.items():
        ns[f"__math_{fname}"] = fn
    return ns


_SAFE_NAMESPACE: dict[str, Any] = _build_safe_namespace()


# ---------------------------------------------------------------------------
# AST-walking evaluator
# ---------------------------------------------------------------------------

class _EvalError(Exception):
    """Raised internally to abort evaluation."""


class _SafeASTEvaluator:
    """Walk a Python AST and evaluate it with a restricted set of operations.

    This evaluator *never* calls ``eval()`` or ``exec()``.  Every node type
    is handled explicitly, and anything unexpected raises ``_EvalError``.
    """

    def __init__(self, namespace: dict[str, Any], max_depth: int = MAX_RECURSION_DEPTH):
        self._ns = namespace
        self._max_depth = max_depth
        self._depth = 0

    # -- public interface ---------------------------------------------------

    def evaluate(self, node: ast.AST) -> Any:
        """Evaluate a single AST node and return the result."""
        self._depth += 1
        if self._depth > self._max_depth:
            raise _EvalError("Maximum recursion depth exceeded")
        try:
            return self._eval(node)
        finally:
            self._depth -= 1

    # -- dispatcher ---------------------------------------------------------

    def _eval(self, node: ast.AST) -> Any:  # noqa: C901 -- unavoidable dispatch
        if isinstance(node, ast.Expression):
            return self._eval(node.body)

        if isinstance(node, ast.Module):
            # Module with a single Expr statement (common from ast.parse in
            # "exec" mode with a bare expression).
            if len(node.body) == 1 and isinstance(node.body[0], ast.Expr):
                return self._eval(node.body[0].value)
            raise _EvalError("Only single-expression modules are supported")

        # -- Literals -------------------------------------------------------
        if isinstance(node, ast.Constant):
            return node.value

        # Python <3.8 compat (Num, Str) -- kept for safety
        if isinstance(node, ast.Num):  # type: ignore[attr-defined]
            return node.n  # type: ignore[attr-defined]
        if isinstance(node, ast.Str):  # type: ignore[attr-defined]
            return node.s  # type: ignore[attr-defined]

        # -- Unary operators ------------------------------------------------
        if isinstance(node, ast.UnaryOp):
            op_fn = _UNARY_OPS.get(type(node.op))
            if op_fn is None:
                raise _EvalError(f"Unsupported unary operator: {type(node.op).__name__}")
            operand = self.evaluate(node.operand)
            return op_fn(operand)

        # -- Binary operators -----------------------------------------------
        if isinstance(node, ast.BinOp):
            op_fn = _BIN_OPS.get(type(node.op))
            if op_fn is None:
                raise _EvalError(f"Unsupported binary operator: {type(node.op).__name__}")
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
            # Guard: prevent absurdly large exponentials
            if isinstance(node.op, ast.Pow):
                if isinstance(right, (int, float)) and abs(right) > 10_000:
                    raise _EvalError("Exponent too large")
            return op_fn(left, right)

        # -- Boolean operators (and / or) -----------------------------------
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result: Any = True
                for val in node.values:
                    result = self.evaluate(val)
                    if not result:
                        return result
                return result
            if isinstance(node.op, ast.Or):
                result = False
                for val in node.values:
                    result = self.evaluate(val)
                    if result:
                        return result
                return result
            raise _EvalError(f"Unsupported bool operator: {type(node.op).__name__}")

        # -- Comparisons ----------------------------------------------------
        if isinstance(node, ast.Compare):
            left = self.evaluate(node.left)
            for op_node, comparator in zip(node.ops, node.comparators):
                cmp_fn = _CMP_OPS.get(type(op_node))
                if cmp_fn is None:
                    raise _EvalError(f"Unsupported comparison: {type(op_node).__name__}")
                right = self.evaluate(comparator)
                if not cmp_fn(left, right):
                    return False
                left = right
            return True

        # -- Conditional expression (ternary) --------------------------------
        if isinstance(node, ast.IfExp):
            test = self.evaluate(node.test)
            return self.evaluate(node.body) if test else self.evaluate(node.orelse)

        # -- Tuple / List ---------------------------------------------------
        if isinstance(node, (ast.Tuple, ast.List)):
            return type(node.elts)(self.evaluate(e) for e in node.elts) if False else [
                self.evaluate(e) for e in node.elts
            ]

        # -- Name lookup ----------------------------------------------------
        if isinstance(node, ast.Name):
            if node.id in self._ns:
                return self._ns[node.id]
            raise _EvalError(f"Undefined name: {node.id!r}")

        # -- Attribute access (limited: only base64.b64decode etc.) ----------
        if isinstance(node, ast.Attribute):
            value = self.evaluate(node.value)
            # Allow attribute access on module-like objects we control
            if isinstance(value, dict) and node.attr in value:
                return value[node.attr]
            raise _EvalError(f"Attribute access not allowed: .{node.attr}")

        # -- Function calls -------------------------------------------------
        if isinstance(node, ast.Call):
            func = self.evaluate(node.func)
            if not callable(func):
                raise _EvalError(f"Object is not callable: {func!r}")
            args = [self.evaluate(a) for a in node.args]
            # No **kwargs / *args support
            if node.starargs if hasattr(node, "starargs") else False:
                raise _EvalError("Star-args not supported")
            kwargs: dict[str, Any] = {}
            for kw in node.keywords:
                if kw.arg is None:
                    raise _EvalError("**kwargs not supported")
                kwargs[kw.arg] = self.evaluate(kw.value)
            result = func(*args, **kwargs)
            # Guard result size
            if isinstance(result, str) and len(result) > MAX_RESULT_LENGTH:
                raise _EvalError("Result string exceeds maximum length")
            return result

        # -- Subscript (indexing) -------------------------------------------
        if isinstance(node, ast.Subscript):
            value = self.evaluate(node.value)
            slice_val = self._eval_slice(node.slice)
            return value[slice_val]

        # -- JoinedStr (f-string) -------------------------------------------
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    parts.append(str(self.evaluate(v.value)))
                else:
                    parts.append(str(self.evaluate(v)))
            return "".join(parts)

        raise _EvalError(f"Unsupported AST node: {type(node).__name__}")

    # -- slice handling -----------------------------------------------------

    def _eval_slice(self, node: ast.AST) -> Any:
        """Evaluate a subscript slice node."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Slice):
            lower = self.evaluate(node.lower) if node.lower else None
            upper = self.evaluate(node.upper) if node.upper else None
            step = self.evaluate(node.step) if node.step else None
            return slice(lower, upper, step)
        # Python 3.8-: Index wrapper
        if isinstance(node, ast.Index):  # type: ignore[attr-defined]
            return self.evaluate(node.value)  # type: ignore[attr-defined]
        # Fall back -- try evaluating the node directly (Python 3.9+
        # uses plain expression nodes as slices)
        return self.evaluate(node)


# ---------------------------------------------------------------------------
# Python expression preprocessing
# ---------------------------------------------------------------------------

def _preprocess_python_expr(expr: str) -> str:
    """Normalise a Python expression before parsing.

    Rewrites ``base64.b64decode(...)`` and ``base64.b64encode(...)`` into
    calls to our safe helpers.
    """
    s = expr
    s = re.sub(r"\bbase64\s*\.\s*b64decode\s*\(", "__b64decode(", s)
    s = re.sub(r"\bbase64\s*\.\s*b64encode\s*\(", "__b64encode(", s)
    return s


# ---------------------------------------------------------------------------
# Timeout helper (thread-based, works on Windows and Unix)
# ---------------------------------------------------------------------------

_ResultType = Union[int, float, str, None]


def _run_with_timeout(
    fn: Callable[[], _ResultType],
    timeout: float = EVAL_TIMEOUT_SECONDS,
) -> _ResultType:
    """Execute *fn* in a daemon thread and return its result, or ``None`` if
    the call exceeds *timeout* seconds."""
    result_box: list[_ResultType] = [None]
    error_box: list[BaseException | None] = [None]

    def _worker() -> None:
        try:
            result_box[0] = fn()
        except BaseException as exc:
            error_box[0] = exc

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        logger.debug("safe_eval: evaluation timed out (%.0f ms)", timeout * 1000)
        # Thread will be abandoned (daemon); we cannot forcibly kill it in
        # Python, but the daemon flag means it won't block process exit.
        return None
    if error_box[0] is not None:
        logger.debug("safe_eval: evaluation raised %s", error_box[0])
        return None
    return result_box[0]


# ---------------------------------------------------------------------------
# Core evaluator (no timeout -- called from within the worker thread)
# ---------------------------------------------------------------------------

def _eval_core(expr: str, namespace: dict[str, Any]) -> _ResultType:
    """Parse and evaluate *expr* using the safe AST walker.

    Returns the result (int, float, or str) or ``None`` on any failure.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        # Retry in exec mode for bare expressions that ast thinks are
        # statements (shouldn't normally happen, but just in case).
        try:
            tree = ast.parse(expr, mode="exec")
        except SyntaxError:
            logger.debug("safe_eval: expression failed to parse: %.120s", expr)
            return None

    evaluator = _SafeASTEvaluator(namespace)
    try:
        result = evaluator.evaluate(tree)
    except _EvalError as exc:
        logger.debug("safe_eval: %s -- expr: %.120s", exc, expr)
        return None
    except Exception as exc:
        logger.debug("safe_eval: unexpected error %s -- expr: %.120s", exc, expr)
        return None

    # Coerce to allowed return types
    if isinstance(result, bool):
        return int(result)
    if isinstance(result, (int, float)):
        return result
    if isinstance(result, str):
        if len(result) > MAX_RESULT_LENGTH:
            logger.debug("safe_eval: result string too long (%d chars)", len(result))
            return None
        return result
    # Discard anything else (lists, dicts, None-like sentinels, ...)
    if result is None:
        return None
    logger.debug("safe_eval: discarding non-scalar result of type %s", type(result).__name__)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def safe_eval(expr: str, language: str = "") -> int | float | str | None:
    """Safely evaluate *expr* and return the result.

    Parameters
    ----------
    expr:
        The expression string to evaluate.  May be a Python expression, a
        JavaScript expression, or a language-agnostic arithmetic/string
        expression.
    language:
        Optional hint: ``"javascript"`` / ``"js"`` causes JS-specific
        preprocessing; ``"python"`` / ``"py"`` causes Python-specific
        preprocessing.  When empty or unrecognised, the function attempts
        both JS and Python preprocessing.

    Returns
    -------
    int | float | str | None
        The evaluated result, or ``None`` if the expression could not be
        evaluated safely within the time and complexity limits.

    Examples
    --------
    >>> safe_eval("2 + 3")
    5
    >>> safe_eval("0xFF ^ 0x12")
    237
    >>> safe_eval('String.fromCharCode(72, 101, 108)', 'js')
    'Hel'
    >>> safe_eval("chr(65) + chr(66)", "python")
    'AB'
    """
    if not isinstance(expr, str) or not expr.strip():
        return None
    expr = expr.strip()
    if len(expr) > MAX_EXPR_LENGTH:
        logger.debug("safe_eval: expression too long (%d chars), skipping", len(expr))
        return None

    lang = (language or "").lower().strip()

    # Decide preprocessing strategy
    if lang in ("javascript", "js"):
        return _eval_js(expr)
    if lang in ("python", "py"):
        return _eval_python(expr)

    # Unknown or empty language -- try JS first (more common in obfuscation),
    # fall back to Python.
    result = _eval_js(expr)
    if result is not None:
        return result
    return _eval_python(expr)


def safe_eval_js(expr: str) -> int | float | str | None:
    """Convenience wrapper: evaluate a JavaScript expression.

    Parameters
    ----------
    expr:
        A JavaScript expression string.

    Returns
    -------
    int | float | str | None
        The evaluated result, or ``None`` on failure.

    Examples
    --------
    >>> safe_eval_js("parseInt('ff', 16)")
    255
    >>> safe_eval_js('Math.floor(3.7)')
    3
    >>> safe_eval_js('atob("SGVsbG8=")')
    'Hello'
    """
    return safe_eval(expr, language="js")


# ---------------------------------------------------------------------------
# Internal language-specific evaluators
# ---------------------------------------------------------------------------

def _eval_js(expr: str) -> _ResultType:
    """Preprocess a JS expression and evaluate it."""
    py_expr = _js_to_python_source(expr)
    py_expr = _preprocess_python_expr(py_expr)  # also handle base64.* in JS

    namespace = dict(_SAFE_NAMESPACE)

    def _do_eval() -> _ResultType:
        return _eval_core(py_expr, namespace)

    return _run_with_timeout(_do_eval)


def _eval_python(expr: str) -> _ResultType:
    """Preprocess a Python expression and evaluate it."""
    py_expr = _preprocess_python_expr(expr)
    namespace = dict(_SAFE_NAMESPACE)

    def _do_eval() -> _ResultType:
        return _eval_core(py_expr, namespace)

    return _run_with_timeout(_do_eval)
