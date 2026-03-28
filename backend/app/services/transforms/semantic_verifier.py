from __future__ import annotations

import ast
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from app.services.transforms.js_tooling import parse_javascript_ast
from app.services.transforms.source_preprocessor import normalize_source_anomalies

_MAX_SEMANTIC_SOURCE_LENGTH = 160_000

_JS_DYNAMIC_EXEC_CALLEES = {"eval", "function", "global.eval", "window.eval"}
_JS_IMPORT_CALLEES = {"require", "import"}
_PY_DYNAMIC_EXEC_CALLEES = {"eval", "exec", "compile", "__import__"}
_PS_DYNAMIC_EXEC_COMMANDS = {"iex", "invoke-expression"}
_PS_NON_CALL_TOKENS = {
    "begin",
    "break",
    "catch",
    "class",
    "continue",
    "data",
    "do",
    "dynamicparam",
    "else",
    "elseif",
    "end",
    "exit",
    "filter",
    "finally",
    "for",
    "foreach",
    "function",
    "if",
    "in",
    "param",
    "process",
    "return",
    "switch",
    "throw",
    "trap",
    "try",
    "until",
    "using",
    "while",
    "workflow",
}

_POWERSHELL_IMPORT_RE = re.compile(r"^\s*Import-Module\s+([^\s#;]+)", flags=re.IGNORECASE)
_POWERSHELL_DOTSOURCE_RE = re.compile(r"^\s*\.\s+([^\s#;]+)")
_POWERSHELL_EXPORT_RE = re.compile(
    r"^\s*Export-ModuleMember\b(?P<args>.*)$",
    flags=re.IGNORECASE,
)
_POWERSHELL_FUNCTION_FLAG_RE = re.compile(
    r"-Function\s+([^#;]+?)(?=\s+-[A-Za-z]+|\s*$)",
    flags=re.IGNORECASE,
)
_POWERSHELL_FUNCTION_DEF_RE = re.compile(
    r"^\s*function\s+([A-Za-z_][\w.-]*)",
    flags=re.IGNORECASE,
)
_POWERSHELL_CALL_RE = re.compile(r"^\s*(?:&\s+)?([A-Za-z_][\w.-]*)")


def semantic_validation_summary(
    *,
    language: str,
    before: str,
    after: str,
    size_ratio: Optional[float] = None,
) -> Dict[str, Any]:
    before_signature = semantic_signature(language, before)
    after_signature = semantic_signature(language, after)
    available = bool(before_signature.get("available")) and bool(after_signature.get("available"))

    reasons: List[str] = []
    details: Dict[str, Any] = {}

    if available:
        before_exports = set(before_signature.get("exports", []))
        after_exports = set(after_signature.get("exports", []))
        missing_exports = sorted(before_exports - after_exports)
        if missing_exports:
            reasons.append("export_surface_changed")
            details["missing_exports"] = missing_exports[:12]

        before_imports = set(before_signature.get("imports", []))
        after_imports = set(after_signature.get("imports", []))
        missing_imports = sorted(before_imports - after_imports)
        if (
            before_imports
            and missing_imports
            and len(missing_imports) >= max(1, int(len(before_imports) * 0.6))
            and (size_ratio or 1.0) < 0.85
        ):
            reasons.append("dependency_surface_changed")
            details["missing_imports"] = missing_imports[:12]

        before_calls = set(before_signature.get("top_level_calls", []))
        after_calls = set(after_signature.get("top_level_calls", []))
        missing_calls = sorted(before_calls - after_calls)
        if before_calls and not after_calls:
            reasons.append("entrypoint_call_surface_removed")
            details["missing_top_level_calls"] = missing_calls[:12]

    return {
        "available": available,
        "mode": _combine_modes(
            str(before_signature.get("mode") or ""),
            str(after_signature.get("mode") or ""),
        ),
        "reasons": reasons,
        "before": before_signature,
        "after": after_signature,
        **details,
    }


def semantic_signature(language: str, code: str) -> Dict[str, Any]:
    lang = (language or "").lower().strip()
    cleaned, _ = normalize_source_anomalies(code)
    if len(cleaned) > _MAX_SEMANTIC_SOURCE_LENGTH:
        return {
            "available": False,
            "mode": f"{lang or 'unknown'}_skipped",
            "reason": "source_too_large",
        }

    if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx"}:
        return _javascript_semantic_signature(cleaned, lang)
    if lang in {"python", "py"}:
        return _python_semantic_signature(cleaned)
    if lang == "powershell":
        return _powershell_semantic_signature(cleaned)

    return {
        "available": False,
        "mode": f"{lang or 'unknown'}_unsupported",
        "reason": "language_not_supported",
    }


def _combine_modes(before_mode: str, after_mode: str) -> str:
    if before_mode and after_mode and before_mode != after_mode:
        return f"{before_mode}->{after_mode}"
    return before_mode or after_mode or "unknown"


def _sorted_unique(values: Iterable[str]) -> List[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _javascript_semantic_signature(code: str, language: str) -> Dict[str, Any]:
    program = parse_javascript_ast(code, language=language)
    if program is None:
        return {
            "available": False,
            "mode": "javascript_ast",
            "reason": "parse_unavailable",
        }

    imports: Set[str] = set()
    exports: Set[str] = set()
    top_level_calls: Set[str] = set()
    local_symbols: Set[str] = set()

    for statement in getattr(program, "body", []) or []:
        local_symbols.update(_javascript_declared_names(statement))

    for statement in getattr(program, "body", []) or []:
        _collect_javascript_semantics(
            statement,
            imports=imports,
            exports=exports,
        )
        _collect_javascript_top_level_calls(
            statement,
            top_level_calls=top_level_calls,
            local_symbols=local_symbols,
        )

    return {
        "available": True,
        "mode": "javascript_ast",
        "imports": _sorted_unique(imports),
        "exports": _sorted_unique(exports),
        "top_level_calls": _sorted_unique(top_level_calls),
        "local_symbols": _sorted_unique(local_symbols),
    }


def _collect_javascript_semantics(
    node: Any,
    *,
    imports: Set[str],
    exports: Set[str],
) -> None:
    node_type = _javascript_node_type(node)
    if not node_type:
        return
    if node_type in {
        "FunctionDeclaration",
        "FunctionExpression",
        "ArrowFunctionExpression",
        "ClassMethod",
        "ObjectMethod",
    }:
        return

    if node_type == "ImportDeclaration":
        source = _javascript_string_value(getattr(node, "source", None))
        if source:
            imports.add(source)

    if node_type == "ExportDefaultDeclaration":
        exports.add("default")

    if node_type == "ExportNamedDeclaration":
        declaration = getattr(node, "declaration", None)
        for name in _javascript_declared_names(declaration):
            exports.add(name)
        for specifier in getattr(node, "specifiers", []) or []:
            exported = _javascript_name_value(getattr(specifier, "exported", None))
            local = _javascript_name_value(getattr(specifier, "local", None))
            if exported or local:
                exports.add(exported or local)
        source = _javascript_string_value(getattr(node, "source", None))
        if source:
            imports.add(source)

    if node_type == "ExportAllDeclaration":
        exports.add("*")
        source = _javascript_string_value(getattr(node, "source", None))
        if source:
            imports.add(source)

    if node_type == "AssignmentExpression":
        export_name = _javascript_commonjs_export_name(getattr(node, "left", None))
        if export_name:
            exports.add(export_name)

    if node_type in {"CallExpression", "OptionalCallExpression", "NewExpression"}:
        callee_name = _javascript_callee_name(getattr(node, "callee", None))
        if callee_name:
            lowered = callee_name.lower()
            if lowered in _JS_IMPORT_CALLEES:
                source = _javascript_string_value(_first_argument(node))
                if source:
                    imports.add(source)

    for child in _javascript_child_nodes(node):
        _collect_javascript_semantics(
            child,
            imports=imports,
            exports=exports,
        )


def _javascript_child_nodes(node: Any) -> List[Any]:
    children: List[Any] = []
    for key, value in getattr(node, "__dict__", {}).items():
        if key in {"loc", "range", "start", "end", "extra"}:
            continue
        if isinstance(value, list):
            children.extend(item for item in value if hasattr(item, "__dict__"))
        elif hasattr(value, "__dict__"):
            children.append(value)
    return children


def _collect_javascript_top_level_calls(
    node: Any,
    *,
    top_level_calls: Set[str],
    local_symbols: Set[str],
) -> None:
    node_type = _javascript_node_type(node)
    if not node_type:
        return

    if node_type == "ExpressionStatement":
        _collect_javascript_effect_calls_from_expression(
            getattr(node, "expression", None),
            top_level_calls=top_level_calls,
            local_symbols=local_symbols,
        )
        return

    if node_type == "BlockStatement":
        for statement in getattr(node, "body", []) or []:
                _collect_javascript_top_level_calls(
                    statement,
                    top_level_calls=top_level_calls,
                    local_symbols=local_symbols,
                )
        return

    if node_type in {
        "IfStatement",
        "LabeledStatement",
        "WhileStatement",
        "DoWhileStatement",
        "ForStatement",
        "ForInStatement",
        "ForOfStatement",
        "WithStatement",
    }:
        for child in (
            getattr(node, "consequent", None),
            getattr(node, "alternate", None),
            getattr(node, "body", None),
        ):
            if child is not None:
                _collect_javascript_top_level_calls(
                    child,
                    top_level_calls=top_level_calls,
                    local_symbols=local_symbols,
                )
        return

    if node_type == "TryStatement":
        for child in (
            getattr(node, "block", None),
            getattr(node, "handler", None),
            getattr(node, "finalizer", None),
        ):
            if child is not None:
                _collect_javascript_top_level_calls(
                    child,
                    top_level_calls=top_level_calls,
                    local_symbols=local_symbols,
                )
        return

    if node_type == "SwitchStatement":
        for case in getattr(node, "cases", []) or []:
            for statement in getattr(case, "consequent", []) or []:
                _collect_javascript_top_level_calls(
                    statement,
                    top_level_calls=top_level_calls,
                    local_symbols=local_symbols,
                )


def _collect_javascript_effect_calls_from_expression(
    node: Any,
    *,
    top_level_calls: Set[str],
    local_symbols: Set[str],
) -> None:
    node_type = _javascript_node_type(node)
    if not node_type:
        return
    if node_type in {
        "FunctionExpression",
        "ArrowFunctionExpression",
        "ClassExpression",
        "ClassMethod",
        "ObjectMethod",
    }:
        return
    if node_type in {"CallExpression", "OptionalCallExpression", "NewExpression"}:
        callee_name = _javascript_callee_name(getattr(node, "callee", None))
        if callee_name:
            lowered = callee_name.lower()
            if lowered not in _JS_IMPORT_CALLEES and lowered not in _JS_DYNAMIC_EXEC_CALLEES:
                top_level_calls.add(_normalize_javascript_call_name(callee_name, local_symbols))
    for child in _javascript_child_nodes(node):
        _collect_javascript_effect_calls_from_expression(
            child,
            top_level_calls=top_level_calls,
            local_symbols=local_symbols,
        )


def _normalize_javascript_call_name(name: str, local_symbols: Set[str]) -> str:
    value = str(name).strip()
    if not value:
        return value
    base = value.split(".", 1)[0]
    if base in local_symbols:
        return "local_member_call" if "." in value else "local_call"
    return value


def _javascript_node_type(node: Any) -> str:
    return str(getattr(node, "type", "") or "").strip()


def _javascript_name_value(node: Any) -> str:
    node_type = _javascript_node_type(node)
    if node_type == "Identifier":
        return str(getattr(node, "name", "") or "").strip()
    if node_type == "PrivateName":
        return _javascript_name_value(getattr(node, "id", None))
    if node_type in {"Literal", "StringLiteral"}:
        value = getattr(node, "value", None)
        return str(value).strip() if isinstance(value, str) else ""
    return ""


def _javascript_string_value(node: Any) -> str:
    node_type = _javascript_node_type(node)
    if node_type in {"Literal", "StringLiteral"}:
        value = getattr(node, "value", None)
        return str(value).strip() if isinstance(value, str) else ""
    if node_type == "TemplateLiteral":
        expressions = getattr(node, "expressions", []) or []
        if expressions:
            return ""
        parts: List[str] = []
        for quasi in getattr(node, "quasis", []) or []:
            value = getattr(quasi, "value", None)
            cooked = getattr(value, "cooked", None) if value is not None else None
            raw = getattr(value, "raw", None) if value is not None else None
            if isinstance(cooked, str):
                parts.append(cooked)
            elif isinstance(raw, str):
                parts.append(raw)
        return "".join(parts).strip()
    return ""


def _javascript_declared_names(node: Any) -> List[str]:
    node_type = _javascript_node_type(node)
    if node_type in {"FunctionDeclaration", "ClassDeclaration"}:
        name = _javascript_name_value(getattr(node, "id", None))
        return [name] if name else []
    if node_type in {"TSInterfaceDeclaration", "TSTypeAliasDeclaration"}:
        name = _javascript_name_value(getattr(node, "id", None))
        return [name] if name else []
    if node_type == "VariableDeclaration":
        names: List[str] = []
        for declaration in getattr(node, "declarations", []) or []:
            names.extend(_javascript_pattern_names(getattr(declaration, "id", None)))
        return names
    return []


def _javascript_pattern_names(node: Any) -> List[str]:
    node_type = _javascript_node_type(node)
    if node_type == "Identifier":
        name = _javascript_name_value(node)
        return [name] if name else []
    if node_type == "AssignmentPattern":
        return _javascript_pattern_names(getattr(node, "left", None))
    if node_type == "RestElement":
        return _javascript_pattern_names(getattr(node, "argument", None))
    if node_type == "ObjectPattern":
        names: List[str] = []
        for prop in getattr(node, "properties", []) or []:
            prop_type = _javascript_node_type(prop)
            if prop_type == "RestElement":
                names.extend(_javascript_pattern_names(getattr(prop, "argument", None)))
            else:
                names.extend(_javascript_pattern_names(getattr(prop, "value", None)))
        return names
    if node_type == "ArrayPattern":
        names: List[str] = []
        for element in getattr(node, "elements", []) or []:
            names.extend(_javascript_pattern_names(element))
        return names
    return []


def _javascript_callee_name(node: Any) -> str:
    node_type = _javascript_node_type(node)
    if node_type == "Identifier":
        return _javascript_name_value(node)
    if node_type == "ThisExpression":
        return "this"
    if node_type == "Super":
        return "super"
    if node_type == "Import":
        return "import"
    if node_type == "MetaProperty":
        meta = _javascript_name_value(getattr(node, "meta", None))
        prop = _javascript_name_value(getattr(node, "property", None))
        return ".".join(part for part in (meta, prop) if part)
    if node_type in {"MemberExpression", "OptionalMemberExpression"}:
        object_name = _javascript_callee_name(getattr(node, "object", None))
        property_name = _javascript_property_name(
            getattr(node, "property", None),
            computed=bool(getattr(node, "computed", False)),
        )
        if object_name and property_name:
            return f"{object_name}.{property_name}"
        return object_name or property_name
    if node_type in {"CallExpression", "OptionalCallExpression", "NewExpression"}:
        return _javascript_callee_name(getattr(node, "callee", None))
    if node_type == "ChainExpression":
        return _javascript_callee_name(getattr(node, "expression", None))
    if node_type == "AwaitExpression":
        return _javascript_callee_name(getattr(node, "argument", None))
    return ""


def _javascript_property_name(node: Any, *, computed: bool) -> str:
    name = _javascript_name_value(node)
    if name:
        return name
    if computed:
        return _javascript_string_value(node)
    return ""


def _javascript_commonjs_export_name(node: Any) -> str:
    node_type = _javascript_node_type(node)
    if node_type not in {"MemberExpression", "OptionalMemberExpression"}:
        return ""
    object_name = _javascript_callee_name(getattr(node, "object", None))
    property_name = _javascript_property_name(
        getattr(node, "property", None),
        computed=bool(getattr(node, "computed", False)),
    )
    if object_name == "module" and property_name == "exports":
        return "default"
    if object_name in {"module.exports", "exports"}:
        return property_name or "default"
    return ""


def _first_argument(node: Any) -> Any:
    arguments = getattr(node, "arguments", []) or []
    return arguments[0] if arguments else None


def _python_semantic_signature(code: str) -> Dict[str, Any]:
    try:
        module = ast.parse(code)
    except SyntaxError:
        return {
            "available": False,
            "mode": "python_ast",
            "reason": "parse_unavailable",
        }

    imports: Set[str] = set()
    exports: Set[str] = set()
    top_level_calls: Set[str] = set()
    local_symbols: Set[str] = set()

    for statement in module.body:
        local_symbols.update(_python_declared_names(statement))

    for statement in module.body:
        _collect_python_semantics(
            statement,
            imports=imports,
            exports=exports,
        )
        _collect_python_top_level_calls(
            statement,
            top_level_calls=top_level_calls,
            local_symbols=local_symbols,
        )

    return {
        "available": True,
        "mode": "python_ast",
        "imports": _sorted_unique(imports),
        "exports": _sorted_unique(exports),
        "top_level_calls": _sorted_unique(top_level_calls),
        "local_symbols": _sorted_unique(local_symbols),
    }


def _collect_python_semantics(
    node: ast.AST,
    *,
    imports: Set[str],
    exports: Set[str],
) -> None:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return

    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name:
                imports.add(alias.name)
    elif isinstance(node, ast.ImportFrom):
        module = "." * node.level + (node.module or "")
        if module:
            imports.add(module)
    elif isinstance(node, (ast.Assign, ast.AnnAssign)):
        if _python_assigns_name(node, "__all__"):
            for item in _python_string_collection(getattr(node, "value", None)):
                exports.add(item)

    for child in ast.iter_child_nodes(node):
        _collect_python_semantics(
            child,
            imports=imports,
            exports=exports,
        )


def _collect_python_top_level_calls(
    node: ast.AST,
    *,
    top_level_calls: Set[str],
    local_symbols: Set[str],
) -> None:
    if isinstance(node, ast.Expr):
        _collect_python_effect_calls_from_expression(
            node.value,
            top_level_calls=top_level_calls,
            local_symbols=local_symbols,
        )
        return

    if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
        for statement in list(node.body) + list(node.orelse):
            _collect_python_top_level_calls(
                statement,
                top_level_calls=top_level_calls,
                local_symbols=local_symbols,
            )
        return

    if isinstance(node, ast.Try):
        for statement in list(node.body) + list(node.orelse) + list(node.finalbody):
            _collect_python_top_level_calls(
                statement,
                top_level_calls=top_level_calls,
                local_symbols=local_symbols,
            )
        for handler in node.handlers:
            for statement in handler.body:
                _collect_python_top_level_calls(
                    statement,
                    top_level_calls=top_level_calls,
                    local_symbols=local_symbols,
                )


def _collect_python_effect_calls_from_expression(
    node: ast.AST,
    *,
    top_level_calls: Set[str],
    local_symbols: Set[str],
) -> None:
    if isinstance(node, ast.Lambda):
        return
    if isinstance(node, ast.Call):
        call_name = _python_call_name(node.func)
        if call_name and call_name.lower() not in _PY_DYNAMIC_EXEC_CALLEES:
            top_level_calls.add(_normalize_python_call_name(call_name, local_symbols))
    for child in ast.iter_child_nodes(node):
        _collect_python_effect_calls_from_expression(
            child,
            top_level_calls=top_level_calls,
            local_symbols=local_symbols,
        )


def _python_declared_names(node: ast.AST) -> Set[str]:
    names: Set[str] = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(node.name)
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            names.update(_python_assignment_names(target))
    elif isinstance(node, ast.AnnAssign):
        names.update(_python_assignment_names(node.target))
    return names


def _python_assignment_names(node: ast.AST) -> Set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: Set[str] = set()
        for item in node.elts:
            names.update(_python_assignment_names(item))
        return names
    return set()


def _normalize_python_call_name(name: str, local_symbols: Set[str]) -> str:
    value = str(name).strip()
    if not value:
        return value
    base = value.split(".", 1)[0]
    if base in local_symbols:
        return "local_member_call" if "." in value else "local_call"
    return value


def _python_assigns_name(node: ast.AST, name: str) -> bool:
    targets: List[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    for target in targets:
        if isinstance(target, ast.Name) and target.id == name:
            return True
    return False


def _python_string_collection(node: Optional[ast.AST]) -> List[str]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    values: List[str] = []
    for item in node.elts:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            values.append(item.value)
        else:
            return []
    return values


def _python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _python_call_name(node.func)
    return ""


def _powershell_semantic_signature(code: str) -> Dict[str, Any]:
    imports: Set[str] = set()
    exports: Set[str] = set()
    top_level_calls: Set[str] = set()
    local_functions: Set[str] = set()
    brace_depth = 0

    for raw_line in code.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        function_match = _POWERSHELL_FUNCTION_DEF_RE.match(line)
        if function_match:
            local_functions.add(function_match.group(1))

    for raw_line in code.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            brace_depth += raw_line.count("{") - raw_line.count("}")
            brace_depth = max(brace_depth, 0)
            continue

        if brace_depth == 0:
            import_match = _POWERSHELL_IMPORT_RE.match(line)
            if import_match:
                imports.add(import_match.group(1).strip("\"'"))

            dotsource_match = _POWERSHELL_DOTSOURCE_RE.match(line)
            if dotsource_match:
                imports.add(dotsource_match.group(1).strip("\"'"))

            export_match = _POWERSHELL_EXPORT_RE.match(line)
            if export_match:
                for function_block in _POWERSHELL_FUNCTION_FLAG_RE.findall(export_match.group("args") or ""):
                    for name in re.split(r"[\s,]+", function_block):
                        cleaned_name = name.strip("\"',")
                        if cleaned_name:
                            exports.add(cleaned_name)

            call_match = _POWERSHELL_CALL_RE.match(line)
            if call_match:
                command = call_match.group(1).strip()
                lowered = command.lower()
                if (
                    command
                    and not command.startswith("$")
                    and lowered not in _PS_NON_CALL_TOKENS
                    and lowered not in _PS_DYNAMIC_EXEC_COMMANDS
                ):
                    top_level_calls.add(
                        "local_call" if command in local_functions else command
                    )

        brace_depth += raw_line.count("{") - raw_line.count("}")
        brace_depth = max(brace_depth, 0)

    return {
        "available": True,
        "mode": "powershell_regex",
        "imports": _sorted_unique(imports),
        "exports": _sorted_unique(exports),
        "top_level_calls": _sorted_unique(top_level_calls),
        "local_symbols": _sorted_unique(local_functions),
    }
