"""
Reflection chain resolver for .NET and PowerShell.

Detects and simplifies common reflection-based invocation patterns that
obfuscate the actual API being called.  Replaces indirect calls with
their direct equivalents where statically determinable.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# .NET reflection patterns
# ---------------------------------------------------------------------------

# Type.GetMethod("MethodName").Invoke(instance, args)
_GETMETHOD_INVOKE_RE = re.compile(
    r"""(?:GetType|typeof)\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""\.GetMethod\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""\.Invoke\s*\(\s*([^)]*)\)""",
    re.IGNORECASE,
)

# Assembly.Load(bytes).GetType("T").GetMethod("M").Invoke(null, args)
_ASSEMBLY_LOAD_CHAIN_RE = re.compile(
    r"""Assembly\.Load\w*\s*\([^)]+\)"""
    r"""\.GetType\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""\.GetMethod\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""\.Invoke\s*\(\s*[^)]*\)""",
    re.IGNORECASE,
)

# Activator.CreateInstance(Type.GetType("full.name"), args)
_ACTIVATOR_RE = re.compile(
    r"""Activator\.CreateInstance\s*\(\s*"""
    r"""(?:Type\.GetType\s*\(\s*)?['"]([^'"]+)['"]\s*\)?\s*"""
    r"""(?:,\s*([^)]*))?\)""",
    re.IGNORECASE,
)

# [System.Reflection.Assembly]::LoadFrom("path")
_PS_ASSEMBLY_LOAD_RE = re.compile(
    r"""\[(?:System\.Reflection\.)?Assembly\]::(?:Load|LoadFrom|LoadFile)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# PowerShell reflection patterns
# ---------------------------------------------------------------------------

# $obj.GetType().GetMethod("X").Invoke($obj, @(args))
_PS_GETMETHOD_RE = re.compile(
    r"""\$(\w+)\.GetType\(\)\.GetMethod\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""\.Invoke\s*\(\s*\$\1\s*,\s*@?\(([^)]*)\)\s*\)""",
    re.IGNORECASE,
)

# [Reflection.Assembly]::LoadWithPartialName("name")
_PS_PARTIAL_NAME_RE = re.compile(
    r"""\[(?:System\.)?Reflection\.Assembly\]::LoadWithPartialName\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Invoke-Expression variants via reflection:
# $x = [scriptblock]::Create("code"); $x.Invoke()
_PS_SCRIPTBLOCK_RE = re.compile(
    r"""\[scriptblock\]::Create\s*\(\s*['"]([^'"]{10,})['"]""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Python reflection patterns
# ---------------------------------------------------------------------------

# getattr(__import__('module'), 'func')(args)
_PY_GETATTR_IMPORT_RE = re.compile(
    r"""getattr\s*\(\s*__import__\s*\(\s*['"]([^'"]+)['"]\s*\)\s*,\s*['"]([^'"]+)['"]\s*\)"""
    r"""\s*\(([^)]*)\)""",
)

# globals()["func"](args) or locals()["func"](args)
_PY_GLOBALS_CALL_RE = re.compile(
    r"""(?:globals|locals)\s*\(\s*\)\s*\[\s*['"]([^'"]+)['"]\s*\]\s*\(([^)]*)\)""",
)


class ReflectionResolver(BaseTransform):
    """Resolve reflection-based indirect calls to direct equivalents."""

    name = "reflection_resolver"
    description = (
        "Resolve .NET/PowerShell/Python reflection chains "
        "(GetMethod+Invoke, Activator, getattr+__import__) to direct calls."
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        if not code or len(code) < 20:
            return False
        return bool(
            _GETMETHOD_INVOKE_RE.search(code)
            or _ASSEMBLY_LOAD_CHAIN_RE.search(code)
            or _ACTIVATOR_RE.search(code)
            or _PS_GETMETHOD_RE.search(code)
            or _PS_SCRIPTBLOCK_RE.search(code)
            or _PY_GETATTR_IMPORT_RE.search(code)
            or _PY_GLOBALS_CALL_RE.search(code)
            # Also detect concatenated string arguments in reflection calls
            or re.search(
                r"""(?:GetMethod|GetType|CreateInstance|__import__|getattr)\s*\(\s*['"][^'"]*['"]\s*\+""",
                code, re.IGNORECASE,
            )
            # String.Concat / [string]::Concat
            or re.search(
                r"""(?:\[string\]::|\bString\.)Concat\s*\(""",
                code, re.IGNORECASE,
            )
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        resolutions: List[Dict[str, Any]] = []
        new_code = code
        techniques: List[str] = []

        # Pre-process: resolve concatenated string arguments in reflection calls
        # Pattern: GetMethod("Down" + "load" + "String") → GetMethod("DownloadString")
        concat_in_call = re.compile(
            r"""(GetMethod|GetType|CreateInstance|__import__|getattr)\s*\(\s*"""
            r"""((?:['"][^'"]*['"]\s*\+\s*)*['"][^'"]*['"])\s*\)""",
            re.IGNORECASE,
        )
        for m in concat_in_call.finditer(new_code):
            concat_expr = m.group(2)
            # Extract and join all string parts
            parts = re.findall(r"""['"]([^'"]*)['"]""", concat_expr)
            if len(parts) > 1:
                joined = "".join(parts)
                original = m.group(0)
                resolved = f'{m.group(1)}("{joined}")'
                new_code = new_code.replace(original, resolved)
                resolutions.append({
                    "pattern": "concatenated_string",
                    "original": original[:120],
                    "resolved": resolved[:200],
                })
                techniques.append("string_concatenation")

        # Also handle: [string]::Concat("Down","load") or String.Concat(...)
        string_concat_re = re.compile(
            r"""(?:\[string\]::|\bString\.)Concat\s*\(\s*"""
            r"""((?:['"][^'"]*['"]\s*,\s*)*['"][^'"]*['"])\s*\)""",
            re.IGNORECASE,
        )
        for m in string_concat_re.finditer(new_code):
            parts = re.findall(r"""['"]([^'"]*)['"]""", m.group(1))
            if parts:
                joined = "".join(parts)
                new_code = new_code.replace(m.group(0), f'"{joined}"')
                resolutions.append({
                    "pattern": "String.Concat",
                    "resolved": joined[:200],
                })
                techniques.append("string_concatenation")

        # .NET: Type.GetMethod("M").Invoke(...)
        for m in _GETMETHOD_INVOKE_RE.finditer(new_code):
            type_name = m.group(1)
            method_name = m.group(2)
            args = m.group(3).strip()
            direct_call = f"{type_name}.{method_name}({args})"
            resolutions.append({
                "pattern": "GetMethod+Invoke",
                "original": m.group(0)[:120],
                "resolved": direct_call[:200],
                "type": type_name,
                "method": method_name,
            })
            new_code = new_code.replace(m.group(0), f"/* resolved: */ {direct_call}")
            techniques.append("reflection")

        # .NET: Assembly.Load chain
        for m in _ASSEMBLY_LOAD_CHAIN_RE.finditer(new_code):
            type_name = m.group(1)
            method_name = m.group(2)
            resolutions.append({
                "pattern": "Assembly.Load+GetType+Invoke",
                "resolved": f"{type_name}.{method_name}(...)",
                "type": type_name,
                "method": method_name,
            })
            new_code = new_code.replace(
                m.group(0),
                f"/* resolved: Assembly.Load → {type_name}.{method_name}() */"
            )
            techniques.append("reflection")

        # .NET: Activator.CreateInstance
        for m in _ACTIVATOR_RE.finditer(new_code):
            type_name = m.group(1)
            args = (m.group(2) or "").strip()
            resolutions.append({
                "pattern": "Activator.CreateInstance",
                "resolved": f"new {type_name}({args})",
                "type": type_name,
            })
            new_code = new_code.replace(m.group(0), f"new {type_name}({args})")
            techniques.append("reflection")

        # PowerShell: $obj.GetType().GetMethod("X").Invoke(...)
        for m in _PS_GETMETHOD_RE.finditer(new_code):
            var = m.group(1)
            method_name = m.group(2)
            args = m.group(3).strip()
            direct = f"${var}.{method_name}({args})"
            resolutions.append({
                "pattern": "PS GetMethod+Invoke",
                "resolved": direct[:200],
                "method": method_name,
            })
            new_code = new_code.replace(m.group(0), direct)
            techniques.append("reflection")

        # PowerShell: [scriptblock]::Create("code")
        for m in _PS_SCRIPTBLOCK_RE.finditer(new_code):
            inner_code = m.group(1)
            resolutions.append({
                "pattern": "ScriptBlock.Create",
                "resolved": inner_code[:200],
            })
            new_code = new_code.replace(
                m.group(0),
                f"/* resolved scriptblock: */ {inner_code[:200]}"
            )
            techniques.append("reflection")

        # Python: getattr(__import__('mod'), 'func')(args)
        for m in _PY_GETATTR_IMPORT_RE.finditer(new_code):
            module = m.group(1)
            func = m.group(2)
            args = m.group(3).strip()
            direct = f"{module}.{func}({args})"
            resolutions.append({
                "pattern": "getattr+__import__",
                "resolved": direct[:200],
                "module": module,
                "function": func,
            })
            new_code = new_code.replace(m.group(0), direct)
            techniques.append("reflection")

        # Python: globals()["func"](args)
        for m in _PY_GLOBALS_CALL_RE.finditer(new_code):
            func = m.group(1)
            args = m.group(2).strip()
            direct = f"{func}({args})"
            resolutions.append({
                "pattern": "globals/locals dict call",
                "resolved": direct[:200],
                "function": func,
            })
            new_code = new_code.replace(m.group(0), direct)
            techniques.append("reflection")

        # Assembly load paths (detection only)
        for m in _PS_ASSEMBLY_LOAD_RE.finditer(new_code):
            resolutions.append({
                "pattern": "Assembly.Load (path)",
                "resolved": f"Loads assembly from: {m.group(1)}",
            })
            techniques.append("reflection")

        for m in _PS_PARTIAL_NAME_RE.finditer(new_code):
            resolutions.append({
                "pattern": "LoadWithPartialName",
                "resolved": f"Loads assembly: {m.group(1)}",
            })
            techniques.append("reflection")

        success = len(resolutions) > 0
        confidence = min(0.5 + len(resolutions) * 0.1, 0.85) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Resolved {len(resolutions)} reflection chain(s) to direct calls."
                if success else "No reflection patterns found."
            ),
            details={
                "resolutions": resolutions[:20],
                "count": len(resolutions),
                "detected_techniques": list(set(techniques)),
                "suspicious_apis": [
                    r.get("resolved", "")[:80] for r in resolutions[:10]
                ],
            },
        )
