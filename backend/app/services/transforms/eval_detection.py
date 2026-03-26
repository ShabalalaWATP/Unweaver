"""
EvalExecDetector transform -- finds dangerous eval/exec/invoke calls across
JavaScript, Python, PowerShell, and C#.  Extracts the argument expressions
where possible and flags them as suspicious APIs.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Per-language suspicious API patterns
# ---------------------------------------------------------------------------


@dataclass
class _APIPattern:
    """One suspicious API to look for."""

    name: str
    language: str
    pattern: re.Pattern
    severity: str  # "high", "medium", "low"
    description: str
    arg_group: int = 1  # capture group index for the argument


# -- JavaScript / TypeScript -------------------------------------------------

_JS_PATTERNS: list[_APIPattern] = [
    _APIPattern(
        name="eval",
        language="javascript",
        pattern=re.compile(
            r"\beval\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="eval() executes arbitrary code",
    ),
    _APIPattern(
        name="Function",
        language="javascript",
        pattern=re.compile(
            r"\bnew\s+Function\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="new Function() creates executable code from a string",
    ),
    _APIPattern(
        name="Function_call",
        language="javascript",
        pattern=re.compile(
            r"\bFunction\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="Function() constructor creates executable code",
    ),
    _APIPattern(
        name="setTimeout_string",
        language="javascript",
        pattern=re.compile(
            r"\bsetTimeout\s*\(\s*(['\"](?:[^'\"\\]|\\.)*['\"])\s*,"
        ),
        severity="medium",
        description="setTimeout with string argument executes code",
    ),
    _APIPattern(
        name="setInterval_string",
        language="javascript",
        pattern=re.compile(
            r"\bsetInterval\s*\(\s*(['\"](?:[^'\"\\]|\\.)*['\"])\s*,"
        ),
        severity="medium",
        description="setInterval with string argument executes code",
    ),
    _APIPattern(
        name="document_write",
        language="javascript",
        pattern=re.compile(
            r"\bdocument\.write(?:ln)?\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="medium",
        description="document.write can inject executable content",
    ),
    _APIPattern(
        name="innerHTML",
        language="javascript",
        pattern=re.compile(
            r"\.innerHTML\s*=\s*([^\n;]+)"
        ),
        severity="medium",
        description="innerHTML assignment can execute scripts",
    ),
]

# -- Python ------------------------------------------------------------------

_PY_PATTERNS: list[_APIPattern] = [
    _APIPattern(
        name="eval",
        language="python",
        pattern=re.compile(
            r"\beval\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="eval() executes arbitrary Python expressions",
    ),
    _APIPattern(
        name="exec",
        language="python",
        pattern=re.compile(
            r"\bexec\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="exec() executes arbitrary Python statements",
    ),
    _APIPattern(
        name="compile",
        language="python",
        pattern=re.compile(
            r"\bcompile\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="medium",
        description="compile() creates executable code objects",
    ),
    _APIPattern(
        name="__import__",
        language="python",
        pattern=re.compile(
            r"\b__import__\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="medium",
        description="__import__() dynamically imports modules",
    ),
    _APIPattern(
        name="os_system",
        language="python",
        pattern=re.compile(
            r"\bos\.system\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="os.system() executes shell commands",
    ),
    _APIPattern(
        name="subprocess",
        language="python",
        pattern=re.compile(
            r"\bsubprocess\.(?:call|run|Popen|check_output)\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="subprocess executes external commands",
    ),
    _APIPattern(
        name="getattr",
        language="python",
        pattern=re.compile(
            r"\bgetattr\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="low",
        description="getattr() can access arbitrary attributes dynamically",
    ),
]

# -- PowerShell --------------------------------------------------------------

_PS_PATTERNS: list[_APIPattern] = [
    _APIPattern(
        name="Invoke-Expression",
        language="powershell",
        pattern=re.compile(
            r"\b(?:Invoke-Expression|iex)\s+([^\n|;]+)",
            re.IGNORECASE,
        ),
        severity="high",
        description="Invoke-Expression (IEX) executes arbitrary PowerShell",
    ),
    _APIPattern(
        name="IEX_pipe",
        language="powershell",
        pattern=re.compile(
            r"\|\s*(?:Invoke-Expression|iex)\b",
            re.IGNORECASE,
        ),
        severity="high",
        description="Piped to IEX -- executes piped string as code",
        arg_group=0,
    ),
    _APIPattern(
        name="Invoke_method",
        language="powershell",
        pattern=re.compile(
            r"\.Invoke\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description=".Invoke() calls a delegate or script block",
    ),
    _APIPattern(
        name="ScriptBlock_Create",
        language="powershell",
        pattern=re.compile(
            r"\[ScriptBlock\]::Create\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)",
            re.IGNORECASE,
        ),
        severity="high",
        description="ScriptBlock::Create builds executable script blocks",
    ),
    _APIPattern(
        name="EncodedCommand",
        language="powershell",
        pattern=re.compile(
            r"-(?:EncodedCommand|enc)\s+([^\s;|]+)",
            re.IGNORECASE,
        ),
        severity="high",
        description="EncodedCommand runs base64-encoded PowerShell",
    ),
    _APIPattern(
        name="DownloadString",
        language="powershell",
        pattern=re.compile(
            r"\.DownloadString\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)",
            re.IGNORECASE,
        ),
        severity="high",
        description="DownloadString fetches remote content for execution",
    ),
    _APIPattern(
        name="Start-Process",
        language="powershell",
        pattern=re.compile(
            r"\bStart-Process\s+([^\n|;]+)",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Start-Process launches external processes",
    ),
]

# -- C# / .NET --------------------------------------------------------------

_CS_PATTERNS: list[_APIPattern] = [
    _APIPattern(
        name="Assembly_Load",
        language="csharp",
        pattern=re.compile(
            r"\bAssembly\.Load(?:From|File)?\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="Assembly.Load dynamically loads .NET assemblies",
    ),
    _APIPattern(
        name="Activator_CreateInstance",
        language="csharp",
        pattern=re.compile(
            r"\bActivator\.CreateInstance\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="Activator.CreateInstance dynamically instantiates types",
    ),
    _APIPattern(
        name="Process_Start",
        language="csharp",
        pattern=re.compile(
            r"\bProcess\.Start\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="Process.Start launches external processes",
    ),
    _APIPattern(
        name="Invoke_Member",
        language="csharp",
        pattern=re.compile(
            r"\.InvokeMember\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="InvokeMember dynamically calls methods via reflection",
    ),
    _APIPattern(
        name="DynamicInvoke",
        language="csharp",
        pattern=re.compile(
            r"\.DynamicInvoke\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="DynamicInvoke calls delegates dynamically",
    ),
    _APIPattern(
        name="CompileAssemblyFromSource",
        language="csharp",
        pattern=re.compile(
            r"\.CompileAssemblyFromSource\s*\(\s*((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\s*\)"
        ),
        severity="high",
        description="CompileAssemblyFromSource compiles and runs C# at runtime",
    ),
]

# Combine all
_ALL_PATTERNS: dict[str, list[_APIPattern]] = {
    "javascript": _JS_PATTERNS,
    "typescript": _JS_PATTERNS,
    "js": _JS_PATTERNS,
    "ts": _JS_PATTERNS,
    "python": _PY_PATTERNS,
    "py": _PY_PATTERNS,
    "powershell": _PS_PATTERNS,
    "ps1": _PS_PATTERNS,
    "ps": _PS_PATTERNS,
    "csharp": _CS_PATTERNS,
    "cs": _CS_PATTERNS,
    "c#": _CS_PATTERNS,
}


_JS_LITERAL_EVAL = re.compile(
    r"""\beval\s*\(\s*(?P<literal>(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"))\s*\)\s*;?""",
    re.DOTALL,
)


def _sink_family(api_name: str) -> str:
    value = api_name.lower()
    if value in {"eval", "function", "function_call", "invoke-expression", "iex_pipe", "scriptblock_create"}:
        return "dynamic_code_execution"
    if "process" in value or value in {"os_system", "subprocess", "start-process"}:
        return "process_execution"
    if "download" in value:
        return "network_retrieval"
    if "assembly" in value or "compile" in value:
        return "dynamic_loading"
    if "invoke" in value:
        return "reflection_invocation"
    return "suspicious_sink"


def _parse_literal_string(literal: str) -> str | None:
    try:
        parsed = ast.literal_eval(literal)
    except (SyntaxError, ValueError):
        return None
    return parsed if isinstance(parsed, str) else None


def _balanced_snippet(snippet: str) -> bool:
    pairs = {"(": ")", "{": "}", "[": "]"}
    closing = {value: key for key, value in pairs.items()}
    stack: list[str] = []
    quote: str | None = None
    escaped = False

    for char in snippet:
        if quote is not None:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = None
            continue

        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in pairs:
            stack.append(char)
            continue
        if char in closing:
            if not stack or stack[-1] != closing[char]:
                return False
            stack.pop()

    return not stack and quote is None


def _looks_like_js_code(snippet: str) -> bool:
    candidate = snippet.strip()
    if len(candidate) < 4:
        return False
    indicators = (
        r"""\b(?:var|let|const|function|return|if|for|while|switch|try|catch|new|class|import|export)\b""",
        r"""\b[A-Za-z_$][\w$]*\s*\(""",
        r"""\b[A-Za-z_$][\w$]*\s*=""",
        r"""\b[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*\s*\(""",
        r"""[{};]""",
    )
    return any(re.search(pattern, candidate) for pattern in indicators)


class EvalExecDetector(BaseTransform):
    name = "eval_exec_detector"
    description = "Detect eval/exec/invoke and other dangerous API calls"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        patterns = self._get_patterns(language)
        return any(p.pattern.search(code) for p in patterns)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        patterns = self._get_patterns(language)
        findings: list[dict[str, Any]] = []
        output = code
        unwrapped_calls: list[dict[str, str]] = []

        for api in patterns:
            for m in api.pattern.finditer(code):
                arg = ""
                try:
                    if api.arg_group and api.arg_group <= m.lastindex:
                        arg = m.group(api.arg_group).strip()
                except (IndexError, TypeError):
                    arg = m.group(0).strip()

                findings.append({
                    "api": api.name,
                    "language": api.language,
                    "severity": api.severity,
                    "description": api.description,
                    "match": m.group(0)[:200],
                    "argument": arg[:500] if arg else "",
                    "position": m.start(),
                })

        if not findings:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No suspicious eval/exec APIs detected.",
            )

        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

        high_count = sum(1 for f in findings if f["severity"] == "high")
        confidence = min(0.98, 0.70 + 0.05 * high_count)

        identified_sinks = [
            {
                "api": finding["api"],
                "family": _sink_family(finding["api"]),
                "severity": finding["severity"],
                "argument": finding["argument"],
                "position": finding["position"],
            }
            for finding in findings
        ]
        suspicious_api_labels = [
            f'{item["api"]}:{item["severity"]}'
            for item in findings
        ]

        state.setdefault("suspicious_apis", []).extend(findings)

        severity_summary = {}
        for f in findings:
            severity_summary[f["severity"]] = (
                severity_summary.get(f["severity"], 0) + 1
            )

        summary = ", ".join(
            f"{count} {sev}" for sev, count in severity_summary.items()
        )

        lang = (language or "").lower().strip()
        if lang in {"javascript", "js", "typescript", "ts"}:
            def _unwrap_literal_eval(match: re.Match[str]) -> str:
                literal = match.group("literal")
                decoded = _parse_literal_string(literal)
                if decoded is None or not _looks_like_js_code(decoded):
                    return match.group(0)

                snippet = decoded.strip()
                if not snippet:
                    return match.group(0)
                if snippet[-1] not in {";", "}"}:
                    snippet += ";"
                if not _balanced_snippet(snippet):
                    return match.group(0)

                unwrapped_calls.append({
                    "api": "eval",
                    "original": match.group(0)[:240],
                    "rewritten": snippet[:240],
                })
                return snippet

            output = _JS_LITERAL_EVAL.sub(_unwrap_literal_eval, output)

        return TransformResult(
            success=True,
            output=output,
            confidence=confidence,
            description=(
                f"Detected {len(findings)} suspicious API call(s): {summary}."
                + (
                    f" Unwrapped {len(unwrapped_calls)} literal eval payload(s)."
                    if unwrapped_calls else ""
                )
            ),
            details={
                "finding_count": len(findings),
                "severity_summary": severity_summary,
                "findings": findings,
                "identified_sinks": identified_sinks,
                "suspicious_apis": suspicious_api_labels,
                "unwrapped_calls": unwrapped_calls,
            },
        )

    def _get_patterns(self, language: str) -> list[_APIPattern]:
        """Return patterns for the given language, or all if unknown."""
        lang = (language or "").lower().strip()
        if lang in _ALL_PATTERNS:
            return _ALL_PATTERNS[lang]
        # Unknown language -- search everything
        seen: set[str] = set()
        all_pats: list[_APIPattern] = []
        for pats in _ALL_PATTERNS.values():
            for p in pats:
                key = f"{p.language}:{p.name}"
                if key not in seen:
                    seen.add(key)
                    all_pats.append(p)
        return all_pats
