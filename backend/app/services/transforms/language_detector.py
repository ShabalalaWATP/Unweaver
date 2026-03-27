"""
LanguageDetector -- scores source code against heuristics for
JavaScript/TypeScript, Python, PowerShell, and C# and returns the
most likely language with a confidence score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .base import BaseTransform, TransformResult
from .binary_analysis import binary_text_to_bytes, looks_like_dotnet_assembly_bytes

# ---------------------------------------------------------------------------
# Heuristic definitions per language
# ---------------------------------------------------------------------------


@dataclass
class _LangHeuristic:
    """A single heuristic check for a language."""

    pattern: re.Pattern
    weight: float  # positive = evidence for the language
    description: str


# --- JavaScript / TypeScript ------------------------------------------------

_JS_HEURISTICS: list[_LangHeuristic] = [
    _LangHeuristic(re.compile(r"\bfunction\s+\w+\s*\("), 2.0, "function declaration"),
    _LangHeuristic(re.compile(r"\bconst\s+\w+\s*="), 1.5, "const assignment"),
    _LangHeuristic(re.compile(r"\blet\s+\w+\s*="), 1.5, "let assignment"),
    _LangHeuristic(re.compile(r"\bvar\s+\w+\s*="), 2.0, "var assignment"),
    _LangHeuristic(re.compile(r"=>\s*\{"), 2.0, "arrow function"),
    _LangHeuristic(re.compile(r"\bconsole\.log\b"), 3.0, "console.log"),
    _LangHeuristic(re.compile(r"\bdocument\.\w+"), 3.0, "document API"),
    _LangHeuristic(re.compile(r"\bwindow\.\w+"), 3.0, "window object"),
    _LangHeuristic(re.compile(r"\brequire\s*\("), 2.5, "require()"),
    _LangHeuristic(re.compile(r"\bmodule\.exports\b"), 3.0, "module.exports"),
    _LangHeuristic(re.compile(r"\bimport\s+\{"), 1.5, "ES import"),
    _LangHeuristic(re.compile(r"\bexport\s+(?:default\s+)?(?:function|class|const)"), 2.0, "ES export"),
    _LangHeuristic(re.compile(r"==="), 2.5, "strict equality"),
    _LangHeuristic(re.compile(r"!=="), 2.5, "strict inequality"),
    _LangHeuristic(re.compile(r"\bnew\s+Promise\b"), 2.0, "Promise constructor"),
    _LangHeuristic(re.compile(r"\.then\s*\("), 1.0, ".then()"),
    _LangHeuristic(re.compile(r"\basync\s+function\b"), 2.0, "async function"),
    _LangHeuristic(re.compile(r"\bawait\s+"), 1.0, "await"),
    _LangHeuristic(re.compile(r"`[^`]*\$\{"), 2.0, "template literal"),
    _LangHeuristic(re.compile(r"\btypeof\s+"), 2.0, "typeof"),
    _LangHeuristic(re.compile(r"\bundefined\b"), 1.5, "undefined keyword"),
    _LangHeuristic(re.compile(r";\s*$", re.MULTILINE), 0.5, "semicolons"),
    # TypeScript-specific
    _LangHeuristic(re.compile(r":\s*(?:string|number|boolean|any|void)\b"), 2.5, "TS type annotation"),
    _LangHeuristic(re.compile(r"\binterface\s+\w+\s*\{"), 2.0, "TS interface"),
    _LangHeuristic(re.compile(r"<\w+>"), 0.5, "generic type"),
]

# --- Python -----------------------------------------------------------------

_PY_HEURISTICS: list[_LangHeuristic] = [
    _LangHeuristic(re.compile(r"^def\s+\w+\s*\(", re.MULTILINE), 3.0, "def statement"),
    _LangHeuristic(re.compile(r"^class\s+\w+.*:", re.MULTILINE), 2.5, "class with colon"),
    _LangHeuristic(re.compile(r"^import\s+\w+", re.MULTILINE), 2.0, "import statement"),
    _LangHeuristic(re.compile(r"^from\s+\w+\s+import\b", re.MULTILINE), 3.0, "from-import"),
    _LangHeuristic(re.compile(r"\bself\.\w+"), 3.0, "self reference"),
    _LangHeuristic(re.compile(r"\bprint\s*\("), 1.5, "print()"),
    _LangHeuristic(re.compile(r"^if\s+.+:", re.MULTILINE), 1.5, "if with colon"),
    _LangHeuristic(re.compile(r"^for\s+\w+\s+in\s+", re.MULTILINE), 2.5, "for-in loop"),
    _LangHeuristic(re.compile(r"^while\s+.+:", re.MULTILINE), 1.0, "while with colon"),
    _LangHeuristic(re.compile(r"\bTrue\b"), 1.5, "True keyword"),
    _LangHeuristic(re.compile(r"\bFalse\b"), 1.5, "False keyword"),
    _LangHeuristic(re.compile(r"\bNone\b"), 2.0, "None keyword"),
    _LangHeuristic(re.compile(r"\belif\b"), 3.0, "elif keyword"),
    _LangHeuristic(re.compile(r"\bexcept\b"), 2.0, "except keyword"),
    _LangHeuristic(re.compile(r"^#\s*!", re.MULTILINE), 1.0, "shebang"),
    _LangHeuristic(re.compile(r"^#.*python", re.MULTILINE | re.IGNORECASE), 3.0, "python in comment"),
    _LangHeuristic(re.compile(r'"""'), 2.0, "triple-quote docstring"),
    _LangHeuristic(re.compile(r"\bif\s+__name__\s*=="), 5.0, "__name__ guard"),
    _LangHeuristic(re.compile(r"\blambda\s+"), 1.5, "lambda"),
    _LangHeuristic(re.compile(r"\bwith\s+\w+.*as\s+\w+:"), 2.5, "with-as statement"),
    _LangHeuristic(re.compile(r"\b@\w+"), 1.0, "decorator"),
    _LangHeuristic(re.compile(r"^\s{4}", re.MULTILINE), 0.3, "4-space indent"),
]

# --- PowerShell -------------------------------------------------------------

_PS_HEURISTICS: list[_LangHeuristic] = [
    _LangHeuristic(re.compile(r"\$\w+\s*="), 2.0, "$ variable assignment"),
    _LangHeuristic(re.compile(r"\bfunction\s+\w+\s*\{", re.IGNORECASE), 1.5, "PS function"),
    _LangHeuristic(re.compile(r"\bparam\s*\(", re.IGNORECASE), 3.0, "param block"),
    _LangHeuristic(re.compile(r"\bWrite-(?:Host|Output|Error)\b", re.IGNORECASE), 3.0, "Write-* cmdlet"),
    _LangHeuristic(re.compile(r"\bGet-\w+", re.IGNORECASE), 2.5, "Get-* cmdlet"),
    _LangHeuristic(re.compile(r"\bSet-\w+", re.IGNORECASE), 2.5, "Set-* cmdlet"),
    _LangHeuristic(re.compile(r"\bNew-\w+", re.IGNORECASE), 2.5, "New-* cmdlet"),
    _LangHeuristic(re.compile(r"\bInvoke-\w+", re.IGNORECASE), 3.0, "Invoke-* cmdlet"),
    _LangHeuristic(re.compile(r"\b-(?:eq|ne|lt|gt|le|ge|like|match|contains)\b", re.IGNORECASE), 3.0, "PS comparison operator"),
    _LangHeuristic(re.compile(r"\b-(?:and|or|not)\b", re.IGNORECASE), 2.0, "PS logical operator"),
    _LangHeuristic(re.compile(r"\|\s*(?:Where-Object|ForEach-Object|Select-Object)", re.IGNORECASE), 3.0, "pipeline cmdlet"),
    _LangHeuristic(re.compile(r"\|\s*%\s*\{"), 2.0, "ForEach shorthand"),
    _LangHeuristic(re.compile(r"\|\s*\?\s*\{"), 2.0, "Where shorthand"),
    _LangHeuristic(re.compile(r"\[(?:string|int|bool|array|hashtable)\]", re.IGNORECASE), 2.5, "type cast"),
    _LangHeuristic(re.compile(r"\[System\.\w+\]", re.IGNORECASE), 3.0, ".NET type usage"),
    _LangHeuristic(re.compile(r"::"), 1.5, "static method call"),
    _LangHeuristic(re.compile(r"\bbegin\b.*\bprocess\b.*\bend\b", re.IGNORECASE | re.DOTALL), 3.0, "begin/process/end"),
    _LangHeuristic(re.compile(r"#\s*requires\s+-", re.IGNORECASE), 3.0, "#requires directive"),
    _LangHeuristic(re.compile(r"\bcmdletbinding\b", re.IGNORECASE), 4.0, "CmdletBinding"),
    _LangHeuristic(re.compile(r"-(?:replace|split|join)\b", re.IGNORECASE), 1.5, "string operator"),
]

# --- C# / .NET -------------------------------------------------------------

_CS_HEURISTICS: list[_LangHeuristic] = [
    _LangHeuristic(re.compile(r"\busing\s+System"), 4.0, "using System"),
    _LangHeuristic(re.compile(r"\bnamespace\s+\w+"), 3.0, "namespace"),
    _LangHeuristic(re.compile(r"\bpublic\s+(?:class|static|void|int|string)\b"), 3.0, "public modifier"),
    _LangHeuristic(re.compile(r"\bprivate\s+(?:class|static|void|int|string)\b"), 2.5, "private modifier"),
    _LangHeuristic(re.compile(r"\bstatic\s+void\s+Main\b"), 5.0, "Main method"),
    _LangHeuristic(re.compile(r"\bConsole\.Write(?:Line)?\b"), 3.0, "Console.Write"),
    _LangHeuristic(re.compile(r"\bnew\s+\w+\s*\("), 1.0, "new constructor"),
    _LangHeuristic(re.compile(r"\bvar\s+\w+\s*=\s*new\b"), 2.0, "var with new"),
    _LangHeuristic(re.compile(r"\bstring\[\]\b"), 2.5, "string array type"),
    _LangHeuristic(re.compile(r"\bint\[\]\b"), 2.0, "int array type"),
    _LangHeuristic(re.compile(r"\basync\s+Task\b"), 3.0, "async Task"),
    _LangHeuristic(re.compile(r"\bList<\w+>"), 2.5, "generic List"),
    _LangHeuristic(re.compile(r"\bDictionary<\w+,\s*\w+>"), 3.0, "Dictionary generic"),
    _LangHeuristic(re.compile(r"\bforeach\s*\("), 2.0, "foreach loop"),
    _LangHeuristic(re.compile(r"\bcatch\s*\(\s*\w+Exception"), 2.5, "typed catch"),
    _LangHeuristic(re.compile(r"///<summary>"), 2.0, "XML doc comment"),
    _LangHeuristic(re.compile(r"\[Serializable\]"), 2.5, "attribute"),
    _LangHeuristic(re.compile(r"\bget\s*;\s*set\s*;"), 3.0, "auto-property"),
    _LangHeuristic(re.compile(r"\bstring\.(?:Format|IsNullOrEmpty|Concat)\b"), 2.0, "string methods"),
]

_LANGUAGE_MAP: dict[str, tuple[str, list[_LangHeuristic]]] = {
    "javascript": ("javascript", _JS_HEURISTICS),
    "python": ("python", _PY_HEURISTICS),
    "powershell": ("powershell", _PS_HEURISTICS),
    "csharp": ("csharp", _CS_HEURISTICS),
}

# File extension hints
_EXTENSION_MAP: dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".pyw": "python",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".cs": "csharp",
    ".csx": "csharp",
    ".dll": "dotnet",
    ".exe": "dotnet",
}


class LanguageDetector(BaseTransform):
    name = "language_detector"
    description = "Detect the programming language of source code"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        # Always applicable -- it is an analysis pass.
        return bool(code and code.strip())

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        if looks_like_dotnet_assembly_bytes(binary_text_to_bytes(code)):
            state["detected_language"] = "dotnet"
            state["language_confidence"] = 0.99
            state["language_scores"] = {"dotnet": 20.0}
            return TransformResult(
                success=True,
                output=code,
                confidence=0.99,
                description="Detected language: dotnet (confidence 99%).",
                details={
                    "detected_language": "dotnet",
                    "detected": "dotnet",
                    "confidence": 0.99,
                    "scores": {"dotnet": 20.0},
                    "raw_scores": {"dotnet": 20.0},
                    "match_details": {"dotnet": ["PE/CLR metadata signature"]},
                },
            )

        scores: dict[str, float] = {}
        match_details: dict[str, list[str]] = {}

        for lang_name, (_, heuristics) in _LANGUAGE_MAP.items():
            total = 0.0
            matches: list[str] = []
            for h in heuristics:
                count = len(h.pattern.findall(code))
                if count > 0:
                    # Diminishing returns for repeated matches
                    contribution = h.weight * min(count, 5)
                    total += contribution
                    matches.append(f"{h.description} (x{count}, +{contribution:.1f})")
            scores[lang_name] = total
            match_details[lang_name] = matches

        # Check for file extension hint in state
        file_ext = state.get("file_extension", "")
        if file_ext and file_ext in _EXTENSION_MAP:
            hint_lang = _EXTENSION_MAP[file_ext]
            scores[hint_lang] = scores.get(hint_lang, 0) + 10.0

        if not any(scores.values()):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.1,
                description="Unable to determine language.",
                details={"scores": scores},
            )

        # Normalise to 0-1
        max_score = max(scores.values())
        total_score = sum(scores.values())

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        best_lang, best_score = ranked[0]

        if total_score > 0:
            confidence = best_score / total_score
        else:
            confidence = 0.0

        # Clamp confidence
        confidence = min(0.99, max(0.0, confidence))

        state["detected_language"] = best_lang
        state["language_confidence"] = confidence
        state["language_scores"] = dict(ranked)

        return TransformResult(
            success=True,
            output=code,
            confidence=confidence,
            description=(
                f"Detected language: {best_lang} "
                f"(confidence {confidence:.0%})."
            ),
            details={
                "detected_language": best_lang,
                "detected": best_lang,
                "confidence": confidence,
                "scores": dict(ranked),
                "raw_scores": scores,
                "match_details": match_details,
            },
        )
