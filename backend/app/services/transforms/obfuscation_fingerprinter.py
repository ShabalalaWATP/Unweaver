"""
ObfuscationFingerprinter -- detects signatures of common obfuscation tools
and techniques across JavaScript, Python, PowerShell, and .NET.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .base import BaseTransform, TransformResult


@dataclass
class _Signature:
    """One obfuscation tool/technique signature."""

    tool: str
    language: str
    patterns: list[re.Pattern]
    min_matches: int  # how many patterns must hit to be confident
    description: str


# ---------------------------------------------------------------------------
# JavaScript obfuscation signatures
# ---------------------------------------------------------------------------

_JS_OBFUSCATOR_IO = _Signature(
    tool="javascript-obfuscator (obfuscator.io)",
    language="javascript",
    patterns=[
        # Hex-named variables: _0x1a2b
        re.compile(r"\b_0x[0-9a-f]{4,6}\b"),
        # Array of strings with rotation function
        re.compile(r"var\s+_0x[0-9a-f]+\s*=\s*\["),
        # String array rotation IIFE
        re.compile(
            r"\(\s*function\s*\(\s*_0x\w+\s*,\s*_0x\w+\s*\)\s*\{"
            r"[^}]*\.push\s*\(\s*_0x\w+\.shift\s*\(",
            re.DOTALL,
        ),
        # Wrapper function pattern
        re.compile(r"function\s+_0x[0-9a-f]+\s*\(\s*_0x\w+\s*,\s*_0x\w+\s*\)"),
        # parseInt chains
        re.compile(r"parseInt\s*\(\s*_0x[0-9a-f]+\("),
    ],
    min_matches=2,
    description=(
        "javascript-obfuscator tool: hex variable names, string array "
        "rotation, wrapper functions"
    ),
)

_JJENCODE = _Signature(
    tool="JJEncode",
    language="javascript",
    patterns=[
        re.compile(r"\$=~\[\];"),
        re.compile(r"\$=\{___:"),
        re.compile(r"\$\.\$\$\$\$"),
        re.compile(r"\(\!\[\]\+\"\"\)"),
    ],
    min_matches=2,
    description="JJEncode: encodes JavaScript using only symbols $ and _",
)

_AAENCODE = _Signature(
    tool="AAEncode",
    language="javascript",
    patterns=[
        re.compile(r"\u00DF\u00E0"),
        re.compile(r"\(\s*\u309C\s*\u0414\s*\u309C\s*\)"),
        re.compile(r"[\u0300-\u036f]{3,}"),
        # Also ASCII representation
        re.compile(r"\(\s*\xDF\s*\xE0\s*\)"),
    ],
    min_matches=1,
    description="AAEncode: encodes JavaScript using emoticons/unicode art",
)

_JSFUCK = _Signature(
    tool="JSFuck",
    language="javascript",
    patterns=[
        # JSFuck uses only []()!+
        re.compile(r"^[\[\]\(\)!+\s]{50,}$", re.MULTILINE),
        re.compile(r"\[\]\[!\[\]\+!\[\]\]"),
        re.compile(r"\(\!\!\[\]\+\[\]\)"),
        re.compile(r"\(\!\[\]\+\[\]\)"),
    ],
    min_matches=1,
    description="JSFuck: encodes JavaScript using only []()!+ characters",
)

_JS_PACKER = _Signature(
    tool="Dean Edwards Packer",
    language="javascript",
    patterns=[
        re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)"),
        re.compile(r"\.split\s*\(\s*'\|'\s*\)"),
        re.compile(r"while\s*\(\s*c\s*--\s*\)"),
    ],
    min_matches=2,
    description="Dean Edwards Packer: eval(function(p,a,c,k,e,d/r)) pattern",
)

# ---------------------------------------------------------------------------
# Python obfuscation signatures
# ---------------------------------------------------------------------------

_PYARMOR = _Signature(
    tool="PyArmor",
    language="python",
    patterns=[
        re.compile(r"from\s+pytransform\s+import\s+pyarmor_runtime"),
        re.compile(r"\bpyarmor_runtime\s*\(\s*\)"),
        re.compile(r"__pyarmor__"),
        re.compile(r"# Pyarmor"),
    ],
    min_matches=1,
    description="PyArmor: commercial Python code protection tool",
)

_PYOBFUSCATE = _Signature(
    tool="pyobfuscate / generic Python obfuscation",
    language="python",
    patterns=[
        # exec(base64.b64decode('...'))
        re.compile(r"exec\s*\(\s*base64\.b64decode\s*\("),
        # exec(compile(... 'exec'))
        re.compile(r"exec\s*\(\s*compile\s*\("),
        # exec(zlib.decompress(...))
        re.compile(r"exec\s*\(\s*zlib\.decompress\s*\("),
        # exec(marshal.loads(...))
        re.compile(r"exec\s*\(\s*marshal\.loads\s*\("),
        # Many layers of encoding
        re.compile(r"exec\s*\(\s*codecs\.decode\s*\("),
    ],
    min_matches=1,
    description="Generic Python obfuscation: exec with encoding layers",
)

_PYOBFUSCATE_NAMES = _Signature(
    tool="Python name obfuscation",
    language="python",
    patterns=[
        # Variables named with Il patterns or underscores
        re.compile(r"\b[Il]{6,}\b"),
        # Variables like ____ (multiple underscores)
        re.compile(r"\b_{4,}\w*\b"),
        # Hex-named variables
        re.compile(r"\b_0x[0-9a-f]{4,}\b"),
        # base64 + lambda chains
        re.compile(r"lambda\s+\w+\s*:\s*exec"),
    ],
    min_matches=2,
    description="Python name obfuscation: meaningless identifier patterns",
)

# ---------------------------------------------------------------------------
# PowerShell obfuscation signatures
# ---------------------------------------------------------------------------

_INVOKE_OBFUSCATION = _Signature(
    tool="Invoke-Obfuscation",
    language="powershell",
    patterns=[
        # Tick obfuscation: p`ow`er`sh`ell
        re.compile(r"\w`\w`\w"),
        # Character-by-character building with [char]
        re.compile(r"(?:\[char\]\d+\s*\+\s*){3,}", re.IGNORECASE),
        # Format string obfuscation
        re.compile(r'"\{0\}\{1\}"\s*-f', re.IGNORECASE),
        # Reorder/reverse tricks
        re.compile(r"-join\s*\[\s*\d+(?:\s*,\s*\d+)+\s*\]", re.IGNORECASE),
        # String replace chains
        re.compile(r"(?:-replace\s+['\"][^'\"]+['\"]\s*,\s*['\"][^'\"]*['\"]\s*){2,}", re.IGNORECASE),
        # SET or env variable tricks
        re.compile(r"\$env:\w+\[\d+\]", re.IGNORECASE),
    ],
    min_matches=2,
    description="Invoke-Obfuscation: PowerShell obfuscation framework",
)

_PS_ENCODED = _Signature(
    tool="PowerShell Encoded Command",
    language="powershell",
    patterns=[
        re.compile(r"-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
        re.compile(r"\[(?:System\.)?Convert\]::FromBase64String", re.IGNORECASE),
        re.compile(r"\[System\.Text\.Encoding\]::Unicode\.GetString", re.IGNORECASE),
    ],
    min_matches=1,
    description="PowerShell base64-encoded command patterns",
)

# ---------------------------------------------------------------------------
# .NET obfuscation signatures
# ---------------------------------------------------------------------------

_CONFUSER_EX = _Signature(
    tool="ConfuserEx",
    language="csharp",
    patterns=[
        re.compile(r"ConfuserEx\s+v[\d.]+"),
        re.compile(r"\bConfuser\b"),
        # ConfuserEx resource protection pattern
        re.compile(r"Assembly\.GetExecutingAssembly\(\)\.GetManifestResourceStream"),
        # Anti-debug
        re.compile(r"Debugger\.IsAttached"),
        # Proxy delegates
        re.compile(r"internal\s+delegate\s+\w+\s+\w+\("),
    ],
    min_matches=2,
    description="ConfuserEx: open-source .NET obfuscator",
)

_SMART_ASSEMBLY = _Signature(
    tool="SmartAssembly",
    language="csharp",
    patterns=[
        re.compile(r"SmartAssembly"),
        re.compile(r"\bPowerBy\b.*SmartAssembly"),
        # String encryption delegate pattern
        re.compile(r"\.GetString\s*\(\s*Convert\.FromBase64String\s*\("),
        # Assembly resolver
        re.compile(r"AppDomain\.CurrentDomain\.AssemblyResolve"),
    ],
    min_matches=1,
    description="SmartAssembly: commercial .NET obfuscator",
)

_DOTFUSCATOR = _Signature(
    tool="Dotfuscator",
    language="csharp",
    patterns=[
        re.compile(r"Dotfuscator"),
        re.compile(r"\ba\b\.\ba\b\.\ba\b"),  # heavily renamed a.a.a
        # Short obfuscated names like single letters
        re.compile(r"\bclass\s+[a-z]\s*\{"),
    ],
    min_matches=1,
    description="Dotfuscator: commercial .NET obfuscator",
)

# Gather all signatures
_ALL_SIGNATURES: list[_Signature] = [
    _JS_OBFUSCATOR_IO,
    _JJENCODE,
    _AAENCODE,
    _JSFUCK,
    _JS_PACKER,
    _PYARMOR,
    _PYOBFUSCATE,
    _PYOBFUSCATE_NAMES,
    _INVOKE_OBFUSCATION,
    _PS_ENCODED,
    _CONFUSER_EX,
    _SMART_ASSEMBLY,
    _DOTFUSCATOR,
]

_TOOL_TECHNIQUE_MAP = {
    "JJEncode": "jjencode_encoding",
    "AAEncode": "aaencode_encoding",
    "JSFuck": "jsfuck_encoding",
    "Dean Edwards Packer": "dean_edwards_packer",
}

_GENERIC_TECHNIQUES: list[tuple[str, re.Pattern[str]]] = [
    ("base64_encoding", re.compile(r"(?:atob\s*\(|b64decode\s*\(|FromBase64String\s*\(|[A-Za-z0-9+/]{20,}={0,2})", re.IGNORECASE)),
    ("hex_encoding", re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}\s*,?\s*){4,}|(?:[0-9a-fA-F]{2}){16,}")),
    ("char_code_construction", re.compile(r"(?:String\.fromCharCode|\bchr\s*\(|\bChr\s*\(|\[char\]\s*)", re.IGNORECASE)),
    ("string_concatenation", re.compile(r"""(?:["'][^"'\\]{0,8}["']\s*(?:\+|&|\.)\s*){3,}""")),
    ("eval_exec", re.compile(r"\b(?:eval|exec|Invoke-Expression|IEX|Execute|ExecuteGlobal)\s*[\(]", re.IGNORECASE)),
    ("variable_renaming", re.compile(r"\b(?:_0x[a-fA-F0-9]{4,}|[Il]{6,}|_[A-Za-z0-9]{1,4})\b")),
    ("array_indexing", re.compile(r"\b\w+\s*\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]", re.IGNORECASE)),
    ("xor_encryption", re.compile(r"(?:\^|\bxor\b|-bxor\b)", re.IGNORECASE)),
    ("dean_edwards_packer", re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)", re.IGNORECASE)),
    ("control_flow_flattening", re.compile(r"(?:while\s*\(\s*(?:true|!0|1)\s*\)\s*\{?\s*switch|for\s*\(\s*;\s*;\s*\)\s*\{?\s*switch)", re.IGNORECASE)),
    ("junk_code", re.compile(r"(?:if\s*\(\s*false\s*\)|if\s*\(\s*0\s*\)|if\s*\(\s*!\s*1\s*\)|\bpass\b|void\s*\(?\s*0\s*\)?)", re.IGNORECASE)),
    ("reflection", re.compile(r"(?:GetType|GetMethod|Reflection|Assembly\.Load|Type\.GetMethod|Activator\.CreateInstance|\[scriptblock\]::Create|getattr\s*\()", re.IGNORECASE)),
    ("string_encryption", re.compile(r"(?:decrypt|decipher|decode|unscramble)\s*\(", re.IGNORECASE)),
    ("powershell_encoded_command", re.compile(r"-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE)),
    ("python_serialization", re.compile(r"(?:pickle|marshal)\.loads\s*\(|zlib\.decompress\s*\(", re.IGNORECASE)),
]


class ObfuscationFingerprinter(BaseTransform):
    name = "obfuscation_fingerprinter"
    description = (
        "Detect common obfuscation tool signatures and techniques"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(code and len(code.strip()) > 20)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        detections: list[dict[str, Any]] = []
        detected_techniques: list[str] = []
        lang = (language or "").lower().strip()

        for sig in _ALL_SIGNATURES:
            # If language is known, skip unrelated signatures
            if lang:
                lang_aliases = {
                    "javascript": ["javascript", "js", "ts", "typescript"],
                    "python": ["python", "py"],
                    "powershell": ["powershell", "ps1", "ps"],
                    "csharp": ["csharp", "cs", "c#"],
                }
                sig_aliases = lang_aliases.get(sig.language, [sig.language])
                if lang not in sig_aliases and lang != "":
                    # Still check, but with lower priority
                    pass

            match_count = 0
            matched_patterns: list[str] = []
            for pat in sig.patterns:
                hits = pat.findall(code)
                if hits:
                    match_count += 1
                    matched_patterns.append(
                        f"{pat.pattern[:60]} ({len(hits)} hit(s))"
                    )

            if match_count >= sig.min_matches:
                confidence = min(
                    0.95,
                    0.50 + 0.15 * match_count
                )
                mapped = _TOOL_TECHNIQUE_MAP.get(sig.tool)
                if mapped:
                    detected_techniques.append(mapped)
                detections.append({
                    "tool": sig.tool,
                    "language": sig.language,
                    "confidence": round(confidence, 2),
                    "description": sig.description,
                    "matched_patterns": match_count,
                    "total_patterns": len(sig.patterns),
                    "pattern_details": matched_patterns,
                })

        for technique_name, pattern in _GENERIC_TECHNIQUES:
            if pattern.search(code):
                detected_techniques.append(technique_name)

        detected_techniques = list(dict.fromkeys(detected_techniques))

        if not detections and not detected_techniques:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.1,
                description="No known obfuscation tool signatures detected.",
            )

        # Sort by confidence
        detections.sort(key=lambda d: d["confidence"], reverse=True)

        state.setdefault("obfuscation_signatures", []).extend(detections)

        overall_confidence = (
            detections[0]["confidence"]
            if detections
            else min(0.9, 0.45 + 0.05 * len(detected_techniques))
        )

        tools_found = [d["tool"] for d in detections]
        description_bits: list[str] = []
        if tools_found:
            description_bits.append(
                f"Detected {len(detections)} obfuscation signature(s): {', '.join(tools_found)}"
            )
        if detected_techniques:
            description_bits.append(
                "generic techniques: " + ", ".join(detected_techniques[:10])
            )
        description = ". ".join(description_bits) + "."

        return TransformResult(
            success=True,
            output=code,
            confidence=overall_confidence,
            description=description,
            details={
                "detection_count": len(detections),
                "detections": detections,
                "detected_techniques": detected_techniques,
                "identified_tools": tools_found,
            },
        )
