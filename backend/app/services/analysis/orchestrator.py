"""
Multi-pass agentic deobfuscation orchestrator.

Loop stages (8-stage pipeline):
1. Planner         - inspect current state, determine what needs doing
2. Action Selector - choose best next action from action space
3. Pre-flight      - validate preconditions (language, size, attempts, conflicts)
4. Executor        - run the chosen transform/action
5. Post-processor  - normalise output (whitespace, encoding, artefact cleanup)
6. Verifier/Scorer - measure if the step improved deobfuscation
7. State Reconciler- merge results into state (strings, IOCs, techniques, metadata)
8. Stop Decision   - continue, retry, backtrack, or stop

The harness uses: current state, prior actions, prior outputs,
confidence scores, and improvement metrics to make decisions.
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type

from app.models.schemas import (
    AnalysisState,
    Finding,
    IOC,
    IOCType,
    Severity,
    StringEntry,
    TransformRecord,
)
from app.services.ingest.workspace_bundle import (
    extract_workspace_context,
    parse_workspace_bundle,
    truncate_workspace_bundle,
    workspace_context_prompt,
)
from app.services.analysis.action_queue import ActionQueue, QueuedAction
from app.services.analysis.findings_generator import FindingsGenerator
from app.services.analysis.state_manager import StateManager
from app.services.transforms.base import BaseTransform, TransformResult
from app.services.transforms.source_preprocessor import normalize_source_anomalies

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Inline deterministic transforms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# These are bundled here so the orchestrator works out-of-the-box
# without requiring every transform module to exist yet.  When the
# corresponding module under app.services.transforms is created, the
# ACTION_SPACE registry below will prefer the external class.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class _LanguageDetector(BaseTransform):
    """Detect the scripting language of the sample."""

    name = "LanguageDetector"
    description = "Detect scripting language via heuristic signatures."

    # Weighted keyword / pattern signatures per language.
    _SIGNATURES: Dict[str, List[Tuple[re.Pattern[str], float]]] = {
        "powershell": [
            (re.compile(r"\$\w+\s*=", re.IGNORECASE), 1.0),
            (re.compile(r"\b(Get|Set|New|Remove|Invoke)-\w+", re.IGNORECASE), 2.0),
            (re.compile(r"\bparam\s*\(", re.IGNORECASE), 1.5),
            (re.compile(r"\b\[System\.\w+\]", re.IGNORECASE), 2.0),
            (re.compile(r"-eq\b|-ne\b|-lt\b|-gt\b", re.IGNORECASE), 1.0),
            (re.compile(r"\bWrite-Host\b", re.IGNORECASE), 1.5),
            (re.compile(r"\bForEach-Object\b", re.IGNORECASE), 1.5),
            (re.compile(r"\b\$env:", re.IGNORECASE), 2.0),
            (re.compile(r"\bfunction\s+\w+", re.IGNORECASE), 0.5),
            (re.compile(r"<#.*?#>", re.DOTALL), 1.5),
        ],
        "javascript": [
            (re.compile(r"\bvar\s+\w+\s*="), 1.0),
            (re.compile(r"\blet\s+\w+\s*="), 1.0),
            (re.compile(r"\bconst\s+\w+\s*="), 1.0),
            (re.compile(r"\bfunction\s*\w*\s*\("), 1.0),
            (re.compile(r"=>\s*\{"), 1.5),
            (re.compile(r"\bdocument\.\w+"), 2.0),
            (re.compile(r"\bwindow\.\w+"), 2.0),
            (re.compile(r"\bconsole\.\w+"), 1.5),
            (re.compile(r"\brequire\s*\("), 1.5),
            (re.compile(r"\bString\.fromCharCode\b"), 2.0),
            (re.compile(r"\bparseInt\s*\("), 1.0),
            (re.compile(r"===|!=="), 1.0),
        ],
        "python": [
            (re.compile(r"^import\s+\w+", re.MULTILINE), 1.5),
            (re.compile(r"^from\s+\w+\s+import", re.MULTILINE), 1.5),
            (re.compile(r"\bdef\s+\w+\s*\("), 1.5),
            (re.compile(r"\bclass\s+\w+.*:"), 1.5),
            (re.compile(r"\bprint\s*\("), 1.0),
            (re.compile(r"\bself\.\w+"), 2.0),
            (re.compile(r"^\s+elif\s+", re.MULTILINE), 2.0),
            (re.compile(r"\bexcept\s+\w+"), 1.5),
            (re.compile(r"__\w+__"), 1.5),
            (re.compile(r":\s*$", re.MULTILINE), 0.5),
        ],
        "vbscript": [
            (re.compile(r"\bDim\s+\w+", re.IGNORECASE), 2.0),
            (re.compile(r"\bSub\s+\w+", re.IGNORECASE), 2.0),
            (re.compile(r"\bFunction\s+\w+", re.IGNORECASE), 1.5),
            (re.compile(r"\bCreateObject\s*\(", re.IGNORECASE), 2.0),
            (re.compile(r"\bWScript\.\w+", re.IGNORECASE), 2.0),
            (re.compile(r"\bEnd\s+(Sub|Function|If)\b", re.IGNORECASE), 2.0),
            (re.compile(r"\bMsgBox\b", re.IGNORECASE), 1.5),
            (re.compile(r"'\s+.*$", re.MULTILINE), 0.5),  # VBS comment
        ],
        "batch": [
            (re.compile(r"^@echo\s+off", re.IGNORECASE | re.MULTILINE), 3.0),
            (re.compile(r"\bset\s+/[ap]\b", re.IGNORECASE), 2.0),
            (re.compile(r"\bgoto\s+:", re.IGNORECASE), 2.0),
            (re.compile(r"^:\w+", re.MULTILINE), 1.5),
            (re.compile(r"%\w+%"), 1.5),
            (re.compile(r"\bif\s+exist\b", re.IGNORECASE), 1.5),
        ],
    }

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return True  # always applicable

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        scores: Dict[str, float] = {}
        for lang, signatures in self._SIGNATURES.items():
            score = 0.0
            for pattern, weight in signatures:
                matches = pattern.findall(code)
                score += len(matches) * weight
            scores[lang] = score

        if not any(scores.values()):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.1,
                description="Could not determine language.",
                details={"scores": scores},
            )

        best_lang = max(scores, key=lambda k: scores[k])
        best_score = scores[best_lang]
        total = sum(scores.values()) or 1.0
        confidence = min(best_score / total, 0.99) if total > 0 else 0.1

        # Also flag runner-up for close calls.
        sorted_langs = sorted(scores.items(), key=lambda x: -x[1])
        runner_up = sorted_langs[1] if len(sorted_langs) > 1 else (None, 0)

        return TransformResult(
            success=True,
            output=code,
            confidence=confidence,
            description=f"Detected language: {best_lang} (confidence {confidence:.0%})",
            details={
                "detected_language": best_lang,
                "scores": scores,
                "runner_up": runner_up[0],
            },
        )


class _ObfuscationFingerprinter(BaseTransform):
    """Fingerprint obfuscation techniques present in the code."""

    name = "ObfuscationFingerprinter"
    description = "Identify obfuscation techniques via pattern matching."

    _TECHNIQUE_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
        ("base64_encoding",
         re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),
         "Base64-like strings detected"),
        ("hex_encoding",
         re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}[,\s]*){4,}"),
         "Hex-encoded byte sequences"),
        ("char_code_construction",
         re.compile(r"(?:String\.fromCharCode|chr\s*\(|Chr\s*\(|\[char\]\s*)\s*\d+", re.IGNORECASE),
         "Character code construction"),
        ("string_concatenation",
         re.compile(r"""(?:["'][^"']{0,3}["']\s*[+&\.]\s*){4,}"""),
         "Excessive string concatenation"),
        ("eval_exec",
         re.compile(r"\b(?:eval|exec|Invoke-Expression|IEX|Execute|ExecuteGlobal)\s*[\(]", re.IGNORECASE),
         "Dynamic code execution"),
        ("variable_renaming",
         re.compile(r"\b(?:_0x[a-fA-F0-9]{4,}|[a-zA-Z](?:_[a-zA-Z0-9]){4,})\b"),
         "Obfuscated variable names"),
        ("array_indexing",
         re.compile(r"\[\s*(?:0x[0-9a-f]+|\d+)\s*\](?:\s*\[\s*(?:0x[0-9a-f]+|\d+)\s*\]){2,}"),
         "Nested array index access"),
        ("xor_encryption",
         re.compile(r"(?:\^|\bxor\b|-bxor\b)", re.IGNORECASE),
         "XOR operations"),
        ("control_flow_flattening",
         re.compile(r"switch\s*\(\s*\w+\s*\)\s*\{(?:\s*case\s+[\w\"']+\s*:){5,}", re.IGNORECASE),
         "Switch-based control flow flattening"),
        ("junk_code",
         re.compile(r"(?:if\s*\(\s*false\s*\)|if\s*\(\s*0\s*\)|if\s*\(\s*!\s*1\s*\))", re.IGNORECASE),
         "Dead/junk code branches"),
        ("reflection",
         re.compile(r"(?:GetType|Reflection|Assembly\.Load|Type\.GetMethod)", re.IGNORECASE),
         "Reflection-based invocation"),
        ("string_encryption",
         re.compile(r"(?:decrypt|decipher|decode|unscramble)\s*\(", re.IGNORECASE),
         "String decryption function calls"),
    ]

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(code and code.strip())

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        detected: List[str] = []
        evidence: Dict[str, List[str]] = {}

        for technique_name, pattern, desc in self._TECHNIQUE_PATTERNS:
            matches = pattern.findall(code)
            if matches:
                detected.append(technique_name)
                samples = [m[:80] if isinstance(m, str) else str(m)[:80] for m in matches[:3]]
                evidence[technique_name] = samples

        confidence = min(len(detected) / 5.0, 0.95) if detected else 0.1
        return TransformResult(
            success=bool(detected),
            output=code,
            confidence=confidence,
            description=(
                f"Detected {len(detected)} obfuscation technique(s): {', '.join(detected)}"
                if detected else "No known obfuscation techniques detected."
            ),
            details={
                "detected_techniques": detected,
                "evidence": evidence,
            },
        )


class _StringExtractor(BaseTransform):
    """Extract string literals from code."""

    name = "StringExtractor"
    description = "Extract string literals and interesting constants."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(code and code.strip())

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        strings: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        # Double-quoted strings.
        for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', code):
            val = m.group(1)
            if len(val) >= 3 and val not in seen:
                strings.append({"value": val, "encoding": "utf-8", "context": "double-quoted"})
                seen.add(val)

        # Single-quoted strings.
        for m in re.finditer(r"'([^'\\]*(?:\\.[^'\\]*)*)'", code):
            val = m.group(1)
            if len(val) >= 3 and val not in seen:
                strings.append({"value": val, "encoding": "utf-8", "context": "single-quoted"})
                seen.add(val)

        # Backtick template literals (JS).
        for m in re.finditer(r"`([^`]*)`", code):
            val = m.group(1)
            if len(val) >= 3 and val not in seen:
                strings.append({"value": val, "encoding": "utf-8", "context": "template-literal"})
                seen.add(val)

        confidence = min(len(strings) / 20.0, 0.9) if strings else 0.1
        return TransformResult(
            success=bool(strings),
            output=code,
            confidence=confidence,
            description=f"Extracted {len(strings)} string literal(s).",
            details={"strings": strings, "count": len(strings)},
        )


class _Base64Decoder(BaseTransform):
    """Decode Base64-encoded strings inline."""

    name = "Base64Decoder"
    description = "Find and decode Base64 strings."

    _B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(self._B64_RE.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        import base64

        decoded_strings: List[Dict[str, str]] = []
        new_code = code

        def _try_decode(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                # Pad if needed.
                padded = raw + "=" * (-len(raw) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                # Only accept if result looks like text.
                printable_ratio = sum(
                    1 for c in decoded_text if c.isprintable() or c in "\n\r\t"
                ) / len(decoded_text) if decoded_text else 0
                if printable_ratio > 0.7 and len(decoded_text) >= 2:
                    decoded_strings.append({
                        "encoded": raw[:80],
                        "decoded": decoded_text[:500],
                    })
                    return decoded_text
            except Exception:
                pass
            return raw

        new_code = self._B64_RE.sub(_try_decode, code)

        success = bool(decoded_strings)
        confidence = min(len(decoded_strings) * 0.2, 0.95) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Decoded {len(decoded_strings)} Base64 string(s)."
                if success else "No valid Base64 strings found."
            ),
            details={
                "decoded_strings": decoded_strings,
                "count": len(decoded_strings),
            },
        )


class _HexDecoder(BaseTransform):
    """Decode hex-encoded byte strings inline."""

    name = "HexDecoder"
    description = "Find and decode hex-encoded strings."

    _HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    _HEX_ARRAY_RE = re.compile(r"(?:0x[0-9a-fA-F]{2}[\s,]*){4,}")

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(self._HEX_ESCAPE_RE.search(code) or self._HEX_ARRAY_RE.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        decoded_strings: List[Dict[str, str]] = []
        new_code = code

        def _decode_escape_seq(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                hex_bytes = bytes(
                    int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", raw)
                )
                text = hex_bytes.decode("utf-8", errors="replace")
                printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
                if printable / len(text) > 0.7 and len(text) >= 2:
                    decoded_strings.append({"encoded": raw[:80], "decoded": text[:500]})
                    return repr(text)
            except Exception:
                pass
            return raw

        def _decode_hex_array(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                hex_bytes = bytes(
                    int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", raw)
                )
                text = hex_bytes.decode("utf-8", errors="replace")
                printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
                if printable / len(text) > 0.7 and len(text) >= 2:
                    decoded_strings.append({"encoded": raw[:80], "decoded": text[:500]})
                    return repr(text)
            except Exception:
                pass
            return raw

        new_code = self._HEX_ESCAPE_RE.sub(_decode_escape_seq, new_code)
        new_code = self._HEX_ARRAY_RE.sub(_decode_hex_array, new_code)

        success = bool(decoded_strings)
        confidence = min(len(decoded_strings) * 0.25, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Decoded {len(decoded_strings)} hex string(s)."
                if success else "No valid hex-encoded strings found."
            ),
            details={"decoded_strings": decoded_strings, "count": len(decoded_strings)},
        )


class _XorRecovery(BaseTransform):
    """Attempt single-byte XOR key recovery on suspicious blobs."""

    name = "XorRecovery"
    description = "Brute-force single-byte XOR decryption."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(re.search(r"(?:\^|\bxor\b|-bxor\b)", code, re.IGNORECASE))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        # Look for hex blobs or byte arrays that might be XOR-encrypted.
        blob_pattern = re.compile(
            r"(?:(?:0x[0-9a-fA-F]{2}[\s,]*){8,}|"
            r"(?:\\x[0-9a-fA-F]{2}){8,})"
        )
        blobs = blob_pattern.findall(code)
        if not blobs:
            return TransformResult(
                success=False, output=code, confidence=0.1,
                description="No suitable byte blobs found for XOR recovery.",
                details={},
            )

        recovered: List[Dict[str, Any]] = []
        for blob_str in blobs[:5]:  # cap attempts
            # Extract raw bytes.
            hex_vals = re.findall(r"[0-9a-fA-F]{2}", blob_str)
            if len(hex_vals) < 8:
                continue
            raw_bytes = bytes(int(h, 16) for h in hex_vals)

            # Try each single-byte key.
            best_key = 0
            best_score = 0.0
            best_text = ""
            for key in range(1, 256):
                decoded = bytes(b ^ key for b in raw_bytes)
                try:
                    text = decoded.decode("ascii", errors="strict")
                    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t ")
                    score = printable / len(text) if text else 0
                    if score > best_score:
                        best_score = score
                        best_key = key
                        best_text = text
                except UnicodeDecodeError:
                    continue

            if best_score > 0.75 and best_text:
                recovered.append({
                    "key": best_key,
                    "key_hex": f"0x{best_key:02x}",
                    "decoded": best_text[:500],
                    "score": best_score,
                })

        success = bool(recovered)
        confidence = min(max(r["score"] for r in recovered), 0.95) if success else 0.1
        return TransformResult(
            success=success,
            output=code,
            confidence=confidence,
            description=(
                f"Recovered {len(recovered)} XOR-encrypted blob(s)."
                if success else "XOR brute-force did not yield readable text."
            ),
            details={"recovered": recovered, "count": len(recovered)},
        )


class _ConstantFolder(BaseTransform):
    """Fold constant expressions (arithmetic, string concat)."""

    name = "ConstantFolder"
    description = "Evaluate and fold constant expressions."

    # Simple integer arithmetic: e.g. (3 + 5), (10 - 2), (4 * 8)
    _ARITH_RE = re.compile(r"\(\s*(\d+)\s*([+\-*/])\s*(\d+)\s*\)")
    # String concat: "abc" + "def"
    _CONCAT_RE = re.compile(r'"([^"]*?)"\s*\+\s*"([^"]*?)"')
    _CONCAT_SQ_RE = re.compile(r"'([^']*?)'\s*\+\s*'([^']*?)'")

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(
            self._ARITH_RE.search(code)
            or self._CONCAT_RE.search(code)
            or self._CONCAT_SQ_RE.search(code)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        fold_count = 0
        new_code = code

        # Fold arithmetic (multiple passes for nested expressions).
        for _ in range(10):
            prev = new_code

            def _fold_arith(m: re.Match[str]) -> str:
                nonlocal fold_count
                a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
                try:
                    if op == "+":
                        result = a + b
                    elif op == "-":
                        result = a - b
                    elif op == "*":
                        result = a * b
                    elif op == "/" and b != 0:
                        result = a // b
                    else:
                        return m.group(0)
                    fold_count += 1
                    return str(result)
                except Exception:
                    return m.group(0)

            new_code = self._ARITH_RE.sub(_fold_arith, new_code)
            if new_code == prev:
                break

        # Fold string concatenation (multiple passes).
        for _ in range(20):
            prev = new_code

            def _fold_concat(m: re.Match[str]) -> str:
                nonlocal fold_count
                fold_count += 1
                return f'"{m.group(1)}{m.group(2)}"'

            def _fold_concat_sq(m: re.Match[str]) -> str:
                nonlocal fold_count
                fold_count += 1
                return f"'{m.group(1)}{m.group(2)}'"

            new_code = self._CONCAT_RE.sub(_fold_concat, new_code)
            new_code = self._CONCAT_SQ_RE.sub(_fold_concat_sq, new_code)
            if new_code == prev:
                break

        success = fold_count > 0
        confidence = min(fold_count * 0.1, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Folded {fold_count} constant expression(s)."
                if success else "No constant expressions to fold."
            ),
            details={"fold_count": fold_count},
        )


class _JunkCodeRemover(BaseTransform):
    """Remove dead code, no-op statements, and unreachable branches."""

    name = "JunkCodeRemover"
    description = "Identify and remove junk / dead code."

    _DEAD_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
        (re.compile(r"if\s*\(\s*false\s*\)\s*\{[^}]*\}", re.IGNORECASE | re.DOTALL),
         "if(false) block"),
        (re.compile(r"if\s*\(\s*0\s*\)\s*\{[^}]*\}", re.DOTALL),
         "if(0) block"),
        (re.compile(r"if\s*\(\s*!\s*1\s*\)\s*\{[^}]*\}", re.DOTALL),
         "if(!1) block"),
        (re.compile(r"if\s*\(\s*!\s*true\s*\)\s*\{[^}]*\}", re.IGNORECASE | re.DOTALL),
         "if(!true) block"),
        # Empty statements / blocks.
        (re.compile(r";\s*;"), "double semicolons"),
        # Void expression statements in JS.
        (re.compile(r"\bvoid\s+0\s*;"), "void 0 statement"),
    ]

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return any(p.search(code) for p, _ in self._DEAD_PATTERNS)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        removed_count = 0
        new_code = code

        for pattern, label in self._DEAD_PATTERNS:
            matches = pattern.findall(new_code)
            if matches:
                removed_count += len(matches)
                new_code = pattern.sub("/* removed: junk */", new_code)

        # Clean up multiple blank lines left behind.
        new_code = re.sub(r"\n{3,}", "\n\n", new_code)

        success = removed_count > 0
        confidence = min(removed_count * 0.15, 0.85) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Removed {removed_count} junk code fragment(s)."
                if success else "No junk code detected."
            ),
            details={"removed_count": removed_count},
        )


class _EvalExecDetector(BaseTransform):
    """Detect and annotate eval/exec/reflection patterns."""

    name = "EvalExecDetector"
    description = "Detect dynamic code execution patterns."

    _PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
        ("eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
        ("exec", re.compile(r"\bexec\s*\(", re.IGNORECASE)),
        ("Function_constructor", re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)),
        ("Invoke-Expression", re.compile(r"\bInvoke-Expression\b", re.IGNORECASE)),
        ("IEX", re.compile(r"\bIEX\b")),
        ("ExecuteGlobal", re.compile(r"\bExecuteGlobal\b", re.IGNORECASE)),
        ("Execute", re.compile(r"\bExecute\b", re.IGNORECASE)),
        ("setTimeout_string", re.compile(r"\bsetTimeout\s*\(\s*['\"]", re.IGNORECASE)),
        ("compile", re.compile(r"\bcompile\s*\(", re.IGNORECASE)),
        ("__import__", re.compile(r"\b__import__\s*\(")),
        ("Assembly.Load", re.compile(r"\bAssembly\.Load", re.IGNORECASE)),
        ("Reflection", re.compile(r"\bReflection\.\w+", re.IGNORECASE)),
    ]

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return any(p.search(code) for _, p in self._PATTERNS)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        found: Dict[str, int] = {}
        for name, pattern in self._PATTERNS:
            matches = pattern.findall(code)
            if matches:
                found[name] = len(matches)

        success = bool(found)
        total_matches = sum(found.values())
        confidence = min(total_matches * 0.15, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=code,
            confidence=confidence,
            description=(
                f"Detected {total_matches} dynamic execution pattern(s): "
                f"{', '.join(found.keys())}"
                if success else "No dynamic execution patterns found."
            ),
            details={"patterns": found, "total": total_matches},
        )


class _JavaScriptArrayResolver(BaseTransform):
    """Resolve JavaScript array-based string obfuscation.

    Handles patterns like:
        var _0xabc = ["string1", "string2", ...];
        ... _0xabc[0x0] ... _0xabc[0x1] ...
    """

    name = "JavaScriptArrayResolver"
    description = "Resolve JS array-indexed string lookups."

    _ARRAY_DECL_RE = re.compile(
        r"(?:var|let|const)\s+(\w+)\s*=\s*\[((?:\s*['\"][^'\"]*['\"]\s*,?\s*)+)\]",
        re.IGNORECASE,
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = language.lower() if language else ""
        if lang and lang not in ("javascript", "js", ""):
            return False
        return bool(self._ARRAY_DECL_RE.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        arrays_found = 0
        replacements = 0
        new_code = code

        for m in self._ARRAY_DECL_RE.finditer(code):
            arr_name = m.group(1)
            arr_body = m.group(2)
            # Extract string elements.
            elements = re.findall(r"['\"]([^'\"]*)['\"]", arr_body)
            if not elements:
                continue
            arrays_found += 1

            # Replace arr[N] references.
            def _make_replacer(elems: List[str]):
                def _replace_index(idx_match: re.Match[str]) -> str:
                    nonlocal replacements
                    idx_str = idx_match.group(1)
                    try:
                        idx = int(idx_str, 0)  # handles 0x notation
                        if 0 <= idx < len(elems):
                            replacements += 1
                            return f'"{elems[idx]}"'
                    except (ValueError, IndexError):
                        pass
                    return idx_match.group(0)
                return _replace_index

            # Pattern: arrName[index]
            idx_pattern = re.compile(
                re.escape(arr_name) + r"\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]"
            )
            new_code = idx_pattern.sub(_make_replacer(elements), new_code)

        success = replacements > 0
        confidence = min(replacements * 0.1, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Resolved {replacements} array-indexed string lookup(s) "
                f"across {arrays_found} array(s)."
                if success else "No array-based string obfuscation resolved."
            ),
            details={
                "arrays_found": arrays_found,
                "replacements": replacements,
            },
        )


class _RenameSuggester(BaseTransform):
    """Suggest meaningful names for obfuscated identifiers.

    This is a deterministic heuristic pass.  When an LLM is available,
    the orchestrator can enhance these suggestions.
    """

    name = "RenameSuggester"
    description = "Suggest renames for obfuscated identifiers."

    _OBFUSCATED_ID_RE = re.compile(
        r"\b(_0x[a-fA-F0-9]{4,}|[a-zA-Z]{1,2}\d{3,}|"
        r"[a-z](?:_[a-z0-9]){3,}|_[a-z]{1})\b"
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(self._OBFUSCATED_ID_RE.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        from collections import Counter
        ids = self._OBFUSCATED_ID_RE.findall(code)
        counts = Counter(ids)
        # Only suggest renames for identifiers used multiple times.
        suggestions: Dict[str, str] = {}
        idx = 0
        for name, count in counts.most_common(30):
            if count >= 2:
                suggestions[name] = f"var_{idx}"
                idx += 1

        success = bool(suggestions)
        confidence = 0.4 if success else 0.1  # low confidence: heuristic only
        return TransformResult(
            success=success,
            output=code,  # We don't actually rename here; just suggest.
            confidence=confidence,
            description=(
                f"Identified {len(suggestions)} obfuscated identifier(s) for renaming."
                if success else "No obfuscated identifiers detected."
            ),
            details={"suggestions": suggestions, "count": len(suggestions)},
        )


class _IOCExtractor(BaseTransform):
    """Extract IOCs (IPs, domains, URLs, hashes, emails, file paths, etc.)."""

    name = "IOCExtractor"
    description = "Extract indicators of compromise from code."

    _IOC_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
        ("ip", re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        )),
        ("url", re.compile(
            r"https?://[^\s'\"<>\)\]}{,]{5,}"
        )),
        ("domain", re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
            r"{1,3}(?:com|net|org|info|io|co|ru|cn|xyz|top|tk|ml|ga|cf|gq|"
            r"pw|cc|biz|me|tv|ws|onion)\b",
            re.IGNORECASE,
        )),
        ("email", re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        )),
        ("hash_md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
        ("hash_sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
        ("hash_sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
        ("filepath_windows", re.compile(
            r"[a-zA-Z]:\\(?:[^\s\\:*?\"<>|]+\\)*[^\s\\:*?\"<>|]+"
        )),
        ("filepath_unix", re.compile(r"/(?:tmp|etc|var|usr|home|opt)/[^\s'\"]{3,}")),
        ("registry", re.compile(
            r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s'\"]{5,}",
            re.IGNORECASE,
        )),
    ]

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(code and code.strip())

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        iocs: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        for ioc_type, pattern in self._IOC_PATTERNS:
            for m in pattern.finditer(code):
                value = m.group(0).rstrip(".,;:)")
                if value in seen:
                    continue
                seen.add(value)

                # Map sub-types to IOCType values.
                if ioc_type.startswith("hash"):
                    mapped_type = "hash"
                elif ioc_type.startswith("filepath"):
                    mapped_type = "filepath"
                else:
                    mapped_type = ioc_type

                iocs.append({
                    "type": mapped_type,
                    "value": value,
                    "context": code[max(0, m.start() - 30):m.end() + 30],
                    "confidence": 0.7,
                })

        success = bool(iocs)
        confidence = min(len(iocs) * 0.1, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=code,
            confidence=confidence,
            description=(
                f"Extracted {len(iocs)} IOC(s)."
                if success else "No IOCs found."
            ),
            details={"iocs": iocs, "count": len(iocs)},
        )


class _PowerShellDecoder(BaseTransform):
    """Decode PowerShell-specific obfuscation."""

    name = "PowerShellDecoder"
    description = "Decode PowerShell encoded commands and string tricks."

    # -EncodedCommand / -enc base64 payloads.
    _ENC_CMD_RE = re.compile(
        r"-(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]{20,})",
        re.IGNORECASE,
    )
    # [Convert]::FromBase64String(...)
    _FROM_B64_RE = re.compile(
        r"\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]\s*\)",
        re.IGNORECASE,
    )
    # Char-code construction: [char]65, [char]0x41
    _CHAR_RE = re.compile(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)
    # String replacement obfuscation: ('text').replace('a','b')
    _REPLACE_RE = re.compile(
        r"""['\"]([^'\"]+)['\"]\s*(?:-replace|-creplace)\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]""",
        re.IGNORECASE,
    )
    # Backtick escape removal: `t `n etc.
    _BACKTICK_RE = re.compile(r"`([tnrvfab0e])")
    _BACKTICK_MAP = {
        "t": "\t", "n": "\n", "r": "\r", "v": "\v",
        "f": "\f", "a": "\a", "b": "\b", "0": "\0", "e": "\x1b",
    }

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower()
        if lang and lang not in ("powershell", "ps1", "ps", ""):
            return False
        return bool(
            self._ENC_CMD_RE.search(code)
            or self._FROM_B64_RE.search(code)
            or self._CHAR_RE.search(code)
            or self._BACKTICK_RE.search(code)
        )

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        import base64

        changes = 0
        new_code = code
        decoded_payloads: List[str] = []

        # 1. Decode -EncodedCommand payloads.
        for m in self._ENC_CMD_RE.finditer(new_code):
            b64 = m.group(1)
            try:
                padded = b64 + "=" * (-len(b64) % 4)
                raw = base64.b64decode(padded)
                # PowerShell encoded commands are UTF-16LE.
                text = raw.decode("utf-16-le", errors="replace")
                decoded_payloads.append(text[:2000])
                new_code = new_code.replace(m.group(0), f"# Decoded: {text[:200]}")
                changes += 1
            except Exception:
                continue

        # 2. Decode FromBase64String calls.
        for m in self._FROM_B64_RE.finditer(new_code):
            b64 = m.group(1)
            try:
                padded = b64 + "=" * (-len(b64) % 4)
                raw = base64.b64decode(padded)
                # Try UTF-16LE first, then UTF-8.
                for enc in ("utf-16-le", "utf-8"):
                    try:
                        text = raw.decode(enc)
                        break
                    except UnicodeDecodeError:
                        text = raw.decode("utf-8", errors="replace")
                decoded_payloads.append(text[:2000])
                new_code = new_code.replace(m.group(0), f'"{text[:200]}"')
                changes += 1
            except Exception:
                continue

        # 3. Resolve [char] constructions.
        def _resolve_char(m: re.Match[str]) -> str:
            nonlocal changes
            try:
                val = int(m.group(1), 0)
                if 32 <= val <= 126:
                    changes += 1
                    return f"'{chr(val)}'"
            except (ValueError, OverflowError):
                pass
            return m.group(0)

        new_code = self._CHAR_RE.sub(_resolve_char, new_code)

        # 4. Remove backtick escapes.
        def _resolve_backtick(m: re.Match[str]) -> str:
            nonlocal changes
            char = self._BACKTICK_MAP.get(m.group(1))
            if char is not None:
                changes += 1
                return char
            return m.group(0)

        new_code = self._BACKTICK_RE.sub(_resolve_backtick, new_code)

        success = changes > 0
        confidence = min(changes * 0.15, 0.95) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Applied {changes} PowerShell decoding operation(s)."
                if success else "No PowerShell encoding found to decode."
            ),
            details={
                "changes": changes,
                "decoded_payloads": decoded_payloads[:5],
            },
        )


class _PythonDecoder(BaseTransform):
    """Decode Python-specific obfuscation patterns."""

    name = "PythonDecoder"
    description = "Decode Python obfuscation (exec/eval chains, chr() sequences)."

    _CHR_SEQ_RE = re.compile(r"(?:chr\s*\(\s*(\d+)\s*\)\s*\+?\s*){3,}")
    _EXEC_COMPILE_RE = re.compile(
        r"exec\s*\(\s*compile\s*\(\s*['\"]([^'\"]+)['\"]\s*,",
        re.IGNORECASE,
    )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower()
        if lang and lang not in ("python", "py", ""):
            return False
        return bool(self._CHR_SEQ_RE.search(code) or self._EXEC_COMPILE_RE.search(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        changes = 0
        new_code = code

        # Resolve chr() sequences.
        def _resolve_chr_seq(m: re.Match[str]) -> str:
            nonlocal changes
            raw = m.group(0)
            char_codes = re.findall(r"chr\s*\(\s*(\d+)\s*\)", raw)
            try:
                text = "".join(chr(int(c)) for c in char_codes)
                if all(c.isprintable() or c in "\n\r\t" for c in text):
                    changes += 1
                    return f'"{text}"'
            except (ValueError, OverflowError):
                pass
            return raw

        new_code = self._CHR_SEQ_RE.sub(_resolve_chr_seq, new_code)

        success = changes > 0
        confidence = min(changes * 0.2, 0.9) if success else 0.1
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Decoded {changes} Python obfuscation pattern(s)."
                if success else "No Python-specific obfuscation decoded."
            ),
            details={"changes": changes},
        )


class _FindingsGeneratorTransform(BaseTransform):
    """Wrap FindingsGenerator as a transform so it fits the action space."""

    name = "FindingsGenerator"
    description = "Synthesise analyst-facing findings from accumulated evidence."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return True

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        # This transform is special: it reads accumulated state and produces
        # findings as details, but does not modify the code.
        from app.models.schemas import AnalysisState
        from app.services.analysis.findings_generator import FindingsGenerator

        try:
            analysis_state = AnalysisState(**state) if isinstance(state, dict) else state
        except Exception:
            analysis_state = AnalysisState()

        gen = FindingsGenerator(language=language)
        findings = gen.generate(analysis_state, code)
        return TransformResult(
            success=bool(findings),
            output=code,
            confidence=0.9 if findings else 0.5,
            description=f"Generated {len(findings)} finding(s).",
            details={
                "findings": [f.model_dump() for f in findings],
                "count": len(findings),
            },
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Result container
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@dataclass
class AnalysisResult:
    """Final result produced by the orchestrator."""

    sample_id: str
    success: bool
    original_code: str
    deobfuscated_code: str
    language: Optional[str]
    iterations: int
    findings: List[Finding] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    strings: List[StringEntry] = field(default_factory=list)
    transform_history: List[TransformRecord] = field(default_factory=list)
    state: Optional[AnalysisState] = None
    confidence: float = 0.0
    stop_reason: str = ""
    elapsed_seconds: float = 0.0
    was_stopped: bool = False


def _residual_obfuscation_markers(
    code: str,
    language: Optional[str],
    state: Optional[AnalysisState] = None,
) -> Dict[str, Any]:
    """Estimate whether obvious decode/runtime wrappers still remain."""
    if not code or not code.strip():
        return {"score": 0.0, "reasons": [], "has_residual": False}

    sample = code[:20_000]
    lang = (language or "").lower().strip()
    score = 0.0
    reasons: List[str] = []
    critical_residual = False

    def _flag(
        pattern: str,
        weight: float,
        reason: str,
        flags: int = re.IGNORECASE,
    ) -> None:
        nonlocal score, critical_residual
        if re.search(pattern, sample, flags):
            score += weight
            if weight >= 0.9:
                critical_residual = True
            if reason not in reasons:
                reasons.append(reason)

    _flag(r"[A-Za-z0-9+/]{48,}={0,2}", 0.4, "Encoded/base64-like blobs remain")
    _flag(
        r"""(?:"[^"\n]*"|'[^'\n]*')\s*\+\s*(?:"[^"\n]*"|'[^'\n]*')""",
        0.7,
        "Literal string concatenation remains",
        flags=0,
    )

    if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx"}:
        _flag(
            r"""\b\w+\s*\(\s*['"]0x[0-9a-fA-F]+['"]\s*\)""",
            1.4,
            "JavaScript wrapper-function lookups remain",
            flags=0,
        )
        _flag(r"\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]", 0.7, "Array-indexed lookups remain")
        _flag(r"\batob\s*\(", 0.9, "Base64 decode wrappers remain")
        _flag(
            r"\b(?:eval|Function|setTimeout|setInterval)\s*\(",
            1.1,
            "Dynamic JavaScript execution wrappers remain",
        )
        _flag(r"\bString\.fromCharCode\s*\(", 0.9, "Character-code builders remain")
    elif lang in {"python", "py"}:
        _flag(r"\bexec\s*\(", 1.2, "Python exec wrappers remain")
        _flag(r"\bcompile\s*\(", 0.7, "Python compile wrappers remain")
        _flag(r"(?:base64\.)?b64decode\s*\(", 1.0, "Python base64 decode wrappers remain")
        _flag(r"\bzlib\.decompress\s*\(", 0.9, "Compressed Python payload wrappers remain")
        _flag(r"\bmarshal\.loads\s*\(", 1.2, "Serialized Python code objects remain")
        _flag(r"\bcodecs\.decode\s*\(", 0.6, "Python codec decode wrappers remain")
    elif lang in {"powershell", "ps1", "ps"}:
        _flag(r"\b(?:Invoke-Expression|IEX)\b", 1.2, "PowerShell execution wrappers remain")
        _flag(
            r"(?:\[System\.Convert\]::|\[Convert\]::|Convert\.)FromBase64String\s*\(",
            1.0,
            "PowerShell base64 decode wrappers remain",
        )
        _flag(
            r"\[System\.Text\.Encoding\]::(?:Unicode|UTF8)\.GetString\s*\(",
            0.9,
            "PowerShell GetString wrappers remain",
        )
        _flag(r"`[A-Za-z]", 0.5, "PowerShell backtick obfuscation remains")
        _flag(r"\bNew-Object\b", 0.4, "PowerShell object-construction wrappers remain")

    if state is not None:
        techniques = {
            str(item).lower().replace(" ", "_")
            for item in getattr(state, "detected_techniques", [])
        }
        lingering = techniques.intersection(
            {
                "array_indexing",
                "base64_encoding",
                "hex_encoding",
                "char_code_construction",
                "string_encryption",
                "powershell_encoded_command",
                "python_serialization",
            }
        )
        score += min(len(lingering), 3) * 0.2

    score = round(min(score, 9.9), 2)
    return {
        "score": score,
        "reasons": reasons[:6],
        "has_residual": score >= 1.0 or critical_residual,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Stop decision
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class StopAction(str, Enum):
    CONTINUE = "continue"
    RETRY = "retry"
    BACKTRACK = "backtrack"
    STOP = "stop"


@dataclass
class StopVerdict:
    action: StopAction
    reason: str


class StopDecision:
    """Evaluate stopping conditions after each iteration.

    When an LLM client is provided, the evaluator will consult the LLM
    on borderline cases (stall or moderate confidence) to determine
    whether further transforms are likely to improve the output.  The LLM
    is asked a bounded yes/no question — it does not rewrite code.
    """

    def __init__(
        self,
        max_iterations: int = 20,
        stall_limit: int = 3,
        min_confidence: float = 0.3,
        max_consecutive_failures: int = 4,
        sufficiency_threshold: float = 0.85,
        llm_client: Optional[Any] = None,
    ) -> None:
        self.max_iterations = max_iterations
        self.stall_limit = stall_limit
        self.min_confidence = min_confidence
        self.max_consecutive_failures = max_consecutive_failures
        self.sufficiency_threshold = sufficiency_threshold
        self.llm_client = llm_client
        self._consecutive_failures: int = 0
        self._llm_consulted: bool = False  # only consult once per analysis

    def record_failure(self) -> None:
        self._consecutive_failures += 1

    def record_success(self) -> None:
        self._consecutive_failures = 0

    def evaluate(
        self,
        state_manager: StateManager,
        action_queue: ActionQueue,
        last_transform_success: bool,
        improvement_score: float,
    ) -> StopVerdict:
        """Decide whether to CONTINUE, RETRY, BACKTRACK, or STOP.

        Checks (in priority order):
        1. Max iterations reached.
        2. Confidence dropped too low after initial ramp-up.
        3. Repeated consecutive failures.
        4. Stall limit (no improvement for N iterations).
        5. Queue exhausted (nothing left to try).
        6. Sufficiently deobfuscated.
        7. Otherwise: continue.
        """
        iteration = state_manager.current_iteration
        confidence = state_manager.overall_confidence
        stall = state_manager.stall_counter
        pending_high_confidence = action_queue.peek()
        residual = _residual_obfuscation_markers(
            state_manager.current_code,
            state_manager.state.language,
            state_manager.state,
        )

        def _pending_can_reduce_residual() -> bool:
            pending = action_queue.peek()
            if pending is None:
                return False
            if residual["has_residual"]:
                return (
                    pending.confidence >= 0.55
                    or pending.action_name.startswith("llm_")
                )
            return (
                pending.confidence >= 0.7
                and not action_queue.has_been_tried(pending.action_name)
            )

        residual_reason = ", ".join(residual["reasons"][:2]) or "residual decode wrappers remain"

        # 1. Budget exhausted.
        if iteration >= self.max_iterations:
            return StopVerdict(
                StopAction.STOP,
                f"Maximum iterations reached ({self.max_iterations}).",
            )

        # 2. Confidence regression after meaningful progress.
        if iteration > 3 and confidence < self.min_confidence:
            history = state_manager.confidence_history
            if len(history) > 3 and max(history) > self.min_confidence:
                return StopVerdict(
                    StopAction.BACKTRACK,
                    f"Confidence dropped to {confidence:.2f}, below minimum "
                    f"{self.min_confidence:.2f}. Backtracking.",
                )

        # 3. Too many consecutive failures.
        if self._consecutive_failures >= self.max_consecutive_failures:
            return StopVerdict(
                StopAction.STOP,
                f"Too many consecutive failures ({self._consecutive_failures}).",
            )

        # 4. Stall detection.
        if stall >= self.stall_limit:
            # If there are still high-confidence items, try one more round.
            if _pending_can_reduce_residual():
                return StopVerdict(
                    StopAction.CONTINUE,
                    (
                        "Stalled, but another action may still recover code."
                        if not residual["has_residual"]
                        else f"Stalled, but {residual_reason}."
                    ),
                )
            return StopVerdict(
                StopAction.STOP,
                f"Improvement stalled for {stall} consecutive iterations.",
            )

        # 5. Queue empty.
        if action_queue.is_empty:
            if (
                residual["has_residual"]
                and last_transform_success
                and improvement_score > 0.0
            ):
                return StopVerdict(
                    StopAction.CONTINUE,
                    (
                        "Queue exhausted after a successful transform, but "
                        f"{residual_reason}; allowing one more planning cycle."
                    ),
                )
            return StopVerdict(
                StopAction.STOP,
                "Action queue exhausted; no more transforms to try.",
            )

        # 6. Sufficiently deobfuscated — check both confidence and readability.
        if confidence >= self.sufficiency_threshold:
            if residual["has_residual"] and _pending_can_reduce_residual():
                return StopVerdict(
                    StopAction.CONTINUE,
                    (
                        f"High confidence, but {residual_reason}; "
                        "continuing with remaining transforms."
                    ),
                )
            return StopVerdict(
                StopAction.STOP,
                f"Code sufficiently deobfuscated (confidence {confidence:.2f}).",
            )

        # 6b. High readability with moderate confidence — good enough.
        readability_history = state_manager.readability_history
        if (
            len(readability_history) >= 3
            and readability_history[-1] >= 0.75
            and confidence >= 0.6
        ):
            if residual["has_residual"] and _pending_can_reduce_residual():
                return StopVerdict(
                    StopAction.CONTINUE,
                    (
                        "Readable output, but another transform is still pending."
                        if not residual["has_residual"]
                        else f"Readable output, but {residual_reason}."
                    ),
                )
            # Readability is high and confidence is decent — code is clean.
            return StopVerdict(
                StopAction.STOP,
                f"Code highly readable ({readability_history[-1]:.2f}) "
                f"with adequate confidence ({confidence:.2f}).",
            )

        # 6c. Readability plateau — no improvement in last 3 measurements.
        if len(readability_history) >= 4:
            recent = readability_history[-3:]
            if all(abs(recent[i] - recent[i - 1]) < 0.02 for i in range(1, len(recent))):
                # Readability has plateaued — further transforms are unlikely to help.
                if confidence >= 0.5 and iteration >= 5:
                    if residual["has_residual"] and _pending_can_reduce_residual():
                        return StopVerdict(
                            StopAction.CONTINUE,
                            (
                                "Readability plateaued, but another transform is still pending."
                                if not residual["has_residual"]
                                else f"Readability plateaued, but {residual_reason}."
                            ),
                        )
                    return StopVerdict(
                        StopAction.STOP,
                        f"Readability plateaued at {recent[-1]:.2f}; "
                        f"further transforms unlikely to improve output.",
                    )

        # 7. LLM-assisted stop decision on borderline cases.
        #    Consult the LLM at most once when we're stalling but haven't
        #    hit the hard limit yet, or when confidence is moderate.
        if (
            self.llm_client is not None
            and not self._llm_consulted
            and iteration >= 4
            and (stall >= max(1, self.stall_limit - 1) or 0.5 <= confidence < 0.7)
        ):
            llm_verdict = self._consult_llm(state_manager)
            if llm_verdict is not None:
                return llm_verdict

        # 8. Last action failed -> consider retry or continue.
        if not last_transform_success:
            if self._consecutive_failures < 2:
                return StopVerdict(
                    StopAction.CONTINUE,
                    "Last action failed; trying next action.",
                )
            else:
                return StopVerdict(
                    StopAction.RETRY,
                    f"Multiple failures ({self._consecutive_failures}); retrying alternate path.",
                )

        return StopVerdict(StopAction.CONTINUE, "Progress ongoing.")

    def _consult_llm(self, state_manager: StateManager) -> Optional[StopVerdict]:
        """Ask the LLM whether further deobfuscation is worthwhile.

        Returns a StopVerdict if the LLM recommends stopping, or None
        to let the heuristic evaluation continue.
        """
        self._llm_consulted = True

        code = state_manager.current_code
        # Truncate for the LLM prompt — we only need a representative sample.
        excerpt = code[:3000] if len(code) > 3000 else code
        confidence = state_manager.overall_confidence
        iteration = state_manager.current_iteration

        prompt = (
            "You are an expert malware analyst reviewing partially deobfuscated code.\n"
            f"Iteration: {iteration}, Confidence: {confidence:.2f}\n"
            f"Code excerpt ({len(code)} chars total):\n```\n{excerpt}\n```\n\n"
            "Answer with ONLY 'STOP' or 'CONTINUE' followed by a one-sentence reason.\n"
            "STOP if the code is already mostly readable and further transforms are "
            "unlikely to improve it significantly.\n"
            "CONTINUE if there are still clearly obfuscated sections that could benefit "
            "from more transforms."
        )

        try:
            # Run the async LLM call in the current event loop.
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're already in an async context — use a new task.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    reply = pool.submit(
                        asyncio.run,
                        self.llm_client.chat(
                            [{"role": "user", "content": prompt}],
                            temperature=0.0,
                            max_tokens=60,
                        ),
                    ).result(timeout=30)
            else:
                reply = loop.run_until_complete(
                    self.llm_client.chat(
                        [{"role": "user", "content": prompt}],
                        temperature=0.0,
                        max_tokens=60,
                    )
                )

            reply = reply.strip().upper()
            if reply.startswith("STOP"):
                reason = reply[4:].strip().lstrip(":").strip() or "LLM recommends stopping."
                logger.info("LLM stop decision: STOP — %s", reason)
                return StopVerdict(
                    StopAction.STOP,
                    f"LLM assessment: {reason}",
                )
            else:
                logger.info("LLM stop decision: CONTINUE")
                return None  # let heuristics decide

        except Exception as exc:
            logger.debug("LLM stop consultation failed (non-critical): %s", exc)
            return None  # fall back to heuristic evaluation


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Verifier
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class Verifier:
    """Score the improvement after a transform step."""

    def verify(
        self,
        code_before: str,
        code_after: str,
        result: TransformResult,
        state_manager: StateManager,
    ) -> float:
        """Return an improvement score in [-1.0, 1.0].

        Positive = improvement, negative = regression, zero = no change.
        Never raises — returns 0.0 on any internal error.
        """
        try:
            return self._verify_inner(code_before, code_after, result, state_manager)
        except Exception:
            logger.exception("Verifier encountered an internal error")
            return 0.0

    def _verify_inner(
        self,
        code_before: str,
        code_after: str,
        result: TransformResult,
        state_manager: StateManager,
    ) -> float:
        if code_before == code_after and not result.details:
            return 0.0

        scores: List[Tuple[float, float]] = []  # (weight, score)
        details = result.details or {}
        language = (state_manager.state.language or "").lower()

        # 1. Readability delta.
        workspace_delta = self._workspace_readability_delta(code_before, code_after)
        read_before = StateManager._estimate_readability(code_before)
        read_after = StateManager._estimate_readability(code_after)
        read_delta = workspace_delta if workspace_delta is not None else (read_after - read_before)
        scores.append((0.20, read_delta))

        # 1b. Structural validity delta. LLM transforms can otherwise score
        # well on readability while still returning broken code.
        syntax_score = self._syntax_delta(language, code_before, code_after)
        if syntax_score != 0.0:
            scores.append((0.15, syntax_score))

        # 2. Length change (shorter is usually better for deobfuscation).
        if len(code_before) > 0:
            len_ratio = (len(code_before) - len(code_after)) / len(code_before)
            if 0 < len_ratio < 0.5:
                len_score = len_ratio
            elif len_ratio >= 0.5:
                len_score = 0.5 - (len_ratio - 0.5)
            else:
                len_score = len_ratio * 0.5
            scores.append((0.10, len_score))

        # 3. String recovery.
        new_strings = details.get("strings") or []
        decoded_strings = details.get("decoded_strings") or []
        recovered = details.get("recovered") or []
        decrypted_strings = details.get("decrypted_strings") or []
        string_count = (
            len(new_strings) + len(decoded_strings)
            + len(recovered) + len(decrypted_strings)
        )
        if string_count > 0:
            scores.append((0.20, min(string_count * 0.1, 0.5)))

        # 4. IOC extraction.
        iocs = details.get("iocs") or details.get("iocs_found") or []
        if iocs:
            scores.append((0.10, min(len(iocs) * 0.1, 0.5)))

        # 4b. Sink identification. Recognising actual execution sinks or
        # reflective dispatch points materially increases analyst confidence.
        sink_score = self._sink_identification_score(details)
        if sink_score > 0.0:
            scores.append((0.14, sink_score))

        # 5. Transform confidence as a signal.
        scores.append((0.15, result.confidence * 0.5))

        # 6. Entropy improvement (lower entropy after decode = better).
        if details.get("overall_entropy") is not None:
            # Entropy analysis provides info but doesn't modify code.
            scores.append((0.05, result.confidence * 0.3))
        elif code_before != code_after:
            ent_score = self._entropy_delta(code_before, code_after)
            if ent_score != 0.0:
                scores.append((0.10, ent_score))

        # 7. Identifier quality improvement (renames, deobfuscation).
        rename_count = details.get("rename_count", 0)
        if not rename_count and details.get("renames"):
            rename_count = len(details["renames"])
        if rename_count > 0:
            scores.append((0.10, min(rename_count * 0.05, 0.4)))

        # 8. Structural improvements (CFF unflattened, layers unwrapped).
        dispatchers = details.get("dispatchers_resolved", 0)
        layers = details.get("layers", [])
        if dispatchers:
            scores.append((0.10, min(dispatchers * 0.2, 0.5)))
        if layers:
            scores.append((0.10, min(len(layers) * 0.15, 0.5)))
        changed_workspace_files = details.get("deobfuscated_files", [])
        if changed_workspace_files:
            scores.append((0.12, min(len(changed_workspace_files) * 0.08, 0.45)))

        # Weighted sum.
        total_weight = sum(w for w, _ in scores)
        if total_weight == 0:
            return 0.0
        improvement = sum(w * s for w, s in scores) / total_weight

        # Regression check: code became less readable AND no new intelligence
        if read_after < read_before * 0.8 and not string_count:
            improvement = min(improvement, -0.1)
        if syntax_score < 0:
            improvement = min(improvement, syntax_score)

        return max(-1.0, min(1.0, improvement))

    @staticmethod
    def _sink_identification_score(details: Dict[str, Any]) -> float:
        sinks = details.get("identified_sinks") or []
        if not isinstance(sinks, list) or not sinks:
            return 0.0
        severity_weight = {"high": 0.18, "medium": 0.11, "low": 0.06}
        score = 0.0
        families: set[str] = set()
        for sink in sinks[:12]:
            if not isinstance(sink, dict):
                continue
            score += severity_weight.get(str(sink.get("severity", "")).lower(), 0.05)
            family = str(sink.get("family", "")).strip()
            if family:
                families.add(family)
        score += min(0.18, len(families) * 0.04)
        return min(0.7, score)

    @classmethod
    def _syntax_delta(cls, language: str, before: str, after: str) -> float:
        before_ok = cls._is_syntax_healthy(language, before)
        after_ok = cls._is_syntax_healthy(language, after)
        if before_ok and not after_ok:
            return -0.35
        if not before_ok and after_ok:
            return 0.2
        return 0.0

    @classmethod
    def _workspace_readability_delta(cls, before: str, after: str) -> Optional[float]:
        before_files = parse_workspace_bundle(before)
        after_files = parse_workspace_bundle(after)
        if not before_files or not after_files or len(before_files) != len(after_files):
            return None

        after_by_path = {item.path: item.text for item in after_files}
        weighted_delta = 0.0
        total_weight = 0.0
        changed_files = 0

        for item in before_files:
            after_text = after_by_path.get(item.path)
            if after_text is None or after_text == item.text:
                continue
            before_score = StateManager._estimate_readability(item.text)
            after_score = StateManager._estimate_readability(after_text)
            delta = after_score - before_score
            weight = float(max(min(len(after_text), 20_000), 200))
            weighted_delta += delta * weight
            total_weight += weight
            changed_files += 1

        if changed_files == 0 or total_weight == 0:
            return 0.0

        average_delta = weighted_delta / total_weight
        coverage_bonus = min(changed_files / max(len(before_files), 1), 0.4) * 0.05
        if average_delta > 0:
            average_delta += coverage_bonus
        return max(-1.0, min(1.0, average_delta))

    @classmethod
    def _is_syntax_healthy(cls, language: str, code: str) -> bool:
        code, _ = normalize_source_anomalies(code)
        lang = (language or "").lower()
        if lang in {"python", "py"}:
            try:
                ast.parse(code)
                return True
            except SyntaxError:
                return False
        if lang == "json":
            try:
                json.loads(code)
                return True
            except (json.JSONDecodeError, TypeError):
                return False
        return cls._balanced_delimiters(code)

    @staticmethod
    def _balanced_delimiters(code: str) -> bool:
        code, _ = normalize_source_anomalies(code)
        pairs = {"(": ")", "{": "}", "[": "]"}
        closing = {value: key for key, value in pairs.items()}
        stack: List[str] = []
        quote: Optional[str] = None
        in_line_comment = False
        in_block_comment = False
        i = 0

        while i < len(code):
            ch = code[i]
            nxt = code[i + 1] if i + 1 < len(code) else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if quote is not None:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue

            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == "#":
                in_line_comment = True
                i += 1
                continue
            if ch in {"'", '"', "`"}:
                quote = ch
                i += 1
                continue

            if ch in pairs:
                stack.append(ch)
            elif ch in closing:
                if not stack or stack[-1] != closing[ch]:
                    return False
                stack.pop()
            i += 1

        return not stack and quote is None and not in_block_comment

    @staticmethod
    def _entropy_delta(before: str, after: str) -> float:
        """Estimate Shannon entropy change. Lower entropy = improvement.
        Returns positive if entropy decreased."""
        import math
        from collections import Counter

        def _ent(s: str) -> float:
            if not s:
                return 0.0
            c = Counter(s[:50000])
            n = sum(c.values())
            return -sum((v / n) * math.log2(v / n) for v in c.values() if v > 0)

        ent_before = _ent(before)
        ent_after = _ent(after)
        if ent_before == 0:
            return 0.0
        # Normalise: if entropy dropped by 0.5+ bits, that's meaningful
        delta = ent_before - ent_after
        return max(-0.3, min(0.3, delta * 0.15))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Planner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _extract_planning_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON object from an LLM planning response.

    Handles markdown code fences, leading prose, etc.  Mirrors the
    ``LLMTransform.extract_json`` approach from ``llm_base.py``.
    """
    # Direct parse.
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # Code-fence extraction.
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except (json.JSONDecodeError, TypeError):
            pass

    # First { ... } block.
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except (json.JSONDecodeError, TypeError):
            pass

    return None


@dataclass
class PlannedAction:
    """A single action recommended by the planner."""
    action_name: str
    confidence: float
    reason: str
    priority: float = 0.0  # lower = sooner


class Planner:
    """Inspect current state and recommend next actions.

    The planner runs purely deterministic heuristics.  When LLM transforms
    are available in the action space, it schedules them at appropriate
    phases alongside the deterministic transforms.

    Key intelligence features:
    - **Re-scanning**: After any successful code-modifying transform,
      re-fingerprints to discover newly exposed patterns.
    - **Entropy-driven**: Uses entropy analysis to decide between
      decoding (high entropy) and simplification (medium entropy).
    - **Context-aware decoding**: Schedules unicode normalisation and
      string decryption when escape sequences or decrypt patterns found.
    - **Control flow recovery**: Schedules CFF unflattening when
      dispatcher patterns are detected.
    - **Adaptive renaming**: Applies deterministic renaming before
      (optionally) LLM-assisted semantic renaming.
    """

    def __init__(self, available_actions: Optional[Set[str]] = None, llm_client: Optional[Any] = None) -> None:
        self._available_actions: Set[str] = available_actions or set()
        self._llm_client = llm_client

    # Ordered plan templates by analysis phase.
    _PHASE_INITIAL: List[str] = [
        "profile_workspace",
        "preprocess_source",
        "detect_language",
        "fingerprint_obfuscation",
        "extract_strings",
        "analyze_entropy",
    ]
    _PHASE_DECODE: List[str] = [
        "analyze_dotnet_assembly",
        "decode_base64",
        "decode_hex",
        "decode_base32_base85",
        "normalize_unicode",
        "try_xor_recovery",
        "decrypt_crypto",
        "decode_js_encoder",
        "unpack_js_packer",
        "deobfuscate_js_bundle",
        "powershell_decode",
        "python_decode",
        "decode_python_serialization",
        "identify_string_resolver",
        "decrypt_strings",
    ]
    _PHASE_SIMPLIFY: List[str] = [
        "constant_fold",
        "simplify_junk_code",
        "unflatten_control_flow",
        "detect_eval_exec_reflection",
        "resolve_reflection",
    ]
    _PHASE_FINAL: List[str] = [
        "recover_literals",
        "apply_renames",
        "suggest_renames",
        "extract_iocs",
        "generate_findings",
    ]

    def _should_rescan(self, action_queue: ActionQueue) -> bool:
        """Determine if re-fingerprinting is warranted.

        Re-scan when a code-modifying transform succeeded since the last
        fingerprint run, exposing potentially new patterns.
        """
        _CODE_MODIFYING = {
            "preprocess_source",
            "deobfuscate_workspace_files",
            "analyze_dotnet_assembly",
            "decode_base64", "decode_hex", "try_xor_recovery",
            "decode_js_encoder", "unpack_js_packer", "deobfuscate_js_bundle",
            "powershell_decode", "python_decode", "constant_fold",
            "recover_literals",
            "simplify_junk_code", "identify_string_resolver",
            "normalize_unicode", "decrypt_strings",
            "unflatten_control_flow",
            "llm_deobfuscate", "llm_multilayer_unwrap",
        }
        fingerprint_count = action_queue.success_count("fingerprint_obfuscation")
        if fingerprint_count == 0:
            return False  # hasn't run yet at all
        # Count total successful code-modifying transforms since start
        modifying_successes = sum(
            action_queue.success_count(a) for a in _CODE_MODIFYING
        )
        # Re-scan if code-modifying transforms have succeeded more times
        # than we've fingerprinted (roughly: new modifications since last scan).
        return modifying_successes >= fingerprint_count

    @staticmethod
    def _looks_like_javascript(language: str, code: str) -> bool:
        lang = (language or "").lower().strip()
        if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx"}:
            return True
        if lang == "workspace":
            return bool(
                re.search(
                    r"languages:\s.*(?:javascript|typescript)\s*=",
                    code[:800],
                    re.IGNORECASE,
                )
            )
        if lang:
            return False
        return bool(
            re.search(
                r"\b(?:var|let|const|function|document\.|window\.|require\s*\(|=>)\b",
                code[:6000],
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _detect_javascript_hard_mode(
        code: str,
        language: str,
        techniques: Set[str],
        residual_score: float,
        llm_classification: Optional[Dict[str, Any]],
        *,
        js_string_array_hint: bool,
        js_packer_hint: bool,
        js_encoder_hint: bool,
        entropy_profile: str = "",
        workspace_mode: bool = False,
    ) -> Dict[str, Any]:
        if not Planner._looks_like_javascript(language, code):
            return {"enabled": False, "score": 0.0, "signals": [], "profile": "off"}

        from app.services.transforms.source_preprocessor import detect_minified_source

        sample = code[:20_000]
        minified_profile = detect_minified_source(code, "javascript")
        classification_terms: List[str] = []
        if isinstance(llm_classification, dict):
            classification_terms.extend(
                str(item)
                for item in llm_classification.get("tools_identified", [])[:8]
            )
            for key in ("obfuscation_type", "recommended_strategy"):
                value = str(llm_classification.get(key, "")).strip()
                if value:
                    classification_terms.append(value)
        classification_text = " ".join(classification_terms).lower()

        signals: List[str] = []
        score = 0.0

        def _add(condition: bool, weight: float, signal: str) -> None:
            nonlocal score
            if condition and signal not in signals:
                signals.append(signal)
                score += weight

        _add(
            js_string_array_hint
            or (
                "array_indexing" in techniques
                and "variable_renaming" in techniques
            ),
            1.1,
            "string_array_wrappers",
        )
        _add(
            js_encoder_hint
            or bool(
                {
                    "jsfuck_encoding",
                    "jjencode_encoding",
                    "aaencode_encoding",
                    "javascript_runtime_encoder",
                }.intersection(techniques)
            ),
            1.3,
            "runtime_encoder_chains",
        )
        _add(
            js_packer_hint or "dean_edwards_packer" in techniques,
            0.9,
            "packer_wrappers",
        )
        _add(
            "control_flow_flattening" in techniques
            or bool(
                re.search(
                    r"while\s*\(\s*(?:true|1|!0)\s*\)\s*\{?\s*switch",
                    sample,
                    re.IGNORECASE,
                )
            ),
            1.0,
            "control_flow_flattening",
        )
        _add(
            bool(
                re.search(
                    r"\bdebugger\b|disableConsoleOutput|console\[['\"](?:log|warn|info|error)['\"]\]\s*=\s*function",
                    sample,
                    re.IGNORECASE,
                )
            ),
            0.8,
            "anti_debugger_guards",
        )
        _add(
            bool(
                re.search(
                    r"\b(?:eval|Function|setTimeout|setInterval)\s*\(",
                    sample,
                    re.IGNORECASE,
                )
            ),
            0.7,
            "dynamic_execution_wrappers",
        )
        _add(
            bool(
                re.search(
                    r"\bselfDefending\b|toString\s*\(\s*\)\s*\[\s*['\"]constructor['\"]\s*\]",
                    sample,
                    re.IGNORECASE,
                )
            ),
            0.9,
            "self_defending_wrappers",
        )
        _add(
            bool(
                re.search(
                    r"\b(?:domainLock|location\.(?:href|host|hostname)|document\.domain|window\.location)\b",
                    sample,
                    re.IGNORECASE,
                )
            ),
            0.7,
            "domain_lock_checks",
        )
        _add(
            bool(
                re.search(
                    r"\b(?:CryptoJS|RC4|rc4|fromCharCode|charCodeAt|decodeURIComponent|decrypt)\b",
                    sample,
                    re.IGNORECASE,
                )
                or re.search(
                    r"\.split\(\s*['\"]{0,1}\s*['\"]{0,1}\s*\)\.reverse\(\)\.join",
                    sample,
                    re.IGNORECASE,
                )
            ),
            0.8,
            "custom_string_decryptors",
        )
        _add(
            float(minified_profile.get("score", 0.0)) >= 0.55,
            0.6,
            "heavy_minification",
        )
        _add(residual_score >= 2.6, 0.9, "residual_runtime_wrappers")
        _add(
            entropy_profile in ("encrypted", "heavily_obfuscated"),
            0.5,
            "high_entropy_payload",
        )
        _add(
            "javascript-obfuscator" in classification_text
            or "obfuscator.io" in classification_text,
            1.0,
            "javascript_obfuscator_profile",
        )
        _add(
            any(term in classification_text for term in ("jsfuck", "jjencode", "aaencode")),
            0.9,
            "runtime_encoder_profile",
        )
        _add(
            workspace_mode
            and bool(
                re.search(
                    r"languages:\s.*(?:javascript|typescript)\s*=",
                    code[:800],
                    re.IGNORECASE,
                )
            ),
            0.2,
            "workspace_js_bundle",
        )

        enabled = (
            score >= 2.4
            or (
                "runtime_encoder_chains" in signals
                and "control_flow_flattening" in signals
            )
            or (
                "string_array_wrappers" in signals
                and "custom_string_decryptors" in signals
            )
        )
        return {
            "enabled": enabled,
            "score": round(score, 2),
            "signals": signals,
            "profile": "aggressive" if score >= 4.0 else "assisted" if enabled else "off",
        }

    @staticmethod
    def _planner_code_excerpt(code: str, max_chars: int = 4000) -> str:
        if extract_workspace_context(code):
            return truncate_workspace_bundle(code, max_chars)
        if len(code) <= max_chars:
            return code
        segment = max(max_chars // 3, 1)
        middle_start = max((len(code) // 2) - (segment // 2), 0)
        middle_end = middle_start + segment
        return (
            code[:segment]
            + f"\n\n... [{len(code) - (segment * 3)} chars omitted] ...\n\n"
            + code[middle_start:middle_end]
            + "\n\n... [tail excerpt] ...\n\n"
            + code[-segment:]
        )

    @staticmethod
    def _planner_state_context(state_manager: StateManager) -> str:
        state = state_manager.state
        parts: List[str] = []
        workspace = workspace_context_prompt(state_manager.current_code)
        stored_workspace = state.workspace_context if hasattr(state, "workspace_context") else {}

        if workspace:
            parts.append(workspace)
        elif isinstance(stored_workspace, dict) and stored_workspace:
            entry_points = stored_workspace.get("entry_points", [])
            suspicious_files = stored_workspace.get("suspicious_files", [])
            prioritized_files = stored_workspace.get("prioritized_files", [])
            dependency_hotspots = stored_workspace.get("dependency_hotspots", [])
            execution_paths = stored_workspace.get("execution_paths", [])
            included = stored_workspace.get("included_files")
            archive_name = stored_workspace.get("archive_name")
            summary_parts = []
            if archive_name:
                summary_parts.append(f"Workspace bundle: {archive_name}")
            if included:
                summary_parts.append(f"Included files: {included}")
            if entry_points:
                summary_parts.append(
                    "Entry points: " + " | ".join(str(item) for item in entry_points[:6])
                )
            if suspicious_files:
                summary_parts.append(
                    "Suspicious files: "
                    + " | ".join(str(item) for item in suspicious_files[:6])
                )
            hotspot_paths = []
            for item in prioritized_files[:6]:
                if isinstance(item, dict):
                    value = str(item.get("path", "")).strip()
                else:
                    value = str(item).strip()
                if value:
                    hotspot_paths.append(value)
            if dependency_hotspots:
                summary_parts.append(
                    "Workspace hotspots: "
                    + " | ".join(str(item) for item in dependency_hotspots[:6])
                )
            elif hotspot_paths:
                summary_parts.append(
                    "Workspace hotspots: " + " | ".join(hotspot_paths[:6])
                )
            if execution_paths:
                summary_parts.append(
                    "Execution paths: " + " | ".join(str(item) for item in execution_paths[:4])
                )
            if summary_parts:
                parts.append("\n".join(summary_parts))

        if state.detected_techniques:
            parts.append(
                "Detected techniques: " + ", ".join(state.detected_techniques[:12])
            )
        if state.suspicious_apis:
            parts.append(
                "Suspicious APIs: " + ", ".join(state.suspicious_apis[:10])
            )
        if state.imports:
            parts.append("Imports: " + " | ".join(state.imports[:10]))
        if state.functions:
            parts.append("Functions: " + " | ".join(state.functions[:10]))
        if state.recovered_literals:
            parts.append(
                "Recovered literals: "
                + " | ".join(v[:80] for v in state.recovered_literals[:8])
            )
        if state.strings:
            sample_strings = [s.value[:80] for s in state.strings[:8] if s.value]
            if sample_strings:
                parts.append("String sample: " + " | ".join(sample_strings))
        if state.transform_history:
            recent = [
                f"{item.action}:{'ok' if item.success else 'fail'}"
                for item in state.transform_history[-6:]
            ]
            parts.append("Recent transforms: " + " -> ".join(recent))

        parts.append(f"Overall confidence: {state_manager.overall_confidence:.2f}")
        readability_hist = state_manager.readability_history
        if readability_hist:
            parts.append(f"Current readability: {readability_hist[-1]:.2f}")

        return "\n".join(parts)

    async def plan_with_llm(
        self,
        state_manager: StateManager,
        action_queue: ActionQueue,
    ) -> List[PlannedAction]:
        """Produce LLM-assisted recommendations, merged with deterministic ones.

        When ``self._llm_client`` is available, sends a planning prompt to
        the LLM describing the current obfuscation state and asks for
        recommended next actions.  The LLM suggestions are merged with the
        deterministic plan: overlapping actions use the LLM-suggested
        priority, and novel LLM suggestions are appended.

        Falls back to purely deterministic planning on any error.
        """
        # Always start with deterministic recommendations as a baseline.
        deterministic = self.plan(state_manager, action_queue)

        if self._llm_client is None:
            return deterministic

        try:
            state = state_manager.state
            iteration = state_manager.current_iteration
            code = state_manager.current_code
            techniques = list(state.detected_techniques)
            actions_list = sorted(self._available_actions)

            # Build success / failure summaries from the action queue ledger.
            successes: List[str] = []
            failures: List[str] = []
            for action_name in sorted(action_queue._ledger.keys()):
                s_count = action_queue.success_count(action_name)
                f_count = action_queue.failure_count(action_name)
                if s_count:
                    successes.append(f"{action_name} (x{s_count})")
                if f_count:
                    failures.append(f"{action_name} (x{f_count})")

            confidence = state_manager.overall_confidence
            readability_hist = state_manager.readability_history
            readability = readability_hist[-1] if readability_hist else 0.0

            code_snippet = self._planner_code_excerpt(code)
            state_context = self._planner_state_context(state_manager)

            prompt = (
                "You are an expert code deobfuscation planner. Analyze the "
                "following obfuscated code and recommend the next "
                "deobfuscation actions to take.\n\n"
                f"Current code excerpt:\n{code_snippet}\n\n"
                f"State summary:\n{state_context}\n\n"
                f"Available actions: {actions_list}\n"
                f"Already tried (successes): {successes}\n"
                f"Already tried (failures): {failures}\n"
                f"Current iteration: {iteration}\n"
                f"Current confidence: {confidence}\n"
                f"Current readability: {readability}\n\n"
                "Respond with a JSON object:\n"
                "{\n"
                '  "analysis": "Brief analysis of what kind of obfuscation this is",\n'
                '  "recommended_actions": [\n'
                '    {"action": "action_name", "confidence": 0.9, '
                '"reason": "why this action", "priority": 1.0},\n'
                "    ...\n"
                "  ]\n"
                "}\n\n"
                "Only recommend actions from the available actions list. "
                "Prioritize actions that haven't been tried yet, avoid actions "
                "that have repeatedly failed without new evidence, and prefer "
                "deterministic decoders before broad LLM rewrites when the "
                "state already points to a specific layer."
            )

            messages = [{"role": "user", "content": prompt}]
            reply = await self._llm_client.chat(
                messages=messages,
                temperature=0.3,
                max_tokens=1024,
            )

            # Parse the LLM response using the same pattern as LLMTransform.
            parsed = _extract_planning_json(reply)
            if parsed is None:
                logger.warning("LLM planner returned unparseable response; "
                               "falling back to deterministic plan")
                return deterministic

            llm_actions: List[PlannedAction] = []
            for item in parsed.get("recommended_actions", []):
                action = item.get("action", "")
                if action not in self._available_actions:
                    continue
                llm_actions.append(PlannedAction(
                    action_name=action,
                    confidence=float(item.get("confidence", 0.7)),
                    reason=str(item.get("reason", "LLM recommendation")),
                    priority=float(item.get("priority", 10.0)),
                ))

            if not llm_actions:
                logger.debug("LLM planner returned no valid actions; "
                             "using deterministic plan")
                return deterministic

            # Merge: LLM suggestions override priorities for overlapping
            # actions; novel LLM suggestions are appended.
            llm_by_name = {a.action_name: a for a in llm_actions}
            merged: List[PlannedAction] = []
            seen: Set[str] = set()

            for det in deterministic:
                if det.action_name in llm_by_name:
                    # Use LLM priority/confidence when there's overlap.
                    llm_rec = llm_by_name[det.action_name]
                    merged.append(PlannedAction(
                        action_name=det.action_name,
                        confidence=llm_rec.confidence,
                        reason=f"{det.reason} [LLM: {llm_rec.reason}]",
                        priority=llm_rec.priority,
                    ))
                else:
                    merged.append(det)
                seen.add(det.action_name)

            # Append novel LLM suggestions not in deterministic set.
            for llm_rec in llm_actions:
                if llm_rec.action_name not in seen:
                    merged.append(llm_rec)
                    seen.add(llm_rec.action_name)

            merged.sort(key=lambda r: r.priority)

            analysis = parsed.get("analysis", "")
            if analysis:
                logger.info("LLM planner analysis: %s", analysis[:200])
                # Store analysis for display in Agent Notebook
                state.iteration_state["planner_analysis"] = analysis

            logger.debug(
                "LLM-assisted plan: %d actions (deterministic=%d, llm=%d, merged=%d)",
                len(merged), len(deterministic), len(llm_actions), len(merged),
            )

            # ── Multi-turn refinement (Turn 2) ──────────────────────
            # If the LLM's analysis mentions uncertainty or if we're past
            # iteration 3 with stalls, ask a follow-up refinement question.
            # This gives the LLM a chance to reconsider its strategy with
            # the deterministic plan as additional context.
            classification = state.iteration_state.get("llm_classification")
            should_refine = (
                iteration >= 3
                and state_manager.stall_counter >= 1
                and len(merged) >= 2
            )
            if should_refine:
                try:
                    det_names = [a.action_name for a in deterministic]
                    llm_names = [a.action_name for a in llm_actions]

                    refinement_prompt = (
                        "Here is what the deterministic planner recommended: "
                        f"{det_names}\n"
                        f"Your initial recommendations: {llm_names}\n"
                        f"Your analysis: {analysis}\n\n"
                    )
                    if classification:
                        refinement_prompt += (
                            f"Classification: {classification.get('obfuscation_type', 'unknown')}\n"
                            f"Strategy: {classification.get('recommended_strategy', '')}\n\n"
                        )

                    refinement_prompt += (
                        f"The analysis has stalled for {state_manager.stall_counter} "
                        f"iteration(s) at confidence {confidence:.2f}.\n\n"
                        "Considering what has already been tried and what failed, "
                        "should we adjust the strategy? Respond with JSON:\n"
                        "{\n"
                        '  "strategy_change": "describe any change or say \'no change needed\'",\n'
                        '  "recommended_actions": [\n'
                        '    {"action": "action_name", "confidence": 0.8, '
                        '"reason": "why", "priority": 1.0}\n'
                        "  ]\n"
                        "}\n"
                        f"Available actions: {actions_list}"
                    )

                    # Build multi-turn conversation
                    turn2_messages = [
                        {"role": "user", "content": prompt},
                        {"role": "assistant", "content": reply},
                        {"role": "user", "content": refinement_prompt},
                    ]

                    from app.services.transforms.llm_base import LLMTransform
                    turn2_reply = await self._llm_client.chat(
                        messages=turn2_messages,
                        temperature=0.2,
                        max_tokens=LLMTransform.compute_token_budget(
                            len(refinement_prompt), "reflect"
                        ),
                    )

                    turn2_parsed = _extract_planning_json(turn2_reply)
                    if turn2_parsed:
                        strategy_change = turn2_parsed.get("strategy_change", "")
                        if strategy_change and "no change" not in strategy_change.lower():
                            logger.info(
                                "LLM planner turn 2 strategy change: %s",
                                strategy_change[:200],
                            )
                            state.iteration_state["planner_analysis"] = (
                                f"{analysis}\n\n"
                                f"[Refinement] {strategy_change}"
                            )

                        # Merge turn-2 recommendations with higher priority
                        for item in turn2_parsed.get("recommended_actions", []):
                            action = item.get("action", "")
                            if action in self._available_actions:
                                # Override or append with boosted priority
                                found = False
                                for m in merged:
                                    if m.action_name == action:
                                        m.priority = min(
                                            m.priority,
                                            float(item.get("priority", m.priority)),
                                        )
                                        m.confidence = max(
                                            m.confidence,
                                            float(item.get("confidence", m.confidence)),
                                        )
                                        m.reason += f" [refined: {item.get('reason', '')}]"
                                        found = True
                                        break
                                if not found and action not in seen:
                                    merged.append(PlannedAction(
                                        action_name=action,
                                        confidence=float(item.get("confidence", 0.7)),
                                        reason=f"[turn-2] {item.get('reason', '')}",
                                        priority=float(item.get("priority", 5.0)),
                                    ))
                                    seen.add(action)

                        merged.sort(key=lambda r: r.priority)
                except Exception:
                    logger.debug("LLM planner turn 2 failed (non-critical)")

            return merged

        except Exception:
            logger.exception("LLM-assisted planning failed; falling back to "
                             "deterministic plan")
            return deterministic

    async def classify_obfuscation(
        self,
        state_manager: StateManager,
    ) -> Optional[Dict[str, Any]]:
        """Ask the LLM to classify the obfuscation type and recommend strategy.

        Called once on iteration 1 after fingerprinting.  Returns a dict with
        obfuscation_type, tools_identified, layers, recommended_strategy,
        priority_transforms, and confidence.  Returns None on any failure.
        """
        if self._llm_client is None:
            return None

        try:
            from app.services.transforms.llm_base import LLMTransform

            code = state_manager.current_code
            excerpt = self._planner_code_excerpt(code, max_chars=3000)
            techniques = list(state_manager.state.detected_techniques)
            language = state_manager.state.language or "unknown"
            state_context = LLMTransform.build_state_context(
                state_manager.state.model_dump(),
                code=code,
                compact=True,
            )

            prompt = (
                "You are an expert malware analyst. Classify the obfuscation "
                "used in this code sample and recommend a deobfuscation strategy.\n\n"
                f"Language: {language}\n"
                f"Regex-detected techniques: {techniques}\n\n"
                f"State context:\n{state_context}\n\n"
                f"Code excerpt:\n```\n{excerpt}\n```\n\n"
                "Respond with ONLY a JSON object:\n"
                "{\n"
                '  "obfuscation_type": "primary obfuscation category",\n'
                '  "tools_identified": ["specific tool names if recognizable"],\n'
                '  "layers": ["ordered list of encoding/obfuscation layers"],\n'
                '  "recommended_strategy": "brief strategy description",\n'
                '  "priority_transforms": ["ordered action names to try first"],\n'
                '  "confidence": 0.0\n'
                "}\n\n"
                f"Available action names: {sorted(self._available_actions)}"
            )

            reply = await self._llm_client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=LLMTransform.compute_token_budget(len(excerpt), "classify"),
            )

            parsed = _extract_planning_json(reply)
            if parsed is None:
                logger.warning("LLM classification returned unparseable response")
                return None

            # Validate: priority_transforms must be from available actions
            valid_transforms = [
                t for t in parsed.get("priority_transforms", [])
                if t in self._available_actions
            ]
            parsed["priority_transforms"] = valid_transforms

            raw_conf = parsed.get("confidence", 0.5)
            parsed["confidence"] = max(0.0, min(1.0, float(raw_conf)))

            logger.info(
                "LLM classification: type=%s, strategy=%s, confidence=%.2f",
                parsed.get("obfuscation_type", "unknown"),
                parsed.get("recommended_strategy", "none"),
                parsed["confidence"],
            )
            return parsed

        except Exception:
            logger.exception("LLM obfuscation classification failed (non-critical)")
            return None

    async def reflect_on_failure(
        self,
        failed_action: str,
        result: TransformResult,
        state_manager: StateManager,
        action_queue: ActionQueue,
    ) -> List[PlannedAction]:
        """Ask the LLM why a transform failed and what to try instead.

        Called at most once per analysis when a stall is detected.  Returns
        a list of recommended alternative actions, or an empty list on failure.
        """
        if self._llm_client is None:
            return []

        try:
            from app.services.transforms.llm_base import LLMTransform

            code_excerpt = self._planner_code_excerpt(
                state_manager.current_code, max_chars=2000
            )
            state_context = self._planner_state_context(state_manager)

            error_detail = result.description[:200]
            if result.details.get("error"):
                error_detail += f" Error: {result.details['error']}"

            prompt = (
                "You are an expert deobfuscation analyst. A transform just failed "
                "or produced no improvement. Analyze why and recommend alternatives.\n\n"
                f"Failed action: {failed_action}\n"
                f"Failure detail: {error_detail}\n\n"
                f"State:\n{state_context}\n\n"
                f"Code excerpt:\n```\n{code_excerpt}\n```\n\n"
                f"Available actions: {sorted(self._available_actions)}\n\n"
                "Respond with ONLY a JSON object:\n"
                "{\n"
                '  "failure_reason": "why the transform failed",\n'
                '  "alternatives": [\n'
                '    {"action": "action_name", "confidence": 0.8, '
                '"reason": "why this might work instead"}\n'
                "  ]\n"
                "}\n"
                "Only suggest actions from the available list. Limit to 1-3."
            )

            reply = await self._llm_client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=LLMTransform.compute_token_budget(len(code_excerpt), "reflect"),
            )

            parsed = _extract_planning_json(reply)
            if parsed is None:
                return []

            failure_reason = parsed.get("failure_reason", "")
            if failure_reason:
                logger.info(
                    "LLM reflection on '%s' failure: %s",
                    failed_action, failure_reason[:150],
                )

            alternatives: List[PlannedAction] = []
            for item in parsed.get("alternatives", [])[:3]:
                action = item.get("action", "")
                if action in self._available_actions and not action_queue.is_capped(action):
                    alternatives.append(PlannedAction(
                        action_name=action,
                        confidence=max(0.3, min(0.9, float(item.get("confidence", 0.6)))),
                        reason=f"[reflection] {item.get('reason', 'LLM alternative')}",
                        priority=8.0,
                    ))

            return alternatives

        except Exception:
            logger.exception("LLM failure reflection failed (non-critical)")
            return []

    def plan(
        self,
        state_manager: StateManager,
        action_queue: ActionQueue,
    ) -> List[PlannedAction]:
        """Produce a ranked list of recommended actions."""
        state = state_manager.state
        iteration = state_manager.current_iteration
        code = state_manager.current_code
        language = (state.language or "").lower()
        workspace_mode = (
            extract_workspace_context(code) is not None
            or bool(getattr(state, "workspace_context", {}))
        )

        recommendations: List[PlannedAction] = []

        def _not_tried(action_name: str) -> bool:
            return not action_queue.has_been_tried(action_name)

        # ── LLM Classification boost ─────────────────────────────────
        # If the LLM classified the obfuscation type on iteration 1,
        # boost its recommended transforms on iterations 1-3.
        llm_classification = state.iteration_state.get("llm_classification")
        if llm_classification and iteration <= 3:
            for t_name in llm_classification.get("priority_transforms", []):
                if t_name in self._available_actions and not action_queue.has_been_tried(t_name):
                    recommendations.append(PlannedAction(
                        action_name=t_name,
                        confidence=min(llm_classification.get("confidence", 0.7), 0.9),
                        reason=f"LLM classification: {llm_classification.get('obfuscation_type', 'unknown')}",
                        priority=7.0,
                    ))

        # ── Phase 1: Initial reconnaissance ──────────────────────────
        if iteration <= 1:
            from app.services.transforms.source_preprocessor import source_needs_preprocessing

            for i, action in enumerate(self._PHASE_INITIAL):
                if workspace_mode and action in {"detect_language", "preprocess_source"}:
                    continue
                if not workspace_mode and action == "profile_workspace":
                    continue
                if action == "preprocess_source" and not source_needs_preprocessing(code, language):
                    continue
                if action in self._available_actions and not action_queue.has_been_tried(action):
                    recommendations.append(PlannedAction(
                        action_name=action,
                        confidence=0.95,
                        reason=(
                            "Initial workspace reconnaissance phase."
                            if workspace_mode else "Initial reconnaissance phase."
                        ),
                        priority=float(i),
                    ))

        # ── Smart re-scanning after code changes ─────────────────────
        if iteration > 1 and self._should_rescan(action_queue):
            recommendations.append(PlannedAction(
                action_name="fingerprint_obfuscation",
                confidence=0.90,
                reason="Re-scanning after code modifications to discover new patterns.",
                priority=5.0,
            ))

        # ── Entropy-driven scheduling ────────────────────────────────
        # If entropy analysis was done and found high-entropy sections,
        # prioritise decoding transforms.
        entropy_details = {}
        for record in state.transform_history:
            if record.action == "analyze_entropy" and record.success:
                entropy_details = record.outputs or {}
        entropy_profile = entropy_details.get("entropy_profile", "")

        if entropy_profile in ("encrypted", "heavily_obfuscated"):
            # Aggressively schedule all decoders
            for action in self._PHASE_DECODE:
                if action in self._available_actions and not action_queue.success_count(action):
                    recommendations.append(PlannedAction(
                        action_name=action,
                        confidence=0.85,
                        reason=f"High entropy ({entropy_profile}) — aggressive decoding.",
                        priority=8.0,
                    ))

        # ── Phase 2: Decoding — driven by detected techniques ────────
        techniques = set(t.lower().replace(" ", "_") for t in state.detected_techniques)
        if "base64_blob" in techniques:
            techniques.add("base64_encoding")
        if "hex_stream" in techniques or "escaped_hex" in techniques:
            techniques.add("hex_encoding")
        if "python_serialization" in techniques:
            techniques.add("marshal_bytecode")
        if "powershell_encoded_command" in techniques:
            techniques.add("base64_encoding")

        base64_hint = bool(re.search(
            r"(?:atob\s*\(|(?:base64\.)?b64decode\s*\(|(?:\[(?:System\.)?Convert\]::|Convert\.)FromBase64String\s*\(|-(?:EncodedCommand|enc)\b)",
            code[:12000],
            re.IGNORECASE,
        ))
        hex_hint = bool(re.search(
            r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|0x[0-9a-fA-F]{2}\s*,|(?:[0-9a-fA-F]{2}){16,})",
            code[:12000],
        ))
        python_serial_hint = bool(re.search(
            r"(?:pickle|marshal)\.loads\s*\(|zlib\.decompress\s*\(",
            code[:12000],
            re.IGNORECASE,
        ))
        dotnet_binary_hint = False
        try:
            from app.services.transforms.binary_analysis import (
                binary_text_to_bytes,
                looks_like_dotnet_assembly_bytes,
            )

            dotnet_binary_hint = looks_like_dotnet_assembly_bytes(binary_text_to_bytes(code))
        except Exception:
            dotnet_binary_hint = False
        xor_hint = (
            bool(re.search(r"(?:\^|-bxor\b)", code[:12000], re.IGNORECASE))
            and bool(re.search(
                r"(?:\\x[0-9a-fA-F]{2}|\[\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){3,}\s*\])",
                code[:12000],
                re.IGNORECASE,
            ))
        )
        js_string_array_hint = (
            language in ("javascript", "js", "jsx", "typescript", "ts", "tsx")
            and bool(re.search(
                r"(?:\b_0x[0-9a-fA-F]{3,}\b|"
                r"(?:var|let|const)\s+\w+\s*=\s*\[[^\]]+\]\s*;?.{0,240}"
                r"(?:\.push\s*\(\s*\w+\.shift\s*\(|return\s+\w+\s*\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]))",
                code[:12000],
                re.IGNORECASE | re.DOTALL,
            ))
        )
        js_packer_hint = (
            language in ("javascript", "js", "jsx", "typescript", "ts", "tsx", "")
            and bool(re.search(
                r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)",
                code[:12000],
                re.IGNORECASE,
            ))
        )
        js_encoder_hint = (
            language in ("javascript", "js", "jsx", "typescript", "ts", "tsx", "")
            and (
                bool(re.search(r"""(?:\[\s*['"]\w+['"]\s*\]\s*){1,4}\[\s*['"]constructor['"]\s*\]\s*\(""", code[:12000]))
                or bool(re.search(r"""(?:\$=~\[\];|\$=\{___:|ﾟДﾟ|ﾟωﾟ)""", code[:12000]))
            )
        )
        js_bundle_hint = (
            language in ("javascript", "js", "jsx", "typescript", "ts", "tsx", "")
            and bool(re.search(
                r"(?:__webpack_require__|webpackJsonp|parcelRequire|\bmodule\.exports\b|\bexports\.default\b|\(function\s*\(\s*modules\s*\)|\b\d+\s*:\s*function\s*\()",
                code[:25000],
                re.IGNORECASE,
            ))
        )
        js_minified_bundle_hint = (
            language in ("javascript", "js", "jsx", "typescript", "ts", "tsx", "")
            and (
                "minified_code_beautification" in techniques
                or bool(re.search(r"^[^\n]{220,}$", code[:8000], re.MULTILINE))
            )
        )
        literal_eval_hint = (
            language in ("javascript", "js", "jsx", "typescript", "ts", "tsx")
            and bool(re.search(
                r"""\beval\s*\(\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*\)""",
                code[:12000],
                re.DOTALL,
            ))
        )
        residual = _residual_obfuscation_markers(code, language, state)
        residual_score = float(residual["score"])
        residual_reasons = residual["reasons"]
        js_hard_mode = self._detect_javascript_hard_mode(
            code,
            language,
            techniques,
            residual_score,
            llm_classification,
            js_string_array_hint=js_string_array_hint,
            js_packer_hint=js_packer_hint,
            js_encoder_hint=js_encoder_hint,
            entropy_profile=entropy_profile,
            workspace_mode=workspace_mode,
        )
        state.iteration_state["js_hard_mode"] = js_hard_mode
        js_hard_enabled = bool(js_hard_mode.get("enabled"))
        js_hard_score = float(js_hard_mode.get("score", 0.0))
        js_hard_signals = {
            str(item)
            for item in js_hard_mode.get("signals", [])
            if str(item).strip()
        }

        if (
            "analyze_dotnet_assembly" in self._available_actions
            and ((language or "").lower().strip() == "dotnet" or dotnet_binary_hint)
            and _not_tried("analyze_dotnet_assembly")
        ):
            recommendations.append(PlannedAction(
                action_name="analyze_dotnet_assembly",
                confidence=0.92,
                reason=".NET PE/CLR assembly detected.",
                priority=9.8,
            ))
        if (
            ("base64_encoding" in techniques or base64_hint)
            and _not_tried("decode_base64")
        ):
            recommendations.append(PlannedAction(
                action_name="decode_base64",
                confidence=0.9,
                reason="Base64 encoding detected.",
                priority=10.0,
            ))
        if (
            ("hex_encoding" in techniques or hex_hint)
            and _not_tried("decode_hex")
        ):
            recommendations.append(PlannedAction(
                action_name="decode_hex",
                confidence=0.85,
                reason="Hex encoding detected.",
                priority=11.0,
            ))
        if (
            ("xor_encryption" in techniques or xor_hint)
            and _not_tried("try_xor_recovery")
        ):
            recommendations.append(PlannedAction(
                action_name="try_xor_recovery",
                confidence=0.6,
                reason="XOR encryption patterns detected.",
                priority=12.0,
            ))

        # Unicode/escape normalisation — schedule if code has escape sequences.
        if ("normalize_unicode" in self._available_actions
                and not action_queue.success_count("normalize_unicode")):
            _escape_hint = bool(
                re.search(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#\d+;', code[:5000])
            )
            if _escape_hint or "unicode_escape" in techniques:
                recommendations.append(PlannedAction(
                    action_name="normalize_unicode",
                    confidence=0.88,
                    reason="Unicode/hex escape sequences detected.",
                    priority=9.5,
                ))

        # String decryption — schedule if custom decrypt functions suspected.
        if ("decrypt_strings" in self._available_actions
                and _not_tried("decrypt_strings")):
            _decrypt_hint = bool(
                re.search(
                    r'function\s+\w{1,12}\s*\(\s*\w+\s*(?:,\s*\w+\s*)*\)\s*\{.*?(?:split|reverse|fromCharCode|charCodeAt|charAt|atob|b64decode|\^)\b',
                    code[:10000],
                    re.DOTALL,
                )
            ) or "string_encryption" in techniques
            if _decrypt_hint or (
                js_hard_enabled
                and bool(
                    {
                        "custom_string_decryptors",
                        "residual_runtime_wrappers",
                    }.intersection(js_hard_signals)
                )
            ):
                recommendations.append(PlannedAction(
                    action_name="decrypt_strings",
                    confidence=0.82 if js_hard_enabled else 0.75,
                    reason=(
                        "JavaScript hard mode: custom string decryptor helpers remain."
                        if js_hard_enabled else
                        "Custom string decrypt function detected."
                    ),
                    priority=11.0 if js_hard_enabled else 11.5,
                ))

        # Language-specific decoders.
        if language in ("powershell", "ps1", "ps"):
            if _not_tried("powershell_decode"):
                recommendations.append(PlannedAction(
                    action_name="powershell_decode",
                    confidence=0.85,
                    reason="PowerShell code detected.",
                    priority=9.3,
                ))
        if language in ("python", "py"):
            if _not_tried("python_decode"):
                recommendations.append(PlannedAction(
                    action_name="python_decode",
                    confidence=0.8,
                    reason="Python code detected.",
                    priority=9.35,
                ))
        if (
            "decode_python_serialization" in self._available_actions
            and (python_serial_hint or "marshal_bytecode" in techniques)
            and _not_tried("decode_python_serialization")
        ):
            recommendations.append(PlannedAction(
                action_name="decode_python_serialization",
                confidence=0.82,
                reason="Python serialization or compressed bytecode chain detected.",
                priority=10.8,
            ))
        if (
            "array_indexing" in techniques
            or "char_code_construction" in techniques
            or js_string_array_hint
        ):
            if _not_tried("identify_string_resolver"):
                recommendations.append(PlannedAction(
                    action_name="identify_string_resolver",
                    confidence=0.86 if (js_string_array_hint or js_hard_enabled) else 0.75,
                    reason=(
                        "JavaScript hard mode: string-array resolver helpers detected."
                        if js_hard_enabled and js_string_array_hint
                        else "JavaScript string-array obfuscation pattern detected."
                        if js_string_array_hint
                        else "Array/char-code string obfuscation detected."
                    ),
                    priority=8.9 if (js_hard_enabled and js_string_array_hint) else 9.6 if js_string_array_hint else 10.9,
                ))
        if (
            "decode_js_encoder" in self._available_actions
            and (
                js_encoder_hint
                or bool(
                    {
                        "jsfuck_encoding",
                        "jjencode_encoding",
                        "aaencode_encoding",
                        "javascript_runtime_encoder",
                    }.intersection(techniques)
                )
            )
            and _not_tried("decode_js_encoder")
        ):
            recommendations.append(PlannedAction(
                action_name="decode_js_encoder",
                confidence=0.88,
                reason="JavaScript runtime encoder pattern detected.",
                priority=10.6,
            ))
        if (
            "unpack_js_packer" in self._available_actions
            and ("dean_edwards_packer" in techniques or js_packer_hint)
            and _not_tried("unpack_js_packer")
        ):
            recommendations.append(PlannedAction(
                action_name="unpack_js_packer",
                confidence=0.9,
                reason="Dean Edwards Packer wrapper detected.",
                priority=10.7,
            ))
        if (
            "deobfuscate_js_bundle" in self._available_actions
            and (js_bundle_hint or (js_minified_bundle_hint and (js_hard_enabled or iteration >= 2)))
            and _not_tried("deobfuscate_js_bundle")
        ):
            recommendations.append(PlannedAction(
                action_name="deobfuscate_js_bundle",
                confidence=0.87 if js_bundle_hint else 0.8,
                reason=(
                    "Bundled JavaScript runtime detected; use specialist bundle deobfuscation."
                    if js_bundle_hint else
                    "Large minified JavaScript remains after preprocessing; try specialist bundle deobfuscation."
                ),
                priority=10.55 if js_bundle_hint else 11.1,
            ))

        if (
            workspace_mode
            and "deobfuscate_workspace_files" in self._available_actions
            and iteration >= 2
        ):
            workspace_context = state.workspace_context if hasattr(state, "workspace_context") else {}
            prioritized_files = workspace_context.get("prioritized_files", [])
            suspicious_files = workspace_context.get("suspicious_files", [])
            entry_points = workspace_context.get("entry_points", [])
            remaining_frontier = workspace_context.get("remaining_frontier_paths", [])
            workspace_attempts = action_queue.total_attempts("deobfuscate_workspace_files")
            should_run_workspace_pass = (
                workspace_attempts == 0
                or (remaining_frontier and workspace_attempts < 3)
            )
            if should_run_workspace_pass and (prioritized_files or suspicious_files or entry_points):
                recommendations.append(PlannedAction(
                    action_name="deobfuscate_workspace_files",
                    confidence=0.84 if workspace_attempts == 0 else 0.8,
                    reason=(
                        "Run deterministic per-file deobfuscation against prioritized "
                        "workspace hotspots instead of only whole-bundle passes."
                        if workspace_attempts == 0 else
                        "Continue workspace hotspot expansion against remaining high-priority files."
                    ),
                    priority=12.2 if workspace_attempts == 0 else 13.1 + workspace_attempts,
                ))

        if (
            "preprocess_source" in self._available_actions
            and not workspace_mode
            and action_queue.success_count("preprocess_source") < 2
        ):
            from app.services.transforms.source_preprocessor import source_needs_preprocessing

            if source_needs_preprocessing(code, language):
                recommendations.append(PlannedAction(
                    action_name="preprocess_source",
                    confidence=0.87 if js_hard_enabled else 0.83,
                    reason=(
                        "JavaScript hard mode: minified or parser-hostile code still needs layout recovery."
                        if js_hard_enabled else
                        "Parser-hostile anomalies or minified code detected in the current working sample."
                    ),
                    priority=11.8 if js_hard_enabled else 12.4,
                ))

        # ── Phase 3: Simplification ──────────────────────────────────
        if "string_concatenation" in techniques or "junk_code" in techniques:
            if not action_queue.success_count("constant_fold"):
                recommendations.append(PlannedAction(
                    action_name="constant_fold",
                    confidence=0.85,
                    reason="String concatenation / constant expressions detected.",
                    priority=15.0,
                ))
            if not action_queue.success_count("simplify_junk_code"):
                recommendations.append(PlannedAction(
                    action_name="simplify_junk_code",
                    confidence=0.8,
                    reason="Junk code detected.",
                    priority=16.0,
                ))
        if "eval_exec" in techniques:
            if not action_queue.success_count("detect_eval_exec_reflection"):
                recommendations.append(PlannedAction(
                    action_name="detect_eval_exec_reflection",
                    confidence=0.8,
                    reason="Dynamic execution patterns detected.",
                    priority=14.0,
                ))
            elif (
                literal_eval_hint
                and action_queue.success_count("detect_eval_exec_reflection") == 1
                and not action_queue.is_capped("detect_eval_exec_reflection")
            ):
                recommendations.append(PlannedAction(
                    action_name="detect_eval_exec_reflection",
                    confidence=0.78,
                    reason=(
                        "Re-run dynamic execution analysis now that the eval "
                        "payload is a literal string."
                    ),
                    priority=4.8,
                ))

        # Control flow unflattening — if CFF detected.
        if ("unflatten_control_flow" in self._available_actions
                and not action_queue.success_count("unflatten_control_flow")):
            _cff_hint = (
                "control_flow_flattening" in techniques
                or bool(re.search(
                    r'while\s*\(\s*(?:true|1|!0)\s*\)\s*\{?\s*switch',
                    code[:10000],
                    re.IGNORECASE,
                ))
            )
            if _cff_hint:
                recommendations.append(PlannedAction(
                    action_name="unflatten_control_flow",
                    confidence=0.78 if js_hard_enabled else 0.70,
                    reason=(
                        "JavaScript hard mode: switch-dispatch control flow flattening detected."
                        if js_hard_enabled else
                        "Control flow flattening detected."
                    ),
                    priority=13.6 if js_hard_enabled else 14.5,
                ))

        early_deterministic_progress = sum(
            action_queue.success_count(action)
            for action in (
                self._PHASE_DECODE
                + self._PHASE_SIMPLIFY
                + ["deobfuscate_workspace_files", "preprocess_source"]
            )
        )

        # ── Phase 4: Final passes ────────────────────────────────────
        if iteration >= 3 or (
            js_hard_enabled
            and iteration >= 2
            and early_deterministic_progress >= 1
        ):
            # Deterministic renaming before LLM renaming.
            if ("apply_renames" in self._available_actions
                    and _not_tried("apply_renames")):
                recommendations.append(PlannedAction(
                    action_name="apply_renames",
                    confidence=0.8 if js_hard_enabled else 0.75,
                    reason=(
                        "Apply JSNice-style deterministic renaming after structural recovery."
                        if js_hard_enabled else
                        "Apply deterministic variable renaming."
                    ),
                    priority=18.7 if js_hard_enabled else 19.0,
                ))

            for i, action in enumerate(self._PHASE_FINAL):
                if action == "apply_renames":
                    continue  # already handled above
                if _not_tried(action):
                    recommendations.append(PlannedAction(
                        action_name=action,
                        confidence=0.7 if action != "generate_findings" else 0.95,
                        reason="Final analysis pass.",
                        priority=20.0 + i,
                    ))

        # ── Exploratory sweep (if nothing recommended early on) ──────
        if not recommendations and iteration < 10:
            for action in self._PHASE_DECODE:
                if action in self._available_actions and not action_queue.has_been_tried(action):
                    recommendations.append(PlannedAction(
                        action_name=action,
                        confidence=0.5,
                        reason="Exploratory decoding pass.",
                        priority=30.0,
                    ))

        # Second-pass constant folding after decoders have run.
        if iteration >= 4 and action_queue.success_count("constant_fold") == 1:
            if action_queue.success_count("decode_base64") or action_queue.success_count("decode_hex"):
                recommendations.append(PlannedAction(
                    action_name="recover_literals",
                    confidence=0.78,
                    reason="Second-pass literal propagation and dead-branch pruning after decoding.",
                    priority=18.0,
                ))

        # Second-pass string decryption after decoders expose new functions.
        if (iteration >= 5
                and "decrypt_strings" in self._available_actions
                and action_queue.success_count("decrypt_strings") == 1):
            total_decode_successes = sum(
                action_queue.success_count(a) for a in [
                    "decode_base64", "decode_hex", "normalize_unicode",
                ]
            )
            if total_decode_successes >= 2:
                recommendations.append(PlannedAction(
                    action_name="decrypt_strings",
                    confidence=0.65,
                    reason="Second-pass string decryption after decoders exposed new code.",
                    priority=18.5,
                ))

        # Second-pass CFF after constant folding / junk removal may
        # have simplified dispatcher structures.
        if (iteration >= 5
                and "unflatten_control_flow" in self._available_actions
                and action_queue.success_count("unflatten_control_flow") == 1):
            simplify_successes = sum(
                action_queue.success_count(a) for a in [
                    "constant_fold", "simplify_junk_code",
                ]
            )
            if simplify_successes >= 1:
                recommendations.append(PlannedAction(
                    action_name="unflatten_control_flow",
                    confidence=0.60,
                    reason="Second CFF pass after simplification exposed cleaner dispatchers.",
                    priority=18.0,
                ))

        # Second-pass renaming after LLM deobfuscation may have
        # introduced new identifiers worth renaming.
        if (iteration >= 6
                and "apply_renames" in self._available_actions
                and action_queue.success_count("apply_renames") == 1
                and action_queue.success_count("llm_deobfuscate") >= 1):
            recommendations.append(PlannedAction(
                action_name="apply_renames",
                confidence=0.60,
                reason="Second rename pass after LLM deobfuscation.",
                priority=19.5,
            ))

        # Re-extract strings after significant code changes.
        if (iteration >= 4
                and action_queue.success_count("extract_strings") == 1):
            total_code_changes = sum(
                action_queue.success_count(a) for a in [
                    "decode_base64", "decode_hex", "normalize_unicode",
                    "decrypt_strings", "unflatten_control_flow",
                    "constant_fold", "llm_deobfuscate",
                ]
            )
            if total_code_changes >= 2:
                recommendations.append(PlannedAction(
                    action_name="extract_strings",
                    confidence=0.70,
                    reason="Re-extracting strings after significant code changes.",
                    priority=17.0,
                ))

        # ── Multi-layer re-decode (supports 6+ encoding layers) ───────
        # After decoding succeeds, the decoded content may itself be
        # encoded.  Re-queue decode transforms when the code still
        # contains encoding signatures, even if the transform already ran.
        if iteration >= 2:
            _DECODE_RESCAN = {
                "analyze_dotnet_assembly": r"MZ.{58,400}PE\x00\x00",
                "decode_base64": r"[A-Za-z0-9+/\-_=]{40,}",
                "decode_hex": r"(?:\\x[0-9a-f]{2}){4,}",
                "decode_base32_base85": r"(?:[A-Z2-7]{16,}|<~[!-u]{4,}~>)",
                "try_xor_recovery": (
                    r"(?s)(?:\^|-bxor\b).{0,160}"
                    r"(?:\\x[0-9a-f]{2}|\[\s*(?:0x[0-9a-f]{1,2}|\d{1,3})"
                    r"(?:\s*,\s*(?:0x[0-9a-f]{1,2}|\d{1,3})){3,}\s*\])"
                ),
                "decode_js_encoder": (
                    r"""(?:(?:\[\s*['"]\w+['"]\s*\]\s*){1,4}\[\s*['"]constructor['"]\s*\]\s*\(|\$=~\[\];|\$=\{___:|ﾟДﾟ|ﾟωﾟ)"""
                ),
                "unpack_js_packer": (
                    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)"
                ),
                "decrypt_crypto": r"(?:AES|RC4|CryptoJS|Cipher|decrypt)",
                "powershell_decode": (
                    r"(?:-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}|"
                    r"(?:\[System\.Convert\]::|\[Convert\]::|Convert\.)FromBase64String\s*\(|"
                    r"\[System\.Text\.Encoding\]::(?:Unicode|UTF8)\.GetString\s*\(|"
                    r"`[A-Za-z]|-(?:replace|creplace)\b)"
                ),
                "python_decode": (
                    r"(?:\bexec\s*\(|\bcompile\s*\(|(?:base64\.)?b64decode\s*\(|"
                    r"\bzlib\.decompress\s*\(|\bmarshal\.loads\s*\(|\bcodecs\.decode\s*\()"
                ),
                "decode_python_serialization": r"(?:pickle|marshal)\.loads|\bzlib\.decompress\s*\(",
                "identify_string_resolver": (
                    r"""(?:\b\w+\s*\(\s*['"]0x[0-9a-f]+['"]\s*\)|"""
                    r"\.push\s*\(\s*\w+\.shift\s*\(|"
                    r"return\s+\w+\s*\[\s*(?:0x[0-9a-f]+|\d+|\w+)\s*\])"
                ),
            }
            for action, pattern in _DECODE_RESCAN.items():
                if action not in self._available_actions:
                    continue
                prev_successes = action_queue.success_count(action)
                # Allow up to 5 re-runs of each decoder for deep nesting
                if prev_successes < 1 or prev_successes >= 5:
                    continue
                if action_queue.failure_streak(action) >= 2:
                    continue  # recent failures mean it's no longer productive
                # Check if the code still contains patterns this decoder handles
                if pattern is not None:
                    import re as _re
                    if not _re.search(pattern, code, _re.IGNORECASE):
                        continue
                recommendations.append(PlannedAction(
                    action_name=action,
                    confidence=0.7,
                    reason=f"Re-decode pass {prev_successes + 1}: code still contains encoded patterns.",
                    priority=9.0 + prev_successes,  # gradually lower priority
                ))

        workspace_context = state.workspace_context if hasattr(state, "workspace_context") else {}
        prioritized_files = workspace_context.get("prioritized_files", [])
        suspicious_files = workspace_context.get("suspicious_files", [])
        entry_points = workspace_context.get("entry_points", [])
        remaining_frontier = workspace_context.get("remaining_frontier_paths", [])
        indexed_from_archive = bool(workspace_context.get("indexed_from_archive"))

        deterministic_progress = early_deterministic_progress
        preprocess_successes = action_queue.success_count("preprocess_source")
        decode_successes = sum(
            action_queue.success_count(action)
            for action in self._PHASE_DECODE
        )
        targeted_deterministic_pending = any(
            rec.action_name in (
                set(self._PHASE_DECODE)
                | set(self._PHASE_SIMPLIFY)
                | {"deobfuscate_workspace_files", "preprocess_source"}
            )
            for rec in recommendations
        )
        recent_failures = sum(
            1 for record in state.transform_history[-4:]
            if not record.success
        )
        evidence_score = (
            min(len(techniques), 3)
            + min(len(state.suspicious_apis), 3)
            + min(len(state.recovered_literals), 3)
            + min(len(state.imports), 2)
            + min(len(state.functions), 2)
            + min(len(state.strings), 2)
            + min(len(prioritized_files), 2)
            + min(len(suspicious_files), 2)
            + min(len(entry_points), 1)
            + min(len(remaining_frontier), 2)
        )
        hard_js_evidence = (
            evidence_score
            + min(int(round(js_hard_score)), 4)
            + min(len(js_hard_signals), 2)
        )
        beautified_minified_js = (
            self._looks_like_javascript(language, code)
            and preprocess_successes >= 1
            and "minified_code_beautification" in techniques
        )
        layered_signal_score = sum(
            1
            for flag in (
                len(techniques) >= 2,
                entropy_profile in ("encrypted", "heavily_obfuscated"),
                base64_hint,
                hex_hint,
                xor_hint,
                python_serial_hint,
                js_string_array_hint,
                js_encoder_hint,
                js_packer_hint,
                bool(suspicious_files or prioritized_files),
            )
            if flag
        )
        llm_stall = state_manager.stall_counter >= 2 or recent_failures >= 2

        # ── LLM-powered actions (when provider is available) ─────────
        has_llm = bool(
            {
                "llm_deobfuscate",
                "llm_multilayer_unwrap",
                "llm_rename",
                "llm_summarize",
            }.intersection(self._available_actions)
        )
        if has_llm:
            llm_deobfuscate_ready = (
                llm_stall
                or (
                    iteration >= 3
                    and deterministic_progress >= 1
                    and not targeted_deterministic_pending
                )
                or (
                    iteration >= 4
                    and evidence_score >= 5
                )
                or (
                    residual_score >= 2.8
                    and iteration >= 2
                    and deterministic_progress >= 1
                )
                or (
                    beautified_minified_js
                    and iteration >= 2
                    and (
                        residual_score >= 1.8
                        or evidence_score >= 4
                        or recent_failures >= 1
                    )
                )
                or (
                    js_hard_enabled
                    and iteration >= 2
                    and (
                        deterministic_progress >= 1
                        or residual_score >= 3.0
                        or js_hard_score >= 4.0
                    )
                    and hard_js_evidence >= 4
                )
                or (
                    workspace_mode
                    and indexed_from_archive
                    and iteration >= 3
                    and (
                        remaining_frontier
                        or action_queue.success_count("deobfuscate_workspace_files") >= 1
                    )
                    and (
                        deterministic_progress >= 1
                        or decode_successes >= 1
                        or llm_stall
                    )
                )
            )
            if (
                "llm_deobfuscate" in self._available_actions
                and llm_deobfuscate_ready
                and not action_queue.has_been_tried("llm_deobfuscate")
            ):
                llm_reason = "LLM-assisted deep deobfuscation after deterministic passes."
                if llm_stall:
                    llm_reason = "LLM-assisted recovery after deterministic passes stalled."
                elif beautified_minified_js:
                    llm_reason = (
                        "AI follow-up after minified JavaScript beautification "
                        "to recover semantics and naming."
                    )
                elif js_hard_enabled:
                    llm_reason = (
                        "JavaScript hard mode: escalate AI early for "
                        + ", ".join(sorted(js_hard_signals)[:3])
                        + "."
                    )
                elif residual_score >= 2.8 and residual_reasons:
                    llm_reason = (
                        "LLM-assisted recovery for residual obfuscation markers: "
                        + ", ".join(residual_reasons[:2])
                        + "."
                    )
                elif workspace_mode:
                    llm_reason = (
                        "LLM-assisted workspace deobfuscation across prioritized files."
                        if not indexed_from_archive else
                        "LLM-assisted workspace deobfuscation across prioritized files with full-archive hotspot context."
                    )
                recommendations.append(PlannedAction(
                    action_name="llm_deobfuscate",
                    confidence=0.88 if js_hard_enabled else 0.85 if workspace_mode else 0.8,
                    reason=llm_reason,
                    priority=12.2 if js_hard_enabled else 12.6 if workspace_mode else 13.0,
                ))

            multilayer_ready = (
                (
                    layered_signal_score >= 3
                    and iteration >= 3
                    and (decode_successes >= 1 or not targeted_deterministic_pending)
                )
                or (
                    llm_stall
                    and layered_signal_score >= 2
                )
                or (
                    residual_score >= 3.4
                    and iteration >= 2
                    and deterministic_progress >= 1
                )
                or (
                    beautified_minified_js
                    and iteration >= 2
                    and residual_score >= 2.2
                )
                or (
                    js_hard_enabled
                    and iteration >= 2
                    and (
                        js_hard_score >= 3.4
                        or len(js_hard_signals) >= 3
                        or (
                            "runtime_encoder_chains" in js_hard_signals
                            and decode_successes >= 1
                        )
                        or (
                            "string_array_wrappers" in js_hard_signals
                            and residual_score >= 2.6
                        )
                    )
                )
                or (
                    workspace_mode
                    and indexed_from_archive
                    and iteration >= 3
                    and (
                        layered_signal_score >= 2
                        or remaining_frontier
                    )
                    and (
                        decode_successes >= 1
                        or action_queue.success_count("deobfuscate_workspace_files") >= 1
                        or llm_stall
                    )
                )
            )
            if (
                "llm_multilayer_unwrap" in self._available_actions
                and multilayer_ready
                and not action_queue.has_been_tried("llm_multilayer_unwrap")
            ):
                multilayer_reason = (
                    "Multiple layered signals remain after deterministic decoding."
                    if not residual_reasons
                    else "Residual wrappers remain after deterministic decoding: "
                    + ", ".join(residual_reasons[:2])
                    + "."
                )
                if js_hard_enabled:
                    multilayer_reason = (
                        "JavaScript hard mode: layered wrappers remain after deterministic decoding."
                        if not residual_reasons
                        else "JavaScript hard mode: residual wrappers remain after deterministic decoding: "
                        + ", ".join(residual_reasons[:2])
                        + "."
                    )
                if workspace_mode:
                    multilayer_reason = (
                        "Workspace bundle may hide layered obfuscation across file boundaries."
                        if not indexed_from_archive else
                        "Workspace bundle may hide layered obfuscation across file boundaries; full-archive hotspot context is available."
                    )
                recommendations.append(PlannedAction(
                    action_name="llm_multilayer_unwrap",
                    confidence=0.84 if js_hard_enabled else 0.8 if workspace_mode else 0.75,
                    reason=multilayer_reason,
                    priority=12.8 if js_hard_enabled else 13.2 if workspace_mode else 13.5,
                ))

            rename_ready = (
                (
                    iteration >= 5
                    and evidence_score >= 4
                    and (
                        action_queue.success_count("apply_renames") >= 1
                        or action_queue.success_count("llm_deobfuscate") >= 1
                        or deterministic_progress >= 2
                    )
                )
                or (
                    js_hard_enabled
                    and iteration >= 3
                    and hard_js_evidence >= 4
                    and (
                        action_queue.success_count("apply_renames") >= 1
                        or action_queue.success_count("llm_deobfuscate") >= 1
                        or deterministic_progress >= 1
                    )
                )
            )
            if (
                "llm_rename" in self._available_actions
                and rename_ready
                and not action_queue.has_been_tried("llm_rename")
            ):
                recommendations.append(PlannedAction(
                    action_name="llm_rename",
                    confidence=0.78 if js_hard_enabled else 0.7,
                    reason=(
                        "LLM-assisted JSNice-style semantic renaming after structural recovery."
                        if js_hard_enabled else
                        "LLM-assisted semantic identifier renaming after structural recovery."
                    ),
                    priority=19.1 if js_hard_enabled else 19.5,
                ))

            summarizer_ready = (
                iteration >= 4
                and evidence_score >= 3
                and (
                    action_queue.success_count("extract_iocs") >= 1
                    or action_queue.success_count("generate_findings") >= 1
                    or llm_stall
                    or (
                        deterministic_progress >= 2
                        and not targeted_deterministic_pending
                    )
                )
            )
            if (
                "llm_summarize" in self._available_actions
                and summarizer_ready
                and not action_queue.has_been_tried("llm_summarize")
            ):
                recommendations.append(PlannedAction(
                    action_name="llm_summarize",
                    confidence=0.85,
                    reason="LLM-assisted behaviour analysis and threat assessment.",
                    priority=21.0,
                ))

        # Sort by priority.
        recommendations.sort(key=lambda r: r.priority)
        return recommendations


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Action Selector
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class ActionSelector:
    """Select the best action from planner recommendations."""

    def select(
        self,
        recommendations: List[PlannedAction],
        action_queue: ActionQueue,
        state_manager: StateManager,
    ) -> Optional[QueuedAction]:
        """Enqueue recommendations and return the best eligible action.

        Selection criteria:
        * Prefer actions not previously failed.
        * Prefer high-confidence deterministic transforms.
        * Avoid repeating actions that already succeeded (unless multi-pass).
        * Never select an action that has hit its attempt cap.
        """
        # Feed planner output into the queue.
        for rec in recommendations:
            action_queue.enqueue(
                rec.action_name,
                confidence=rec.confidence,
                reason=rec.reason,
                priority=rec.priority,
            )

        # Pop the best eligible action.
        return action_queue.dequeue()

    async def select_with_llm(
        self,
        recommendations: List[PlannedAction],
        action_queue: ActionQueue,
        state_manager: StateManager,
        llm_client: Any,
    ) -> Optional[QueuedAction]:
        """LLM-informed action selection from queued candidates.

        Asks the LLM to pick from the top pending candidates given the
        current state and recent history.  Falls back to greedy ``dequeue()``
        on any failure.
        """
        # Enqueue all recommendations first (same as deterministic)
        for rec in recommendations:
            action_queue.enqueue(
                rec.action_name,
                confidence=rec.confidence,
                reason=rec.reason,
                priority=rec.priority,
            )

        # Collect pending candidates
        pending = [
            a for a in action_queue._heap
            if a.status == ActionStatus.PENDING
        ]
        if len(pending) <= 1:
            return action_queue.dequeue()

        pending.sort()
        candidates = pending[:6]

        try:
            from app.services.transforms.llm_base import LLMTransform

            code_excerpt = Planner._planner_code_excerpt(
                state_manager.current_code,
                max_chars=2200,
            )
            confidence = state_manager.overall_confidence
            iteration = state_manager.current_iteration
            state_context = LLMTransform.build_state_context(
                state_manager.state.model_dump(),
                code=state_manager.current_code,
                compact=True,
            )

            history_lines = []
            for record in state_manager.state.transform_history[-8:]:
                status = "succeeded" if record.success else "failed"
                history_lines.append(
                    f"  {record.action}: {status} "
                    f"(conf_delta: {record.confidence_after - record.confidence_before:+.2f})"
                )
            history_str = "\n".join(history_lines) if history_lines else "  (none yet)"

            candidate_str = "\n".join(
                f"  {i+1}. {c.action_name} (priority={c.priority:.1f}, "
                f"confidence={c.confidence:.2f}, reason='{c.reason}')"
                for i, c in enumerate(candidates)
            )

            prompt = (
                "You are a deobfuscation pipeline controller. Given the current "
                "state, choose which transform to run next.\n\n"
                f"Iteration: {iteration}, Overall confidence: {confidence:.2f}\n\n"
                f"State summary:\n{state_context}\n\n"
                f"Recent transform history:\n{history_str}\n\n"
                f"Candidate actions (ranked by heuristic priority):\n{candidate_str}\n\n"
                f"Code excerpt ({len(state_manager.current_code)} chars total):\n"
                f"```\n{code_excerpt}\n```\n\n"
                "Respond with ONLY a JSON object:\n"
                '{"choice": <number 1-N>, "reason": "one sentence"}\n\n'
                "Pick the number most likely to make progress."
            )

            reply = await llm_client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=LLMTransform.compute_token_budget(len(code_excerpt), "select"),
            )

            parsed = _extract_planning_json(reply)
            if parsed and "choice" in parsed:
                choice_idx = int(parsed["choice"]) - 1
                if 0 <= choice_idx < len(candidates):
                    chosen = candidates[choice_idx]
                    logger.info(
                        "LLM selected action '%s': %s",
                        chosen.action_name,
                        parsed.get("reason", ""),
                    )
                    # Boost the chosen action's priority so dequeue picks it
                    chosen.priority = -999.0
                    return action_queue.dequeue()

            logger.debug("LLM selection returned invalid choice; falling back")
        except Exception:
            logger.exception("LLM action selection failed; falling back to greedy")

        return action_queue.dequeue()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Executor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class Executor:
    """Run a selected transform and capture results."""

    def __init__(self, action_space: Dict[str, BaseTransform]) -> None:
        self.action_space = action_space

    async def execute(
        self,
        action_name: str,
        code: str,
        language: str,
        state: dict,
    ) -> TransformResult:
        """Run the named transform.

        Returns a TransformResult.  On error, returns a failed result
        rather than raising.
        """
        transform = self.action_space.get(action_name)
        if transform is None:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description=f"Unknown action: {action_name}",
                details={"error": f"No transform registered for '{action_name}'"},
            )

        try:
            # Check applicability first.
            if not transform.can_apply(code, language, state):
                return TransformResult(
                    success=False,
                    output=code,
                    confidence=0.0,
                    description=f"Transform '{action_name}' is not applicable.",
                    details={"skipped": True},
                )

            # LLM transforms provide an async path; deterministic transforms
            # are synchronous and need to run in a thread executor.
            if getattr(transform, "is_llm", False) and hasattr(transform, "apply_async"):
                result = await transform.apply_async(code, language, state)
            else:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None,
                    transform.apply,
                    code,
                    language,
                    state,
                )
            return result

        except Exception as exc:
            logger.exception("Transform '%s' raised an exception", action_name)
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description=f"Transform '{action_name}' failed: {exc}",
                details={"error": str(exc)},
            )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Pre-flight Validator  (Stage 3)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@dataclass
class PreflightResult:
    """Outcome of a pre-flight validation check."""
    approved: bool
    skip_reason: str = ""


class PreflightValidator:
    """Validate preconditions before executing a transform.

    Checks:
    - Action exists in the action space.
    - Language compatibility (language-specific transforms aren't run on
      the wrong language).
    - Input isn't empty or below a minimum size.
    - Action hasn't already exceeded its retry cap.
    - Conflicting transforms aren't running back-to-back.
    """

    # Map of actions to the languages they apply to.
    # If an action isn't listed here, it's considered language-agnostic.
    _LANGUAGE_AFFINITY: Dict[str, Set[str]] = {
        "analyze_dotnet_assembly": {"dotnet"},
        "powershell_decode": {"powershell", "ps1", "ps"},
        "python_decode": {"python", "py"},
        "deobfuscate_js_bundle": {"javascript", "js", "jsx", "typescript", "ts", "tsx"},
        "identify_string_resolver": {"javascript", "js", "jsx", "typescript", "ts", "tsx"},
    }

    # Actions that shouldn't run back-to-back (no point re-running immediately).
    _CONFLICT_PAIRS: List[Tuple[str, str]] = [
        ("deobfuscate_workspace_files", "deobfuscate_workspace_files"),
        ("decode_base64", "decode_base64"),
        ("decode_hex", "decode_hex"),
        ("constant_fold", "constant_fold"),
        ("simplify_junk_code", "simplify_junk_code"),
        ("normalize_unicode", "normalize_unicode"),
        ("unflatten_control_flow", "unflatten_control_flow"),
        ("apply_renames", "apply_renames"),
        ("analyze_entropy", "analyze_entropy"),
        ("llm_deobfuscate", "llm_deobfuscate"),
        ("llm_rename", "llm_rename"),
        ("llm_summarize", "llm_summarize"),
        ("llm_multilayer_unwrap", "llm_multilayer_unwrap"),
    ]

    def validate(
        self,
        action_name: str,
        code: str,
        language: str,
        action_space: Dict[str, BaseTransform],
        action_queue: ActionQueue,
        state_manager: StateManager,
    ) -> PreflightResult:
        """Run all pre-flight checks.  Returns approved=True if the
        action should proceed, or approved=False with a skip reason."""

        # 1. Action must exist.
        if action_name not in action_space:
            return PreflightResult(
                approved=False,
                skip_reason=f"Action '{action_name}' not in action space.",
            )

        # 2. Input must have content.
        if not code or len(code.strip()) < 2:
            return PreflightResult(
                approved=False,
                skip_reason="Input code is empty or too short to analyse.",
            )

        # 3. Language compatibility.
        affinity = self._LANGUAGE_AFFINITY.get(action_name)
        if affinity and language.lower() not in affinity:
            return PreflightResult(
                approved=False,
                skip_reason=(
                    f"Action '{action_name}' requires language "
                    f"{affinity} but got '{language}'."
                ),
            )

        # 4. Retry cap — if the queue already capped this action, skip.
        if action_queue.is_capped(action_name):
            return PreflightResult(
                approved=False,
                skip_reason=f"Action '{action_name}' has hit its retry cap.",
            )

        # 5. Conflict pairs — check the most recent successful transform.
        history = state_manager.state.transform_history
        if history:
            last_action = history[-1].action
            for a, b in self._CONFLICT_PAIRS:
                if (last_action == a and action_name == b) or (
                    last_action == b and action_name == a
                ):
                    return PreflightResult(
                        approved=False,
                        skip_reason=(
                            f"Action '{action_name}' conflicts with the "
                            f"previous action '{last_action}'."
                        ),
                    )

        logger.debug("Pre-flight approved: %s", action_name)
        return PreflightResult(approved=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Post-processor  (Stage 5)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class PostProcessor:
    """Clean up transform output before it enters verification.

    Applies lightweight normalisation that no individual transform should
    need to handle:
    - Strip trailing whitespace on every line.
    - Normalise line endings to ``\\n``.
    - Collapse runs of 3+ blank lines into 2.
    - Remove null bytes and other non-printable control chars (except
      tab and newline).
    - Strip a leading UTF-8 BOM if present.
    - Ensure file ends with a single newline.
    """

    # Non-printable chars except \t (\x09) and \n (\x0a).
    _CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    _MULTI_BLANK_RE = re.compile(r"\n{4,}")
    _BOM = "\ufeff"

    def process(self, code: str, original: str) -> str:
        """Return cleaned-up code.  If the transform produced empty or
        identical output, returns the original unchanged."""
        if not code or not code.strip():
            return original

        # Strip BOM.
        if code.startswith(self._BOM):
            code = code[len(self._BOM):]

        # Remove dangerous control chars.
        code = self._CONTROL_RE.sub("", code)

        # Normalise line endings.
        code = code.replace("\r\n", "\n").replace("\r", "\n")

        # Strip trailing whitespace per line.
        lines = code.split("\n")
        lines = [line.rstrip() for line in lines]
        code = "\n".join(lines)

        # Collapse excessive blank lines.
        code = self._MULTI_BLANK_RE.sub("\n\n\n", code)

        # Ensure trailing newline.
        if not code.endswith("\n"):
            code += "\n"

        return code


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  State Reconciler  (Stage 7)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class StateReconciler:
    """Merge transform results into the canonical analysis state.

    Centralises the logic that was previously inline in the orchestrator
    loop.  Responsible for:
    - Extracting strings, IOCs, techniques, APIs, and literals from
      TransformResult details.
    - De-duplicating before adding to the state manager.
    - Recording the transform entry and updating code if successful.
    - Tracking queue feedback (succeeded / skipped / failed).
    - Updating stall counter.
    """

    def reconcile(
        self,
        action_name: str,
        selected: QueuedAction,
        result: TransformResult,
        improvement: float,
        code_before: str,
        iteration: int,
        state_manager: StateManager,
        action_queue: ActionQueue,
        stop_decision: StopDecision,
        all_iocs: List[IOC],
        confidence_fn: Any,
    ) -> TransformRecord:
        """Merge a single transform's output into the global state.

        Returns the TransformRecord that was persisted.
        """
        sm = state_manager

        # ── Apply structured details to state ──────────────────────
        self._apply_details(action_name, result, sm, all_iocs)

        # ── Confidence and readability ─────────────────────────────
        conf_before = sm.overall_confidence
        new_confidence = confidence_fn(conf_before, result, improvement)
        sm.update_confidence(overall=new_confidence)
        readability = sm.update_readability(result.output)

        # ── Create transform record ───────────────────────────────
        record = TransformRecord(
            iteration=iteration,
            action=action_name,
            reason=selected.reason,
            inputs={"code_length": len(code_before)},
            outputs={
                "code_length": len(result.output),
                "description": result.description,
            },
            confidence_before=conf_before,
            confidence_after=new_confidence,
            readability_before=(
                sm.readability_history[-2]
                if len(sm.readability_history) > 1
                else 0.0
            ),
            readability_after=readability,
            success=result.success,
            retry_revert=False,
        )
        sm.record_transform(
            record,
            new_code=result.output if result.success else None,
        )

        # ── Queue feedback ─────────────────────────────────────────
        is_skipped = (
            not result.success
            and result.details.get("skipped")
            or (not result.success and "error" not in result.details)
        )
        if result.success:
            action_queue.mark_succeeded(action_name)
            stop_decision.record_success()
        elif is_skipped:
            action_queue.mark_skipped(action_name)
        else:
            action_queue.mark_failed(action_name)
            stop_decision.record_failure()

        # ── Stall tracking ─────────────────────────────────────────
        # Decode transforms (base64, hex, XOR, PowerShell, Python) that
        # succeed should NOT count as stalls even if readability doesn't
        # improve — they're peeling layers and the next decode will benefit.
        _DECODE_ACTIONS = {
            "analyze_dotnet_assembly",
            "decode_base64", "decode_hex", "decode_base32_base85",
            "try_xor_recovery", "decrypt_crypto",
            "decode_js_encoder", "unpack_js_packer", "deobfuscate_js_bundle",
            "powershell_decode", "python_decode", "decrypt_strings",
            "normalize_unicode", "identify_string_resolver",
            "llm_multilayer_unwrap",
            "decode_python_serialization",
        }
        if improvement > 0.01:
            sm.reset_stall()
        elif result.success and action_name in _DECODE_ACTIONS:
            # Successful decode but low improvement — don't penalise,
            # the decoded content likely has more layers to peel.
            pass
        else:
            sm.increment_stall()

        return record

    # ── Detail extraction helpers ──────────────────────────────────

    @staticmethod
    def _apply_details(
        action_name: str,
        result: TransformResult,
        sm: StateManager,
        all_iocs: List[IOC],
    ) -> None:
        """Extract structured data from result.details into state."""
        details = result.details

        # Language detection.
        if action_name == "detect_language" and result.success:
            detected = details.get("detected_language") or details.get("detected")
            if detected:
                sm.set_language(detected)

        # Obfuscation techniques.
        techniques = details.get("detected_techniques", [])
        if techniques:
            sm.add_detected_techniques(techniques)

        direct_apis = details.get("suspicious_apis", [])
        if direct_apis:
            sm.add_suspicious_apis([str(item)[:160] for item in direct_apis[:30]])

        imports = details.get("imports", [])
        if imports:
            sm.add_imports([str(item)[:160] for item in imports[:80]])

        functions = details.get("functions", [])
        if functions:
            sm.add_functions([str(item)[:160] for item in functions[:80]])

        evidence_references = details.get("evidence_references", [])
        if evidence_references:
            existing_refs = set(sm.state.evidence_references)
            for ref in evidence_references[:80]:
                ref_str = str(ref)[:200]
                if ref_str and ref_str not in existing_refs:
                    sm.state.evidence_references.append(ref_str)
                    existing_refs.add(ref_str)

        workspace_context = details.get("workspace_context")
        if isinstance(workspace_context, dict):
            sm.merge_workspace_context(workspace_context)

        # Strings.
        raw_strings = details.get("strings", [])
        if raw_strings:
            entries = []
            for s in raw_strings:
                if isinstance(s, dict):
                    entries.append(StringEntry(
                        value=s.get("value", ""),
                        encoding=s.get("encoding", "utf-8"),
                        context=s.get("context"),
                    ))
                elif isinstance(s, StringEntry):
                    entries.append(s)
            sm.add_strings(entries)

        # Decoded strings (from base64, hex, etc.).
        decoded = details.get("decoded_strings", [])
        if not decoded:
            fallback_items = details.get("items", [])
            if isinstance(fallback_items, list):
                decoded = []
                for item in fallback_items:
                    if not isinstance(item, dict):
                        continue
                    if "decoded" in item:
                        decoded.append({
                            "encoded": item.get("encoded", item.get("format", "")),
                            "decoded": item.get("decoded", ""),
                        })
                    elif "plaintext" in item:
                        decoded.append({
                            "encoded": item.get("method", "decrypted_payload"),
                            "decoded": item.get("plaintext", ""),
                        })
        if decoded:
            entries = []
            for d in decoded:
                if isinstance(d, dict):
                    entries.append(StringEntry(
                        value=d.get("decoded", ""),
                        encoding="decoded",
                        context=d.get("encoded", "")[:80],
                    ))
            sm.add_strings(entries)

        # Recovered XOR blobs.
        recovered = details.get("recovered", [])
        if recovered:
            for r in recovered:
                if isinstance(r, dict):
                    sm.add_recovered_literals([r.get("decoded", "")])

        # Decoded PowerShell / Python payloads.
        decoded_payloads = details.get("decoded_payloads", [])
        if decoded_payloads:
            sm.add_recovered_literals(decoded_payloads)

        # IOCs.
        raw_iocs = details.get("iocs", [])
        for ioc_data in raw_iocs:
            if isinstance(ioc_data, dict):
                try:
                    ioc_type = IOCType(ioc_data.get("type", "other"))
                except ValueError:
                    ioc_type = IOCType.OTHER
                ioc = IOC(
                    type=ioc_type,
                    value=ioc_data.get("value", ""),
                    context=ioc_data.get("context"),
                    confidence=float(ioc_data.get("confidence", 0.5)),
                )
                all_iocs.append(ioc)

        # Suspicious patterns from eval/exec detector.
        patterns = details.get("patterns", {})
        if patterns and (
            action_name == "detect_eval_exec_reflection"
            or isinstance(patterns, dict)
        ):
            if isinstance(patterns, dict):
                pattern_names = list(patterns.keys())
            elif isinstance(patterns, list):
                pattern_names = [str(item)[:160] for item in patterns[:30]]
            else:
                pattern_names = [str(patterns)[:160]]
            sm.add_suspicious_apis(pattern_names)
            if "eval_exec" not in [
                t.lower() for t in sm.state.detected_techniques
            ]:
                sm.add_detected_techniques(["eval_exec"])

        # Rename suggestions (informational).
        suggestions = details.get("suggestions", {})
        if suggestions and isinstance(suggestions, dict):
            sm.state.llm_suggestions.extend(
                f"Rename '{old}' -> '{new}'"
                for old, new in list(suggestions.items())[:10]
            )
        elif suggestions and isinstance(suggestions, list):
            sm.state.llm_suggestions.extend(
                str(s)[:80] for s in suggestions[:10]
            )

        # Deterministic renamer applied renames.
        renames = details.get("renames", {})
        if renames and isinstance(renames, dict):
            sm.state.llm_suggestions.extend(
                f"Renamed '{old}' -> '{new}'"
                for old, new in list(renames.items())[:20]
            )

        # String decryptor results.
        decrypted_strings = details.get("decrypted_strings", [])
        if decrypted_strings:
            entries = []
            for d in decrypted_strings:
                if isinstance(d, dict):
                    entries.append(StringEntry(
                        value=d.get("decrypted", d.get("value", "")),
                        encoding="decrypted",
                        context=d.get("original", d.get("context", ""))[:80],
                    ))
                elif isinstance(d, str):
                    entries.append(StringEntry(
                        value=d,
                        encoding="decrypted",
                    ))
            sm.add_strings(entries)

        # Unicode normaliser results.
        unicode_decoded = details.get("unicode_decoded_count", 0)
        if unicode_decoded > 0:
            sm.state.llm_suggestions.append(
                f"Normalised {unicode_decoded} Unicode/hex escape sequences."
            )

        # Control flow unflattener results.
        dispatchers_found = details.get("dispatchers_found", 0)
        dispatchers_resolved = details.get("dispatchers_resolved", 0)
        if dispatchers_found > 0:
            sm.state.llm_suggestions.append(
                f"Found {dispatchers_found} CFF dispatchers, "
                f"resolved {dispatchers_resolved}."
            )

        # Entropy analysis metadata.
        entropy_profile = details.get("entropy_profile")
        if entropy_profile:
            sm.state.llm_suggestions.append(
                f"Entropy profile: {entropy_profile} "
                f"(overall: {details.get('overall_entropy', '?'):.2f} bits)"
            )
            high_regions = details.get("high_entropy_regions", [])
            if high_regions:
                sm.add_detected_techniques(["high_entropy_blob"])

        # ── LLM-specific detail extraction ────────────────────────

        # IOCs from LLM summarizer (uses "iocs_found" key).
        llm_iocs = details.get("iocs_found", [])
        for ioc_data in llm_iocs:
            if isinstance(ioc_data, dict):
                try:
                    ioc_type = IOCType(ioc_data.get("type", "other"))
                except ValueError:
                    ioc_type = IOCType.OTHER
                ioc = IOC(
                    type=ioc_type,
                    value=ioc_data.get("value", ""),
                    context=ioc_data.get("context"),
                    confidence=float(ioc_data.get("confidence", 0.7)),
                )
                all_iocs.append(ioc)

        # Hidden payloads from multi-layer unwrapper.
        hidden_payloads = details.get("hidden_payloads", [])
        if hidden_payloads:
            payload_strings = [
                str(p)[:500] for p in hidden_payloads[:10]
                if isinstance(p, str)
            ]
            if payload_strings:
                sm.add_recovered_literals(payload_strings)

        decoded_artifacts = details.get("decoded_artifacts", [])
        if decoded_artifacts:
            sm.add_recovered_literals(
                [str(item)[:500] for item in decoded_artifacts[:10]]
            )

        # LLM analysis metadata (capabilities, risk factors, etc.).
        capabilities = details.get("capabilities", [])
        if capabilities:
            sm.add_detected_techniques(
                [f"capability:{c}" for c in capabilities[:20]]
            )
        risk_factors = details.get("risk_factors", [])
        if risk_factors:
            sm.state.llm_suggestions.extend(
                f"Risk: {r}" for r in risk_factors[:10]
            )
        recommended_actions = details.get("recommended_actions", [])
        if recommended_actions:
            sm.state.llm_suggestions.extend(
                f"Action: {a}" for a in recommended_actions[:10]
            )
        uncertainties = details.get("remaining_uncertainties", [])
        if uncertainties:
            sm.state.llm_suggestions.extend(
                f"Uncertainty: {u}" for u in uncertainties[:10]
            )

        summary = details.get("summary")
        if summary:
            intent = details.get("intent", "unknown")
            severity = details.get("severity", "info")
            sm.set_summary(
                f"{summary} Intent={intent}; severity={severity}."
            )

        # LLM layers info (from multi-layer unwrapper).
        layers = details.get("layers", [])
        if layers:
            layer_types = [
                l.get("type", "unknown")
                for l in layers
                if isinstance(l, dict)
            ]
            if layer_types:
                sm.add_detected_techniques(layer_types)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _build_action_space(llm_client: Optional[Any] = None) -> Dict[str, BaseTransform]:
    """Build the action-name -> transform-instance mapping.

    Tries to import from ``app.services.transforms`` first.  Falls back
    to the inline implementations bundled in this module.  When an
    ``llm_client`` is provided, LLM-powered transforms are added.
    """
    # Mapping of action name -> (module_path, class_name).
    _EXTERNAL_MAP: Dict[str, Tuple[str, str]] = {
        "profile_workspace": ("app.services.transforms.workspace_profiler", "WorkspaceProfiler"),
        "preprocess_source": ("app.services.transforms.source_preprocessor", "SourcePreprocessor"),
        "deobfuscate_workspace_files": (
            "app.services.transforms.workspace_file_deobfuscator",
            "WorkspaceFileDeobfuscator",
        ),
        "detect_language": ("app.services.transforms.language_detector", "LanguageDetector"),
        "fingerprint_obfuscation": ("app.services.transforms.obfuscation_fingerprinter", "ObfuscationFingerprinter"),
        "extract_strings": ("app.services.transforms.string_extraction", "StringExtractor"),
        "analyze_dotnet_assembly": ("app.services.transforms.dotnet_assembly_analyzer", "DotNetAssemblyAnalyzer"),
        "decode_base64": ("app.services.transforms.base64_decoder", "Base64Decoder"),
        "decode_hex": ("app.services.transforms.hex_decoder", "HexDecoder"),
        "try_xor_recovery": ("app.services.transforms.xor_recovery", "XorRecovery"),
        "constant_fold": ("app.services.transforms.constant_folder", "ConstantFolder"),
        "recover_literals": ("app.services.transforms.literal_propagator", "LiteralPropagator"),
        "simplify_junk_code": ("app.services.transforms.junk_code", "JunkCodeRemover"),
        "detect_eval_exec_reflection": ("app.services.transforms.eval_detection", "EvalExecDetector"),
        "decode_js_encoder": ("app.services.transforms.javascript_encoder_decoder", "JavaScriptEncoderDecoder"),
        "unpack_js_packer": ("app.services.transforms.js_packer_unpacker", "JavaScriptPackerUnpacker"),
        "deobfuscate_js_bundle": ("app.services.transforms.javascript_bundle_deobfuscator", "JavaScriptBundleDeobfuscator"),
        "identify_string_resolver": ("app.services.transforms.js_resolvers", "JavaScriptArrayResolver"),
        "suggest_renames": ("app.services.transforms.rename_suggester", "RenameSuggester"),
        "extract_iocs": ("app.services.transforms.ioc_extractor", "IOCExtractor"),
        "powershell_decode": ("app.services.transforms.powershell_decoder", "PowerShellDecoder"),
        "python_decode": ("app.services.transforms.python_decoder", "PythonDecoder"),
        "generate_findings": ("app.services.transforms.findings_generator", "FindingsGeneratorTransform"),
        # ── New transforms ──
        "analyze_entropy": ("app.services.transforms.entropy_analyzer", "EntropyAnalyzer"),
        "normalize_unicode": ("app.services.transforms.unicode_normalizer", "UnicodeNormalizer"),
        "unflatten_control_flow": ("app.services.transforms.control_flow_unflattener", "ControlFlowUnflattener"),
        "apply_renames": ("app.services.transforms.deterministic_renamer", "DeterministicRenamer"),
        "decrypt_strings": ("app.services.transforms.string_decryptor", "StringDecryptor"),
        "decode_base32_base85": ("app.services.transforms.base32_base85_decoder", "Base32Base85Decoder"),
        "decrypt_crypto": ("app.services.transforms.crypto_decryptor", "CryptoDecryptor"),
        "resolve_reflection": ("app.services.transforms.reflection_resolver", "ReflectionResolver"),
        "decode_python_serialization": ("app.services.transforms.python_serialization_decoder", "PythonSerializationDecoder"),
    }

    # Inline fallbacks.
    _INLINE_MAP: Dict[str, Type[BaseTransform]] = {
        "detect_language": _LanguageDetector,
        "fingerprint_obfuscation": _ObfuscationFingerprinter,
        "extract_strings": _StringExtractor,
        "decode_base64": _Base64Decoder,
        "decode_hex": _HexDecoder,
        "try_xor_recovery": _XorRecovery,
        "constant_fold": _ConstantFolder,
        "recover_literals": _ConstantFolder,  # second pass
        "simplify_junk_code": _JunkCodeRemover,
        "detect_eval_exec_reflection": _EvalExecDetector,
        "identify_string_resolver": _JavaScriptArrayResolver,
        "suggest_renames": _RenameSuggester,
        "extract_iocs": _IOCExtractor,
        "powershell_decode": _PowerShellDecoder,
        "python_decode": _PythonDecoder,
        "generate_findings": _FindingsGeneratorTransform,
    }

    space: Dict[str, BaseTransform] = {}
    for action_name, (mod_path, cls_name) in _EXTERNAL_MAP.items():
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            space[action_name] = cls()
            logger.debug("Loaded external transform: %s from %s", cls_name, mod_path)
        except (ImportError, AttributeError):
            fallback_cls = _INLINE_MAP.get(action_name)
            if fallback_cls:
                space[action_name] = fallback_cls()
                logger.debug("Using inline fallback for: %s", action_name)

    # Ensure all inline-only actions are covered.
    for action_name, cls in _INLINE_MAP.items():
        if action_name not in space:
            space[action_name] = cls()

    # ── LLM-powered transforms (only when a client is available) ──
    if llm_client is not None:
        try:
            from app.services.transforms.llm_deobfuscator import LLMDeobfuscator
            from app.services.transforms.llm_renamer import LLMRenamer
            from app.services.transforms.llm_summarizer import LLMSummarizer
            from app.services.transforms.llm_multilayer import LLMMultiLayerUnwrapper

            space["llm_deobfuscate"] = LLMDeobfuscator(llm_client)
            space["llm_rename"] = LLMRenamer(llm_client)
            space["llm_summarize"] = LLMSummarizer(llm_client)
            space["llm_multilayer_unwrap"] = LLMMultiLayerUnwrapper(llm_client)
            logger.info(
                "Registered %d LLM-powered transforms",
                sum(1 for k in space if k.startswith("llm_")),
            )
        except Exception:
            logger.exception("Failed to load LLM transforms; continuing without them")

    return space


class Orchestrator:
    """Multi-pass agentic deobfuscation harness.

    Takes raw obfuscated code and produces meaningful deobfuscation
    results through iterative planning, execution, verification, and
    decision-making.  Works entirely in deterministic mode without an
    LLM connection.
    """

    def __init__(
        self,
        sample_id: str,
        original_code: str,
        language: Optional[str] = None,
        settings: Optional[Any] = None,
        db_session: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        analysis_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.sample_id = sample_id
        self.original_code = original_code
        self.language = language
        self.settings = settings
        self.db_session = db_session
        self.llm_client = llm_client
        self.analysis_metadata = analysis_metadata or {}

        # Sub-components initialised in run().
        self._state_manager: Optional[StateManager] = None
        self._action_queue: Optional[ActionQueue] = None
        self._planner: Optional[Planner] = None
        self._selector: Optional[ActionSelector] = None
        self._preflight: Optional[PreflightValidator] = None
        self._executor: Optional[Executor] = None
        self._post_processor: Optional[PostProcessor] = None
        self._verifier: Optional[Verifier] = None
        self._reconciler: Optional[StateReconciler] = None
        self._stop_decision: Optional[StopDecision] = None
        self._findings_gen: Optional[FindingsGenerator] = None

        # LLM intelligence tracking (bounded call budgets per analysis).
        self._reflected_this_analysis: bool = False
        self._llm_confidence_checks: int = 0
        _MAX_LLM_CONFIDENCE_CHECKS = 2

        # Action space registry (includes LLM transforms when client available).
        self.action_space: Dict[str, BaseTransform] = _build_action_space(llm_client)

    # ------------------------------------------------------------------
    #  Main entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        auto_approve_threshold: float = 0.85,
        min_confidence: float = 0.3,
        max_iterations: int = 20,
        stall_limit: int = 3,
        progress_callback: Optional[Callable[[int, int, str, float], None]] = None,
        stop_requested: Optional[Callable[[], bool]] = None,
        event_callback: Optional[Callable[[str, dict], None]] = None,
    ) -> AnalysisResult:
        """Execute the full multi-pass deobfuscation pipeline.

        Parameters
        ----------
        auto_approve_threshold:
            Confidence above which deterministic actions are auto-approved.
        min_confidence:
            Minimum confidence before the engine considers backtracking.
        max_iterations:
            Hard cap on the number of iterations.
        stall_limit:
            Number of consecutive no-improvement iterations before stopping.

        Returns
        -------
        AnalysisResult with deobfuscated code, findings, IOCs, etc.
        """
        start_time = time.monotonic()

        # Initialise sub-components (8 stages + findings).
        self._state_manager = StateManager(
            sample_id=self.sample_id,
            original_code=self.original_code,
            language=self.language,
            db_session=self.db_session,
        )
        if self.analysis_metadata:
            metadata = {
                str(key): value
                for key, value in self.analysis_metadata.items()
                if value not in (None, "", [], {})
            }
            if metadata:
                self._state_manager.state.iteration_state["sample_metadata"] = metadata

        initial_workspace_context = extract_workspace_context(self._state_manager.current_code)
        if initial_workspace_context:
            if self.analysis_metadata.get("content_kind") == "archive_bundle":
                initial_workspace_context["source_mode"] = "archive_bundle"
                if self.analysis_metadata.get("stored_file_path"):
                    initial_workspace_context["archive_source_available"] = True
            self._state_manager.merge_workspace_context(initial_workspace_context)
        self._action_queue = ActionQueue(
            auto_approve_threshold=auto_approve_threshold,
        )
        self._planner = Planner(
            available_actions=set(self.action_space.keys()),
            llm_client=self.llm_client,
        )
        self._selector = ActionSelector()
        self._preflight = PreflightValidator()
        self._executor = Executor(self.action_space)
        self._post_processor = PostProcessor()
        self._verifier = Verifier()
        self._reconciler = StateReconciler()
        self._stop_decision = StopDecision(
            max_iterations=max_iterations,
            stall_limit=stall_limit,
            min_confidence=min_confidence,
            llm_client=self.llm_client,
        )
        self._findings_gen = FindingsGenerator(language=self.language)

        # Collected IOCs across all iterations.
        all_iocs: List[IOC] = []

        preprocess_transform = self.action_space.get("preprocess_source")
        if preprocess_transform is not None and self._state_manager is not None and self._action_queue is not None:
            try:
                bootstrap_code = self._state_manager.current_code
                bootstrap_lang = self.language or ""
                if preprocess_transform.can_apply(bootstrap_code, bootstrap_lang, {}):
                    bootstrap_result = preprocess_transform.apply(bootstrap_code, bootstrap_lang, {})
                    if bootstrap_result.success and bootstrap_result.output != bootstrap_code:
                        readability_before = self._state_manager.readability_history[-1]
                        self._reconciler._apply_details(
                            "preprocess_source",
                            bootstrap_result,
                            self._state_manager,
                            all_iocs,
                        )
                        self._state_manager.current_code = bootstrap_result.output
                        readability_after = self._state_manager.update_readability(bootstrap_result.output)
                        self._state_manager.record_transform(
                            TransformRecord(
                                iteration=0,
                                action="preprocess_source",
                                reason="Bootstrap preprocessing before iterative analysis.",
                                inputs={"code_length": len(bootstrap_code)},
                                outputs={
                                    "code_length": len(bootstrap_result.output),
                                    "description": bootstrap_result.description,
                                },
                                confidence_before=0.0,
                                confidence_after=0.0,
                                readability_before=readability_before,
                                readability_after=readability_after,
                                success=True,
                                retry_revert=False,
                            ),
                            new_code=bootstrap_result.output,
                        )
                        self._action_queue.mark_succeeded("preprocess_source")
                    else:
                        self._action_queue.mark_skipped("preprocess_source")
            except Exception:
                logger.exception("Bootstrap preprocessing failed (non-critical)")

        logger.info(
            "Starting orchestration for sample %s (%d chars, language=%s)",
            self.sample_id,
            len(self._state_manager.current_code),
            self.language or "auto-detect",
        )

        stop_reason = "Completed normally."
        iterations_run = 0
        was_stopped = False

        def _emit(event_type: str, data: dict | None = None) -> None:
            """Emit a typed event to the analysis tracker if a callback is set."""
            if event_callback is not None:
                try:
                    event_callback(event_type, data or {})
                except Exception:
                    pass

        consecutive_stage_errors = 0
        _MAX_STAGE_ERRORS = 5  # abort if too many iterations fail entirely

        def _maybe_stop(stage: str) -> bool:
            nonlocal stop_reason, was_stopped
            if stop_requested is None or not stop_requested():
                return False
            was_stopped = True
            stop_reason = f"Stop requested by user during {stage}."
            logger.info(stop_reason)
            if self._state_manager is not None:
                self._state_manager.mark_stopped()
            if progress_callback is not None:
                pct = (
                    min((iterations_run / max_iterations) * 100.0, 99.0)
                    if max_iterations > 0 else 0.0
                )
                progress_callback(
                    iterations_run,
                    max_iterations,
                    "stop requested",
                    pct,
                )
            return True

        try:
            for _ in range(max_iterations):
                if _maybe_stop("iteration dispatch"):
                    break

                iteration = self._state_manager.advance_iteration()
                iterations_run = iteration
                code_before = self._state_manager.current_code
                language = self._state_manager.state.language or self.language or ""

                logger.debug("=== Iteration %d ===", iteration)

                # Report progress via callback if provided.
                if progress_callback is not None:
                    pct = (iteration / max_iterations) * 100.0
                    progress_callback(iteration, max_iterations,
                                      f"iteration {iteration}", pct)

                # ── Stage 1: Plan ────────────────────────────────────
                try:
                    if self._planner._llm_client is not None:
                        recommendations = await self._planner.plan_with_llm(
                            self._state_manager,
                            self._action_queue,
                        )
                    else:
                        recommendations = self._planner.plan(
                            self._state_manager,
                            self._action_queue,
                        )
                except Exception:
                    logger.exception("Planner failed at iteration %d", iteration)
                    recommendations = []

                logger.debug(
                    "Planner recommended %d action(s): %s",
                    len(recommendations),
                    [r.action_name for r in recommendations],
                )

                # ── LLM Obfuscation Classification (once, iteration 1) ──
                if (
                    iteration == 1
                    and self.llm_client is not None
                    and "llm_classification" not in self._state_manager.state.iteration_state
                ):
                    try:
                        classification = await self._planner.classify_obfuscation(
                            self._state_manager,
                        )
                        if classification:
                            self._state_manager.state.iteration_state["llm_classification"] = classification
                            for t_name in classification.get("priority_transforms", []):
                                self._action_queue.enqueue(
                                    t_name,
                                    confidence=0.88,
                                    reason=f"LLM classification: {classification.get('recommended_strategy', '')}",
                                    priority=6.0,
                                )
                            _emit("classification", {
                                "obfuscation_type": classification.get("obfuscation_type"),
                                "tools_identified": classification.get("tools_identified", []),
                                "layers": classification.get("layers", []),
                                "recommended_strategy": classification.get("recommended_strategy"),
                                "confidence": classification.get("confidence"),
                            })
                    except Exception:
                        logger.exception("LLM classification failed (non-critical)")

                # ── Stage 2: Select ──────────────────────────────────
                try:
                    if (
                        self.llm_client is not None
                        and iteration >= 2
                        and self._action_queue.pending_count >= 3
                    ):
                        selected = await self._selector.select_with_llm(
                            recommendations,
                            self._action_queue,
                            self._state_manager,
                            self.llm_client,
                        )
                    else:
                        selected = self._selector.select(
                            recommendations,
                            self._action_queue,
                            self._state_manager,
                        )
                except Exception:
                    logger.exception("Selector failed at iteration %d", iteration)
                    selected = None

                if selected is None:
                    # Nothing to do -- check stop conditions.
                    verdict = self._stop_decision.evaluate(
                        self._state_manager,
                        self._action_queue,
                        last_transform_success=True,
                        improvement_score=0.0,
                    )
                    stop_reason = verdict.reason
                    if verdict.action == StopAction.STOP:
                        logger.info("Stopping: %s", stop_reason)
                        break
                    # Force generate_findings if nothing else to do.
                    self._action_queue.enqueue(
                        "generate_findings",
                        confidence=0.95,
                        reason="Fallback: generate final findings.",
                    )
                    selected = self._action_queue.dequeue()
                    if selected is None:
                        stop_reason = "No actions available."
                        break

                action_name = selected.action_name
                logger.info(
                    "Iteration %d: executing '%s' (confidence=%.2f, reason='%s')",
                    iteration,
                    action_name,
                    selected.confidence,
                    selected.reason,
                )

                if _maybe_stop(f"iteration {iteration} before executing {action_name}"):
                    break

                # ── Stage 3: Pre-flight ──────────────────────────────
                try:
                    preflight = self._preflight.validate(
                        action_name,
                        code_before,
                        language,
                        self.action_space,
                        self._action_queue,
                        self._state_manager,
                    )
                except Exception:
                    logger.exception(
                        "Pre-flight validation crashed for '%s'", action_name,
                    )
                    # Treat as approved — let the executor handle errors.
                    preflight = PreflightResult(approved=True)

                if not preflight.approved:
                    logger.info(
                        "Pre-flight rejected '%s': %s",
                        action_name,
                        preflight.skip_reason,
                    )
                    self._action_queue.mark_skipped(action_name)
                    continue

                # ── Stage 4: Execute ─────────────────────────────────
                try:
                    state_dict = self._state_manager.state.model_dump()
                except Exception:
                    logger.exception("Failed to serialise state for executor")
                    state_dict = {}

                result = await self._executor.execute(
                    action_name,
                    code_before,
                    language,
                    state_dict,
                )

                # ── Stage 5: Post-process ────────────────────────────
                try:
                    if result.success and result.output != code_before:
                        cleaned = self._post_processor.process(
                            result.output, code_before,
                        )
                        if cleaned != result.output:
                            logger.debug(
                                "Post-processor normalised output "
                                "(%d -> %d chars)",
                                len(result.output),
                                len(cleaned),
                            )
                            result = TransformResult(
                                success=result.success,
                                output=cleaned,
                                confidence=result.confidence,
                                description=result.description,
                                details=result.details,
                            )
                except Exception:
                    logger.exception(
                        "Post-processor failed; using raw executor output",
                    )
                    # result stays as-is from executor — safe to continue

                # ── Stage 6: Verify / Score ──────────────────────────
                try:
                    improvement = self._verifier.verify(
                        code_before,
                        result.output,
                        result,
                        self._state_manager,
                    )
                except Exception:
                    logger.exception("Verifier failed; assuming zero improvement")
                    improvement = 0.0

                # ── Stage 7: State Reconciler ────────────────────────
                try:
                    self._reconciler.reconcile(
                        action_name=action_name,
                        selected=selected,
                        result=result,
                        improvement=improvement,
                        code_before=code_before,
                        iteration=iteration,
                        state_manager=self._state_manager,
                        action_queue=self._action_queue,
                        stop_decision=self._stop_decision,
                        all_iocs=all_iocs,
                        confidence_fn=self._compute_new_confidence,
                    )
                    consecutive_stage_errors = 0  # reconciler OK
                except Exception:
                    logger.exception(
                        "State reconciler failed at iteration %d; "
                        "marking action as failed and continuing",
                        iteration,
                    )
                    # Ensure queue doesn't re-pick this broken action.
                    try:
                        self._action_queue.mark_failed(action_name)
                        self._stop_decision.record_failure()
                    except Exception:
                        pass
                    consecutive_stage_errors += 1
                    if consecutive_stage_errors >= _MAX_STAGE_ERRORS:
                        stop_reason = (
                            f"Aborting: {_MAX_STAGE_ERRORS} consecutive "
                            f"stage errors."
                        )
                        logger.error(stop_reason)
                        break
                    continue

                if _maybe_stop(f"iteration {iteration} after {action_name}"):
                    break

                # Update orchestrator-level language if detect succeeded.
                if action_name == "detect_language" and result.success:
                    detected = (
                        result.details.get("detected_language")
                        or result.details.get("detected")
                    )
                    if detected:
                        self.language = detected

                # Take snapshot (non-fatal if it fails).
                try:
                    self._state_manager.take_snapshot()
                    await self._state_manager.persist_snapshot()
                except Exception:
                    logger.exception(
                        "Failed to persist snapshot at iteration %d; "
                        "continuing without snapshot",
                        iteration,
                    )

                # ── LLM Reflection on failure ──────────────────────
                if (
                    not result.success
                    and self.llm_client is not None
                    and self._state_manager.stall_counter >= 2
                    and not self._reflected_this_analysis
                ):
                    try:
                        reflections = await self._planner.reflect_on_failure(
                            action_name,
                            result,
                            self._state_manager,
                            self._action_queue,
                        )
                        for alt in reflections:
                            self._action_queue.enqueue(
                                alt.action_name,
                                confidence=alt.confidence,
                                reason=alt.reason,
                                priority=alt.priority,
                            )
                        if reflections:
                            self._state_manager.reset_stall()
                            logger.info(
                                "LLM reflection enqueued %d alternative(s)",
                                len(reflections),
                            )
                            _emit("reflection", {
                                "failed_action": action_name,
                                "alternatives": [a.action_name for a in reflections],
                            })
                        self._reflected_this_analysis = True
                    except Exception:
                        logger.exception("LLM reflection failed (non-critical)")

                # ── LLM Confidence Assessment ─────────────────────
                if (
                    result.success
                    and self.llm_client is not None
                    and self._llm_confidence_checks < 2
                    and action_name in (
                        "llm_deobfuscate", "llm_multilayer_unwrap", "llm_rename",
                    )
                ):
                    try:
                        llm_scores = await self._llm_assess_confidence(
                            self._state_manager.current_code,
                            self._state_manager,
                        )
                        if llm_scores:
                            self._llm_confidence_checks += 1
                            current = self._state_manager.overall_confidence
                            llm_overall = llm_scores["overall"]
                            blended = current * 0.6 + llm_overall * 0.4
                            self._state_manager.update_confidence(
                                overall=blended,
                                naming=llm_scores.get("naming"),
                                structure=llm_scores.get("structure"),
                                strings=llm_scores.get("strings"),
                            )
                            logger.info(
                                "LLM confidence: heuristic=%.2f, llm=%.2f, blended=%.2f",
                                current, llm_overall, blended,
                            )
                            _emit("confidence_update", {
                                "heuristic": round(current, 3),
                                "llm": round(llm_overall, 3),
                                "blended": round(blended, 3),
                                "naming": llm_scores.get("naming"),
                                "structure": llm_scores.get("structure"),
                                "strings": llm_scores.get("strings"),
                            })
                    except Exception:
                        logger.exception("LLM confidence assessment failed (non-critical)")

                # ── Feedback-driven replanning ──────────────────────
                # After a successful transform with meaningful
                # improvement, re-plan to discover newly exposed
                # patterns without waiting for the next full cycle.
                residual_after = _residual_obfuscation_markers(
                    self._state_manager.current_code,
                    self._state_manager.state.language,
                    self._state_manager.state,
                )
                should_feedback_replan = (
                    result.success
                    and (
                        improvement > 0.05
                        or (
                            improvement > 0.01
                            and residual_after["has_residual"]
                        )
                    )
                )
                if should_feedback_replan:
                    try:
                        logger.info(
                            "Feedback: significant improvement (%.3f), "
                            "re-planning...",
                            improvement,
                        )
                        if self._planner._llm_client is not None:
                            feedback_recs = await self._planner.plan_with_llm(
                                self._state_manager,
                                self._action_queue,
                            )
                        else:
                            feedback_recs = self._planner.plan(
                                self._state_manager,
                                self._action_queue,
                            )
                        enqueued_count = 0
                        for rec in feedback_recs:
                            added = self._action_queue.enqueue(
                                rec.action_name,
                                confidence=rec.confidence,
                                reason=f"[feedback] {rec.reason}",
                                priority=rec.priority,
                            )
                            if added:
                                enqueued_count += 1
                        if enqueued_count:
                            logger.info(
                                "Feedback replanning enqueued %d new action(s)",
                                enqueued_count,
                            )
                    except Exception:
                        logger.exception(
                            "Feedback replanning failed at iteration %d; "
                            "continuing normally",
                            iteration,
                        )

                # ── Stage 8: Stop Decision ───────────────────────────
                try:
                    verdict = self._stop_decision.evaluate(
                        self._state_manager,
                        self._action_queue,
                        last_transform_success=result.success,
                        improvement_score=improvement,
                    )
                except Exception:
                    logger.exception("Stop decision failed; defaulting to CONTINUE")
                    verdict = StopVerdict(
                        action=StopAction.CONTINUE,
                        reason="Stop decision error; continuing.",
                    )

                logger.debug(
                    "Stop decision: %s (%s)",
                    verdict.action.value,
                    verdict.reason,
                )

                if verdict.action == StopAction.STOP:
                    stop_reason = verdict.reason
                    logger.info("Stopping: %s", stop_reason)
                    break
                elif verdict.action == StopAction.BACKTRACK:
                    logger.info("Backtracking: %s", verdict.reason)
                    try:
                        self._state_manager.rollback()
                        self._state_manager.reset_stall()
                    except Exception:
                        logger.exception("Rollback failed; continuing forward")
                    stop_reason = verdict.reason
                elif verdict.action == StopAction.RETRY:
                    logger.info("Retry mode: %s", verdict.reason)
            else:
                stop_reason = f"Maximum iterations reached ({max_iterations})."

        except Exception:
            logger.exception("Orchestrator encountered an unhandled error")
            stop_reason = "Unhandled error during orchestration."

        # ── Final findings generation ────────────────────────────────
        try:
            findings = self._findings_gen.generate(
                self._state_manager.state,
                self._state_manager.current_code,
                iocs=all_iocs,
            )
        except Exception:
            logger.exception("Findings generation failed")
            findings = []

        # Build summary.
        self._state_manager.set_summary(
            self._build_summary(findings, all_iocs, iterations_run, stop_reason)
        )
        self._state_manager.mark_stopped()

        elapsed = time.monotonic() - start_time
        logger.info(
            "Orchestration complete for sample %s: %d iterations, "
            "confidence=%.2f, %d findings, %d IOCs, %.1fs elapsed",
            self.sample_id,
            iterations_run,
            self._state_manager.overall_confidence,
            len(findings),
            len(all_iocs),
            elapsed,
        )

        return AnalysisResult(
            sample_id=self.sample_id,
            success=True,
            original_code=self.original_code,
            deobfuscated_code=self._state_manager.current_code,
            language=self._state_manager.state.language or self.language,
            iterations=iterations_run,
            findings=findings,
            iocs=all_iocs,
            strings=list(self._state_manager.state.strings),
            transform_history=list(self._state_manager.state.transform_history),
            state=self._state_manager.state.model_copy(deep=True),
            confidence=self._state_manager.overall_confidence,
            stop_reason=stop_reason,
            elapsed_seconds=elapsed,
            was_stopped=was_stopped,
        )

    # ------------------------------------------------------------------
    #  Internal helpers
    # ------------------------------------------------------------------

    def _compute_new_confidence(
        self,
        current: float,
        result: TransformResult,
        improvement: float,
    ) -> float:
        """Compute the updated overall confidence score."""
        if not result.success:
            # Slight decay on failure, but never below current.
            return max(current - 0.02, 0.0)

        # Blend current confidence with the transform's confidence and
        # the improvement score.
        sink_bonus = 0.0
        identified_sinks = (result.details or {}).get("identified_sinks", [])
        if isinstance(identified_sinks, list) and identified_sinks:
            high = sum(
                1
                for item in identified_sinks[:12]
                if isinstance(item, dict)
                and str(item.get("severity", "")).lower() == "high"
            )
            sink_bonus = min(0.08, 0.025 + high * 0.015)

        delta = improvement * 0.3 + result.confidence * 0.1 + sink_bonus
        new = current + delta
        # Clamp to [0, 1].
        return max(0.0, min(1.0, new))

    async def _llm_assess_confidence(
        self,
        code: str,
        state_manager: StateManager,
    ) -> Optional[Dict[str, float]]:
        """Ask the LLM to assess deobfuscation quality.

        Returns a dict with overall, naming, structure, strings scores
        (each 0.0-1.0), or None on any failure.  Called at most twice
        per analysis after a major LLM transform succeeds.
        """
        if self.llm_client is None:
            return None

        try:
            from app.services.transforms.llm_base import LLMTransform

            excerpt = code[:3000] if len(code) > 3000 else code
            techniques = list(state_manager.state.detected_techniques)[:10]

            prompt = (
                "You are an expert code analyst. Rate the deobfuscation quality "
                "of this code on a 0.0-1.0 scale.\n\n"
                f"Detected obfuscation techniques: {techniques}\n\n"
                f"Code:\n```\n{excerpt}\n```\n\n"
                "Respond with ONLY a JSON object:\n"
                "{\n"
                '  "overall": 0.0,\n'
                '  "naming": 0.0,\n'
                '  "structure": 0.0,\n'
                '  "strings": 0.0,\n'
                '  "assessment": "one sentence summary"\n'
                "}\n\n"
                "Scoring: 0.0-0.2=heavily obfuscated, 0.3-0.5=partially readable, "
                "0.6-0.7=mostly readable, 0.8-0.9=well deobfuscated, 1.0=clean code."
            )

            reply = await self.llm_client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=LLMTransform.compute_token_budget(len(excerpt), "confidence"),
            )

            parsed = _extract_planning_json(reply)
            if parsed is None:
                return None

            scores: Dict[str, float] = {}
            for key in ("overall", "naming", "structure", "strings"):
                raw = parsed.get(key)
                if isinstance(raw, (int, float)):
                    scores[key] = max(0.0, min(1.0, float(raw)))
                else:
                    return None

            assessment = parsed.get("assessment", "")
            if assessment:
                logger.info("LLM confidence assessment: %s", assessment[:150])

            return scores

        except Exception:
            logger.exception("LLM confidence assessment failed (non-critical)")
            return None

    @staticmethod
    def _build_summary(
        findings: List[Finding],
        iocs: List[IOC],
        iterations: int,
        stop_reason: str,
    ) -> str:
        """Build a human-readable summary."""
        parts = [
            f"Analysis completed in {iterations} iteration(s).",
            f"Stop reason: {stop_reason}",
        ]
        if findings:
            crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in findings if f.severity == Severity.HIGH)
            med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in findings if f.severity in (Severity.LOW, Severity.INFO))
            parts.append(
                f"Findings: {len(findings)} total "
                f"({crit} critical, {high} high, {med} medium, {low} low/info)."
            )
        if iocs:
            parts.append(f"IOCs extracted: {len(iocs)}.")
        return " ".join(parts)
