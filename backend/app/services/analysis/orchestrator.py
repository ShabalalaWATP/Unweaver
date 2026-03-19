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

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Type

from app.models.schemas import (
    AnalysisState,
    Finding,
    IOC,
    IOCType,
    Severity,
    StringEntry,
    TransformRecord,
)
from app.services.analysis.action_queue import ActionQueue, QueuedAction
from app.services.analysis.findings_generator import FindingsGenerator
from app.services.analysis.state_manager import StateManager
from app.services.transforms.base import BaseTransform, TransformResult

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
    """Evaluate stopping conditions after each iteration."""

    def __init__(
        self,
        max_iterations: int = 20,
        stall_limit: int = 3,
        min_confidence: float = 0.3,
        max_consecutive_failures: int = 4,
        sufficiency_threshold: float = 0.85,
    ) -> None:
        self.max_iterations = max_iterations
        self.stall_limit = stall_limit
        self.min_confidence = min_confidence
        self.max_consecutive_failures = max_consecutive_failures
        self.sufficiency_threshold = sufficiency_threshold
        self._consecutive_failures: int = 0

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
            peeked = action_queue.peek()
            if peeked and peeked.confidence >= 0.7:
                return StopVerdict(
                    StopAction.CONTINUE,
                    "Stalled, but high-confidence action available.",
                )
            return StopVerdict(
                StopAction.STOP,
                f"Improvement stalled for {stall} consecutive iterations.",
            )

        # 5. Queue empty.
        if action_queue.is_empty:
            return StopVerdict(
                StopAction.STOP,
                "Action queue exhausted; no more transforms to try.",
            )

        # 6. Sufficiently deobfuscated.
        if confidence >= self.sufficiency_threshold:
            return StopVerdict(
                StopAction.STOP,
                f"Code sufficiently deobfuscated (confidence {confidence:.2f}).",
            )

        # 7. Last action failed -> consider retry or continue.
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
        """
        if code_before == code_after and not result.details:
            return 0.0

        scores: List[Tuple[float, float]] = []  # (weight, score)

        # 1. Readability delta.
        read_before = StateManager._estimate_readability(code_before)
        read_after = StateManager._estimate_readability(code_after)
        read_delta = read_after - read_before
        scores.append((0.25, read_delta))

        # 2. Length change (shorter is usually better for deobfuscation).
        if len(code_before) > 0:
            len_ratio = (len(code_before) - len(code_after)) / len(code_before)
            # Moderate shrinkage is good; extreme shrinkage might be data loss.
            if 0 < len_ratio < 0.5:
                len_score = len_ratio
            elif len_ratio >= 0.5:
                len_score = 0.5 - (len_ratio - 0.5)  # penalise drastic cuts
            else:
                len_score = len_ratio * 0.5  # mild penalty for growth
            scores.append((0.15, len_score))

        # 3. String recovery.
        new_strings = result.details.get("strings", [])
        decoded_strings = result.details.get("decoded_strings", [])
        recovered = result.details.get("recovered", [])
        string_count = len(new_strings) + len(decoded_strings) + len(recovered)
        if string_count > 0:
            scores.append((0.25, min(string_count * 0.1, 0.5)))

        # 4. IOC extraction.
        iocs = result.details.get("iocs", [])
        if iocs:
            scores.append((0.15, min(len(iocs) * 0.1, 0.5)))

        # 5. Transform confidence as a signal.
        scores.append((0.20, result.confidence * 0.5))

        # Weighted sum.
        total_weight = sum(w for w, _ in scores)
        if total_weight == 0:
            return 0.0
        improvement = sum(w * s for w, s in scores) / total_weight

        # Regression check: if code actually got worse.
        if read_after < read_before * 0.8 and not string_count:
            improvement = min(improvement, -0.1)

        return max(-1.0, min(1.0, improvement))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Planner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@dataclass
class PlannedAction:
    """A single action recommended by the planner."""
    action_name: str
    confidence: float
    reason: str
    priority: float = 0.0  # lower = sooner


class Planner:
    """Inspect current state and recommend next actions.

    The planner runs purely deterministic heuristics.
    """

    # Ordered plan templates by analysis phase.
    _PHASE_INITIAL: List[str] = [
        "detect_language",
        "fingerprint_obfuscation",
        "extract_strings",
    ]
    _PHASE_DECODE: List[str] = [
        "decode_base64",
        "decode_hex",
        "try_xor_recovery",
        "powershell_decode",
        "python_decode",
        "identify_string_resolver",
    ]
    _PHASE_SIMPLIFY: List[str] = [
        "constant_fold",
        "simplify_junk_code",
        "detect_eval_exec_reflection",
    ]
    _PHASE_FINAL: List[str] = [
        "recover_literals",
        "suggest_renames",
        "extract_iocs",
        "generate_findings",
    ]

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

        recommendations: List[PlannedAction] = []

        # Phase 1: Initial reconnaissance.
        if iteration <= 1:
            for i, action in enumerate(self._PHASE_INITIAL):
                if not action_queue.has_been_tried(action):
                    recommendations.append(PlannedAction(
                        action_name=action,
                        confidence=0.95,
                        reason="Initial reconnaissance phase.",
                        priority=float(i),
                    ))

        # Phase 2: Decoding -- driven by detected techniques.
        techniques = set(t.lower().replace(" ", "_") for t in state.detected_techniques)
        if "base64_encoding" in techniques and not action_queue.success_count("decode_base64"):
            recommendations.append(PlannedAction(
                action_name="decode_base64",
                confidence=0.9,
                reason="Base64 encoding detected.",
                priority=10.0,
            ))
        if "hex_encoding" in techniques and not action_queue.success_count("decode_hex"):
            recommendations.append(PlannedAction(
                action_name="decode_hex",
                confidence=0.85,
                reason="Hex encoding detected.",
                priority=11.0,
            ))
        if "xor_encryption" in techniques and not action_queue.success_count("try_xor_recovery"):
            recommendations.append(PlannedAction(
                action_name="try_xor_recovery",
                confidence=0.6,
                reason="XOR encryption patterns detected.",
                priority=12.0,
            ))
        if language in ("powershell", "ps1", "ps"):
            if not action_queue.success_count("powershell_decode"):
                recommendations.append(PlannedAction(
                    action_name="powershell_decode",
                    confidence=0.85,
                    reason="PowerShell code detected.",
                    priority=10.5,
                ))
        if language in ("python", "py"):
            if not action_queue.success_count("python_decode"):
                recommendations.append(PlannedAction(
                    action_name="python_decode",
                    confidence=0.8,
                    reason="Python code detected.",
                    priority=10.5,
                ))
        if "array_indexing" in techniques or "char_code_construction" in techniques:
            if not action_queue.success_count("identify_string_resolver"):
                recommendations.append(PlannedAction(
                    action_name="identify_string_resolver",
                    confidence=0.75,
                    reason="Array/char-code string obfuscation detected.",
                    priority=11.0,
                ))

        # Phase 3: Simplification.
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

        # Phase 4: Final passes -- always suggest if not done.
        # But only after at least a few iterations.
        if iteration >= 3:
            for i, action in enumerate(self._PHASE_FINAL):
                if not action_queue.success_count(action):
                    recommendations.append(PlannedAction(
                        action_name=action,
                        confidence=0.7 if action != "generate_findings" else 0.95,
                        reason="Final analysis pass.",
                        priority=20.0 + i,
                    ))

        # If nothing was recommended but we are still early, schedule a broad
        # decoding sweep.
        if not recommendations and iteration < 10:
            for action in self._PHASE_DECODE:
                if not action_queue.has_been_tried(action):
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
                    confidence=0.7,
                    reason="Second-pass constant folding after decoding.",
                    priority=18.0,
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

            # Run the transform.  Since BaseTransform.apply is synchronous,
            # we run it in the default executor to avoid blocking the loop.
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
        "powershell_decode": {"powershell", "ps1", "ps"},
        "python_decode": {"python", "py"},
        "identify_string_resolver": {"javascript", "js", "typescript", "ts"},
    }

    # Actions that shouldn't run back-to-back (no point re-running immediately).
    _CONFLICT_PAIRS: List[Tuple[str, str]] = [
        ("decode_base64", "decode_base64"),
        ("decode_hex", "decode_hex"),
        ("constant_fold", "constant_fold"),
        ("simplify_junk_code", "simplify_junk_code"),
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
        if improvement > 0.01:
            sm.reset_stall()
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
            detected = details.get("detected_language")
            if detected:
                sm.set_language(detected)

        # Obfuscation techniques.
        techniques = details.get("detected_techniques", [])
        if techniques:
            sm.add_detected_techniques(techniques)

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
        if patterns:
            sm.add_suspicious_apis(list(patterns.keys()))
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _build_action_space() -> Dict[str, BaseTransform]:
    """Build the action-name -> transform-instance mapping.

    Tries to import from ``app.services.transforms`` first.  Falls back
    to the inline implementations bundled in this module.
    """
    # Mapping of action name -> (module_path, class_name).
    _EXTERNAL_MAP: Dict[str, Tuple[str, str]] = {
        "detect_language": ("app.services.transforms.language_detector", "LanguageDetector"),
        "fingerprint_obfuscation": ("app.services.transforms.obfuscation_fingerprinter", "ObfuscationFingerprinter"),
        "extract_strings": ("app.services.transforms.string_extractor", "StringExtractor"),
        "decode_base64": ("app.services.transforms.base64_decoder", "Base64Decoder"),
        "decode_hex": ("app.services.transforms.hex_decoder", "HexDecoder"),
        "try_xor_recovery": ("app.services.transforms.xor_recovery", "XorRecovery"),
        "constant_fold": ("app.services.transforms.constant_folder", "ConstantFolder"),
        "simplify_junk_code": ("app.services.transforms.junk_code_remover", "JunkCodeRemover"),
        "detect_eval_exec_reflection": ("app.services.transforms.eval_exec_detector", "EvalExecDetector"),
        "identify_string_resolver": ("app.services.transforms.js_array_resolver", "JavaScriptArrayResolver"),
        "suggest_renames": ("app.services.transforms.rename_suggester", "RenameSuggester"),
        "extract_iocs": ("app.services.transforms.ioc_extractor", "IOCExtractor"),
        "powershell_decode": ("app.services.transforms.powershell_decoder", "PowerShellDecoder"),
        "python_decode": ("app.services.transforms.python_decoder", "PythonDecoder"),
        "generate_findings": ("app.services.transforms.findings_generator", "FindingsGeneratorTransform"),
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
    ) -> None:
        self.sample_id = sample_id
        self.original_code = original_code
        self.language = language
        self.settings = settings
        self.db_session = db_session

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

        # Action space registry.
        self.action_space: Dict[str, BaseTransform] = _build_action_space()

    # ------------------------------------------------------------------
    #  Main entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        auto_approve_threshold: float = 0.85,
        min_confidence: float = 0.3,
        max_iterations: int = 20,
        stall_limit: int = 3,
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
        self._action_queue = ActionQueue(
            auto_approve_threshold=auto_approve_threshold,
        )
        self._planner = Planner()
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
        )
        self._findings_gen = FindingsGenerator(language=self.language)

        # Collected IOCs across all iterations.
        all_iocs: List[IOC] = []

        logger.info(
            "Starting orchestration for sample %s (%d chars, language=%s)",
            self.sample_id,
            len(self.original_code),
            self.language or "auto-detect",
        )

        stop_reason = "Completed normally."
        iterations_run = 0

        try:
            for _ in range(max_iterations):
                iteration = self._state_manager.advance_iteration()
                iterations_run = iteration
                code_before = self._state_manager.current_code
                language = self._state_manager.state.language or self.language or ""

                logger.debug("=== Iteration %d ===", iteration)

                # ── Stage 1: Plan ────────────────────────────────────
                recommendations = self._planner.plan(
                    self._state_manager,
                    self._action_queue,
                )
                logger.debug(
                    "Planner recommended %d action(s): %s",
                    len(recommendations),
                    [r.action_name for r in recommendations],
                )

                # ── Stage 2: Select ──────────────────────────────────
                selected = self._selector.select(
                    recommendations,
                    self._action_queue,
                    self._state_manager,
                )
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

                # ── Stage 3: Pre-flight ──────────────────────────────
                preflight = self._preflight.validate(
                    action_name,
                    code_before,
                    language,
                    self.action_space,
                    self._action_queue,
                    self._state_manager,
                )
                if not preflight.approved:
                    logger.info(
                        "Pre-flight rejected '%s': %s",
                        action_name,
                        preflight.skip_reason,
                    )
                    self._action_queue.mark_skipped(action_name)
                    continue

                # ── Stage 4: Execute ─────────────────────────────────
                state_dict = self._state_manager.state.model_dump()
                result = await self._executor.execute(
                    action_name,
                    code_before,
                    language,
                    state_dict,
                )

                # ── Stage 5: Post-process ────────────────────────────
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

                # ── Stage 6: Verify / Score ──────────────────────────
                improvement = self._verifier.verify(
                    code_before,
                    result.output,
                    result,
                    self._state_manager,
                )

                # ── Stage 7: State Reconciler ────────────────────────
                # Merge results into state, record transform, update
                # queue feedback, stall tracking, confidence.
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

                # Update orchestrator-level language if detect succeeded.
                if action_name == "detect_language" and result.success:
                    detected = result.details.get("detected_language")
                    if detected:
                        self.language = detected

                # Take snapshot.
                self._state_manager.take_snapshot()
                await self._state_manager.persist_snapshot()

                # ── Stage 8: Stop Decision ───────────────────────────
                verdict = self._stop_decision.evaluate(
                    self._state_manager,
                    self._action_queue,
                    last_transform_success=result.success,
                    improvement_score=improvement,
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
                    self._state_manager.rollback()
                    self._state_manager.reset_stall()
                    stop_reason = verdict.reason
                    # Continue the loop to try other actions.
                elif verdict.action == StopAction.RETRY:
                    logger.info("Retry mode: %s", verdict.reason)
                    # The queue will provide a different action next round.
            else:
                stop_reason = f"Maximum iterations reached ({max_iterations})."

        except Exception:
            logger.exception("Orchestrator encountered an unhandled error")
            stop_reason = "Unhandled error during orchestration."

        # ── Final findings generation ────────────────────────────────
        findings = self._findings_gen.generate(
            self._state_manager.state,
            self._state_manager.current_code,
            iocs=all_iocs,
        )

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
        delta = improvement * 0.3 + result.confidence * 0.1
        new = current + delta
        # Clamp to [0, 1].
        return max(0.0, min(1.0, new))

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
