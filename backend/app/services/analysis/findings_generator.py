"""
Findings generator for the Unweaver deobfuscation engine.

Synthesises findings from all collected evidence across iterations,
creates Finding objects with severity / confidence, and categorises
them by: obfuscation technique, suspicious behaviour, IOC, code pattern.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Set

from app.models.schemas import (
    AnalysisState,
    Finding,
    IOC,
    IOCType,
    Severity,
    StringEntry,
    TransformRecord,
)

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Suspicious API / function patterns by language.
_SUSPICIOUS_PATTERNS: Dict[str, List[re.Pattern[str]]] = {
    "javascript": [
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bFunction\s*\(", re.IGNORECASE),
        re.compile(r"\bsetTimeout\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"\bsetInterval\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE),
        re.compile(r"\batob\s*\(", re.IGNORECASE),
        re.compile(r"\bActiveXObject\s*\(", re.IGNORECASE),
        re.compile(r"\bWScript\.Shell", re.IGNORECASE),
        re.compile(r"\bShell\.Application", re.IGNORECASE),
    ],
    "powershell": [
        re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
        re.compile(r"\biex\b", re.IGNORECASE),
        re.compile(r"\bIEX\b"),
        re.compile(r"\bNew-Object\s+.*Net\.WebClient", re.IGNORECASE),
        re.compile(r"\bDownloadString\b", re.IGNORECASE),
        re.compile(r"\bDownloadFile\b", re.IGNORECASE),
        re.compile(r"\bStart-Process\b", re.IGNORECASE),
        re.compile(r"\b-enc\b", re.IGNORECASE),
        re.compile(r"\b-EncodedCommand\b", re.IGNORECASE),
        re.compile(r"\bFromBase64String\b", re.IGNORECASE),
        re.compile(r"\bSet-MpPreference\b", re.IGNORECASE),
        re.compile(r"\bAdd-MpPreference\b", re.IGNORECASE),
        re.compile(r"\bbypass\b", re.IGNORECASE),
    ],
    "python": [
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bcompile\s*\(", re.IGNORECASE),
        re.compile(r"\b__import__\s*\(", re.IGNORECASE),
        re.compile(r"\bsubprocess\b", re.IGNORECASE),
        re.compile(r"\bos\.system\b", re.IGNORECASE),
        re.compile(r"\bctypes\b", re.IGNORECASE),
        re.compile(r"\bsocket\b", re.IGNORECASE),
    ],
    "vbscript": [
        re.compile(r"\bExecute\b", re.IGNORECASE),
        re.compile(r"\bExecuteGlobal\b", re.IGNORECASE),
        re.compile(r"\bCreateObject\b", re.IGNORECASE),
        re.compile(r"\bWScript\.Shell", re.IGNORECASE),
        re.compile(r"\bShell\.Application", re.IGNORECASE),
    ],
}

# Obfuscation technique descriptions.
_TECHNIQUE_DESCRIPTIONS: Dict[str, str] = {
    "base64_encoding": "Code or data encoded with Base64 to hide content from static analysis.",
    "hex_encoding": "Hexadecimal encoded strings used to conceal payloads or commands.",
    "xor_encryption": "XOR-based encryption applied to strings or code blocks.",
    "string_concatenation": "Strings broken into small fragments and concatenated at runtime.",
    "char_code_construction": "Characters built from numeric char codes (e.g. String.fromCharCode).",
    "array_indexing": "String values stored in an array and referenced by index to hinder reading.",
    "eval_exec": "Dynamic code execution via eval(), exec(), Invoke-Expression, or similar.",
    "junk_code": "Dead code, no-op statements, or meaningless variables inserted to confuse analysts.",
    "variable_renaming": "Identifiers replaced with meaningless names (single chars, hex strings, etc.).",
    "control_flow_flattening": "Control flow restructured into a state-machine dispatcher pattern.",
    "string_encryption": "Strings encrypted and decrypted at runtime through a resolver function.",
    "environment_keying": "Execution gated on environment checks (hostname, domain, date, etc.).",
    "reflection": "Use of reflection APIs to invoke methods or load types dynamically.",
}


class FindingsGenerator:
    """Synthesise analyst-facing findings from accumulated evidence."""

    def __init__(self, language: Optional[str] = None) -> None:
        self.language = (language or "").lower()

    def generate(
        self,
        state: AnalysisState,
        code: str,
        iocs: Optional[List[IOC]] = None,
    ) -> List[Finding]:
        """Produce a complete list of findings from the analysis state.

        Categories evaluated:
        1. Obfuscation techniques detected.
        2. Suspicious API / function usage.
        3. IOC-related findings.
        4. Code-pattern findings (eval chains, encoded commands, etc.).
        5. Summary-level findings (overall assessment).
        """
        findings: List[Finding] = []
        seen_titles: Set[str] = set()

        def _add(finding: Finding) -> None:
            if finding.title not in seen_titles:
                findings.append(finding)
                seen_titles.add(finding.title)

        # 1. Obfuscation techniques
        for technique in state.detected_techniques:
            _add(self._finding_for_technique(technique))

        # 2. Suspicious APIs
        api_findings = self._scan_suspicious_apis(code, state)
        for f in api_findings:
            _add(f)

        # 3. IOC findings
        if iocs:
            for ioc_finding in self._findings_from_iocs(iocs):
                _add(ioc_finding)

        # 4. Code-pattern findings
        for pattern_finding in self._scan_code_patterns(code, state):
            _add(pattern_finding)

        # 5. Transform-history-based findings
        for hist_finding in self._findings_from_history(state):
            _add(hist_finding)

        # 6. Overall assessment
        overall = self._overall_assessment(state, code, findings)
        if overall:
            _add(overall)

        return findings

    # ------------------------------------------------------------------
    #  Technique findings
    # ------------------------------------------------------------------

    def _finding_for_technique(self, technique: str) -> Finding:
        key = technique.lower().replace(" ", "_").replace("-", "_")
        description = _TECHNIQUE_DESCRIPTIONS.get(
            key,
            f"Obfuscation technique detected: {technique}.",
        )
        severity = self._technique_severity(key)
        return Finding(
            title=f"Obfuscation: {technique.replace('_', ' ').title()}",
            severity=severity,
            description=description,
            evidence=f"Detected technique: {technique}",
            confidence=0.8,
        )

    @staticmethod
    def _technique_severity(technique_key: str) -> Severity:
        high_sev = {
            "eval_exec", "xor_encryption", "string_encryption",
            "environment_keying", "reflection",
        }
        medium_sev = {
            "base64_encoding", "hex_encoding", "control_flow_flattening",
            "char_code_construction",
        }
        if technique_key in high_sev:
            return Severity.HIGH
        if technique_key in medium_sev:
            return Severity.MEDIUM
        return Severity.LOW

    # ------------------------------------------------------------------
    #  Suspicious API scanning
    # ------------------------------------------------------------------

    def _scan_suspicious_apis(
        self,
        code: str,
        state: AnalysisState,
    ) -> List[Finding]:
        findings: List[Finding] = []
        lang = (state.language or self.language or "").lower()

        # Collect patterns for the detected language + generic ones.
        patterns_to_check: List[tuple[str, re.Pattern[str]]] = []
        for plang in (lang, ""):
            for pattern in _SUSPICIOUS_PATTERNS.get(plang, []):
                patterns_to_check.append((plang or "generic", pattern))

        for plang, pattern in patterns_to_check:
            matches = pattern.findall(code)
            if matches:
                match_sample = matches[0].strip()[:80]
                findings.append(Finding(
                    title=f"Suspicious API: {pattern.pattern[:50]}",
                    severity=Severity.HIGH,
                    description=(
                        f"Found {len(matches)} occurrence(s) of potentially "
                        f"dangerous API pattern in {lang or 'unknown'} code."
                    ),
                    evidence=f"Example match: {match_sample}",
                    confidence=0.75,
                ))

        # Also include any suspicious_apis the transforms already flagged.
        for api in state.suspicious_apis:
            findings.append(Finding(
                title=f"Flagged API: {api}",
                severity=Severity.MEDIUM,
                description=f"Transform pipeline flagged suspicious API usage: {api}",
                evidence=api,
                confidence=0.7,
            ))

        return findings

    # ------------------------------------------------------------------
    #  IOC findings
    # ------------------------------------------------------------------

    @staticmethod
    def _findings_from_iocs(iocs: List[IOC]) -> List[Finding]:
        findings: List[Finding] = []
        severity_map = {
            IOCType.IP: Severity.HIGH,
            IOCType.DOMAIN: Severity.HIGH,
            IOCType.URL: Severity.HIGH,
            IOCType.HASH: Severity.MEDIUM,
            IOCType.EMAIL: Severity.MEDIUM,
            IOCType.FILEPATH: Severity.MEDIUM,
            IOCType.REGISTRY: Severity.HIGH,
            IOCType.MUTEX: Severity.HIGH,
            IOCType.OTHER: Severity.LOW,
        }
        for ioc in iocs:
            sev = severity_map.get(ioc.type, Severity.MEDIUM)
            findings.append(Finding(
                title=f"IOC ({ioc.type.value}): {ioc.value[:60]}",
                severity=sev,
                description=(
                    f"Extracted {ioc.type.value} indicator of compromise."
                    + (f"  Context: {ioc.context}" if ioc.context else "")
                ),
                evidence=ioc.value,
                confidence=ioc.confidence,
            ))
        return findings

    # ------------------------------------------------------------------
    #  Code pattern scanning
    # ------------------------------------------------------------------

    def _scan_code_patterns(
        self,
        code: str,
        state: AnalysisState,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Long single-line payload.
        lines = code.splitlines()
        very_long = [l for l in lines if len(l) > 1000]
        if very_long:
            findings.append(Finding(
                title="Extremely long code lines detected",
                severity=Severity.MEDIUM,
                description=(
                    f"Found {len(very_long)} line(s) exceeding 1000 characters. "
                    "This is common in packed or obfuscated payloads."
                ),
                evidence=f"Longest line: {max(len(l) for l in very_long)} chars",
                confidence=0.6,
            ))

        # High entropy string literals (potential encrypted blobs).
        if state.strings:
            long_strings = [
                s for s in state.strings
                if len(s.value) > 50
            ]
            if long_strings:
                for s in long_strings[:5]:  # cap at 5
                    entropy = self._shannon_entropy(s.value)
                    if entropy > 4.5:
                        findings.append(Finding(
                            title=f"High-entropy string ({entropy:.1f} bits)",
                            severity=Severity.MEDIUM,
                            description=(
                                "A string with high Shannon entropy was found, "
                                "suggesting encrypted or encoded content."
                            ),
                            evidence=s.value[:120] + ("..." if len(s.value) > 120 else ""),
                            confidence=0.65,
                        ))

        # Nested encoding detection.
        b64_count = sum(
            1 for t in state.detected_techniques
            if "base64" in t.lower()
        )
        hex_count = sum(
            1 for t in state.detected_techniques
            if "hex" in t.lower()
        )
        if b64_count and hex_count:
            findings.append(Finding(
                title="Multi-layer encoding detected",
                severity=Severity.HIGH,
                description=(
                    "Both Base64 and hex encoding were detected, suggesting "
                    "layered obfuscation designed to defeat simple decoders."
                ),
                confidence=0.8,
            ))

        return findings

    # ------------------------------------------------------------------
    #  History-based findings
    # ------------------------------------------------------------------

    @staticmethod
    def _findings_from_history(state: AnalysisState) -> List[Finding]:
        findings: List[Finding] = []
        successful = [t for t in state.transform_history if t.success]
        failed = [t for t in state.transform_history if not t.success]

        if len(successful) > 5:
            findings.append(Finding(
                title="Multi-layer obfuscation confirmed",
                severity=Severity.HIGH,
                description=(
                    f"The deobfuscation engine applied {len(successful)} successful "
                    f"transforms, indicating a heavily obfuscated sample."
                ),
                confidence=0.85,
            ))

        # Repeated failures on a specific action may indicate anti-analysis.
        from collections import Counter
        fail_counts = Counter(t.action for t in failed)
        for action, count in fail_counts.items():
            if count >= 2:
                findings.append(Finding(
                    title=f"Resistant to: {action.replace('_', ' ')}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Transform '{action}' failed {count} time(s). "
                        "The sample may employ anti-analysis techniques "
                        "targeting this deobfuscation strategy."
                    ),
                    confidence=0.5,
                ))

        return findings

    # ------------------------------------------------------------------
    #  Overall assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _overall_assessment(
        state: AnalysisState,
        code: str,
        existing_findings: List[Finding],
    ) -> Optional[Finding]:
        high_count = sum(
            1 for f in existing_findings if f.severity in (Severity.HIGH, Severity.CRITICAL)
        )
        technique_count = len(state.detected_techniques)
        confidence = state.confidence.get("overall", 0.0)

        if high_count >= 3 or technique_count >= 4:
            return Finding(
                title="Overall: Highly obfuscated malicious sample",
                severity=Severity.CRITICAL,
                description=(
                    f"Analysis identified {technique_count} obfuscation technique(s) "
                    f"and {high_count} high-severity finding(s). "
                    f"Overall confidence: {confidence:.0%}."
                ),
                confidence=confidence,
            )
        if high_count >= 1 or technique_count >= 2:
            return Finding(
                title="Overall: Moderately obfuscated sample",
                severity=Severity.HIGH,
                description=(
                    f"Analysis identified {technique_count} obfuscation technique(s). "
                    f"Overall confidence: {confidence:.0%}."
                ),
                confidence=confidence,
            )
        if technique_count >= 1:
            return Finding(
                title="Overall: Lightly obfuscated sample",
                severity=Severity.MEDIUM,
                description=(
                    f"Detected {technique_count} obfuscation technique(s). "
                    f"Overall confidence: {confidence:.0%}."
                ),
                confidence=confidence,
            )
        return None

    # ------------------------------------------------------------------
    #  Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Compute Shannon entropy of a string in bits."""
        if not data:
            return 0.0
        import math
        from collections import Counter
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
