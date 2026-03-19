"""
LLM-powered code summarisation and intent analysis.

Asks the LLM to produce a structured analysis of the code: what it does,
whether it's malicious, key behaviours, and a severity assessment.
This replaces generic heuristic findings with rich, contextual analysis.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.services.transforms.base import TransformResult
from app.services.transforms.llm_base import LLMTransform

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a senior malware analyst and reverse engineer. Analyse the following
code (which may be partially deobfuscated) and provide a structured assessment.

Return your answer as JSON with exactly these fields:

```json
{
  "summary": "2-3 sentence plain-English description of what the code does",
  "intent": "benign | suspicious | malicious | unknown",
  "intent_confidence": 0.0 to 1.0,
  "capabilities": ["list", "of", "specific", "capabilities"],
  "techniques": ["list", "of", "attack techniques or MITRE ATT&CK IDs if applicable"],
  "iocs_found": [
    {"type": "url|ip|domain|hash|filepath|registry|email", "value": "...", "context": "..."}
  ],
  "risk_factors": ["list of specific risk factors identified"],
  "recommended_actions": ["list of analyst follow-up actions"],
  "severity": "critical | high | medium | low | info"
}
```

Be specific and evidence-based. Reference exact strings, URLs, IPs, or
code patterns from the sample. If you're unsure, say so.
"""


class LLMSummarizer(LLMTransform):
    """Use the LLM to produce a rich, structured analysis summary."""

    name = "LLMSummarizer"
    description = "LLM-assisted code behaviour analysis and threat assessment."

    def get_temperature(self) -> float:
        return 0.15

    def get_max_tokens(self) -> int:
        return 3000

    def build_messages(
        self, code: str, language: str, state: dict
    ) -> List[Dict[str, str]]:
        truncated = self.truncate_code(code)
        lang = language or state.get("language", "unknown")

        # Provide prior context to the LLM for richer analysis.
        context_parts: List[str] = [f"Language: {lang}"]
        techniques = state.get("detected_techniques", [])
        if techniques:
            context_parts.append(
                f"Previously detected techniques: {', '.join(techniques[:15])}"
            )
        apis = state.get("suspicious_apis", [])
        if apis:
            context_parts.append(
                f"Suspicious APIs: {', '.join(apis[:10])}"
            )
        strings = state.get("strings", [])
        if strings:
            sample_strings = [
                (s.get("value") if isinstance(s, dict) else str(s))[:60]
                for s in strings[:10]
            ]
            context_parts.append(
                f"Extracted strings (sample): {sample_strings}"
            )
        context = "\n".join(context_parts)

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Analyse this code sample.\n\n"
                    f"Context:\n{context}\n\n"
                    f"```\n{truncated}\n```"
                ),
            },
        ]

    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        data = self.extract_json(reply)
        if not data or not isinstance(data, dict):
            # Even if JSON parsing fails, the raw text might be useful.
            return TransformResult(
                success=bool(reply.strip()),
                output=code,
                confidence=0.4,
                description=reply.strip()[:500] if reply.strip() else "LLM analysis returned empty.",
                details={"raw_analysis": reply[:2000], "parse_failed": True},
            )

        summary = data.get("summary", "")
        intent = data.get("intent", "unknown")
        severity = data.get("severity", "info")
        intent_confidence = float(data.get("intent_confidence", 0.5))

        # Extract structured data for the state reconciler.
        capabilities = data.get("capabilities", [])
        techniques = data.get("techniques", [])
        iocs_found = data.get("iocs_found", [])
        risk_factors = data.get("risk_factors", [])
        recommended_actions = data.get("recommended_actions", [])

        description = (
            f"Intent: {intent} (confidence {intent_confidence:.0%}). "
            f"Severity: {severity}. {summary}"
        )

        return TransformResult(
            success=True,
            output=code,  # Summarizer doesn't modify code.
            confidence=intent_confidence,
            description=description[:500],
            details={
                "summary": summary,
                "intent": intent,
                "intent_confidence": intent_confidence,
                "severity": severity,
                "capabilities": capabilities[:20],
                "techniques": techniques[:20],
                "iocs_found": iocs_found[:30],
                "risk_factors": risk_factors[:10],
                "recommended_actions": recommended_actions[:10],
                "llm_analysis": True,
            },
        )
