"""
LLM-powered multi-layer deobfuscation detector and unwrapper.

Analyses code to detect nested obfuscation layers (e.g. base64 wrapping
around hex encoding around XOR encryption) and attempts to unwrap them
in the correct order.  Also handles custom encoding schemes that regex
transforms can't recognise.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.services.transforms.base import TransformResult
from app.services.transforms.llm_base import LLMTransform

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an expert at reverse engineering layered obfuscation in code.

Your task:
1. Identify ALL layers of obfuscation/encoding present in the code
   (they may be nested — e.g. base64 around hex around XOR).
2. Describe the unwrapping order from outermost to innermost layer.
3. Attempt to decode/unwrap as many layers as you can.
4. If you find a payload hidden inside the layers, include it.

Return your answer as JSON:

```json
{
  "layers_detected": [
    {"layer": 1, "type": "base64", "description": "Outer base64 wrapper"},
    {"layer": 2, "type": "xor", "description": "XOR with key 0x42"},
    {"layer": 3, "type": "hex", "description": "Hex-encoded inner payload"}
  ],
  "unwrapped_code": "the final decoded/unwrapped result",
  "partial_results": [
    {"after_layer": 1, "preview": "first 200 chars of intermediate result..."}
  ],
  "hidden_payloads": ["any URLs, commands, or code found within layers"],
  "confidence": 0.0 to 1.0,
  "notes": "any additional observations"
}
```

If you cannot fully unwrap, provide as much partial progress as possible.
"""


class LLMMultiLayerUnwrapper(LLMTransform):
    """Use the LLM to detect and unwrap nested obfuscation layers."""

    name = "LLMMultiLayerUnwrapper"
    description = "LLM-assisted multi-layer obfuscation detection and unwrapping."

    def get_temperature(self) -> float:
        return 0.1

    def build_messages(
        self, code: str, language: str, state: dict
    ) -> List[Dict[str, str]]:
        truncated = self.truncate_code(code)
        lang = language or state.get("language", "unknown")

        techniques = state.get("detected_techniques", [])
        context = f"Language: {lang}"
        if techniques:
            context += f"\nKnown techniques: {', '.join(techniques[:10])}"

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Detect and unwrap any layered obfuscation.\n\n"
                    f"{context}\n\n"
                    f"```\n{truncated}\n```"
                ),
            },
        ]

    def parse_response(
        self, reply: str, code: str, language: str, state: dict
    ) -> TransformResult:
        data = self.extract_json(reply)
        if not data or not isinstance(data, dict):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.2,
                description="LLM multi-layer analysis did not return valid JSON.",
                details={"raw_reply_length": len(reply)},
            )

        layers = data.get("layers_detected", [])
        unwrapped = data.get("unwrapped_code", "")
        hidden_payloads = data.get("hidden_payloads", [])
        partial_results = data.get("partial_results", [])
        confidence = float(data.get("confidence", 0.5))
        notes = data.get("notes", "")

        # Use the unwrapped code if it looks valid.
        use_unwrapped = False
        if unwrapped and len(unwrapped.strip()) >= 10:
            # Sanity check: unwrapped should be different from input.
            if unwrapped.strip() != code.strip():
                use_unwrapped = True

        # Extract techniques from layers for the state.
        detected_techniques = [
            layer.get("type", "unknown")
            for layer in layers
            if isinstance(layer, dict) and layer.get("type")
        ]

        description = (
            f"Detected {len(layers)} obfuscation layer(s). "
            + (f"Successfully unwrapped. " if use_unwrapped else "Partial unwrap. ")
            + (f"Hidden payloads: {len(hidden_payloads)}. " if hidden_payloads else "")
            + (notes[:200] if notes else "")
        )

        return TransformResult(
            success=len(layers) > 0,
            output=unwrapped if use_unwrapped else code,
            confidence=confidence,
            description=description.strip()[:500],
            details={
                "layers": layers[:10],
                "hidden_payloads": hidden_payloads[:10],
                "partial_results": partial_results[:5],
                "detected_techniques": detected_techniques,
                "fully_unwrapped": use_unwrapped,
                "notes": notes[:500],
                "decoded_strings": [
                    {"encoded": "layered", "decoded": p[:500]}
                    for p in hidden_payloads[:5]
                    if isinstance(p, str)
                ],
            },
        )
