"""
Decode JavaScript encoder families that ultimately dispatch through
`eval(...)`, `setTimeout("...")`, or `Function("...")`.

This targets the common runtime-driven families that were previously only
fingerprinted: JSFuck, JJEncode, and AAEncode. The worker runs through the
local Node runtime with the permission model enabled and no filesystem,
network, or child-process access beyond reading the worker script itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .base import BaseTransform, TransformResult

_WORKER_PATH = Path(__file__).with_name("_js_encoder_worker.js")
_WORKER_TIMEOUT_SECONDS = 2.0

_CONSTRUCTOR_CHAIN_HINTS = (
    '["constructor"]',
    "['constructor']",
    ".constructor(",
)
_ENCODER_HINTS = (
    "$=~[];",
    "$={___:",
    "ﾟДﾟ",
    "ﾟωﾟ",
)


def _looks_like_jsfuck(code: str) -> bool:
    stripped = "".join(ch for ch in code if not ch.isspace())
    if len(stripped) < 40:
        return False
    allowed = set("[]()!+")
    return set(stripped).issubset(allowed)


def _node_available() -> str | None:
    return shutil.which("node")


def _invoke_worker(code: str) -> dict[str, Any]:
    node = _node_available()
    if node is None or not _WORKER_PATH.exists():
        return {"ok": False, "decoded": "", "captures": [], "error": "node_unavailable"}

    allow_path = str(_WORKER_PATH.parent)
    payload = json.dumps({"code": code, "timeout_ms": 750})
    try:
        completed = subprocess.run(
            [
                node,
                "--permission",
                f"--allow-fs-read={allow_path}",
                str(_WORKER_PATH),
            ],
            input=payload,
            text=True,
            capture_output=True,
            timeout=_WORKER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "decoded": "", "captures": [], "error": str(exc)}

    stdout = completed.stdout.strip()
    if not stdout:
        return {"ok": False, "decoded": "", "captures": [], "error": completed.stderr.strip() or "empty_output"}

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"ok": False, "decoded": "", "captures": [], "error": stdout[:200]}


class JavaScriptEncoderDecoder(BaseTransform):
    name = "javascript_encoder_decoder"
    description = "Decode JSFuck/JJEncode/AAEncode-style JavaScript encoder wrappers"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang and lang not in ("javascript", "js", "jsx", "typescript", "ts", "tsx", ""):
            return False

        techniques = {
            str(item).lower().replace(" ", "_")
            for item in state.get("detected_techniques", [])
        }
        if techniques.intersection({"jsfuck_encoding", "jjencode_encoding", "aaencode_encoding"}):
            return True

        if _looks_like_jsfuck(code):
            return True
        if any(hint in code for hint in _CONSTRUCTOR_CHAIN_HINTS):
            return True
        return any(hint in code for hint in _ENCODER_HINTS)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        worker = _invoke_worker(code)
        decoded = str(worker.get("decoded") or "").strip()

        if not decoded:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No JavaScript encoder payload could be decoded.",
                details={
                    "worker_error": worker.get("error", ""),
                    "captures": worker.get("captures", []),
                },
            )

        family = "runtime_js_encoder"
        lowered = code.lower()
        if "ﾟ" in code:
            family = "aaencode"
        elif "$=~[];" in lowered or "$={___:" in lowered:
            family = "jjencode"
        elif _looks_like_jsfuck(code):
            family = "jsfuck"

        captures = worker.get("captures", [])
        return TransformResult(
            success=True,
            output=decoded,
            confidence=0.84,
            description=f"Decoded JavaScript runtime encoder payload ({family}).",
            details={
                "decoded_strings": [{"encoded": family, "decoded": decoded}],
                "captures": captures,
                "worker_error": worker.get("error", ""),
                "detected_techniques": [family, "javascript_runtime_encoder"],
                "change_count": 1,
            },
        )
