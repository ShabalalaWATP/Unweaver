from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

_TOOL_DIR = Path(__file__).with_name("js_tooling")
_WORKER_PATH = _TOOL_DIR / "worker.mjs"
_PARSER_MODULE_PATH = _TOOL_DIR / "node_modules" / "@babel" / "parser"
_WEBCRACK_MODULE_PATH = _TOOL_DIR / "node_modules" / "webcrack"
_DEFAULT_TIMEOUT_SECONDS = 4.0
_WEBCRACK_TIMEOUT_SECONDS = 8.0


def javascript_tooling_available() -> bool:
    return (
        shutil.which("node") is not None
        and _WORKER_PATH.exists()
        and _PARSER_MODULE_PATH.exists()
    )


def javascript_bundle_tooling_available() -> bool:
    return javascript_tooling_available() and _WEBCRACK_MODULE_PATH.exists()


def _invoke_worker(
    action: str,
    *,
    code: str,
    language: str,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        return {"ok": False, "error": "node_unavailable"}
    if not _WORKER_PATH.exists():
        return {"ok": False, "error": "worker_missing"}
    if not javascript_tooling_available():
        return {"ok": False, "error": "tooling_unavailable"}
    if action == "webcrack" and not javascript_bundle_tooling_available():
        return {"ok": False, "error": "tooling_unavailable"}

    payload = json.dumps(
        {
            "action": action,
            "code": code,
            "language": language,
        }
    )
    try:
        completed = subprocess.run(
            [
                node,
                "--permission",
                f"--allow-fs-read={str(_TOOL_DIR)}",
                str(_WORKER_PATH),
            ],
            input=payload,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}

    stdout = completed.stdout.strip()
    if not stdout:
        return {
            "ok": False,
            "error": completed.stderr.strip() or "empty_output",
        }

    try:
        response = json.loads(stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": _normalize_worker_error(stdout[:200])}

    if completed.returncode != 0 and response.get("ok", True):
        response = dict(response)
        response["ok"] = False
        response.setdefault("error", completed.stderr.strip() or f"exit_{completed.returncode}")
    if "error" in response:
        response["error"] = _normalize_worker_error(str(response["error"]))
    return response


def _normalize_worker_error(message: str) -> str:
    text = str(message or "").strip()
    lowered = text.lower()
    if (
        "cannot find package" in lowered
        or "err_module_not_found" in lowered
        or "@babel/parser" in lowered
        or "webcrack" in lowered
    ):
        return "tooling_unavailable"
    return text or "unknown_error"


def validate_javascript_source(code: str, language: str = "javascript") -> Dict[str, Any]:
    return _invoke_worker(
        "validate",
        code=code,
        language=language,
    )


def resolve_javascript_arrays_ast(code: str, language: str = "javascript") -> Dict[str, Any]:
    return _invoke_worker(
        "resolve_arrays",
        code=code,
        language=language,
        timeout_seconds=max(_DEFAULT_TIMEOUT_SECONDS, 5.0),
    )


def run_webcrack(code: str, language: str = "javascript") -> Dict[str, Any]:
    return _invoke_worker(
        "webcrack",
        code=code,
        language=language,
        timeout_seconds=_WEBCRACK_TIMEOUT_SECONDS,
    )


def parse_javascript_ast(code: str, language: str = "javascript") -> Optional[Any]:
    response = _invoke_worker(
        "parse",
        code=code,
        language=language,
        timeout_seconds=max(_DEFAULT_TIMEOUT_SECONDS, 5.0),
    )
    if not response.get("ok"):
        return None
    ast = response.get("ast")
    if ast is None:
        return None
    root = _ast_namespace(ast)
    program = getattr(root, "program", None)
    if getattr(program, "type", "") == "Program":
        return program
    return root


def _ast_namespace(value: Any) -> Any:
    if isinstance(value, list):
        return [_ast_namespace(item) for item in value]
    if not isinstance(value, dict):
        return value

    converted = {key: _ast_namespace(item) for key, item in value.items()}
    start = converted.get("start")
    end = converted.get("end")
    if (
        "range" not in converted
        and isinstance(start, int)
        and isinstance(end, int)
    ):
        converted["range"] = [start, end]
    return SimpleNamespace(**converted)
