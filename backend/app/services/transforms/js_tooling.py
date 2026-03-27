from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

from app.core.config import settings

_TOOL_DIR = Path(__file__).with_name("js_tooling")
_WORKER_PATH = _TOOL_DIR / "worker.mjs"
_PACKAGE_PATH = _TOOL_DIR / "package.json"
_LOCKFILE_PATH = _TOOL_DIR / "package-lock.json"
_PARSER_MODULE_PATH = _TOOL_DIR / "node_modules" / "@babel" / "parser"
_WEBCRACK_MODULE_PATH = _TOOL_DIR / "node_modules" / "webcrack"
_DEFAULT_TIMEOUT_SECONDS = 4.0
_WEBCRACK_TIMEOUT_SECONDS = 8.0
_INSTALL_LOCK = threading.Lock()
_INSTALL_ATTEMPTS: set[str] = set()


def _node_executable() -> Optional[str]:
    return shutil.which("node")


def _npm_executable() -> Optional[str]:
    return shutil.which("npm") or shutil.which("npm.cmd")


def _tooling_modules_present(*, require_webcrack: bool = False) -> bool:
    if not (_WORKER_PATH.exists() and _PARSER_MODULE_PATH.exists()):
        return False
    if require_webcrack and not _WEBCRACK_MODULE_PATH.exists():
        return False
    return True


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _javascript_tooling_auto_install_enabled() -> bool:
    return bool(getattr(settings, "JS_TOOLING_AUTO_INSTALL", True))


def _javascript_tooling_cache_dir() -> str:
    configured = str(getattr(settings, "JS_TOOLING_NPM_CACHE_DIR", "") or "").strip()
    if configured:
        return configured
    return str(os.getenv("UNWEAVER_JS_TOOLING_NPM_CACHE_DIR", "")).strip()


def _javascript_tooling_offline() -> bool:
    configured = bool(getattr(settings, "JS_TOOLING_OFFLINE", False))
    return configured or _bool_env("UNWEAVER_JS_TOOLING_OFFLINE", default=False)


def install_javascript_tooling(
    *,
    require_webcrack: bool = True,
    force: bool = False,
    offline: Optional[bool] = None,
    cache_dir: Optional[str] = None,
) -> Dict[str, Any]:
    requirement_key = "bundle" if require_webcrack else "parser"
    if _tooling_modules_present(require_webcrack=require_webcrack):
        return {
            "ok": True,
            "installed": False,
            "requirement": requirement_key,
            "tooling_ready": True,
        }

    node = _node_executable()
    if node is None:
        return {
            "ok": False,
            "error": "node_unavailable",
            "requirement": requirement_key,
        }

    npm = _npm_executable()
    if npm is None:
        return {
            "ok": False,
            "error": "npm_unavailable",
            "requirement": requirement_key,
        }

    if not _PACKAGE_PATH.exists():
        return {
            "ok": False,
            "error": "tool_package_missing",
            "requirement": requirement_key,
        }

    if offline is None:
        offline = _javascript_tooling_offline()
    resolved_cache_dir = str(cache_dir or _javascript_tooling_cache_dir()).strip()

    with _INSTALL_LOCK:
        if _tooling_modules_present(require_webcrack=require_webcrack):
            return {
                "ok": True,
                "installed": False,
                "requirement": requirement_key,
                "tooling_ready": True,
            }
        if requirement_key in _INSTALL_ATTEMPTS and not force:
            return {
                "ok": _tooling_modules_present(require_webcrack=require_webcrack),
                "installed": False,
                "requirement": requirement_key,
                "error": "tooling_unavailable",
            }

        _INSTALL_ATTEMPTS.add(requirement_key)
        command = [
            npm,
            "ci" if _LOCKFILE_PATH.exists() else "install",
            "--no-audit",
            "--no-fund",
        ]
        if resolved_cache_dir:
            command.extend(["--cache", resolved_cache_dir])
        if offline:
            command.append("--offline")

        try:
            completed = subprocess.run(
                command,
                cwd=str(_TOOL_DIR),
                text=True,
                capture_output=True,
                timeout=int(getattr(settings, "JS_TOOLING_INSTALL_TIMEOUT_SECONDS", 180)),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "ok": False,
                "installed": False,
                "requirement": requirement_key,
                "error": _normalize_worker_error(str(exc)),
            }

        if completed.returncode != 0:
            error_text = completed.stderr.strip() or completed.stdout.strip() or f"npm_exit_{completed.returncode}"
            return {
                "ok": False,
                "installed": False,
                "requirement": requirement_key,
                "error": _normalize_worker_error(error_text),
            }

    ready = _tooling_modules_present(require_webcrack=require_webcrack)
    return {
        "ok": ready,
        "installed": ready,
        "requirement": requirement_key,
        "tooling_ready": ready,
        "error": "" if ready else "tooling_unavailable",
    }


def ensure_javascript_tooling(*, require_webcrack: bool = False) -> bool:
    if _tooling_modules_present(require_webcrack=require_webcrack):
        return True
    if not _javascript_tooling_auto_install_enabled():
        return False
    result = install_javascript_tooling(require_webcrack=require_webcrack)
    return bool(result.get("ok"))


def javascript_tooling_available() -> bool:
    return _node_executable() is not None and ensure_javascript_tooling(require_webcrack=False)


def javascript_bundle_tooling_available() -> bool:
    return _node_executable() is not None and ensure_javascript_tooling(require_webcrack=True)


def _invoke_worker(
    action: str,
    *,
    code: str,
    language: str,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    node = _node_executable()
    if node is None:
        return {"ok": False, "error": "node_unavailable"}
    if not _WORKER_PATH.exists():
        return {"ok": False, "error": "worker_missing"}
    if not ensure_javascript_tooling(require_webcrack=False):
        return {"ok": False, "error": "tooling_unavailable"}
    if action == "webcrack" and not ensure_javascript_tooling(require_webcrack=True):
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


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Bootstrap the embedded JavaScript tooling.")
    parser.add_argument(
        "--parser-only",
        action="store_true",
        help="Install only the parser prerequisites instead of the full parser + webcrack bundle.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Retry the installation even if a previous attempt failed in this process.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Pass --offline to npm (requires a populated cache or vendored node_modules).",
    )
    parser.add_argument(
        "--cache-dir",
        default="",
        help="Explicit npm cache directory to use for offline or mirrored installs.",
    )
    args = parser.parse_args()

    result = install_javascript_tooling(
        require_webcrack=not args.parser_only,
        force=args.force,
        offline=args.offline or None,
        cache_dir=args.cache_dir or None,
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_main())
