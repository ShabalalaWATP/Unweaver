"""
Specialist bundled/minified JavaScript deobfuscation via webcrack.

This transform is optional and degrades cleanly when the local Node tooling
bundle is unavailable. It targets webpack/browserify/parcel-style bundles and
large minified JavaScript where a specialist JS pipeline is more accurate than
generic text rewriting.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .base import BaseTransform, TransformResult
from .js_tooling import (
    javascript_bundle_tooling_available,
    run_webcrack,
    validate_javascript_source,
)
from .readability_scorer import compute_readability_score

_SUPPORTED_LANGUAGES = {"javascript", "js", "jsx", "typescript", "ts", "tsx", ""}
_BUNDLE_HINTS = (
    "__webpack_require__",
    "webpackJsonp",
    "parcelRequire",
    "module.exports",
    "exports.default",
)


def _workspace_bundle_module_path(source_path: str, module_path: str, module_id: Any, index: int) -> str:
    source = PurePosixPath(str(source_path or "bundle.js").replace("\\", "/").strip("/"))
    prefix_parts = [part for part in source.parts[:-1]]
    if source.name:
        prefix_parts.append(f"{source.name}.__webcrack__")
    else:
        prefix_parts.append("bundle.js.__webcrack__")

    raw = str(module_path or "").replace("\\", "/").strip()
    parts = [part for part in raw.split("/") if part and part not in {".", ".."}]
    if not parts:
        safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", str(module_id or index))
        parts = [f"module_{safe_id or index}.js"]
    return "/".join(prefix_parts + parts)


def _module_language(path: str, fallback: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    return fallback or "javascript"


def _materialize_bundle_modules(bundle: dict[str, Any], state: dict, language: str) -> list[dict[str, Any]]:
    modules = bundle.get("modules", [])
    if not isinstance(modules, list):
        return []

    source_path = str(state.get("workspace_file_path") or "bundle.js").strip()
    additions: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for index, module in enumerate(modules):
        if not isinstance(module, dict):
            continue
        module_code = str(module.get("code") or "")
        if not module_code.strip():
            continue
        path = _workspace_bundle_module_path(
            source_path=source_path,
            module_path=str(module.get("path") or ""),
            module_id=module.get("id"),
            index=index,
        )
        if path in seen_paths:
            continue
        seen_paths.add(path)
        priority = ["bundle_extracted"]
        if module.get("isEntry"):
            priority.append("entrypoint")
        additions.append(
            {
                "path": path,
                "language": _module_language(path, language or "javascript"),
                "priority": priority,
                "size_bytes": len(module_code.encode("utf-8")),
                "text": module_code,
                "module_id": str(module.get("id") or index),
                "entry": bool(module.get("isEntry")),
                "source_bundle": source_path,
            }
        )
    return additions


def _looks_like_minified(code: str) -> bool:
    lines = [line for line in code.splitlines() if line.strip()]
    if not lines:
        return False
    longest = max((len(line) for line in lines), default=0)
    avg = sum(len(line) for line in lines) / max(len(lines), 1)
    return longest >= 220 and avg >= 120


def _looks_like_bundle(code: str) -> bool:
    excerpt = code[:25_000]
    if any(hint in excerpt for hint in _BUNDLE_HINTS):
        return True
    if re.search(r"\(function\s*\(\s*modules\s*\)", excerpt):
        return True
    if re.search(r"\b(?:exports|module\.exports)\b", excerpt):
        return True
    if re.search(r"\b\d+\s*:\s*function\s*\(", excerpt):
        return True
    return False


class JavaScriptBundleDeobfuscator(BaseTransform):
    name = "javascript_bundle_deobfuscator"
    description = "Use webcrack to unpack and deobfuscate bundled JavaScript."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        lang = (language or "").lower().strip()
        if lang and lang not in _SUPPORTED_LANGUAGES:
            return False
        if not javascript_bundle_tooling_available():
            return False
        return _looks_like_bundle(code) or _looks_like_minified(code)

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        worker = run_webcrack(code, language or "javascript")
        candidate = str(worker.get("output") or "")
        if not worker.get("ok") or not candidate.strip():
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="webcrack could not deobfuscate the JavaScript bundle.",
                details={"worker_error": worker.get("error", "")},
            )

        syntax = validate_javascript_source(candidate, language=language or "javascript")
        if syntax.get("ok") is False and syntax.get("error") not in {"node_unavailable", "worker_missing", "tooling_unavailable"}:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="webcrack produced JavaScript that failed syntax validation.",
                details={
                    "worker_error": worker.get("error", ""),
                    "syntax_validation": syntax,
                },
            )

        readability_before, _ = compute_readability_score(code)
        readability_after, _ = compute_readability_score(candidate)
        readability_delta = round(readability_after - readability_before, 1)
        bundle = worker.get("bundle") if isinstance(worker.get("bundle"), dict) else {}
        workspace_file_additions = _materialize_bundle_modules(bundle, state, language or "javascript")

        techniques = ["javascript_bundle_deobfuscation", "webcrack"]
        bundle_type = str(bundle.get("type") or "").strip()
        if bundle_type:
            techniques.append(f"{bundle_type}_bundle")
        if bundle.get("moduleCount"):
            techniques.append("bundle_module_extraction")
        if workspace_file_additions:
            techniques.append("bundle_module_tree_materialization")

        confidence = 0.82
        if bundle.get("moduleCount"):
            confidence += 0.05
        if readability_delta > 5:
            confidence += 0.05
        if workspace_file_additions:
            confidence += 0.03

        module_count = bundle.get("moduleCount")
        bundle_note = ""
        if bundle_type:
            bundle_note = f" Detected {bundle_type} bundle"
            if isinstance(module_count, int):
                bundle_note += f" with {module_count} module(s)"
            bundle_note += "."

        module_note = ""
        if workspace_file_additions:
            module_note = f" Materialized {len(workspace_file_additions)} extracted module file(s)."

        normalized_original = re.sub(r"\s+", "", code)
        normalized_candidate = re.sub(r"\s+", "", candidate)
        if normalized_original == normalized_candidate and not workspace_file_additions:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="webcrack did not materially change the JavaScript bundle.",
                details={
                    "bundle": bundle,
                    "heuristics": worker.get("heuristics", {}),
                },
            )

        return TransformResult(
            success=True,
            output=candidate,
            confidence=min(confidence, 0.95),
            description=(
                "Deobfuscated bundled/minified JavaScript with webcrack."
                + bundle_note
                + module_note
            ),
            details={
                "bundle": bundle,
                "heuristics": worker.get("heuristics", {}),
                "readability_before": readability_before,
                "readability_after": readability_after,
                "readability_delta": readability_delta,
                "worker_error": worker.get("error", ""),
                "detected_techniques": techniques,
                "workspace_file_additions": workspace_file_additions,
                "bundle_module_paths": [item["path"] for item in workspace_file_additions],
                "decoded_artifacts": [candidate[:2000]],
            },
        )
