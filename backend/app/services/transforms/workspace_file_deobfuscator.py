"""
Workspace-level deterministic deobfuscation.

Runs existing deterministic transforms against the most relevant files inside a
workspace bundle instead of treating the entire bundle as one flat document.
"""

from __future__ import annotations

import ast
import json
import re
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from app.core.config import settings
from app.services.ingest.workspace_bundle import (
    ParsedWorkspaceFile,
    load_workspace_archive_from_path,
    normalise_workspace_path,
    overlay_workspace_files,
    parse_workspace_bundle,
    rebuild_workspace_bundle,
    validate_workspace_bundle_candidate,
)
from app.services.transforms.base import BaseTransform, TransformResult
from app.services.transforms.base64_decoder import Base64Decoder
from app.services.transforms.constant_folder import ConstantFolder
from app.services.transforms.hex_decoder import HexDecoder
from app.services.transforms.javascript_bundle_deobfuscator import JavaScriptBundleDeobfuscator
from app.services.transforms.js_resolvers import JavaScriptArrayResolver
from app.services.transforms.js_tooling import validate_javascript_source
from app.services.transforms.junk_code import JunkCodeRemover
from app.services.transforms.literal_propagator import (
    LiteralPropagator,
    extract_literal_bindings,
)
from app.services.transforms.powershell_decoder import PowerShellDecoder
from app.services.transforms.python_decoder import PythonDecoder
from app.services.transforms.semantic_verifier import semantic_validation_summary
from app.services.transforms.source_preprocessor import normalize_source_anomalies, SourcePreprocessor
from app.services.transforms.string_decryptor import StringDecryptor
from app.services.transforms.unicode_normalizer import UnicodeNormalizer
from app.services.transforms.workspace_profiler import (
    WORKSPACE_DEOBFUSCATION_LANGUAGES,
    _build_python_module_index,
    _extract_import_metadata,
)

_SUPPORTED_LANGUAGES = set(WORKSPACE_DEOBFUSCATION_LANGUAGES)
_LIST_DETAIL_KEYS = (
    "strings",
    "decoded_strings",
    "recovered",
    "decrypted_strings",
    "iocs",
    "decoded_payloads",
    "imports",
    "functions",
    "suspicious_apis",
    "evidence_references",
)
_PACKAGE_ROOT_SEGMENTS = {"apps", "packages", "services", "libs", "modules"}


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _workspace_package_root_for_path(path: str, package_roots: Sequence[str]) -> str:
    value = str(path).strip()
    if not value:
        return ""

    normalized_roots = sorted(
        (
            str(root).strip()
            for root in package_roots
            if str(root).strip()
        ),
        key=len,
        reverse=True,
    )
    for root in normalized_roots:
        if value == root or value.startswith(f"{root}/"):
            return root

    pure = PurePosixPath(value)
    parts = pure.parts
    if len(parts) >= 2 and parts[0].lower() in _PACKAGE_ROOT_SEGMENTS:
        return "/".join(parts[:2])
    if parts:
        return parts[0]
    return value


def _supported_workspace_paths(files: Sequence[ParsedWorkspaceFile]) -> List[str]:
    return [
        file.path
        for file in files
        if file.language in _SUPPORTED_LANGUAGES
    ]


def _safe_ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 4)


def _balanced_delimiters(code: str) -> bool:
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


def _is_syntax_healthy(language: str, code: str) -> bool:
    lang = (language or "").lower()
    cleaned, _ = normalize_source_anomalies(code)
    if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx"}:
        validation = validate_javascript_source(cleaned, language=lang)
        if validation.get("ok") is True:
            return True
        if validation.get("error") in {"node_unavailable", "worker_missing", "tooling_unavailable"}:
            return _balanced_delimiters(cleaned)
        return False
    if lang in {"python", "py"}:
        try:
            ast.parse(cleaned)
            return True
        except SyntaxError:
            return False
    if lang == "json":
        try:
            json.loads(cleaned)
            return True
        except (json.JSONDecodeError, TypeError):
            return False
    return _balanced_delimiters(cleaned)


def _structural_signature(language: str, code: str) -> Dict[str, int]:
    lang = (language or "").lower()
    cleaned, _ = normalize_source_anomalies(code)
    lines = cleaned.splitlines()
    metrics = {
        "lines": len(lines),
        "imports": 0,
        "functions": 0,
        "classes": 0,
    }

    if lang in {"javascript", "js", "jsx", "typescript", "ts", "tsx"}:
        metrics["imports"] = len(re.findall(r"\bimport\b|\brequire\s*\(", cleaned))
        metrics["functions"] = len(re.findall(r"\bfunction\b|=>", cleaned))
        metrics["classes"] = len(re.findall(r"\bclass\b", cleaned))
        return metrics

    if lang in {"python", "py"}:
        metrics["imports"] = len(
            re.findall(r"^\s*(?:from|import)\s+", cleaned, flags=re.MULTILINE)
        )
        metrics["functions"] = len(
            re.findall(r"^\s*(?:async\s+def|def)\s+[A-Za-z_]\w*\s*\(", cleaned, flags=re.MULTILINE)
        )
        metrics["classes"] = len(
            re.findall(r"^\s*class\s+[A-Za-z_]\w*", cleaned, flags=re.MULTILINE)
        )
        return metrics

    if lang == "powershell":
        metrics["imports"] = len(
            re.findall(r"\bImport-Module\b|^\s*\.\s+\S+", cleaned, flags=re.IGNORECASE | re.MULTILINE)
        )
        metrics["functions"] = len(
            re.findall(r"\bfunction\s+[A-Za-z_][\w-]*", cleaned, flags=re.IGNORECASE)
        )
        return metrics

    return metrics


def _coerce_workspace_file_addition(
    item: Any,
    *,
    fallback_language: str,
) -> Optional[ParsedWorkspaceFile]:
    if not isinstance(item, dict):
        return None

    path = normalise_workspace_path(str(item.get("path") or ""))
    if not path:
        return None

    text = str(item.get("text") or "")
    if not text.strip():
        return None

    language = str(item.get("language") or fallback_language or "plaintext").strip().lower()
    priority_raw = item.get("priority", [])
    if isinstance(priority_raw, str):
        priority = (priority_raw.strip(),) if priority_raw.strip() else ()
    elif isinstance(priority_raw, (list, tuple)):
        priority = tuple(
            str(entry).strip()
            for entry in priority_raw
            if str(entry).strip()
        )
    else:
        priority = ()

    if not _is_syntax_healthy(language, text):
        return None

    try:
        size_bytes = int(item.get("size_bytes") or len(text.encode("utf-8")))
    except (TypeError, ValueError):
        size_bytes = len(text.encode("utf-8"))

    return ParsedWorkspaceFile(
        path=path,
        language=language,
        priority=priority,
        size_bytes=size_bytes,
        text=text,
    )


class WorkspaceFileDeobfuscator(BaseTransform):
    name = "WorkspaceFileDeobfuscator"
    description = "Run deterministic deobfuscation against prioritized workspace files."

    _MAX_TARGET_FILES = getattr(settings, "MAX_WORKSPACE_TARGET_FILES", 28)
    _MAX_BUNDLE_ADDITIONS = getattr(settings, "MAX_WORKSPACE_BUNDLE_ADDITIONS", 24)
    _MAX_TRANSFORMS_PER_FILE = 10

    def __init__(self) -> None:
        self._common_transforms: Tuple[BaseTransform, ...] = (
            SourcePreprocessor(),
            UnicodeNormalizer(),
            Base64Decoder(),
            HexDecoder(),
            StringDecryptor(),
            ConstantFolder(),
            LiteralPropagator(),
            JunkCodeRemover(),
        )
        self._js_transforms: Tuple[BaseTransform, ...] = (
            JavaScriptBundleDeobfuscator(),
            JavaScriptArrayResolver(),
        )
        self._python_transforms: Tuple[BaseTransform, ...] = (
            PythonDecoder(),
        )
        self._powershell_transforms: Tuple[BaseTransform, ...] = (
            PowerShellDecoder(),
        )

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        files = parse_workspace_bundle(code)
        return any(file.language in _SUPPORTED_LANGUAGES for file in files)

    def _load_archive_files(self, state: dict) -> List[ParsedWorkspaceFile]:
        iteration_state = state.get("iteration_state", {})
        if not isinstance(iteration_state, dict):
            return []
        sample_metadata = iteration_state.get("sample_metadata", {})
        if not isinstance(sample_metadata, dict):
            return []
        if sample_metadata.get("content_kind") != "archive_bundle":
            return []

        archive_path = str(sample_metadata.get("stored_file_path", "")).strip()
        if not archive_path:
            return []

        try:
            scan = load_workspace_archive_from_path(
                archive_path,
                archive_name=str(sample_metadata.get("filename") or Path(archive_path).name),
                max_member_bytes=getattr(settings, "MAX_ARCHIVE_MEMBER_SIZE", 2 * 1024 * 1024),
                max_scan_files=None,
            )
        except Exception:
            return []

        return [
            ParsedWorkspaceFile(
                path=item.path,
                language=item.language,
                priority=item.priority_tags,
                size_bytes=item.size_bytes,
                text=item.text,
            )
            for item in scan.files
        ]

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        bundled_files = parse_workspace_bundle(code)
        if not bundled_files:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Input is not a parseable workspace bundle.",
                details={},
            )

        archive_files = self._load_archive_files(state)
        source_files = overlay_workspace_files(code, archive_files) if archive_files else bundled_files
        target_paths = self._select_target_paths(
            source_files=source_files,
            bundled_files=bundled_files,
            state=state,
        )
        if not target_paths:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No supported workspace files were eligible for targeted deobfuscation.",
                details={"skipped": True},
            )

        bundled_lookup = {file.path: file for file in bundled_files}
        source_lookup = {file.path: file for file in source_files}
        path_set = set(source_lookup)
        python_modules = _build_python_module_index(source_files)
        symbol_literals = self._build_workspace_literal_index(
            files=source_files,
            path_set=path_set,
            python_modules=python_modules,
        )
        rewritten_files: List[ParsedWorkspaceFile] = []
        changed_files: List[str] = []
        added_files: List[str] = []
        synthetic_additions: Dict[str, ParsedWorkspaceFile] = {}
        file_transform_summary: List[Dict[str, Any]] = []
        aggregate_details = self._initial_aggregate_details()

        for file in bundled_files:
            if file.path not in target_paths:
                rewritten_files.append(file)
                continue

            imported_literals = self._imported_literals_for_file(
                file=file,
                path_set=path_set,
                python_modules=python_modules,
                symbol_literals=symbol_literals,
            )
            transformed_file, summary, details, additions = self._process_file(
                file=file,
                global_state=state,
                imported_literals=imported_literals,
            )
            rewritten_files.append(transformed_file)
            file_transform_summary.append(summary)
            self._merge_transform_details(aggregate_details, details, file.path)
            self._register_workspace_additions(
                additions=additions,
                synthetic_additions=synthetic_additions,
                added_files=added_files,
                file_transform_summary=file_transform_summary,
                aggregate_details=aggregate_details,
                symbol_literals=symbol_literals,
                origin_path=file.path,
            )
            symbol_literals[file.path] = extract_literal_bindings(
                transformed_file.text,
                transformed_file.language,
                imported_literals=imported_literals,
            )
            if transformed_file.text != file.text:
                changed_files.append(file.path)

        for path in target_paths:
            if path in bundled_lookup:
                continue
            file = source_lookup.get(path)
            if file is None:
                continue

            imported_literals = self._imported_literals_for_file(
                file=file,
                path_set=path_set,
                python_modules=python_modules,
                symbol_literals=symbol_literals,
            )
            transformed_file, summary, details, additions = self._process_file(
                file=file,
                global_state=state,
                imported_literals=imported_literals,
            )
            rewritten_files.append(transformed_file)
            file_transform_summary.append(summary)
            self._merge_transform_details(aggregate_details, details, file.path)
            self._register_workspace_additions(
                additions=additions,
                synthetic_additions=synthetic_additions,
                added_files=added_files,
                file_transform_summary=file_transform_summary,
                aggregate_details=aggregate_details,
                symbol_literals=symbol_literals,
                origin_path=file.path,
            )
            symbol_literals[file.path] = extract_literal_bindings(
                transformed_file.text,
                transformed_file.language,
                imported_literals=imported_literals,
            )
            added_files.append(file.path)
            if transformed_file.text != file.text:
                changed_files.append(file.path)

        if synthetic_additions:
            rewritten_files.extend(synthetic_additions.values())

        if not changed_files and not added_files:
            workspace_context = self._updated_workspace_context(
                state=state,
                source_files=source_files,
                target_paths=target_paths,
                changed_files=[],
                added_files=[],
                file_transform_summary=file_transform_summary,
                symbol_literals=symbol_literals,
            )
            return TransformResult(
                success=True,
                output=code,
                confidence=0.0,
                description=(
                    f"Processed {len(target_paths)} workspace file(s); "
                    "no additional safe file-level rewrites were produced in this batch."
                ),
                details={
                    "coverage_advanced": bool(target_paths),
                    "targeted_files": target_paths,
                    "file_transform_summary": file_transform_summary,
                    "workspace_context": workspace_context,
                },
            )

        rebuilt = rebuild_workspace_bundle(code, rewritten_files)
        validation = validate_workspace_bundle_candidate(
            code,
            rebuilt,
            allow_added_files=True,
        )
        if not validation["accepted"]:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Workspace bundle rewrite was rejected by structural validation.",
                details={
                    "workspace_validation": validation,
                    "targeted_files": target_paths,
                    "deobfuscated_files": changed_files,
                    "added_files_to_bundle": added_files,
                },
            )

        aggregate_details["workspace_context"] = self._updated_workspace_context(
            state=state,
            source_files=source_files,
            target_paths=target_paths,
            changed_files=changed_files,
            added_files=added_files,
            file_transform_summary=file_transform_summary,
            symbol_literals=symbol_literals,
        )
        aggregate_details["workspace_validation"] = validation
        aggregate_details["targeted_files"] = target_paths
        aggregate_details["deobfuscated_files"] = changed_files
        aggregate_details["added_files_to_bundle"] = added_files
        aggregate_details["file_transform_summary"] = file_transform_summary
        aggregate_details["evidence_references"] = (changed_files + added_files)[:]
        aggregate_details["detected_techniques"] = list(dict.fromkeys(
            list(aggregate_details.get("detected_techniques", []))
            + [
                "workspace_targeted_deobfuscation",
                "per_file_workspace_pipeline",
                "workspace_bundle_expansion" if added_files else "",
            ]
        ))
        aggregate_details["detected_techniques"] = [
            str(item) for item in aggregate_details["detected_techniques"]
            if str(item).strip()
        ]

        transform_count = sum(
            len(item.get("applied_transforms", []))
            for item in file_transform_summary
        )
        confidence = min(
            0.94,
            0.72
            + len(changed_files) * 0.03
            + len(added_files) * 0.015
            + transform_count * 0.01,
        )
        description = (
            f"Targeted {len(target_paths)} workspace file(s); "
            f"safely rewrote {len(changed_files)} file(s)"
            + (
                f" and added {len(added_files)} high-priority file(s) to the active bundle"
                if added_files else ""
            )
            + f" across {transform_count} deterministic pass(es)."
        )
        return TransformResult(
            success=True,
            output=rebuilt,
            confidence=confidence,
            description=description,
            details=aggregate_details,
        )

    def _select_target_paths(
        self,
        *,
        source_files: Sequence[ParsedWorkspaceFile],
        bundled_files: Sequence[ParsedWorkspaceFile],
        state: dict,
    ) -> List[str]:
        context = state.get("workspace_context", {})
        bundled_path_set = {file.path for file in bundled_files}
        supported_paths = _supported_workspace_paths(source_files)
        supported_path_set = set(supported_paths)
        if not supported_path_set:
            return []

        processed_paths = {
            str(path).strip()
            for path in context.get("processed_supported_files", [])
            if str(path).strip() in supported_path_set
        }
        ranked_paths: List[str] = []
        priority_rank: Dict[str, int] = {}

        prioritized = context.get("prioritized_files", [])
        for item in prioritized:
            if isinstance(item, dict):
                path = str(item.get("path", "")).strip()
            else:
                path = str(item).strip()
            if path:
                if path not in priority_rank:
                    priority_rank[path] = len(priority_rank)
                ranked_paths.append(path)

        for key in (
            "suspicious_files",
            "entry_points",
            "prioritized_paths",
            "analysis_frontier",
            "remaining_frontier_paths",
            "bundle_expansion_paths",
            "llm_focus_paths",
            "unbundled_hotspots",
        ):
            for path in context.get(key, []):
                value = str(path).strip()
                if value:
                    if value not in priority_rank:
                        priority_rank[value] = len(priority_rank)
                    ranked_paths.append(value)

        for key in ("dependency_hotspots", "symbol_hotspots"):
            for path in context.get(key, []):
                value = str(path).strip()
                if value:
                    if value not in priority_rank:
                        priority_rank[value] = len(priority_rank)
                    ranked_paths.append(value)

        for execution_path in context.get("execution_paths", []):
            for segment in str(execution_path).split(" -> "):
                value = segment.split("::", 1)[0].strip()
                if value:
                    if value not in priority_rank:
                        priority_rank[value] = len(priority_rank)
                    ranked_paths.append(value)

        graph_edges = context.get("cross_file_call_edges", [])
        current_seeds = {path for path in ranked_paths if path}
        for edge in graph_edges:
            if not isinstance(edge, dict):
                continue
            source = str(edge.get("source", "")).strip()
            target = str(edge.get("target", "")).strip()
            if source in current_seeds or target in current_seeds:
                if source:
                    if source not in priority_rank:
                        priority_rank[source] = len(priority_rank)
                    ranked_paths.append(source)
                if target:
                    if target not in priority_rank:
                        priority_rank[target] = len(priority_rank)
                    ranked_paths.append(target)

        if not ranked_paths:
            for file in source_files:
                if "suspicious" in file.priority or "entrypoint" in file.priority:
                    if file.path not in priority_rank:
                        priority_rank[file.path] = len(priority_rank)
                    ranked_paths.append(file.path)
            if not ranked_paths:
                for file in source_files:
                    if file.path not in priority_rank:
                        priority_rank[file.path] = len(priority_rank)
                    ranked_paths.append(file.path)

        ranked_paths = _dedupe_preserve_order(ranked_paths)
        ranked_unprocessed = [
            path
            for path in ranked_paths
            if path in supported_path_set and path not in processed_paths
        ]

        package_roots = [
            str(root).strip()
            for root in (context.get("package_roots", []) or context.get("root_dirs", []))
            if str(root).strip()
        ]
        ordered_package_roots = _dedupe_preserve_order(
            [
                _workspace_package_root_for_path(path, package_roots)
                for path in ranked_unprocessed
            ]
            + package_roots
            + [
                _workspace_package_root_for_path(path, package_roots)
                for path in supported_paths
                if path not in processed_paths
            ]
        )
        remaining_by_package: Dict[str, List[str]] = {}
        for path in supported_paths:
            if path in processed_paths:
                continue
            package_root = _workspace_package_root_for_path(path, ordered_package_roots or package_roots)
            remaining_by_package.setdefault(package_root, []).append(path)

        def _path_sort_key(path: str) -> Tuple[int, int, str, str]:
            package_root = _workspace_package_root_for_path(path, ordered_package_roots or package_roots)
            return (
                0 if path in bundled_path_set else 1,
                priority_rank.get(path, 100_000),
                package_root,
                path,
            )

        package_sweep: List[str] = []
        for root in ordered_package_roots:
            bucket = remaining_by_package.pop(root, [])
            bucket.sort(key=_path_sort_key)
            package_sweep.extend(bucket)
        for root in sorted(remaining_by_package):
            bucket = remaining_by_package[root]
            bucket.sort(key=_path_sort_key)
            package_sweep.extend(bucket)

        candidate_paths = _dedupe_preserve_order(
            ranked_unprocessed
            + package_sweep
        )
        if not candidate_paths and processed_paths:
            candidate_paths = [
                path
                for path in _dedupe_preserve_order(ranked_paths + supported_paths)
                if path in supported_path_set
            ]

        selected: List[str] = []
        added_paths = 0
        for path in candidate_paths:
            if path not in supported_path_set or path in selected:
                continue
            if path not in bundled_path_set and added_paths >= self._MAX_BUNDLE_ADDITIONS:
                continue
            selected.append(path)
            if path not in bundled_path_set:
                added_paths += 1
            if len(selected) >= self._MAX_TARGET_FILES:
                break
        return selected

    def _process_file(
        self,
        *,
        file: ParsedWorkspaceFile,
        global_state: dict,
        imported_literals: Dict[str, Any],
    ) -> Tuple[ParsedWorkspaceFile, Dict[str, Any], Dict[str, Any], List[ParsedWorkspaceFile]]:
        current = file.text
        transformed = 0
        details = self._initial_aggregate_details()
        workspace_additions: Dict[str, ParsedWorkspaceFile] = {}
        local_state = deepcopy(global_state)
        local_state["workspace_file_path"] = file.path
        local_state["language"] = file.language
        local_state["imported_literals"] = imported_literals

        summary: Dict[str, Any] = {
            "path": file.path,
            "language": file.language,
            "changed": False,
            "applied_transforms": [],
            "rejected_transforms": [],
            "rejection_reasons": [],
        }
        if imported_literals:
            summary["imported_literals"] = sorted(imported_literals)[:12]

        for transform in self._pipeline_for_language(file.language):
            if transformed >= self._MAX_TRANSFORMS_PER_FILE:
                break
            if not transform.can_apply(current, file.language, local_state):
                continue
            result = transform.apply(current, file.language, local_state)
            self._merge_transform_details(details, result.details or {}, file.path)

            candidate = result.output if result.success else current
            if candidate != current:
                validation = self._candidate_validation_summary(
                    language=file.language,
                    before=current,
                    after=candidate,
                )
                if not validation["safe"]:
                    summary["rejected_transforms"].append(transform.name)
                    summary["rejection_reasons"].append(
                        {
                            "transform": transform.name,
                            "reasons": validation["reasons"],
                            "size_ratio": validation["size_ratio"],
                            "line_ratio": validation["line_ratio"],
                        }
                    )
                    continue

            if result.success and (candidate != current or result.details):
                summary["applied_transforms"].append(transform.name)
                transformed += 1
                current = candidate
                for addition in self._workspace_file_additions_from_details(
                    result.details or {},
                    fallback_language=file.language,
                ):
                    workspace_additions[addition.path] = addition

        summary["changed"] = current != file.text
        summary["final_verification"] = self._candidate_validation_summary(
            language=file.language,
            before=file.text,
            after=current,
        )
        if summary["changed"]:
            details["evidence_references"].append(file.path)

        return (
            ParsedWorkspaceFile(
                path=file.path,
                language=file.language,
                priority=file.priority,
                size_bytes=file.size_bytes,
                text=current,
            ),
            summary,
            details,
            list(workspace_additions.values()),
        )

    def _workspace_file_additions_from_details(
        self,
        details: Dict[str, Any],
        *,
        fallback_language: str,
    ) -> List[ParsedWorkspaceFile]:
        additions = details.get("workspace_file_additions", [])
        if not isinstance(additions, list):
            return []
        parsed: List[ParsedWorkspaceFile] = []
        for item in additions:
            addition = _coerce_workspace_file_addition(
                item,
                fallback_language=fallback_language,
            )
            if addition is not None:
                parsed.append(addition)
        return parsed

    def _register_workspace_additions(
        self,
        *,
        additions: Sequence[ParsedWorkspaceFile],
        synthetic_additions: Dict[str, ParsedWorkspaceFile],
        added_files: List[str],
        file_transform_summary: List[Dict[str, Any]],
        aggregate_details: Dict[str, Any],
        symbol_literals: Dict[str, Dict[str, Any]],
        origin_path: str,
    ) -> None:
        if not additions:
            return

        for addition in additions:
            if addition.path in synthetic_additions or addition.path in added_files:
                continue
            if len(added_files) >= self._MAX_BUNDLE_ADDITIONS:
                break

            synthetic_additions[addition.path] = addition
            added_files.append(addition.path)
            aggregate_details["evidence_references"].append(addition.path)
            symbol_literals[addition.path] = extract_literal_bindings(
                addition.text,
                addition.language,
            )
            file_transform_summary.append(
                {
                    "path": addition.path,
                    "language": addition.language,
                    "changed": True,
                    "synthetic": True,
                    "source_bundle": origin_path,
                    "applied_transforms": ["bundle_module_materialization"],
                    "rejected_transforms": [],
                }
            )

    def _build_workspace_literal_index(
        self,
        *,
        files: Sequence[ParsedWorkspaceFile],
        path_set: set[str],
        python_modules: Dict[str, str],
    ) -> Dict[str, Dict[str, Any]]:
        symbol_literals: Dict[str, Dict[str, Any]] = {
            file.path: extract_literal_bindings(file.text, file.language)
            for file in files
            if file.language in {"javascript", "typescript", "python"}
        }

        for _ in range(3):
            changed = False
            for file in files:
                if file.language not in {"javascript", "typescript", "python"}:
                    continue
                imported_literals = self._imported_literals_for_file(
                    file=file,
                    path_set=path_set,
                    python_modules=python_modules,
                    symbol_literals=symbol_literals,
                )
                updated = extract_literal_bindings(
                    file.text,
                    file.language,
                    imported_literals=imported_literals,
                )
                if updated != symbol_literals.get(file.path, {}):
                    symbol_literals[file.path] = updated
                    changed = True
            if not changed:
                break

        return symbol_literals

    def _imported_literals_for_file(
        self,
        *,
        file: ParsedWorkspaceFile,
        path_set: set[str],
        python_modules: Dict[str, str],
        symbol_literals: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        if file.language not in {"javascript", "typescript", "python"}:
            return {}

        _, _, binding_map = _extract_import_metadata(
            file=file,
            path_set=path_set,
            python_modules=python_modules,
        )
        imported: Dict[str, Any] = {}
        for local_name, info in binding_map.items():
            if not isinstance(info, dict):
                continue
            target_path = str(info.get("resolved", "")).strip()
            if not target_path:
                continue
            target_literals = symbol_literals.get(target_path, {})
            if not isinstance(target_literals, dict) or not target_literals:
                continue

            source_symbol = str(info.get("source_symbol") or "").strip()
            if source_symbol == "default":
                if "default" in target_literals:
                    imported[local_name] = target_literals["default"]
                continue
            if source_symbol and source_symbol in target_literals:
                imported[local_name] = target_literals[source_symbol]
                continue
            if not info.get("qualified_calls") and local_name in target_literals:
                imported[local_name] = target_literals[local_name]

        return imported

    def _pipeline_for_language(self, language: str) -> Sequence[BaseTransform]:
        lang = (language or "").lower()
        if lang in {"javascript", "typescript", "jsx", "tsx"}:
            return (
                self._common_transforms[0],
                *self._js_transforms,
                *self._common_transforms[1:],
            )
        if lang == "python":
            return (
                self._common_transforms[0],
                *self._python_transforms,
                *self._common_transforms[1:],
            )
        if lang == "powershell":
            return (
                *self._powershell_transforms,
                *self._common_transforms,
            )
        return self._common_transforms

    def _candidate_validation_summary(
        self,
        *,
        language: str,
        before: str,
        after: str,
    ) -> Dict[str, Any]:
        before_ok = _is_syntax_healthy(language, before)
        after_ok = _is_syntax_healthy(language, after)
        before_signature = _structural_signature(language, before)
        after_signature = _structural_signature(language, after)
        size_ratio = _safe_ratio(len(after.strip()), len(before.strip()) or 1)
        line_ratio = _safe_ratio(after_signature["lines"], before_signature["lines"] or 1)
        semantic = semantic_validation_summary(
            language=language,
            before=before,
            after=after,
            size_ratio=size_ratio,
        )

        reasons: List[str] = []
        if before_ok and not after_ok:
            reasons.append("syntax_regression")
        if (
            before_signature["imports"] >= 1
            and after_signature["imports"] == 0
            and (size_ratio or 0.0) < 0.65
        ):
            reasons.append("import_surface_removed")
        if (
            before_signature["functions"] >= 2
            and after_signature["functions"] == 0
            and (size_ratio or 0.0) < 0.55
        ):
            reasons.append("function_surface_removed")
        if (
            before_signature["classes"] >= 1
            and after_signature["classes"] == 0
            and (size_ratio or 0.0) < 0.7
        ):
            reasons.append("class_surface_removed")
        if (
            before_signature["lines"] >= 12
            and after_signature["lines"] <= max(2, int(before_signature["lines"] * 0.2))
            and (size_ratio or 0.0) < 0.35
        ):
            reasons.append("destructive_shrink")
        for reason in semantic.get("reasons", []):
            if reason not in reasons:
                reasons.append(str(reason))

        return {
            "safe": not reasons,
            "reasons": reasons,
            "syntax_before": before_ok,
            "syntax_after": after_ok,
            "size_ratio": size_ratio,
            "line_ratio": line_ratio,
            "before": before_signature,
            "after": after_signature,
            "semantic": semantic,
        }

    def _candidate_is_safe(self, *, language: str, before: str, after: str) -> bool:
        return bool(
            self._candidate_validation_summary(
                language=language,
                before=before,
                after=after,
            )["safe"]
        )

    def _initial_aggregate_details(self) -> Dict[str, Any]:
        details: Dict[str, Any] = {key: [] for key in _LIST_DETAIL_KEYS}
        details["detected_techniques"] = []
        details["renames"] = {}
        details["patterns"] = {}
        details["suggestions"] = []
        return details

    def _merge_transform_details(
        self,
        aggregate: Dict[str, Any],
        incoming: Dict[str, Any],
        file_path: str,
    ) -> None:
        if not incoming:
            return

        for key in _LIST_DETAIL_KEYS:
            values = incoming.get(key, [])
            if not values:
                continue
            for item in values:
                aggregate[key].append(self._annotate_detail(item, file_path))

        renames = incoming.get("renames", {})
        if isinstance(renames, dict):
            aggregate["renames"].update(renames)

        patterns = incoming.get("patterns", {})
        if isinstance(patterns, dict):
            aggregate["patterns"].update(patterns)

        detected_techniques = incoming.get("detected_techniques", [])
        if isinstance(detected_techniques, list):
            aggregate["detected_techniques"].extend(
                str(item) for item in detected_techniques[:20] if item
            )

        suggestions = incoming.get("suggestions", [])
        if isinstance(suggestions, dict):
            for old_name, new_name in list(suggestions.items())[:20]:
                aggregate["suggestions"].append(f"{old_name} -> {new_name}")
        elif isinstance(suggestions, list):
            aggregate["suggestions"].extend(str(item) for item in suggestions[:20])

    def _annotate_detail(self, item: Any, file_path: str) -> Any:
        if isinstance(item, dict):
            annotated = dict(item)
            annotated.setdefault("file_path", file_path)
            return annotated
        if isinstance(item, str) and item not in {"", file_path}:
            return f"{item} @ {file_path}" if "@ " not in item else item
        return item

    def _updated_workspace_context(
        self,
        *,
        state: dict,
        source_files: Sequence[ParsedWorkspaceFile],
        target_paths: List[str],
        changed_files: List[str],
        added_files: List[str],
        file_transform_summary: List[Dict[str, Any]],
        symbol_literals: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        context = dict(state.get("workspace_context", {}))
        added_lookup = {
            str(item.get("path", "")).strip(): str(item.get("language", "")).strip().lower()
            for item in file_transform_summary
            if isinstance(item, dict) and str(item.get("path", "")).strip()
        }
        supported_paths = _supported_workspace_paths(source_files)
        supported_path_set = set(supported_paths)
        supported_file_count = max(
            int(context.get("supported_file_count") or 0),
            len(supported_paths),
        )
        indexed_file_count = max(
            int(context.get("indexed_file_count") or 0),
            len(source_files),
        )
        previous_processed = [
            str(path).strip()
            for path in context.get("processed_supported_files", [])
            if str(path).strip() in supported_path_set
        ]
        processed_supported = _dedupe_preserve_order(
            previous_processed
            + [
                str(path).strip()
                for path in target_paths
                if str(path).strip() in supported_path_set
            ]
        )
        processed_supported_set = set(processed_supported)
        remaining_supported = [
            path
            for path in supported_paths
            if path not in processed_supported_set
        ]
        previous_deobfuscated = [
            str(path).strip()
            for path in (
                context.get("all_deobfuscated_files")
                or context.get("deobfuscated_files")
                or []
            )
            if str(path).strip()
        ]
        all_deobfuscated = _dedupe_preserve_order(previous_deobfuscated + changed_files)
        previous_added_to_bundle = [
            str(path).strip()
            for path in (
                context.get("all_added_files_to_bundle")
                or context.get("added_files_to_bundle")
                or []
            )
            if str(path).strip()
        ]
        all_added_to_bundle = _dedupe_preserve_order(previous_added_to_bundle + added_files)
        package_roots = [
            str(root).strip()
            for root in (context.get("package_roots", []) or context.get("root_dirs", []))
            if str(root).strip()
        ]
        processed_package_roots = _dedupe_preserve_order(
            _workspace_package_root_for_path(path, package_roots)
            for path in processed_supported
        )
        remaining_package_roots = _dedupe_preserve_order(
            _workspace_package_root_for_path(path, package_roots)
            for path in remaining_supported
        )
        context["processed_supported_files"] = processed_supported
        context["targeted_files"] = processed_supported[:32]
        context["latest_targeted_files"] = target_paths[:32]
        context["deobfuscated_files"] = all_deobfuscated[:32]
        context["all_deobfuscated_files"] = all_deobfuscated
        context["added_files_to_bundle"] = all_added_to_bundle[:32]
        context["all_added_files_to_bundle"] = all_added_to_bundle
        if added_files:
            context["bundle_expansion_paths"] = added_files[:32]
        context["file_transform_summary"] = file_transform_summary[:12]
        context["targeted_file_count"] = len(processed_supported)
        context["latest_targeted_file_count"] = len(target_paths)
        context["processed_supported_file_count"] = len(processed_supported)
        context["remaining_supported_file_count"] = len(remaining_supported)
        context["remaining_supported_paths_preview"] = remaining_supported[:24]
        context["deobfuscated_file_count"] = len(all_deobfuscated)
        context["latest_deobfuscated_file_count"] = len(changed_files)
        current_bundle_file_count = int(
            context.get("bundle_file_count")
            or context.get("bundled_file_count")
            or 0
        )
        context["bundle_file_count"] = (
            current_bundle_file_count + len(added_files)
            if context.get("bundle_file_count") is not None
            or context.get("bundled_file_count") is not None
            else None
        )
        context["bundled_file_count"] = context["bundle_file_count"]
        added_supported_count = sum(
            1
            for path in added_files
            if added_lookup.get(path) in _SUPPORTED_LANGUAGES
        )
        bundled_supported = int(context.get("bundled_supported_file_count") or 0) + added_supported_count
        context["bundled_supported_file_count"] = bundled_supported
        if supported_file_count:
            context["supported_bundle_coverage_ratio"] = _safe_ratio(
                bundled_supported,
                supported_file_count,
            )
            context["targeted_supported_ratio"] = _safe_ratio(
                len(processed_supported),
                supported_file_count,
            )
        else:
            context["supported_bundle_coverage_ratio"] = None
            context["targeted_supported_ratio"] = None
        if indexed_file_count and context.get("bundle_file_count") is not None:
            context["bundle_coverage_ratio"] = _safe_ratio(
                int(context["bundle_file_count"] or 0),
                indexed_file_count,
            )
        else:
            context["bundle_coverage_ratio"] = None
        remaining_frontier = [
            str(path).strip()
            for path in context.get("analysis_frontier", [])
            if str(path).strip() and str(path).strip() not in processed_supported_set
        ]
        context["remaining_frontier_paths"] = remaining_frontier[:32]
        analysis_frontier = [
            str(path).strip()
            for path in context.get("analysis_frontier", [])
            if str(path).strip()
        ]
        if analysis_frontier:
            targeted_frontier = [
                path for path in analysis_frontier
                if path in processed_supported_set
            ]
            context["analysis_frontier_targeted_count"] = len(targeted_frontier)
            context["analysis_frontier_completion_ratio"] = _safe_ratio(
                len(targeted_frontier),
                len(analysis_frontier),
            )
        else:
            context["analysis_frontier_targeted_count"] = 0
            context["analysis_frontier_completion_ratio"] = None
        if processed_supported:
            context["recovered_target_ratio"] = _safe_ratio(
                len(all_deobfuscated),
                len(processed_supported),
            )
        else:
            context["recovered_target_ratio"] = None
        context["processed_package_roots"] = processed_package_roots[:16]
        context["processed_package_count"] = len(processed_package_roots)
        context["remaining_package_roots"] = remaining_package_roots[:16]
        context["remaining_package_count"] = len(remaining_package_roots)
        context["workspace_pass_index"] = int(context.get("workspace_pass_index") or 0) + 1
        if supported_file_count:
            context["workspace_pass_count_estimate"] = max(
                int(context.get("workspace_pass_count_estimate") or 0),
                max(1, (supported_file_count + self._MAX_TARGET_FILES - 1) // self._MAX_TARGET_FILES),
            )
        else:
            context["workspace_pass_count_estimate"] = int(
                context.get("workspace_pass_count_estimate") or 0
            )
        scope_note = str(context.get("coverage_scope_note") or "").strip()
        progress_note = (
            f"Processed {len(processed_supported)}/{supported_file_count} supported files "
            f"across {int(context.get('workspace_pass_index') or 0)} workspace batch(es)."
            if supported_file_count
            else ""
        )
        if remaining_supported:
            progress_note = f"{progress_note} {len(remaining_supported)} supported file(s) remain outside the active bundle sweep.".strip()
        elif progress_note:
            progress_note = f"{progress_note} Supported workspace coverage is fully swept.".strip()
        if progress_note:
            context["coverage_scope_note"] = (
                f"{scope_note} {progress_note}".strip()
                if scope_note and progress_note not in scope_note
                else progress_note
            )
        context["symbol_literal_files"] = [
            {
                "path": path,
                "symbols": sorted(bindings)[:10],
            }
            for path, bindings in list(symbol_literals.items())[:16]
            if isinstance(bindings, dict) and bindings
        ]
        return context
