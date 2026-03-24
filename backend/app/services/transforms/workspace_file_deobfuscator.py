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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.services.ingest.workspace_bundle import (
    ParsedWorkspaceFile,
    parse_workspace_bundle,
    rebuild_workspace_bundle,
    validate_workspace_bundle_candidate,
)
from app.services.transforms.base import BaseTransform, TransformResult
from app.services.transforms.base64_decoder import Base64Decoder
from app.services.transforms.constant_folder import ConstantFolder
from app.services.transforms.hex_decoder import HexDecoder
from app.services.transforms.js_resolvers import JavaScriptArrayResolver
from app.services.transforms.junk_code import JunkCodeRemover
from app.services.transforms.literal_propagator import (
    LiteralPropagator,
    extract_literal_bindings,
)
from app.services.transforms.powershell_decoder import PowerShellDecoder
from app.services.transforms.python_decoder import PythonDecoder
from app.services.transforms.string_decryptor import StringDecryptor
from app.services.transforms.unicode_normalizer import UnicodeNormalizer
from app.services.transforms.workspace_profiler import (
    _build_python_module_index,
    _extract_import_metadata,
)

_SUPPORTED_LANGUAGES = {"javascript", "typescript", "python", "powershell"}
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
    return _balanced_delimiters(code)


class WorkspaceFileDeobfuscator(BaseTransform):
    name = "WorkspaceFileDeobfuscator"
    description = "Run deterministic deobfuscation against prioritized workspace files."

    _MAX_TARGET_FILES = 8
    _MAX_TRANSFORMS_PER_FILE = 8

    def __init__(self) -> None:
        self._common_transforms: Tuple[BaseTransform, ...] = (
            UnicodeNormalizer(),
            Base64Decoder(),
            HexDecoder(),
            StringDecryptor(),
            ConstantFolder(),
            LiteralPropagator(),
            JunkCodeRemover(),
        )
        self._js_transforms: Tuple[BaseTransform, ...] = (
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

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        files = parse_workspace_bundle(code)
        if not files:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Input is not a parseable workspace bundle.",
                details={},
            )

        target_paths = self._select_target_paths(files, state)
        if not target_paths:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="No supported workspace files were eligible for targeted deobfuscation.",
                details={"skipped": True},
            )

        file_lookup = {file.path: file for file in files}
        path_set = set(file_lookup)
        python_modules = _build_python_module_index(files)
        symbol_literals = self._build_workspace_literal_index(
            files=files,
            path_set=path_set,
            python_modules=python_modules,
        )
        rewritten_files: List[ParsedWorkspaceFile] = []
        changed_files: List[str] = []
        file_transform_summary: List[Dict[str, Any]] = []
        aggregate_details = self._initial_aggregate_details()

        for file in files:
            if file.path not in target_paths:
                rewritten_files.append(file)
                continue

            imported_literals = self._imported_literals_for_file(
                file=file,
                path_set=path_set,
                python_modules=python_modules,
                symbol_literals=symbol_literals,
            )
            transformed_file, summary, details = self._process_file(
                file=file,
                global_state=state,
                imported_literals=imported_literals,
            )
            rewritten_files.append(transformed_file)
            file_transform_summary.append(summary)
            self._merge_transform_details(aggregate_details, details, file.path)
            symbol_literals[file.path] = extract_literal_bindings(
                transformed_file.text,
                transformed_file.language,
                imported_literals=imported_literals,
            )
            if transformed_file.text != file.text:
                changed_files.append(file.path)

        if not changed_files:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Targeted workspace pass did not produce any safe file-level rewrites.",
                details={
                    "skipped": True,
                    "targeted_files": target_paths,
                    "file_transform_summary": file_transform_summary,
                    "workspace_context": self._updated_workspace_context(
                        state=state,
                        target_paths=target_paths,
                        changed_files=[],
                        file_transform_summary=file_transform_summary,
                        symbol_literals=symbol_literals,
                    ),
                },
            )

        rebuilt = rebuild_workspace_bundle(code, rewritten_files)
        validation = validate_workspace_bundle_candidate(code, rebuilt)
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
                },
            )

        aggregate_details["workspace_context"] = self._updated_workspace_context(
            state=state,
            target_paths=target_paths,
            changed_files=changed_files,
            file_transform_summary=file_transform_summary,
            symbol_literals=symbol_literals,
        )
        aggregate_details["workspace_validation"] = validation
        aggregate_details["targeted_files"] = target_paths
        aggregate_details["deobfuscated_files"] = changed_files
        aggregate_details["file_transform_summary"] = file_transform_summary
        aggregate_details["evidence_references"] = changed_files[:]
        aggregate_details["detected_techniques"] = list(dict.fromkeys(
            list(aggregate_details.get("detected_techniques", []))
            + [
                "workspace_targeted_deobfuscation",
                "per_file_workspace_pipeline",
            ]
        ))

        transform_count = sum(
            len(item.get("applied_transforms", []))
            for item in file_transform_summary
        )
        confidence = min(0.92, 0.72 + len(changed_files) * 0.04 + transform_count * 0.01)
        description = (
            f"Targeted {len(target_paths)} workspace file(s); "
            f"safely rewrote {len(changed_files)} file(s) across {transform_count} deterministic pass(es)."
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
        files: Sequence[ParsedWorkspaceFile],
        state: dict,
    ) -> List[str]:
        context = state.get("workspace_context", {})
        ranked_paths: List[str] = []

        prioritized = context.get("prioritized_files", [])
        for item in prioritized:
            if isinstance(item, dict):
                path = str(item.get("path", "")).strip()
            else:
                path = str(item).strip()
            if path:
                ranked_paths.append(path)

        for key in ("suspicious_files", "entry_points", "prioritized_paths"):
            for path in context.get(key, []):
                value = str(path).strip()
                if value:
                    ranked_paths.append(value)

        for key in ("dependency_hotspots", "symbol_hotspots"):
            for path in context.get(key, []):
                value = str(path).strip()
                if value:
                    ranked_paths.append(value)

        for execution_path in context.get("execution_paths", []):
            for segment in str(execution_path).split(" -> "):
                value = segment.split("::", 1)[0].strip()
                if value:
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
                    ranked_paths.append(source)
                if target:
                    ranked_paths.append(target)

        if not ranked_paths:
            for file in files:
                if "suspicious" in file.priority or "entrypoint" in file.priority:
                    ranked_paths.append(file.path)
            if not ranked_paths:
                ranked_paths.extend(file.path for file in files[: self._MAX_TARGET_FILES])

        supported_paths = {
            file.path for file in files
            if file.language in _SUPPORTED_LANGUAGES
        }
        selected = []
        for path in ranked_paths:
            if path in supported_paths and path not in selected:
                selected.append(path)
            if len(selected) >= self._MAX_TARGET_FILES:
                break
        return selected

    def _process_file(
        self,
        *,
        file: ParsedWorkspaceFile,
        global_state: dict,
        imported_literals: Dict[str, Any],
    ) -> Tuple[ParsedWorkspaceFile, Dict[str, Any], Dict[str, Any]]:
        current = file.text
        transformed = 0
        details = self._initial_aggregate_details()
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
            if candidate != current and not self._candidate_is_safe(
                language=file.language,
                before=current,
                after=candidate,
            ):
                summary["rejected_transforms"].append(transform.name)
                continue

            if result.success and (candidate != current or result.details):
                summary["applied_transforms"].append(transform.name)
                transformed += 1
                current = candidate

        summary["changed"] = current != file.text
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
        if lang in {"javascript", "typescript"}:
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

    def _candidate_is_safe(self, *, language: str, before: str, after: str) -> bool:
        before_ok = _is_syntax_healthy(language, before)
        after_ok = _is_syntax_healthy(language, after)
        if before_ok and not after_ok:
            return False
        return True

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
        target_paths: List[str],
        changed_files: List[str],
        file_transform_summary: List[Dict[str, Any]],
        symbol_literals: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        context = dict(state.get("workspace_context", {}))
        context["targeted_files"] = target_paths
        context["deobfuscated_files"] = changed_files
        context["file_transform_summary"] = file_transform_summary[:12]
        context["targeted_file_count"] = len(target_paths)
        context["deobfuscated_file_count"] = len(changed_files)
        context["symbol_literal_files"] = [
            {
                "path": path,
                "symbols": sorted(bindings)[:10],
            }
            for path, bindings in list(symbol_literals.items())[:16]
            if isinstance(bindings, dict) and bindings
        ]
        return context
