"""
Deterministic workspace bundle profiler.

Extracts per-file metadata, likely entrypoints, cross-file imports, and
high-signal symbols from bundled codebase uploads so the planner and reports
can reason about a workspace as a set of files instead of a flat blob.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.core.config import settings
from app.services.ingest.workspace_bundle import (
    ParsedWorkspaceFile,
    extract_workspace_context,
    load_workspace_archive_from_path,
    overlay_workspace_files,
    parse_workspace_bundle,
    workspace_files_preview,
)
from app.services.transforms.base import BaseTransform, TransformResult

WORKSPACE_DEOBFUSCATION_LANGUAGES = frozenset(
    {"javascript", "typescript", "jsx", "tsx", "python", "powershell"}
)
_IMPORT_PATTERNS: Dict[str, Sequence[re.Pattern[str]]] = {
    "javascript": (
        re.compile(r'import\s+.+?\s+from\s+["\']([^"\']+)["\']'),
        re.compile(r'import\s*\(\s*["\']([^"\']+)["\']\s*\)'),
        re.compile(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)'),
    ),
    "typescript": (
        re.compile(r'import\s+.+?\s+from\s+["\']([^"\']+)["\']'),
        re.compile(r'import\s*\(\s*["\']([^"\']+)["\']\s*\)'),
        re.compile(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)'),
    ),
    "python": (
        re.compile(r'^\s*import\s+([a-zA-Z0-9_., ]+)', re.MULTILINE),
        re.compile(r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import', re.MULTILINE),
    ),
    "powershell": (
        re.compile(r'Import-Module\s+([^\s;]+)', re.IGNORECASE),
        re.compile(r'^\s*\.\s+([^\s]+)', re.MULTILINE),
    ),
    "csharp": (
        re.compile(r'^\s*using\s+([A-Za-z0-9_.]+)\s*;', re.MULTILINE),
    ),
    "go": (
        re.compile(r'^\s*import\s+"([^"]+)"', re.MULTILINE),
        re.compile(r'^\s*"([^"]+)"\s*$', re.MULTILINE),
    ),
}
_FUNCTION_PATTERNS: Dict[str, Sequence[re.Pattern[str]]] = {
    "javascript": (
        re.compile(r'function\s+([A-Za-z_]\w*)\s*\('),
        re.compile(r'const\s+([A-Za-z_]\w*)\s*=\s*\([^)]*\)\s*=>'),
    ),
    "typescript": (
        re.compile(r'function\s+([A-Za-z_]\w*)\s*\('),
        re.compile(r'const\s+([A-Za-z_]\w*)\s*=\s*\([^)]*\)\s*=>'),
        re.compile(r'(?:public|private|protected|export)?\s*function\s+([A-Za-z_]\w*)\s*\('),
    ),
    "python": (
        re.compile(r'^\s*def\s+([A-Za-z_]\w*)\s*\(', re.MULTILINE),
        re.compile(r'^\s*class\s+([A-Za-z_]\w*)\b', re.MULTILINE),
    ),
    "powershell": (
        re.compile(r'function\s+([A-Za-z_][\w-]*)\s*\{?', re.IGNORECASE),
    ),
    "csharp": (
        re.compile(r'(?:public|private|internal|protected)?\s*(?:static\s+)?[A-Za-z0-9_<>,\[\]]+\s+([A-Za-z_]\w*)\s*\('),
        re.compile(r'class\s+([A-Za-z_]\w*)\b'),
    ),
    "go": (
        re.compile(r'func\s+(?:\([^)]+\)\s+)?([A-Za-z_]\w*)\s*\('),
        re.compile(r'type\s+([A-Za-z_]\w*)\s+struct\b'),
    ),
}
_JS_NAMED_IMPORT = re.compile(
    r'import\s*{\s*(?P<bindings>[^}]+)\s*}\s*from\s*["\'](?P<target>[^"\']+)["\']',
    re.MULTILINE,
)
_JS_DEFAULT_IMPORT = re.compile(
    r'import\s+(?P<binding>[A-Za-z_]\w*)\s*(?:,\s*{[^}]+})?\s*from\s*["\'](?P<target>[^"\']+)["\']',
    re.MULTILINE,
)
_JS_NAMESPACE_IMPORT = re.compile(
    r'import\s+\*\s+as\s+(?P<binding>[A-Za-z_]\w*)\s+from\s*["\'](?P<target>[^"\']+)["\']',
    re.MULTILINE,
)
_JS_REQUIRE_BINDING = re.compile(
    r'(?:const|let|var)\s+(?P<binding>[A-Za-z_]\w*)\s*=\s*require\(\s*["\'](?P<target>[^"\']+)["\']\s*\)',
    re.MULTILINE,
)
_JS_REQUIRE_DESTRUCT = re.compile(
    r'(?:const|let|var)\s*{\s*(?P<bindings>[^}]+)\s*}\s*=\s*require\(\s*["\'](?P<target>[^"\']+)["\']\s*\)',
    re.MULTILINE,
)
_PY_FROM_IMPORT = re.compile(
    r'^\s*from\s+(?P<target>[.a-zA-Z0-9_]+)\s+import\s+(?P<bindings>[a-zA-Z0-9_., ]+)',
    re.MULTILINE,
)
_PY_IMPORT = re.compile(
    r'^\s*import\s+(?P<bindings>[a-zA-Z0-9_., ]+)',
    re.MULTILINE,
)
_JS_EXPORT_PATTERNS: Dict[str, Sequence[re.Pattern[str]]] = {
    "javascript": (
        re.compile(r'export\s+(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\('),
        re.compile(r'export\s+(?:const|let|var|class)\s+([A-Za-z_]\w*)\b'),
        re.compile(r'exports\.([A-Za-z_]\w*)\s*='),
    ),
    "typescript": (
        re.compile(r'export\s+(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\('),
        re.compile(r'export\s+(?:const|let|var|class|interface|type)\s+([A-Za-z_]\w*)\b'),
        re.compile(r'exports\.([A-Za-z_]\w*)\s*='),
    ),
}
_JS_MODULE_EXPORT_OBJECT = re.compile(
    r'module\.exports\s*=\s*{(?P<bindings>[^}]+)}',
    re.DOTALL,
)
_CALL_NAME_PATTERN = re.compile(r'(?<![\w.])([A-Za-z_]\w*)\s*\(')
_QUALIFIED_CALL_PATTERN = re.compile(r'(?<![\w.])([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(')
_CALL_EXCLUDE = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "function",
    "return",
    "typeof",
    "require",
    "import",
    "class",
    "def",
    "lambda",
    "new",
}
_SUSPICIOUS_API_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (re.compile(r'\beval\s*\(', re.IGNORECASE), "eval"),
    (re.compile(r'\bexec\s*\(', re.IGNORECASE), "exec"),
    (re.compile(r'\b(?:IEX|Invoke-Expression)\b', re.IGNORECASE), "Invoke-Expression"),
    (re.compile(r'\bProcess\.Start\b', re.IGNORECASE), "Process.Start"),
    (re.compile(r'\bAssembly\.Load\b', re.IGNORECASE), "Assembly.Load"),
    (re.compile(r'\bos\.system\s*\(', re.IGNORECASE), "os.system"),
    (re.compile(r'\bsubprocess\.(?:Popen|run|call)\b', re.IGNORECASE), "subprocess"),
    (re.compile(r'\brequests\.(?:get|post)\b', re.IGNORECASE), "requests"),
)
_OBFUSCATION_SIGNAL_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (re.compile(r'\b_0x[a-fA-F0-9]{3,}\b'), "_0x_identifiers"),
    (re.compile(r'String\.fromCharCode', re.IGNORECASE), "charcode_builder"),
    (re.compile(r'\b(?:atob|btoa)\s*\(', re.IGNORECASE), "base64_runtime"),
    (re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'), "hex_escapes"),
    (re.compile(r'[A-Za-z0-9+/]{48,}={0,2}'), "base64_blob"),
    (re.compile(r'\b(?:decrypt|decode|unwrap|unpack|xor)\w*\b', re.IGNORECASE), "decoder_terms"),
    (re.compile(r'\b(?:EncodedCommand|enc)\b', re.IGNORECASE), "powershell_encoded_command"),
    (re.compile(r'\bmarshal\.loads\b', re.IGNORECASE), "python_marshal"),
)
_JS_TS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 4)


def _workspace_language_support(
    *,
    indexed_languages: Counter,
    bundled_languages: Counter,
) -> Dict[str, Any]:
    supported = {
        str(language): int(count)
        for language, count in indexed_languages.items()
        if str(language) in WORKSPACE_DEOBFUSCATION_LANGUAGES and int(count) > 0
    }
    unsupported = {
        str(language): int(count)
        for language, count in indexed_languages.items()
        if str(language) not in WORKSPACE_DEOBFUSCATION_LANGUAGES and int(count) > 0
    }
    supported_file_count = sum(supported.values())
    bundled_supported_file_count = sum(
        int(count)
        for language, count in bundled_languages.items()
        if str(language) in WORKSPACE_DEOBFUSCATION_LANGUAGES and int(count) > 0
    )
    indexed_file_count = sum(int(count) for count in indexed_languages.values())
    bundled_file_count = sum(int(count) for count in bundled_languages.values())
    return {
        "supported_languages": sorted(supported),
        "unsupported_languages": sorted(unsupported),
        "supported_file_count": supported_file_count,
        "unsupported_file_count": sum(unsupported.values()),
        "bundled_supported_file_count": bundled_supported_file_count,
        "bundle_coverage_ratio": _safe_ratio(bundled_file_count, indexed_file_count),
        "supported_bundle_coverage_ratio": _safe_ratio(
            bundled_supported_file_count,
            supported_file_count,
        ),
        "coverage_scope_note": (
            "Coverage is scoped to supported JS/TS/Python/PowerShell files that were indexed "
            "and swept for recovery across iterative workspace batches. Unsupported languages "
            "remain visible in the scan but are excluded from adjusted recovery confidence."
        ),
    }


def _parsed_from_archive_source(state: dict) -> List[ParsedWorkspaceFile]:
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
                max_scan_files=getattr(settings, "MAX_ARCHIVE_SCAN_FILES", 0) or None,
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


def _clean_import_target(raw: str) -> str:
    value = str(raw).strip().strip("'\"")
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]
    return value.strip()


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
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
    if len(parts) >= 2 and parts[0].lower() in {"apps", "packages", "services", "libs", "modules"}:
        return "/".join(parts[:2])
    if parts:
        return parts[0]
    return value


def _build_python_module_index(files: Sequence[ParsedWorkspaceFile]) -> Dict[str, str]:
    index: Dict[str, str] = {}
    for file in files:
        if file.language != "python":
            continue
        path = PurePosixPath(file.path)
        if path.name == "__init__.py":
            module_name = ".".join(path.parent.parts)
        else:
            module_name = ".".join(path.with_suffix("").parts)
        if module_name:
            index[module_name] = file.path
    return index


def _candidate_js_paths(source_path: str, raw_import: str) -> List[str]:
    base_value = raw_import.lstrip("/")
    if raw_import.startswith("."):
        base = PurePosixPath(source_path).parent.joinpath(raw_import)
    else:
        base = PurePosixPath(base_value)

    base_candidates = [base.as_posix()]
    trimmed_relative = re.sub(r"^(?:\.\./)+", "", raw_import).lstrip("./")
    if trimmed_relative:
        base_candidates.append(PurePosixPath(trimmed_relative).as_posix())

    candidates: List[str] = []
    for base_path in base_candidates:
        candidates.append(base_path)
        if PurePosixPath(base_path).suffix:
            continue
        for ext in _JS_TS_EXTENSIONS:
            candidates.append(f"{base_path}{ext}")
        for ext in _JS_TS_EXTENSIONS:
            candidates.append(f"{base_path}/index{ext}")

    return _dedupe_preserve_order(candidates)


def _match_by_suffix(candidate: str, path_set: set[str]) -> Optional[str]:
    if candidate in path_set:
        return candidate
    suffix_matches = sorted(
        path for path in path_set
        if path == candidate or path.endswith(f"/{candidate}")
    )
    if len(suffix_matches) == 1:
        return suffix_matches[0]
    return None


def _safe_json_object(text: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _relative_workspace_reference_candidates(package_root: str, raw_value: str) -> List[str]:
    cleaned = _clean_import_target(raw_value)
    if (
        not cleaned
        or cleaned.startswith("/")
        or cleaned.startswith("#")
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", cleaned)
    ):
        return []

    relative = cleaned[2:] if cleaned.startswith("./") else cleaned
    if not relative:
        return []

    base = PurePosixPath(package_root).joinpath(relative).as_posix() if package_root else relative
    candidates = [base]
    if not PurePosixPath(base).suffix:
        for ext in _JS_TS_EXTENSIONS:
            candidates.append(f"{base}{ext}")
        for ext in _JS_TS_EXTENSIONS:
            candidates.append(f"{base}/index{ext}")
    return _dedupe_preserve_order(candidates)


def _iter_manifest_string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for nested in value.values():
            yield from _iter_manifest_string_values(nested)
        return
    if isinstance(value, list):
        for nested in value:
            yield from _iter_manifest_string_values(nested)


def _package_entry_specs_from_manifest(manifest: Dict[str, Any]) -> List[str]:
    specs: List[str] = []
    for key in ("source", "module", "main", "browser"):
        value = manifest.get(key)
        if isinstance(value, str):
            specs.append(value)

    exports_value = manifest.get("exports")
    specs.extend(_iter_manifest_string_values(exports_value))

    bin_value = manifest.get("bin")
    if isinstance(bin_value, str):
        specs.append(bin_value)
    elif isinstance(bin_value, dict):
        specs.extend(
            str(item)
            for item in bin_value.values()
            if isinstance(item, str)
        )

    return _dedupe_preserve_order(specs)


def _resolve_package_entry_paths(
    *,
    package_root: str,
    manifest: Dict[str, Any],
    path_set: set[str],
    supported_paths: Sequence[str],
) -> List[str]:
    resolved: List[str] = []

    for spec in _package_entry_specs_from_manifest(manifest):
        for candidate in _relative_workspace_reference_candidates(package_root, spec):
            matched = _match_by_suffix(candidate, path_set)
            if matched:
                resolved.append(matched)

    if resolved:
        return _dedupe_preserve_order(resolved)

    fallback_specs = (
        "src/index.ts",
        "src/index.tsx",
        "src/index.js",
        "src/index.jsx",
        "index.ts",
        "index.tsx",
        "index.js",
        "index.jsx",
        "lib/index.js",
        "dist/index.js",
    )
    for spec in fallback_specs:
        for candidate in _relative_workspace_reference_candidates(package_root, spec):
            matched = _match_by_suffix(candidate, path_set)
            if matched:
                resolved.append(matched)

    if resolved:
        return _dedupe_preserve_order(resolved)

    package_prefix = f"{package_root}/" if package_root else ""
    return [
        path
        for path in supported_paths
        if (not package_prefix or path.startswith(package_prefix))
    ][:3]


def _resolve_package_name_import(
    *,
    raw_import: str,
    path_set: set[str],
    local_package_index: Dict[str, Dict[str, Any]],
) -> Optional[str]:
    cleaned = _clean_import_target(raw_import)
    if not cleaned:
        return None

    direct = local_package_index.get(cleaned)
    if isinstance(direct, dict):
        entry_points = [
            str(path).strip()
            for path in direct.get("entry_points", [])
            if str(path).strip()
        ]
        for entry_path in entry_points:
            matched = _match_by_suffix(entry_path, path_set)
            if matched:
                return matched

    for package_name, info in local_package_index.items():
        if cleaned == package_name or not cleaned.startswith(f"{package_name}/"):
            continue
        package_root = str(info.get("root", "")).strip()
        if not package_root:
            continue
        subpath = cleaned[len(package_name) + 1 :]
        for candidate in _relative_workspace_reference_candidates(package_root, subpath):
            matched = _match_by_suffix(candidate, path_set)
            if matched:
                return matched
        for candidate in _relative_workspace_reference_candidates(package_root, f"src/{subpath}"):
            matched = _match_by_suffix(candidate, path_set)
            if matched:
                return matched

    return None


def _order_package_roots(
    *,
    package_infos: Dict[str, Dict[str, Any]],
    root_hints: Sequence[str],
) -> List[str]:
    if not package_infos:
        return []

    package_scores = {
        root: float(info.get("priority_score") or 0.0)
        for root, info in package_infos.items()
    }
    dependency_edges = {
        root: [
            dependency_root
            for dependency_root in info.get("local_dependency_roots", [])
            if dependency_root in package_infos and dependency_root != root
        ]
        for root, info in package_infos.items()
    }
    ordered_roots = _dedupe_preserve_order(
        list(root_hints)
        + sorted(
            package_infos,
            key=lambda root: (-package_scores.get(root, 0.0), root),
        )
    )
    visited: set[str] = set()
    active: set[str] = set()
    result: List[str] = []

    def visit(root: str) -> None:
        if root in visited or root not in package_infos:
            return
        if root in active:
            return
        active.add(root)
        for dependency_root in sorted(
            dependency_edges.get(root, []),
            key=lambda item: (-package_scores.get(item, 0.0), item),
        ):
            visit(dependency_root)
        active.remove(root)
        visited.add(root)
        result.append(root)

    for root in ordered_roots:
        visit(root)
    return result


def _extract_workspace_packages(
    *,
    files: Sequence[ParsedWorkspaceFile],
    package_roots: Sequence[str],
    supported_paths: Sequence[str],
    entry_points: Sequence[str],
    suspicious_files: Sequence[str],
    prioritized_files: Sequence[Dict[str, Any]],
    path_set: set[str],
) -> Dict[str, Any]:
    prioritized_score_by_path = {
        str(item.get("path", "")).strip(): float(item.get("score") or 0.0)
        for item in prioritized_files
        if isinstance(item, dict) and str(item.get("path", "")).strip()
    }
    prioritized_roots = _dedupe_preserve_order(
        _workspace_package_root_for_path(path, package_roots)
        for path in (
            list(entry_points)
            + list(suspicious_files)
            + list(prioritized_score_by_path)
        )
        if str(path).strip()
    )

    package_infos: Dict[str, Dict[str, Any]] = {}
    package_name_index: Dict[str, Dict[str, Any]] = {}

    for file in files:
        if PurePosixPath(file.path).name.lower() != "package.json":
            continue
        manifest = _safe_json_object(file.text)
        if not manifest:
            continue

        manifest_root = PurePosixPath(file.path).parent.as_posix()
        manifest_root = "" if manifest_root == "." else manifest_root
        package_root = (
            _workspace_package_root_for_path(manifest_root, package_roots)
            if manifest_root
            else ""
        )
        supported_in_package = [
            path
            for path in supported_paths
            if (
                (not package_root)
                or path == package_root
                or path.startswith(f"{package_root}/")
            )
        ]
        if not supported_in_package and manifest.get("workspaces"):
            continue

        package_name = str(manifest.get("name") or "").strip()
        package_entry_points = _resolve_package_entry_paths(
            package_root=package_root,
            manifest=manifest,
            path_set=path_set,
            supported_paths=supported_in_package,
        )
        package_hotspots = _dedupe_preserve_order(
            package_entry_points
            + [
                path
                for path in list(entry_points) + list(suspicious_files) + list(prioritized_score_by_path)
                if _workspace_package_root_for_path(path, package_roots) == package_root
            ]
            + supported_in_package[:6]
        )[:8]
        package_infos[package_root] = {
            "root": package_root,
            "name": package_name or package_root,
            "manifest_path": file.path,
            "entry_points": package_entry_points,
            "hotspot_paths": package_hotspots,
            "supported_file_count": len(supported_in_package),
            "suspicious_file_count": sum(
                1
                for path in suspicious_files
                if _workspace_package_root_for_path(path, package_roots) == package_root
            ),
            "entrypoint_file_count": sum(
                1
                for path in entry_points
                if _workspace_package_root_for_path(path, package_roots) == package_root
            ),
            "top_file_score": round(
                sum(
                    prioritized_score_by_path.get(path, 0.0)
                    for path in package_hotspots[:3]
                ),
                2,
            ),
            "manifest": manifest,
        }
        if package_name:
            package_name_index[package_name] = {
                "root": package_root,
                "manifest_path": file.path,
                "entry_points": package_entry_points,
            }

    if not package_infos:
        return {
            "workspace_packages": [],
            "package_dependency_edges": [],
            "package_priority_roots": [],
            "package_dependency_hotspots": [],
            "package_entry_points_by_root": {},
            "package_hotspot_paths_by_root": {},
            "local_package_index": {},
        }

    package_edges: List[Dict[str, Any]] = []
    dependent_counts: Counter[str] = Counter()
    for package_root, info in package_infos.items():
        manifest = info.get("manifest", {})
        local_dependency_names = _dedupe_preserve_order(
            dependency_name
            for section_name in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            )
            for dependency_name in (
                (manifest.get(section_name) or {}).keys()
                if isinstance(manifest.get(section_name), dict)
                else []
            )
            if dependency_name in package_name_index
            and package_name_index[dependency_name]["root"] != package_root
        )
        local_dependency_roots = [
            str(package_name_index[dependency_name]["root"]).strip()
            for dependency_name in local_dependency_names
        ]
        for dependency_name, dependency_root in zip(local_dependency_names, local_dependency_roots):
            package_edges.append(
                {
                    "source_root": package_root,
                    "source_name": info.get("name", package_root),
                    "target_root": dependency_root,
                    "target_name": dependency_name,
                    "kind": "workspace_local",
                }
            )
            dependent_counts[dependency_root] += 1
        info["local_dependency_names"] = local_dependency_names
        info["local_dependency_roots"] = _dedupe_preserve_order(local_dependency_roots)

    for package_root, info in package_infos.items():
        dependent_count = int(dependent_counts.get(package_root, 0))
        local_dependency_count = len(info.get("local_dependency_roots", []))
        priority_score = (
            dependent_count * 3.1
            + float(info.get("suspicious_file_count") or 0) * 2.2
            + float(info.get("entrypoint_file_count") or 0) * 1.8
            + min(float(info.get("top_file_score") or 0.0) * 0.2, 5.0)
            + min(float(info.get("supported_file_count") or 0) * 0.18, 1.8)
        )
        info["dependent_count"] = dependent_count
        info["local_dependency_count"] = local_dependency_count
        info["priority_score"] = round(priority_score, 2)

    ordered_package_roots = _order_package_roots(
        package_infos=package_infos,
        root_hints=prioritized_roots + list(package_roots),
    )
    workspace_packages = [
        {
            key: value
            for key, value in info.items()
            if key != "manifest"
        }
        for root in ordered_package_roots
        for info in [package_infos[root]]
    ]

    return {
        "workspace_packages": workspace_packages[:24],
        "package_dependency_edges": package_edges[:96],
        "package_priority_roots": ordered_package_roots[:24],
        "package_dependency_hotspots": [
            root
            for root in ordered_package_roots
            if int(package_infos[root].get("dependent_count") or 0)
            or int(package_infos[root].get("suspicious_file_count") or 0)
        ][:16],
        "package_entry_points_by_root": {
            root: list(package_infos[root].get("entry_points", []))[:8]
            for root in ordered_package_roots
            if package_infos[root].get("entry_points")
        },
        "package_hotspot_paths_by_root": {
            root: list(package_infos[root].get("hotspot_paths", []))[:8]
            for root in ordered_package_roots
            if package_infos[root].get("hotspot_paths")
        },
        "local_package_index": package_name_index,
    }


def _resolve_python_import(
    *,
    source_path: str,
    raw_import: str,
    module_index: Dict[str, str],
) -> Optional[str]:
    if raw_import in module_index:
        return module_index[raw_import]

    if raw_import.startswith("."):
        level = len(raw_import) - len(raw_import.lstrip("."))
        remainder = raw_import[level:]
        source = PurePosixPath(source_path)
        if source.name == "__init__.py":
            package_parts = list(source.parent.parts)
        else:
            package_parts = list(source.with_suffix("").parts[:-1])
        if level > 1:
            trim = min(level - 1, len(package_parts))
            package_parts = package_parts[:-trim]
        remainder_parts = [part for part in remainder.split(".") if part]
        candidate_module = ".".join(package_parts + remainder_parts)
        if candidate_module in module_index:
            return module_index[candidate_module]
        if not remainder_parts:
            package_only = ".".join(package_parts)
            if package_only in module_index:
                return module_index[package_only]

    suffix_matches = sorted(
        path for module_name, path in module_index.items()
        if module_name.endswith(raw_import)
    )
    if len(suffix_matches) == 1:
        return suffix_matches[0]
    return None


def _resolve_import_target(
    *,
    source_path: str,
    raw_import: str,
    language: str,
    path_set: set[str],
    python_modules: Dict[str, str],
    local_package_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[str]:
    cleaned = _clean_import_target(raw_import)
    if not cleaned:
        return None

    lang = (language or "").lower()
    if lang in {"javascript", "typescript"}:
        for candidate in _candidate_js_paths(source_path, cleaned):
            matched = _match_by_suffix(candidate, path_set)
            if matched:
                return matched
        if local_package_index:
            matched = _resolve_package_name_import(
                raw_import=cleaned,
                path_set=path_set,
                local_package_index=local_package_index,
            )
            if matched:
                return matched
        return None

    if lang == "python":
        return _resolve_python_import(
            source_path=source_path,
            raw_import=cleaned,
            module_index=python_modules,
        )

    return _match_by_suffix(cleaned, path_set)


def _count_pattern_hits(patterns: Sequence[Tuple[re.Pattern[str], str]], text: str) -> Tuple[int, List[str]]:
    hits = 0
    labels: List[str] = []
    excerpt = text[:25_000]
    for pattern, label in patterns:
        if pattern.search(excerpt):
            hits += 1
            labels.append(label)
    return hits, labels


def _parse_js_named_bindings(raw: str) -> List[Tuple[str, str]]:
    bindings: List[Tuple[str, str]] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        if " as " in value:
            source_symbol, local_name = [item.strip() for item in value.split(" as ", 1)]
        else:
            source_symbol = value
            local_name = value
        if source_symbol and local_name:
            bindings.append((source_symbol, local_name))
    return bindings


def _parse_destructured_bindings(raw: str) -> List[Tuple[str, str]]:
    bindings: List[Tuple[str, str]] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        if ":" in value:
            source_symbol, local_name = [item.strip() for item in value.split(":", 1)]
        else:
            source_symbol = value
            local_name = value
        if source_symbol and local_name:
            bindings.append((source_symbol, local_name))
    return bindings


def _parse_python_from_import_bindings(raw: str) -> List[Tuple[str, str]]:
    bindings: List[Tuple[str, str]] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        if " as " in value:
            source_symbol, local_name = [item.strip() for item in value.split(" as ", 1)]
        else:
            source_symbol = value
            local_name = value
        if source_symbol and local_name:
            bindings.append((source_symbol, local_name))
    return bindings


def _parse_python_import_entries(raw: str) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        if " as " in value:
            target, local_name = [item.strip() for item in value.split(" as ", 1)]
        else:
            target = value
            local_name = value.split(".")[-1]
        if target and local_name:
            entries.append((target, local_name))
    return entries


def _extract_defined_symbols(file: ParsedWorkspaceFile) -> List[str]:
    symbols: List[str] = []
    for pattern in _FUNCTION_PATTERNS.get(file.language, ()):
        for match in pattern.findall(file.text[:30_000]):
            value = match[0] if isinstance(match, tuple) else match
            symbol = str(value).strip()
            if symbol:
                symbols.append(symbol)
    return _dedupe_preserve_order(symbols)


def _extract_exported_symbols(file: ParsedWorkspaceFile) -> List[str]:
    symbols: List[str] = []
    lang = (file.language or "").lower()
    for pattern in _JS_EXPORT_PATTERNS.get(lang, ()):
        for match in pattern.findall(file.text[:30_000]):
            value = match[0] if isinstance(match, tuple) else match
            symbol = str(value).strip()
            if symbol:
                symbols.append(symbol)
    if lang == "python":
        symbols.extend(_extract_defined_symbols(file))
    elif lang in {"javascript", "typescript"}:
        for match in _JS_MODULE_EXPORT_OBJECT.finditer(file.text[:30_000]):
            symbols.extend(
                local_name
                for _, local_name in _parse_destructured_bindings(match.group("bindings"))
            )
    return _dedupe_preserve_order(symbols)


def _extract_import_metadata(
    *,
    file: ParsedWorkspaceFile,
    path_set: set[str],
    python_modules: Dict[str, str],
    local_package_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[List[str], List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    imports: List[str] = []
    import_edges: List[Dict[str, Any]] = []
    binding_map: Dict[str, Dict[str, Any]] = {}
    seen_import_keys: set[Tuple[str, Optional[str], Optional[str], Optional[str], str]] = set()

    def record_import(
        raw_target: str,
        *,
        binding_name: Optional[str] = None,
        source_symbol: Optional[str] = None,
        kind: str = "generic",
        qualified_calls: bool = False,
    ) -> None:
        cleaned = _clean_import_target(raw_target)
        if not cleaned:
            return
        resolved = _resolve_import_target(
            source_path=file.path,
            raw_import=cleaned,
            language=file.language,
            path_set=path_set,
            python_modules=python_modules,
            local_package_index=local_package_index,
        )
        key = (cleaned, resolved, binding_name, source_symbol, kind)
        if key not in seen_import_keys:
            seen_import_keys.add(key)
            label = f"{file.path} -> {cleaned}"
            if resolved:
                label += f" [{resolved}]"
            imports.append(label)
            import_edges.append(
                {
                    "source": file.path,
                    "raw": cleaned,
                    "resolved": resolved,
                    "kind": "local" if resolved else "external",
                    "binding": binding_name,
                    "symbol": source_symbol,
                    "import_kind": kind,
                }
            )
        if binding_name and resolved:
            binding_map[binding_name] = {
                "resolved": resolved,
                "source_symbol": source_symbol,
                "qualified_calls": qualified_calls,
                "kind": kind,
            }

    if file.language in {"javascript", "typescript"}:
        for match in _JS_NAMED_IMPORT.finditer(file.text[:20_000]):
            target = match.group("target")
            for source_symbol, local_name in _parse_js_named_bindings(match.group("bindings")):
                record_import(
                    target,
                    binding_name=local_name,
                    source_symbol=source_symbol,
                    kind="named",
                )
        for match in _JS_NAMESPACE_IMPORT.finditer(file.text[:20_000]):
            record_import(
                match.group("target"),
                binding_name=match.group("binding"),
                kind="namespace",
                qualified_calls=True,
            )
        for match in _JS_DEFAULT_IMPORT.finditer(file.text[:20_000]):
            record_import(
                match.group("target"),
                binding_name=match.group("binding"),
                source_symbol="default",
                kind="default",
                qualified_calls=True,
            )
        for match in _JS_REQUIRE_BINDING.finditer(file.text[:20_000]):
            record_import(
                match.group("target"),
                binding_name=match.group("binding"),
                source_symbol="default",
                kind="require",
                qualified_calls=True,
            )
        for match in _JS_REQUIRE_DESTRUCT.finditer(file.text[:20_000]):
            target = match.group("target")
            for source_symbol, local_name in _parse_destructured_bindings(match.group("bindings")):
                record_import(
                    target,
                    binding_name=local_name,
                    source_symbol=source_symbol,
                    kind="require_destructured",
                )

    if file.language == "python":
        for match in _PY_FROM_IMPORT.finditer(file.text[:20_000]):
            target = match.group("target")
            for source_symbol, local_name in _parse_python_from_import_bindings(match.group("bindings")):
                record_import(
                    target,
                    binding_name=local_name,
                    source_symbol=source_symbol,
                    kind="from_import",
                )
        for match in _PY_IMPORT.finditer(file.text[:20_000]):
            for target, local_name in _parse_python_import_entries(match.group("bindings")):
                record_import(
                    target,
                    binding_name=local_name,
                    kind="module_alias",
                    qualified_calls=True,
                )

    for pattern in _IMPORT_PATTERNS.get(file.language, ()):
        for match in pattern.findall(file.text[:20_000]):
            if isinstance(match, tuple):
                match = match[0]
            for item in str(match).split(","):
                record_import(item, kind="generic")

    return imports, import_edges, binding_map


def _extract_cross_file_call_edges(
    *,
    file: ParsedWorkspaceFile,
    binding_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    direct_calls = Counter(
        match.group(1)
        for match in _CALL_NAME_PATTERN.finditer(file.text[:25_000])
        if match.group(1) not in _CALL_EXCLUDE
    )
    qualified_calls = Counter(
        (match.group(1), match.group(2))
        for match in _QUALIFIED_CALL_PATTERN.finditer(file.text[:25_000])
        if match.group(1) not in _CALL_EXCLUDE and match.group(2) not in _CALL_EXCLUDE
    )

    aggregated: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for binding_name, count in direct_calls.items():
        info = binding_map.get(binding_name)
        if not info or not info.get("resolved"):
            continue
        symbol = info.get("source_symbol")
        if not symbol or symbol == "default":
            symbol = binding_name
        aggregated[(file.path, str(info["resolved"]), str(symbol), "direct")] = {
            "source": file.path,
            "target": info["resolved"],
            "symbol": symbol,
            "count": count,
            "call_style": "direct",
        }

    for (qualifier, member), count in qualified_calls.items():
        info = binding_map.get(qualifier)
        if not info or not info.get("resolved") or not info.get("qualified_calls"):
            continue
        aggregated[(file.path, str(info["resolved"]), member, "qualified")] = {
            "source": file.path,
            "target": info["resolved"],
            "symbol": member,
            "count": count,
            "call_style": "qualified",
        }

    return list(aggregated.values())


def _build_execution_paths(
    *,
    start_paths: Sequence[str],
    call_edges: Sequence[Dict[str, Any]],
    max_paths: int = 8,
    max_depth: int = 4,
) -> List[str]:
    adjacency: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        adjacency[str(edge.get("source", ""))].append(edge)

    execution_paths: List[str] = []
    queue: List[Tuple[str, List[str], int]] = [
        (path, [path], 0)
        for path in _dedupe_preserve_order(start_paths)
        if path
    ]

    while queue and len(execution_paths) < max_paths:
        current, segments, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        visited_paths = {segment.split("::", 1)[0] for segment in segments}
        for edge in adjacency.get(current, [])[:8]:
            target = str(edge.get("target", "")).strip()
            symbol = str(edge.get("symbol", "")).strip()
            if not target or target in visited_paths:
                continue
            next_label = f"{target}::{symbol}" if symbol else target
            rendered = " -> ".join(segments + [next_label])
            if rendered not in execution_paths:
                execution_paths.append(rendered)
            queue.append((target, segments + [next_label], depth + 1))
            if len(execution_paths) >= max_paths:
                break

    return execution_paths


def _summarise_priority(
    file: ParsedWorkspaceFile,
    *,
    entry_points: set[str],
    suspicious_files: set[str],
    outbound_local: int,
    inbound_local: int,
    outbound_calls: int,
    inbound_calls: int,
    suspicious_api_hits: int,
    obfuscation_hits: int,
    function_count: int,
    exported_symbol_count: int,
) -> Dict[str, Any]:
    score = 0.0
    reasons: List[str] = []

    if "suspicious" in file.priority or file.path in suspicious_files:
        score += 6.0
        reasons.append("suspicious")
    if "entrypoint" in file.priority or file.path in entry_points:
        score += 4.5
        reasons.append("entrypoint")
    if "manifest" in file.priority:
        score += 1.2
        reasons.append("manifest")
    if inbound_local:
        score += min(inbound_local * 1.4, 4.8)
        reasons.append("inbound_dependencies")
    if outbound_local:
        score += min(outbound_local * 1.0, 3.5)
        reasons.append("outbound_dependencies")
    if inbound_calls:
        score += min(inbound_calls * 1.7, 5.1)
        reasons.append("cross_file_call_target")
    if outbound_calls:
        score += min(outbound_calls * 1.1, 3.3)
        reasons.append("cross_file_calls")
    if suspicious_api_hits:
        score += min(suspicious_api_hits * 1.5, 4.5)
        reasons.append("suspicious_api")
    if obfuscation_hits:
        score += min(obfuscation_hits * 1.2, 4.5)
        reasons.append("obfuscation_signals")
    if function_count:
        score += min(function_count * 0.15, 1.5)
    if exported_symbol_count:
        score += min(exported_symbol_count * 0.18, 1.4)

    if not reasons:
        reasons.append("bundled_order")

    return {
        "path": file.path,
        "language": file.language,
        "score": round(score, 2),
        "reasons": reasons,
        "priority_tags": list(file.priority),
        "inbound_edges": inbound_local,
        "outbound_edges": outbound_local,
        "cross_file_call_in": inbound_calls,
        "cross_file_call_out": outbound_calls,
        "suspicious_api_hits": suspicious_api_hits,
        "obfuscation_signal_hits": obfuscation_hits,
        "function_count": function_count,
        "exported_symbol_count": exported_symbol_count,
    }


class WorkspaceProfiler(BaseTransform):
    """Extract high-signal workspace metadata from a bundled codebase sample."""

    name = "WorkspaceProfiler"
    description = "Profile bundled workspace files, imports, entrypoints, and symbols."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(extract_workspace_context(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        context = extract_workspace_context(code)
        bundled_files = parse_workspace_bundle(code)
        archive_files = _parsed_from_archive_source(state)
        files = overlay_workspace_files(code, archive_files) if archive_files else bundled_files
        if not context or not bundled_files:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Input is not a parseable workspace bundle.",
                details={},
            )

        path_set = {file.path for file in files}
        bundled_path_set = {file.path for file in bundled_files}
        python_modules = _build_python_module_index(files)
        supported_paths = [
            file.path
            for file in files
            if file.language in WORKSPACE_DEOBFUSCATION_LANGUAGES
        ]
        package_roots = list(context.get("package_roots", []) or context.get("root_dirs", []))
        imports: List[str] = []
        import_edges: List[Dict[str, Any]] = []
        functions: List[str] = []
        suspicious_apis: List[str] = []
        evidence_references: List[str] = []
        local_inbound: Dict[str, int] = defaultdict(int)
        local_outbound: Dict[str, int] = defaultdict(int)
        call_inbound: Dict[str, int] = defaultdict(int)
        call_outbound: Dict[str, int] = defaultdict(int)
        function_counts: Dict[str, int] = defaultdict(int)
        suspicious_api_counts: Dict[str, int] = defaultdict(int)
        obfuscation_signal_counts: Dict[str, int] = defaultdict(int)
        defined_symbols_by_file: Dict[str, List[str]] = {}
        exported_symbols_by_file: Dict[str, List[str]] = {}
        cross_file_call_edges: List[Dict[str, Any]] = []
        counted_local_dependencies: set[Tuple[str, str]] = set()

        for file in files:
            evidence_references.append(file.path)
            defined_symbols = _extract_defined_symbols(file)
            exported_symbols = _extract_exported_symbols(file)
            defined_symbols_by_file[file.path] = defined_symbols
            exported_symbols_by_file[file.path] = exported_symbols
            for symbol in defined_symbols:
                functions.append(f"{file.path}::{symbol}")
            function_counts[file.path] = len(defined_symbols)

            for pattern, label in _SUSPICIOUS_API_PATTERNS:
                if pattern.search(file.text[:25_000]):
                    suspicious_apis.append(f"{label} @ {file.path}")
                    suspicious_api_counts[file.path] += 1

            obfuscation_hits, _ = _count_pattern_hits(_OBFUSCATION_SIGNAL_PATTERNS, file.text)
            if obfuscation_hits:
                obfuscation_signal_counts[file.path] += obfuscation_hits

        root_dirs = list(context.get("root_dirs", []))
        entry_points = list(context.get("entry_points", []))
        manifest_files = list(context.get("manifest_files", []))
        suspicious_files = list(context.get("suspicious_files", []))
        languages_counter = Counter(file.language for file in files)
        bundled_languages_counter = Counter(file.language for file in bundled_files)
        language_support = _workspace_language_support(
            indexed_languages=languages_counter,
            bundled_languages=bundled_languages_counter,
        )

        prioritized_files = sorted(
            (
                _summarise_priority(
                    file,
                    entry_points=set(entry_points),
                    suspicious_files=set(suspicious_files),
                    outbound_local=local_outbound[file.path],
                    inbound_local=local_inbound[file.path],
                    outbound_calls=call_outbound[file.path],
                    inbound_calls=call_inbound[file.path],
                    suspicious_api_hits=suspicious_api_counts[file.path],
                    obfuscation_hits=obfuscation_signal_counts[file.path],
                    function_count=function_counts[file.path],
                    exported_symbol_count=len(exported_symbols_by_file.get(file.path, [])),
                )
                for file in files
            ),
            key=lambda item: (-float(item["score"]), item["path"]),
        )[:32]
        package_summary = _extract_workspace_packages(
            files=files,
            package_roots=package_roots,
            supported_paths=supported_paths,
            entry_points=entry_points,
            suspicious_files=suspicious_files,
            prioritized_files=prioritized_files,
            path_set=path_set,
        )
        local_package_index = package_summary["local_package_index"]

        imports.clear()
        import_edges.clear()
        local_inbound.clear()
        local_outbound.clear()
        call_inbound.clear()
        call_outbound.clear()
        cross_file_call_edges.clear()
        counted_local_dependencies.clear()

        for file in files:
            file_imports, file_import_edges, binding_map = _extract_import_metadata(
                file=file,
                path_set=path_set,
                python_modules=python_modules,
                local_package_index=local_package_index,
            )
            imports.extend(file_imports)
            import_edges.extend(file_import_edges)
            for edge in file_import_edges:
                if edge["kind"] == "local" and edge.get("resolved"):
                    dependency_key = (file.path, str(edge["resolved"]))
                    if dependency_key in counted_local_dependencies:
                        continue
                    counted_local_dependencies.add(dependency_key)
                    local_outbound[file.path] += 1
                    local_inbound[str(edge["resolved"])] += 1

            file_call_edges = _extract_cross_file_call_edges(
                file=file,
                binding_map=binding_map,
            )
            cross_file_call_edges.extend(file_call_edges)
            for edge in file_call_edges:
                source = str(edge.get("source", "")).strip()
                target = str(edge.get("target", "")).strip()
                count = int(edge.get("count", 1) or 1)
                if source:
                    call_outbound[source] += count
                if target:
                    call_inbound[target] += count

        prioritized_files = sorted(
            (
                _summarise_priority(
                    file,
                    entry_points=set(entry_points),
                    suspicious_files=set(suspicious_files),
                    outbound_local=local_outbound[file.path],
                    inbound_local=local_inbound[file.path],
                    outbound_calls=call_outbound[file.path],
                    inbound_calls=call_inbound[file.path],
                    suspicious_api_hits=suspicious_api_counts[file.path],
                    obfuscation_hits=obfuscation_signal_counts[file.path],
                    function_count=function_counts[file.path],
                    exported_symbol_count=len(exported_symbols_by_file.get(file.path, [])),
                )
                for file in files
            ),
            key=lambda item: (-float(item["score"]), item["path"]),
        )[:32]
        package_summary = _extract_workspace_packages(
            files=files,
            package_roots=package_roots,
            supported_paths=supported_paths,
            entry_points=entry_points,
            suspicious_files=suspicious_files,
            prioritized_files=prioritized_files,
            path_set=path_set,
        )

        dependency_hotspots = [
            item["path"]
            for item in prioritized_files[:12]
            if item["inbound_edges"] or item["outbound_edges"] or item["reasons"] != ["bundled_order"]
        ]
        symbol_hotspots = [
            item["path"]
            for item in prioritized_files[:12]
            if item["cross_file_call_in"] or item["cross_file_call_out"] or item["exported_symbol_count"]
        ]
        expansion_candidates = [
            item["path"]
            for item in prioritized_files
            if item["path"] not in bundled_path_set
        ][:24]
        unique_local_edges: List[Dict[str, Any]] = []
        unique_external_edges: List[Dict[str, Any]] = []
        seen_local_edges: set[Tuple[str, str]] = set()
        seen_external_edges: set[Tuple[str, str]] = set()
        for edge in import_edges:
            source = str(edge.get("source", "")).strip()
            kind = str(edge.get("kind", "")).strip()
            resolved = str(edge.get("resolved", "")).strip()
            raw = str(edge.get("raw", "")).strip()
            target_key = resolved or raw
            if not source or not target_key:
                continue
            edge_key = (source, target_key)
            if kind == "local":
                if edge_key in seen_local_edges:
                    continue
                seen_local_edges.add(edge_key)
                unique_local_edges.append(edge)
            elif kind == "external":
                if edge_key in seen_external_edges:
                    continue
                seen_external_edges.add(edge_key)
                unique_external_edges.append(edge)

        local_edges = unique_local_edges[:64]
        external_edges = unique_external_edges[:64]
        execution_paths = _build_execution_paths(
            start_paths=entry_points or suspicious_files or dependency_hotspots,
            call_edges=cross_file_call_edges,
        )

        detected_techniques = ["workspace_bundle"]
        if len(root_dirs) > 1:
            detected_techniques.append("monorepo_bundle")
        if entry_points:
            detected_techniques.append("entrypoint_ranked")
        if suspicious_files:
            detected_techniques.append("cross_file_obfuscation_candidate")
        if local_edges:
            detected_techniques.append("import_graph_resolved")
        if cross_file_call_edges:
            detected_techniques.append("cross_file_call_graph")
        if dependency_hotspots or symbol_hotspots:
            detected_techniques.append("workspace_hotspots_ranked")
        if package_summary["workspace_packages"]:
            detected_techniques.append("package_manifest_profiled")
        if package_summary["package_dependency_edges"]:
            detected_techniques.append("monorepo_package_graph")

        summary_parts = [
            f"Workspace codebase with {len(files)} indexed file(s)",
            f"{len(entry_points)} likely entrypoint(s)",
            f"{len(suspicious_files)} suspicious file(s)",
            f"{len(local_edges)} local dependency edge(s)",
        ]
        if package_summary["workspace_packages"]:
            summary_parts.append(
                f"{len(package_summary['workspace_packages'])} workspace package(s)"
            )
        if package_summary["package_dependency_edges"]:
            summary_parts.append(
                f"{len(package_summary['package_dependency_edges'])} package dependency edge(s)"
            )
        if archive_files:
            summary_parts.append(f"{len(bundled_files)} file(s) currently bundled")
        if cross_file_call_edges:
            summary_parts.append(f"{len(cross_file_call_edges)} cross-file call edge(s)")
        if manifest_files:
            summary_parts.append(f"{len(manifest_files)} manifest/config file(s)")
        hotspot_preview = dependency_hotspots[:2] + [
            path for path in symbol_hotspots[:2] if path not in dependency_hotspots[:2]
        ]
        if hotspot_preview:
            summary_parts.append(
                "hotspots: " + " | ".join(hotspot_preview[:3])
            )
        summary = ". ".join(summary_parts) + "."

        analysis_frontier = [item["path"] for item in prioritized_files[:32]]
        supported_frontier_count = sum(
            1
            for item in prioritized_files[:32]
            if str(item.get("language", "")).strip() in WORKSPACE_DEOBFUSCATION_LANGUAGES
        )
        remaining_supported_preview = _dedupe_preserve_order(
            [
                item["path"]
                for item in prioritized_files
                if str(item.get("language", "")).strip() in WORKSPACE_DEOBFUSCATION_LANGUAGES
            ]
            + supported_paths
        )[:24]
        workspace_pass_count_estimate = (
            max(
                1,
                (
                    len(supported_paths)
                    + max(1, int(getattr(settings, "MAX_WORKSPACE_TARGET_FILES", 28)))
                    - 1
                )
                // max(1, int(getattr(settings, "MAX_WORKSPACE_TARGET_FILES", 28))),
            )
            if supported_paths else 0
        )

        workspace_context = {
            **context,
            "files_preview": workspace_files_preview(code, max_files=16),
            "indexed_file_count": len(files),
            "bundled_file_count": len(bundled_files),
            "indexed_from_archive": bool(archive_files),
            "imports_count": len(imports),
            "functions_count": len(functions),
            "languages_by_file": dict(languages_counter),
            **language_support,
            "prioritized_files": prioritized_files,
            "analysis_frontier": analysis_frontier,
            "supported_frontier_count": supported_frontier_count,
            "dependency_hotspots": dependency_hotspots,
            "symbol_hotspots": symbol_hotspots,
            "bundle_expansion_paths": expansion_candidates,
            "remaining_frontier_paths": expansion_candidates[:],
            "llm_focus_paths": _dedupe_preserve_order(
                dependency_hotspots[:6]
                + symbol_hotspots[:6]
                + expansion_candidates[:6]
                + entry_points[:4]
                + suspicious_files[:4]
            )[:10],
            "local_dependency_edges": local_edges,
            "external_dependency_edges": external_edges,
            "cross_file_call_edges": cross_file_call_edges[:96],
            "execution_paths": execution_paths[:8],
            "defined_symbols": [
                {"path": path, "symbols": symbols[:10]}
                for path, symbols in list(defined_symbols_by_file.items())[:16]
                if symbols
            ],
            "exported_symbols": [
                {"path": path, "symbols": symbols[:10]}
                for path, symbols in list(exported_symbols_by_file.items())[:16]
                if symbols
            ],
            "local_dependency_count": len(local_edges),
            "external_dependency_count": len(external_edges),
            "cross_file_call_count": len(cross_file_call_edges),
            "package_roots": context.get("package_roots", []),
            "workspace_packages": package_summary["workspace_packages"],
            "package_dependency_edges": package_summary["package_dependency_edges"],
            "package_priority_roots": package_summary["package_priority_roots"],
            "package_dependency_hotspots": package_summary["package_dependency_hotspots"],
            "package_entry_points_by_root": package_summary["package_entry_points_by_root"],
            "package_hotspot_paths_by_root": package_summary["package_hotspot_paths_by_root"],
            "local_package_index": package_summary["local_package_index"],
            "processed_supported_file_count": 0,
            "remaining_supported_file_count": len(supported_paths),
            "remaining_supported_paths_preview": remaining_supported_preview,
            "processed_package_count": 0,
            "remaining_package_roots": (
                package_summary["package_priority_roots"][:12]
                or package_roots[:12]
            ),
            "workspace_pass_index": 0,
            "workspace_pass_count_estimate": workspace_pass_count_estimate,
            "unbundled_hotspots": expansion_candidates[:12],
            "graph_summary": {
                "indexed_files": len(files),
                "bundled_files": len(bundled_files),
                "local_edges": len(local_edges),
                "external_edges": len(external_edges),
                "cross_file_calls": len(cross_file_call_edges),
                "execution_paths": len(execution_paths),
                "bundle_expansion_candidates": len(expansion_candidates),
                "workspace_packages": len(package_summary["workspace_packages"]),
                "package_dependency_edges": len(package_summary["package_dependency_edges"]),
                "hotspots": _dedupe_preserve_order(dependency_hotspots + symbol_hotspots)[:8],
            },
        }

        return TransformResult(
            success=True,
            output=code,
            confidence=0.88,
            description=summary,
            details={
                "workspace_context": workspace_context,
                "entry_points": entry_points[:12],
                "imports": _dedupe_preserve_order(imports)[:80],
                "import_edges": import_edges[:96],
                "functions": functions[:80],
                "suspicious_apis": sorted(set(suspicious_apis))[:30],
                "detected_techniques": detected_techniques,
                "evidence_references": evidence_references[:96],
                "summary": summary,
            },
        )
