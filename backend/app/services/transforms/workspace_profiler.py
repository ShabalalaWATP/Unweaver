"""
Deterministic workspace bundle profiler.

Extracts per-file metadata, likely entrypoints, cross-file imports, and
high-signal symbols from bundled codebase uploads so the planner and reports
can reason about a workspace as a set of files instead of a flat blob.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Sequence, Tuple

from app.services.ingest.workspace_bundle import (
    extract_workspace_context,
    parse_workspace_bundle,
    workspace_files_preview,
)
from app.services.transforms.base import BaseTransform, TransformResult

_IMPORT_PATTERNS: Dict[str, Sequence[re.Pattern[str]]] = {
    "javascript": (
        re.compile(r'import\s+.+?\s+from\s+["\']([^"\']+)["\']'),
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


class WorkspaceProfiler(BaseTransform):
    """Extract high-signal workspace metadata from a bundled codebase sample."""

    name = "WorkspaceProfiler"
    description = "Profile bundled workspace files, imports, entrypoints, and symbols."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        return bool(extract_workspace_context(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        context = extract_workspace_context(code)
        files = parse_workspace_bundle(code)
        if not context or not files:
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Input is not a parseable workspace bundle.",
                details={},
            )

        imports: List[str] = []
        functions: List[str] = []
        suspicious_apis: List[str] = []
        evidence_references: List[str] = []

        for file in files[:48]:
            evidence_references.append(file.path)
            for pattern in _IMPORT_PATTERNS.get(file.language, ()):
                for match in pattern.findall(file.text[:20_000]):
                    if isinstance(match, tuple):
                        match = match[0]
                    for item in str(match).split(","):
                        value = item.strip()
                        if value:
                            imports.append(f"{file.path} -> {value}")

            for pattern in _FUNCTION_PATTERNS.get(file.language, ()):
                for match in pattern.findall(file.text[:30_000]):
                    if isinstance(match, tuple):
                        match = match[0]
                    value = str(match).strip()
                    if value:
                        functions.append(f"{file.path}::{value}")

            for pattern, label in _SUSPICIOUS_API_PATTERNS:
                if pattern.search(file.text[:25_000]):
                    suspicious_apis.append(f"{label} @ {file.path}")

        root_dirs = list(context.get("root_dirs", []))
        entry_points = list(context.get("entry_points", []))
        manifest_files = list(context.get("manifest_files", []))
        suspicious_files = list(context.get("suspicious_files", []))
        languages_counter = Counter(file.language for file in files)

        detected_techniques = ["workspace_bundle"]
        if len(root_dirs) > 1:
            detected_techniques.append("monorepo_bundle")
        if entry_points:
            detected_techniques.append("entrypoint_ranked")
        if suspicious_files:
            detected_techniques.append("cross_file_obfuscation_candidate")

        summary_parts = [
            f"Workspace bundle with {len(files)} file(s)",
            f"{len(entry_points)} likely entrypoint(s)",
            f"{len(suspicious_files)} suspicious file(s)",
        ]
        if manifest_files:
            summary_parts.append(f"{len(manifest_files)} manifest/config file(s)")
        summary = ". ".join(summary_parts) + "."

        workspace_context = {
            **context,
            "files_preview": workspace_files_preview(code, max_files=16),
            "imports_count": len(imports),
            "functions_count": len(functions),
            "languages_by_file": dict(languages_counter),
        }

        return TransformResult(
            success=True,
            output=code,
            confidence=0.85,
            description=summary,
            details={
                "workspace_context": workspace_context,
                "entry_points": entry_points[:12],
                "imports": imports[:60],
                "functions": functions[:60],
                "suspicious_apis": sorted(set(suspicious_apis))[:30],
                "detected_techniques": detected_techniques,
                "evidence_references": evidence_references[:32],
                "summary": summary,
            },
        )
