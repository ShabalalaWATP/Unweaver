"""
Static .NET assembly analyzer.

Reads PE/CLR assemblies that entered the text-oriented pipeline as Latin-1
strings, then hands them to a local `dotnet` worker that extracts assembly
metadata, method names, manifest resources, user strings, and simple proxy/
loader indicators without executing the assembly.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .base import BaseTransform, TransformResult
from .binary_analysis import binary_text_to_bytes, looks_like_dotnet_assembly_bytes

_WORKER_DIR = Path(__file__).with_name("dotnet_worker")
_WORKER_PROJECT = _WORKER_DIR / "Unweaver.DotNetWorker.csproj"
_WORKER_DLL = _WORKER_DIR / "bin" / "Release" / "net8.0" / "Unweaver.DotNetWorker.dll"
_WORKER_TIMEOUT_SECONDS = 6.0
_BUILD_TIMEOUT_SECONDS = 60.0


def _worker_is_fresh() -> bool:
    if not _WORKER_DLL.exists():
        return False
    source_mtime = max(
        path.stat().st_mtime
        for path in (_WORKER_PROJECT, _WORKER_DIR / "Program.cs")
        if path.exists()
    )
    return _WORKER_DLL.stat().st_mtime >= source_mtime


def _ensure_worker_built() -> tuple[Path | None, str]:
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        return None, "dotnet_unavailable"
    if _worker_is_fresh():
        return _WORKER_DLL, ""

    try:
        completed = subprocess.run(
            [dotnet, "build", "-c", "Release", "--nologo", "-v", "q"],
            cwd=_WORKER_DIR,
            capture_output=True,
            text=True,
            timeout=_BUILD_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)

    if completed.returncode != 0 or not _WORKER_DLL.exists():
        message = (completed.stderr or completed.stdout or "dotnet_build_failed").strip()
        return None, message[:400]
    return _WORKER_DLL, ""


def _run_worker(data: bytes) -> dict[str, Any]:
    dotnet = shutil.which("dotnet")
    worker_path, worker_error = _ensure_worker_built()
    if dotnet is None or worker_path is None:
        return {"ok": False, "error": worker_error or "dotnet_unavailable"}

    payload = json.dumps({"AssemblyBase64": base64.b64encode(data).decode()})
    try:
        completed = subprocess.run(
            [dotnet, str(worker_path)],
            input=payload,
            text=True,
            capture_output=True,
            timeout=_WORKER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}

    stdout = completed.stdout.strip()
    if not stdout:
        return {"ok": False, "error": (completed.stderr or "empty_output").strip()}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": stdout[:400]}


def _render_report(details: dict[str, Any]) -> str:
    lines = ["// .NET assembly analysis"]
    if details.get("assemblyName"):
        lines.append(f"// Assembly: {details['assemblyName']}")
    if details.get("moduleName"):
        lines.append(f"// Module: {details['moduleName']}")
    if details.get("metadataVersion"):
        lines.append(f"// Metadata version: {details['metadataVersion']}")
    if details.get("entryPoint"):
        lines.append(f"// Entry point: {details['entryPoint']}")

    types = details.get("types") or []
    if types:
        lines.append("// Types:")
        for item in types[:20]:
            lines.append(f"//   - {item}")

    methods = details.get("methods") or []
    if methods:
        lines.append("// Methods:")
        for item in methods[:30]:
            lines.append(f"//   - {item}")

    resources = details.get("resources") or []
    if resources:
        lines.append("// Resources:")
        for item in resources[:20]:
            lines.append(f"//   - {item}")

    suspicious = details.get("suspiciousReferences") or []
    if suspicious:
        lines.append("// Suspicious references:")
        for item in suspicious[:20]:
            lines.append(f"//   - {item}")

    proxies = details.get("proxyMethods") or []
    if proxies:
        lines.append("// Likely proxy methods:")
        for item in proxies[:20]:
            lines.append(f"//   - {item}")

    strings = details.get("userStrings") or []
    if strings:
        lines.append("// Extracted user strings:")
        for item in strings[:30]:
            lines.append(f'//   - "{item}"')

    return "\n".join(lines) + "\n"


def _split_type_name(full_name: str) -> tuple[str, str]:
    if "." not in full_name:
        return "", full_name
    namespace, _, name = full_name.rpartition(".")
    return namespace, name


def _resource_preview_lines(resource: dict[str, Any]) -> list[str]:
    name = str(resource.get("name") or "<resource>")
    size = resource.get("size")
    encoding = resource.get("encoding")
    preview = resource.get("decodedTextPreview") or resource.get("textPreview")
    entries = [item for item in (resource.get("entries") or []) if isinstance(item, dict)]
    detail = []
    if encoding:
        detail.append(str(encoding))
    if isinstance(size, int) and size > 0:
        detail.append(f"{size} bytes")
    suffix = f" ({', '.join(detail)})" if detail else ""
    lines = [f"//   - {name}{suffix}"]
    if isinstance(preview, str) and preview.strip():
        for item in preview.splitlines()[:4]:
            lines.append(f"//     {item[:140]}")
    for entry in entries[:4]:
        entry_name = str(entry.get("name") or "<entry>")
        entry_preview = entry.get("decodedTextPreview") or entry.get("textPreview")
        if isinstance(entry_preview, str) and entry_preview.strip():
            lines.append(f"//     [{entry_name}] {entry_preview[:140]}")
        else:
            lines.append(f"//     [{entry_name}]")
    return lines


def _build_constant_return_map(summaries: list[dict[str, Any]]) -> dict[str, str]:
    by_name = {
        str(item.get("fullName")): item
        for item in summaries
        if isinstance(item, dict) and item.get("fullName")
    }
    resolved: dict[str, str] = {}
    visiting: set[str] = set()

    def resolve(name: str) -> str | None:
        if name in resolved:
            return resolved[name]
        if name in visiting:
            return None
        summary = by_name.get(name)
        if not isinstance(summary, dict):
            return None
        direct = summary.get("returnString")
        if direct is not None:
            value = str(direct)
            resolved[name] = value
            return value
        proxy_target = summary.get("proxyTarget")
        if not proxy_target:
            return None
        visiting.add(name)
        try:
            value = resolve(str(proxy_target))
        finally:
            visiting.discard(name)
        if value is not None:
            resolved[name] = value
        return value

    for method_name in by_name:
        resolve(method_name)
    return resolved


def _render_method_summary(
    summary: dict[str, Any],
    return_strings: dict[str, str],
    resource_previews: dict[str, str],
) -> list[str]:
    method_name = str(summary.get("methodName") or "Method")
    return_string = summary.get("returnString")
    proxy_target = summary.get("proxyTarget")
    call_targets = [str(item) for item in (summary.get("callTargets") or []) if item]
    user_strings = [str(item) for item in (summary.get("userStrings") or []) if item]
    resource_names = [str(item) for item in (summary.get("resourceNames") or []) if item]
    suspicious = [str(item) for item in (summary.get("suspiciousReferences") or []) if item]

    if return_string is not None:
        return [
            f"  public string {method_name}()",
            "  {",
            f"    return {json.dumps(str(return_string))};",
            "  }",
        ]
    if proxy_target:
        inlined = return_strings.get(str(proxy_target))
        if inlined is not None:
            return [
                f"  public string {method_name}()",
                "  {",
                f"    // inlined from proxy target {proxy_target}",
                f"    return {json.dumps(inlined)};",
                "  }",
            ]
        return [
            f"  public object {method_name}()",
            "  {",
            "    // Proxy/delegate target recovered from IL",
            f"    return {proxy_target}();",
            "  }",
        ]

    lines = [
        f"  public object {method_name}()",
        "  {",
    ]
    for target in call_targets[:4]:
        lines.append(f"    // calls: {target}")
    for name in resource_names[:3]:
        preview = resource_previews.get(name)
        if preview:
            lines.append(f"    // resource {name}: {json.dumps(preview[:140])}")
        else:
            lines.append(f"    // resource: {name}")
    for value in user_strings[:3]:
        lines.append(f"    // string: {json.dumps(value)}")
    for value in suspicious[:3]:
        lines.append(f"    // suspicious: {value}")
    lines.append("    return default!;")
    lines.append("  }")
    return lines


def _render_pseudo_source(details: dict[str, Any]) -> str:
    summaries = [
        item for item in (details.get("methodSummaries") or [])
        if isinstance(item, dict) and item.get("declaringType")
    ]
    if not summaries:
        return ""

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in summaries:
        grouped.setdefault(str(item["declaringType"]), []).append(item)
    return_strings = _build_constant_return_map(summaries)
    resource_items = [
        item for item in (details.get("embeddedResources") or [])
        if isinstance(item, dict) and item.get("name")
    ]
    resource_previews = {
        str(item["name"]): str(item.get("decodedTextPreview") or item.get("textPreview"))
        for item in resource_items
        if item.get("decodedTextPreview") or item.get("textPreview")
    }
    for item in resource_items:
        for entry in (item.get("entries") or []):
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            preview = entry.get("decodedTextPreview") or entry.get("textPreview")
            if preview:
                resource_previews[str(entry["name"])] = str(preview)

    lines = [
        "// Decompiled pseudo-source (static IL reconstruction)",
        f"// Assembly: {details.get('assemblyName') or '<module>'}",
    ]
    if details.get("entryPoint"):
        lines.append(f"// Entry point: {details['entryPoint']}")
    if resource_items:
        lines.append("// Embedded resources:")
        for item in resource_items[:8]:
            lines.extend(_resource_preview_lines(item))
    lines.append("")

    ordered_types = sorted(grouped.keys())
    current_namespace = None
    for full_type_name in ordered_types:
        namespace, type_name = _split_type_name(full_type_name)
        if namespace != current_namespace:
            if current_namespace is not None:
                lines.append("}")
                lines.append("")
            if namespace:
                lines.append(f"namespace {namespace}")
                lines.append("{")
            current_namespace = namespace
        lines.append(f"public class {type_name}")
        lines.append("{")
        for method in grouped[full_type_name][:20]:
            lines.extend(_render_method_summary(method, return_strings, resource_previews))
            lines.append("")
        if lines[-1] == "":
            lines.pop()
        lines.append("}")
        lines.append("")

    if current_namespace is not None and current_namespace:
        if lines[-1] == "":
            lines.pop()
        lines.append("}")
        lines.append("")

    rendered = "\n".join(lines).rstrip() + "\n"
    return rendered


class DotNetAssemblyAnalyzer(BaseTransform):
    name = "dotnet_assembly_analyzer"
    description = "Analyze .NET assemblies via local PE/CLR metadata and IL inspection"

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        if (language or "").lower().strip() == "dotnet":
            return True
        return looks_like_dotnet_assembly_bytes(binary_text_to_bytes(code))

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        data = binary_text_to_bytes(code)
        if not looks_like_dotnet_assembly_bytes(data):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Input does not look like a .NET assembly.",
            )

        worker = _run_worker(data)
        if not worker.get("ok"):
            return TransformResult(
                success=False,
                output=code,
                confidence=0.0,
                description="Failed to analyze .NET assembly metadata.",
                details={"error": worker.get("error", "")},
            )

        strings = [
            {"encoded": "dotnet_user_string", "decoded": item}
            for item in (worker.get("userStrings") or [])[:80]
            if isinstance(item, str) and item.strip()
        ]
        resource_items = [
            item for item in (worker.get("embeddedResources") or [])
            if isinstance(item, dict) and item.get("name")
        ]
        seen_resource_values: set[str] = set()
        for item in resource_items[:40]:
            for key in ("textPreview", "decodedTextPreview"):
                value = item.get(key)
                if isinstance(value, str) and value.strip() and value not in seen_resource_values:
                    seen_resource_values.add(value)
                    strings.append({"encoded": f"embedded_resource:{item.get('name')}", "decoded": value})
            for entry in (item.get("entries") or [])[:20]:
                if not isinstance(entry, dict) or not entry.get("name"):
                    continue
                for key in ("textPreview", "decodedTextPreview"):
                    value = entry.get(key)
                    if isinstance(value, str) and value.strip() and value not in seen_resource_values:
                        seen_resource_values.add(value)
                        strings.append(
                            {
                                "encoded": f"embedded_resource_entry:{item.get('name')}:{entry.get('name')}",
                                "decoded": value,
                            }
                        )
        imports = [str(item) for item in (worker.get("references") or [])[:80]]
        functions = [str(item) for item in (worker.get("methods") or [])[:120]]
        suspicious = [str(item) for item in (worker.get("suspiciousReferences") or [])[:80]]
        techniques = ["dotnet_assembly"]
        if suspicious:
            techniques.append("reflection")
        if worker.get("proxyMethods"):
            techniques.append("proxy_call")
        if resource_items:
            techniques.append("embedded_resource")
        method_summaries = worker.get("methodSummaries") or []
        if _build_constant_return_map(
            [item for item in method_summaries if isinstance(item, dict)]
        ):
            techniques.append("constant_string_method")

        pseudo_source = _render_pseudo_source(worker)
        report = pseudo_source or _render_report(worker)
        confidence = 0.86
        if strings:
            confidence += 0.04
        if suspicious:
            confidence += 0.03
        if pseudo_source:
            confidence += 0.02
        confidence = min(0.94, confidence)

        return TransformResult(
            success=True,
            output=report,
            confidence=confidence,
            description="Analyzed .NET assembly metadata, strings, and IL call structure.",
            details={
                "decoded_strings": strings,
                "imports": imports,
                "functions": functions,
                "suspicious_apis": suspicious,
                "detected_techniques": techniques,
                "assembly_analysis": worker,
                "method_summaries": method_summaries,
                "embedded_resources": resource_items,
                "evidence_references": [
                    f"dotnet:{value}"
                    for value in [worker.get("assemblyName"), worker.get("entryPoint")]
                    if value
                ],
            },
        )
