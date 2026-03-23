"""
Utilities for turning uploaded archives into bounded workspace bundles.

The analysis engine is fundamentally text-oriented today. For codebases and
monorepos, we therefore build a single synthetic text document that preserves
file boundaries, prioritises likely entrypoints / suspicious files, and stays
within a predictable size budget.
"""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Dict, Iterator, List, Optional, Tuple

WORKSPACE_BUNDLE_HEADER = "UNWEAVER_WORKSPACE_BUNDLE v1"

_ARCHIVE_EXTENSIONS = (".zip", ".tar", ".tgz", ".tar.gz")
_WORKSPACE_MANIFEST_KEYS = (
    "archive_name",
    "included_files",
    "omitted_files",
    "languages",
    "entry_points",
    "suspicious_files",
    "manifest_files",
    "root_dirs",
    "bundle_note",
)
_FILE_MARKER_RE = re.compile(
    r'^<<<FILE path="(?P<path>[^"]+)" language="(?P<language>[^"]+)" '
    r'priority="(?P<priority>[^"]+)" size=(?P<size>\d+)>>>\n'
    r'(?P<body>.*?)\n<<<END FILE>>>',
    re.MULTILINE | re.DOTALL,
)
_COMMENT_PATTERN = re.compile(r"//.*?$|/\*.*?\*/|#.*?$", re.MULTILINE | re.DOTALL)
_OBFUSCATION_PATTERNS: List[Tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"\beval\s*\(", re.IGNORECASE), 2.0, "eval"),
    (re.compile(r"\batob\s*\(", re.IGNORECASE), 2.0, "base64"),
    (re.compile(r"String\.fromCharCode", re.IGNORECASE), 2.0, "charcode"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}"), 2.0, "hex"),
    (re.compile(r"[A-Za-z0-9+/]{48,}={0,2}"), 1.5, "base64_blob"),
    (re.compile(r"\b(?:IEX|Invoke-Expression)\b", re.IGNORECASE), 2.5, "powershell_exec"),
    (re.compile(r"\b(?:exec|compile)\s*\(", re.IGNORECASE), 1.5, "exec"),
    (re.compile(r"\b(?:decrypt|decode|unpack|unwrap|xor)\w*\b", re.IGNORECASE), 1.0, "decoder"),
    (re.compile(r"\b_0x[a-fA-F0-9]{3,}\b"), 2.0, "mangled_names"),
]
_ENTRYPOINT_NAMES = {
    "__main__.py",
    "app.js",
    "app.ts",
    "bootstrap.js",
    "bootstrap.ts",
    "cli.js",
    "cli.ts",
    "index.js",
    "index.ts",
    "main.js",
    "main.ts",
    "main.tsx",
    "program.cs",
    "run.py",
    "server.js",
    "server.ts",
    "startup.ps1",
}
_MANIFEST_FILES = {
    "package.json",
    "pnpm-workspace.yaml",
    "pnpm-workspace.yml",
    "turbo.json",
    "nx.json",
    "lerna.json",
    "workspace.json",
    "tsconfig.json",
    "vite.config.js",
    "vite.config.ts",
    "webpack.config.js",
    "webpack.config.ts",
}
_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".next",
    ".nuxt",
    ".parcel-cache",
    ".pnpm-store",
    ".turbo",
    ".venv",
    "__pycache__",
    "bin",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "obj",
    "out",
    "target",
    "venv",
}
_ALLOWED_EXTENSIONS = {
    ".bat": "bat",
    ".cjs": "javascript",
    ".cmd": "bat",
    ".conf": "plaintext",
    ".cs": "csharp",
    ".go": "go",
    ".gradle": "plaintext",
    ".groovy": "plaintext",
    ".html": "html",
    ".ini": "plaintext",
    ".java": "java",
    ".js": "javascript",
    ".json": "json",
    ".jsx": "javascript",
    ".lua": "lua",
    ".mjs": "javascript",
    ".php": "php",
    ".pl": "perl",
    ".ps1": "powershell",
    ".psd1": "powershell",
    ".psm1": "powershell",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "shell",
    ".sql": "sql",
    ".toml": "plaintext",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".txt": "plaintext",
    ".vb": "vb",
    ".vbs": "vbscript",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}


class WorkspaceBundleError(ValueError):
    """Raised when an uploaded archive cannot be turned into a usable bundle."""


@dataclass(frozen=True)
class WorkspaceFile:
    """A single extracted workspace file selected for bundling."""

    path: str
    language: str
    text: str
    size_bytes: int
    score: float
    priority_tags: tuple[str, ...]


@dataclass(frozen=True)
class WorkspaceBundleResult:
    """A bounded synthetic sample representing a codebase upload."""

    display_name: str
    language: str
    bundle_text: str
    summary: str
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class ParsedWorkspaceFile:
    """A file block parsed back out of a workspace bundle."""

    path: str
    language: str
    priority: tuple[str, ...]
    size_bytes: int
    text: str


def is_archive_upload(filename: str, content_bytes: bytes) -> bool:
    """Return True when the payload looks like a supported archive."""
    lower = filename.lower()
    if lower.endswith(_ARCHIVE_EXTENSIONS):
        return True
    if zipfile.is_zipfile(io.BytesIO(content_bytes)):
        return True
    try:
        with tarfile.open(fileobj=io.BytesIO(content_bytes), mode="r:*"):
            return True
    except tarfile.TarError:
        return False


def build_workspace_bundle(
    *,
    filename: str,
    content_bytes: bytes,
    max_bundle_chars: int,
    max_member_bytes: int,
    max_files: int,
) -> WorkspaceBundleResult:
    """Extract, prioritise, and serialise a codebase archive."""
    candidates: List[WorkspaceFile] = []
    skipped = 0

    for raw_path, payload, declared_size in _iter_archive_members(filename, content_bytes):
        normalised = _normalise_member_path(raw_path)
        if not normalised or _should_skip_path(normalised):
            skipped += 1
            continue
        if declared_size > max_member_bytes or len(payload) > max_member_bytes:
            skipped += 1
            continue
        language = _language_from_path(normalised)
        if language is None:
            skipped += 1
            continue
        text = _decode_text(payload)
        if text is None:
            skipped += 1
            continue
        score, tags = _score_file(normalised, text)
        candidates.append(
            WorkspaceFile(
                path=normalised,
                language=language,
                text=text,
                size_bytes=len(payload),
                score=score,
                priority_tags=tuple(tags),
            )
        )

    if not candidates:
        raise WorkspaceBundleError(
            "Archive did not contain any supported text source files after filtering."
        )

    candidates.sort(key=lambda item: (-item.score, item.size_bytes, item.path))
    selected: List[WorkspaceFile] = []
    omitted = skipped
    used_chars = 0

    for candidate in candidates:
        if len(selected) >= max_files:
            omitted += 1
            continue
        block = _format_file_block(candidate)
        block_len = len(block) + 2
        if selected and used_chars + block_len > max_bundle_chars:
            omitted += 1
            continue
        if not selected and block_len > max_bundle_chars:
            truncated = candidate.text[: max(max_bundle_chars - 256, 256)].rstrip()
            candidate = WorkspaceFile(
                path=candidate.path,
                language=candidate.language,
                text=truncated,
                size_bytes=candidate.size_bytes,
                score=candidate.score,
                priority_tags=candidate.priority_tags,
            )
            block = _format_file_block(candidate)
            block_len = len(block) + 2
        selected.append(candidate)
        used_chars += block_len

    if not selected:
        raise WorkspaceBundleError(
            "Archive files exceeded the bundle budget before any candidate could be included."
        )

    languages = Counter(item.language for item in selected)
    entry_points = [item.path for item in selected if "entrypoint" in item.priority_tags]
    suspicious_files = [item.path for item in selected if "suspicious" in item.priority_tags]
    manifest_files = [item.path for item in selected if "manifest" in item.priority_tags]
    root_dirs = sorted({item.path.split("/", 1)[0] for item in selected if "/" in item.path})[:8]

    header_lines = [
        WORKSPACE_BUNDLE_HEADER,
        f"archive_name: {filename}",
        f"included_files: {len(selected)}",
        f"omitted_files: {max(0, omitted)}",
        "languages: " + ", ".join(
            f"{name}={count}" for name, count in languages.most_common()
        ),
        "entry_points: " + (" | ".join(entry_points[:8]) if entry_points else "none"),
        "suspicious_files: "
        + (" | ".join(suspicious_files[:8]) if suspicious_files else "none"),
        "manifest_files: "
        + (" | ".join(manifest_files[:6]) if manifest_files else "none"),
        "root_dirs: " + (" | ".join(root_dirs) if root_dirs else "none"),
        "bundle_note: files are ordered by likely execution or obfuscation relevance; "
        "preserve <<<FILE ...>>> markers if rewriting only part of the bundle.",
        "",
    ]

    body = "\n\n".join(_format_file_block(item) for item in selected)
    bundle_text = "\n".join(header_lines) + body
    summary = (
        f"Bundled {len(selected)} file(s) from {filename} "
        f"({max(0, omitted)} omitted after filtering/limits)."
    )
    metadata: Dict[str, Any] = {
        "archive_name": filename,
        "included_files": len(selected),
        "omitted_files": max(0, omitted),
        "languages": dict(languages),
        "entry_points": entry_points[:12],
        "suspicious_files": suspicious_files[:12],
        "manifest_files": manifest_files[:12],
        "root_dirs": root_dirs,
        "selected_paths": [item.path for item in selected[:32]],
    }
    return WorkspaceBundleResult(
        display_name=filename,
        language="workspace",
        bundle_text=bundle_text,
        summary=summary,
        metadata=metadata,
    )


def extract_workspace_context(bundle_text: str, *, max_paths: int = 8) -> Optional[Dict[str, Any]]:
    """Parse the manifest portion of a workspace bundle, if present."""
    metadata = _parse_workspace_manifest(bundle_text)
    if metadata is None:
        return None

    file_matches = list(_FILE_MARKER_RE.finditer(bundle_text))
    prioritized_paths = [match.group("path") for match in file_matches[:max_paths]]
    entry_points = _split_manifest_value(metadata.get("entry_points", ""))
    suspicious_files = _split_manifest_value(metadata.get("suspicious_files", ""))
    manifest_files = _split_manifest_value(metadata.get("manifest_files", ""))
    root_dirs = _split_manifest_value(metadata.get("root_dirs", ""))

    return {
        "archive_name": metadata.get("archive_name", ""),
        "included_files": _parse_int(metadata.get("included_files")),
        "omitted_files": _parse_int(metadata.get("omitted_files")),
        "languages": metadata.get("languages", ""),
        "entry_points": entry_points,
        "suspicious_files": suspicious_files,
        "manifest_files": manifest_files,
        "root_dirs": root_dirs,
        "prioritized_paths": prioritized_paths,
        "bundle_note": metadata.get("bundle_note", ""),
    }


def workspace_context_prompt(bundle_text: str) -> Optional[str]:
    """Return a compact prompt-friendly summary when the code is a bundle."""
    context = extract_workspace_context(bundle_text)
    if not context:
        return None

    parts = [
        f"Workspace bundle: {context.get('archive_name') or 'archive upload'}",
        f"Included files: {context.get('included_files') or 0}",
    ]
    omitted = context.get("omitted_files")
    if isinstance(omitted, int):
        parts.append(f"Omitted files: {omitted}")
    if context.get("languages"):
        parts.append(f"Languages: {context['languages']}")
    if context.get("entry_points"):
        parts.append(
            "Entry points: " + " | ".join(str(item) for item in context["entry_points"][:6])
        )
    if context.get("suspicious_files"):
        parts.append(
            "Suspicious files: "
            + " | ".join(str(item) for item in context["suspicious_files"][:6])
        )
    if context.get("manifest_files"):
        parts.append(
            "Manifest files: "
            + " | ".join(str(item) for item in context["manifest_files"][:4])
        )
    if context.get("prioritized_paths"):
        parts.append(
            "Bundled order: "
            + " | ".join(str(item) for item in context["prioritized_paths"][:6])
        )
    note = context.get("bundle_note")
    if note:
        parts.append(str(note))
    return "\n".join(parts)


def parse_workspace_bundle(bundle_text: str) -> List[ParsedWorkspaceFile]:
    """Parse file blocks from a workspace bundle."""
    if not bundle_text.startswith(WORKSPACE_BUNDLE_HEADER):
        return []

    files: List[ParsedWorkspaceFile] = []
    for match in _FILE_MARKER_RE.finditer(bundle_text):
        priority_raw = match.group("priority").strip()
        priority = tuple(
            part.strip() for part in priority_raw.split(",")
            if part.strip() and part.strip() != "normal"
        )
        files.append(
            ParsedWorkspaceFile(
                path=match.group("path"),
                language=match.group("language"),
                priority=priority,
                size_bytes=int(match.group("size")),
                text=match.group("body"),
            )
        )
    return files


def workspace_bundle_signature(bundle_text: str) -> Optional[Dict[str, Any]]:
    """Return structural bundle metadata plus validity diagnostics."""
    manifest = _parse_workspace_manifest(bundle_text)
    if manifest is None:
        return None

    files = parse_workspace_bundle(bundle_text)
    paths = [item.path for item in files]
    duplicate_paths = sorted(
        path for path, count in Counter(paths).items() if count > 1
    )
    missing_manifest_keys = [
        key for key in _WORKSPACE_MANIFEST_KEYS
        if key not in manifest
    ]

    issues: List[str] = []
    if missing_manifest_keys:
        issues.append("workspace_manifest_incomplete")
    if not files:
        issues.append("workspace_has_no_file_blocks")

    included_files = _parse_int(manifest.get("included_files"))
    if included_files is None:
        issues.append("workspace_included_files_missing")
    elif included_files != len(files):
        issues.append("workspace_included_files_mismatch")

    if duplicate_paths:
        issues.append("workspace_duplicate_paths")

    context = extract_workspace_context(bundle_text)
    return {
        "valid": not issues,
        "issues": issues,
        "missing_manifest_keys": missing_manifest_keys,
        "duplicate_paths": duplicate_paths,
        "file_count": len(files),
        "paths": paths,
        "included_files": included_files,
        "context": context,
    }


def pick_workspace_bundle_text(*bundle_candidates: Optional[str]) -> Optional[str]:
    """Return the first structurally valid workspace bundle candidate."""
    for candidate in bundle_candidates:
        if not candidate:
            continue
        signature = workspace_bundle_signature(candidate)
        if signature and signature["valid"]:
            return candidate
    return None


def validate_workspace_bundle_candidate(
    original_bundle: str,
    candidate_bundle: str,
) -> Dict[str, Any]:
    """Ensure a rewritten workspace bundle preserves structure and file set."""
    original_signature = workspace_bundle_signature(original_bundle)
    candidate_signature = workspace_bundle_signature(candidate_bundle)

    if not original_signature or not original_signature["valid"]:
        return {
            "accepted": False,
            "issues": ["workspace_original_invalid"],
            "missing_paths": [],
            "extra_paths": [],
            "original_file_count": 0,
            "candidate_file_count": 0,
            "missing_manifest_keys": [],
            "duplicate_paths": [],
        }

    issues: List[str] = []
    if not candidate_signature:
        issues.append("workspace_bundle_missing")
        return {
            "accepted": False,
            "issues": issues,
            "missing_paths": list(original_signature["paths"]),
            "extra_paths": [],
            "original_file_count": original_signature["file_count"],
            "candidate_file_count": 0,
            "missing_manifest_keys": [],
            "duplicate_paths": [],
        }

    if not candidate_signature["valid"]:
        issues.extend(candidate_signature["issues"])

    original_paths = list(original_signature["paths"])
    candidate_paths = list(candidate_signature["paths"])
    original_path_set = set(original_paths)
    candidate_path_set = set(candidate_paths)
    missing_paths = [path for path in original_paths if path not in candidate_path_set]
    extra_paths = [path for path in candidate_paths if path not in original_path_set]

    if candidate_signature["file_count"] != original_signature["file_count"]:
        issues.append("workspace_file_count_changed")
    if missing_paths:
        issues.append("workspace_file_blocks_missing")
    if extra_paths:
        issues.append("workspace_file_blocks_added")

    original_context = original_signature.get("context") or {}
    entry_points = original_context.get("entry_points", [])
    if entry_points and any(path not in candidate_path_set for path in entry_points):
        issues.append("workspace_entrypoint_missing")

    return {
        "accepted": not issues,
        "issues": issues,
        "missing_paths": missing_paths,
        "extra_paths": extra_paths,
        "original_file_count": original_signature["file_count"],
        "candidate_file_count": candidate_signature["file_count"],
        "missing_manifest_keys": candidate_signature["missing_manifest_keys"],
        "duplicate_paths": candidate_signature["duplicate_paths"],
    }


def rebuild_workspace_bundle(
    bundle_text: str,
    files: List[ParsedWorkspaceFile],
) -> str:
    """Rebuild a workspace bundle from an existing header and parsed files."""
    if not bundle_text.startswith(WORKSPACE_BUNDLE_HEADER):
        raise WorkspaceBundleError("Text is not a workspace bundle.")

    first_file_idx = bundle_text.find("<<<FILE ")
    header = bundle_text[:first_file_idx].rstrip() if first_file_idx != -1 else bundle_text.rstrip()
    body = "\n\n".join(_format_parsed_file_block(item) for item in files)
    if not body:
        return header + "\n"
    return header + "\n\n" + body


def build_workspace_archive(bundle_text: str) -> bytes:
    """Reconstruct a workspace bundle into a downloadable zip archive."""
    signature = workspace_bundle_signature(bundle_text)
    if not signature or not signature["valid"]:
        raise WorkspaceBundleError("Text is not a valid workspace bundle.")

    files = parse_workspace_bundle(bundle_text)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in files:
            archive.writestr(item.path, item.text)
    return buffer.getvalue()


def workspace_files_preview(
    bundle_text: str,
    *,
    max_files: int = 12,
) -> List[Dict[str, Any]]:
    """Return a compact serialisable preview of bundle files."""
    signature = workspace_bundle_signature(bundle_text)
    if not signature or not signature["valid"]:
        return []

    preview: List[Dict[str, Any]] = []
    for item in parse_workspace_bundle(bundle_text)[:max_files]:
        preview.append(
            {
                "path": item.path,
                "language": item.language,
                "priority": list(item.priority),
                "size_bytes": item.size_bytes,
            }
        )
    return preview


def truncate_workspace_bundle(bundle_text: str, max_chars: int) -> str:
    """Keep manifest plus the highest-priority file blocks within the budget."""
    if len(bundle_text) <= max_chars:
        return bundle_text

    context = extract_workspace_context(bundle_text)
    if not context:
        return bundle_text[:max_chars]

    first_file_idx = bundle_text.find("<<<FILE ")
    if first_file_idx == -1:
        return bundle_text[:max_chars]

    header = bundle_text[:first_file_idx].rstrip()
    pieces = [header]
    used = len(header)
    added = 0
    matches = list(_FILE_MARKER_RE.finditer(bundle_text))

    for match in matches:
        block = match.group(0).rstrip()
        extra = len(block) + 2
        if added > 0 and used + extra > max_chars:
            break
        if added == 0 and used + extra > max_chars:
            remaining = max(max_chars - used - 32, 128)
            block = block[:remaining].rstrip() + "\n... [file excerpt truncated] ..."
            pieces.append(block)
            used += len(block) + 2
            added += 1
            break
        pieces.append(block)
        used += extra
        added += 1

    omitted = max(0, len(matches) - added)
    if omitted:
        pieces.append(f"... [{omitted} additional bundled file(s) omitted] ...")
    return "\n\n".join(pieces)


def _iter_archive_members(
    filename: str,
    content_bytes: bytes,
) -> Iterator[Tuple[str, bytes, int]]:
    """Yield raw archive members from zip or tar-like uploads."""
    if zipfile.is_zipfile(io.BytesIO(content_bytes)):
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                with archive.open(member) as handle:
                    yield member.filename, handle.read(), member.file_size
        return

    try:
        with tarfile.open(fileobj=io.BytesIO(content_bytes), mode="r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                yield member.name, handle.read(), int(member.size or 0)
        return
    except tarfile.TarError as exc:
        raise WorkspaceBundleError(
            f"Unsupported archive format for {filename}: {type(exc).__name__}"
        ) from exc


def _normalise_member_path(path: str) -> Optional[str]:
    raw = path.replace("\\", "/").strip()
    if not raw:
        return None
    pure = PurePosixPath(raw)
    if pure.is_absolute():
        return None
    parts = [part for part in pure.parts if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _should_skip_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if any(part in _IGNORED_DIRS for part in pure.parts[:-1]):
        return True
    basename = pure.name.lower()
    if basename.endswith(".min.js") or basename.endswith(".bundle.js"):
        return True
    return False


def _language_from_path(path: str) -> Optional[str]:
    pure = PurePosixPath(path)
    basename = pure.name
    if basename in {"Dockerfile", "Makefile", "Procfile"}:
        return "plaintext"
    suffix = pure.suffix.lower()
    return _ALLOWED_EXTENSIONS.get(suffix)


def _decode_text(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    if b"\x00" in payload[:4096]:
        return None

    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            text = payload.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_text(text):
            return text.replace("\r\n", "\n").replace("\r", "\n")
    return None


def _looks_like_text(text: str) -> bool:
    sample = text[:8000]
    if not sample.strip():
        return False
    printable = sum(
        1 for char in sample if char.isprintable() or char in "\n\r\t"
    )
    return (printable / max(len(sample), 1)) >= 0.72


def _score_file(path: str, text: str) -> Tuple[float, List[str]]:
    score = 0.0
    tags: List[str] = []
    pure = PurePosixPath(path)
    basename = pure.name.lower()
    parts = [part.lower() for part in pure.parts]

    if basename in _ENTRYPOINT_NAMES:
        score += 6.0
        tags.append("entrypoint")
    if basename in _MANIFEST_FILES:
        score += 3.5
        tags.append("manifest")
    if len(parts) <= 2:
        score += 1.0
    if any(part in {"src", "app", "apps", "bin", "cli", "cmd", "packages", "server"} for part in parts):
        score += 1.0

    text_sample = _COMMENT_PATTERN.sub("", text[:20000])
    suspicious_hits = 0
    for pattern, weight, _name in _OBFUSCATION_PATTERNS:
        matches = len(pattern.findall(text_sample))
        if matches:
            suspicious_hits += matches
            score += min(matches, 5) * weight
    longest_line = max((len(line) for line in text_sample.splitlines()), default=0)
    if longest_line > 500:
        score += 1.5
        suspicious_hits += 1
    if suspicious_hits:
        tags.append("suspicious")

    return score, tags


def _format_file_block(item: WorkspaceFile) -> str:
    priority = ",".join(item.priority_tags) if item.priority_tags else "normal"
    return (
        f'<<<FILE path="{item.path}" language="{item.language}" '
        f'priority="{priority}" size={item.size_bytes}>>>\n'
        f"{item.text.rstrip()}\n"
        "<<<END FILE>>>"
    )


def _format_parsed_file_block(item: ParsedWorkspaceFile) -> str:
    priority = ",".join(item.priority) if item.priority else "normal"
    size_bytes = len(item.text.encode("utf-8"))
    return (
        f'<<<FILE path="{item.path}" language="{item.language}" '
        f'priority="{priority}" size={size_bytes}>>>\n'
        f"{item.text.rstrip()}\n"
        "<<<END FILE>>>"
    )


def _parse_workspace_manifest(bundle_text: str) -> Optional[Dict[str, str]]:
    if not bundle_text.startswith(WORKSPACE_BUNDLE_HEADER):
        return None

    metadata: Dict[str, str] = {}
    lines = bundle_text.splitlines()
    for line in lines[1:40]:
        if line.startswith("<<<FILE "):
            break
        if not line.strip():
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def _split_manifest_value(raw: str) -> List[str]:
    value = raw.strip()
    if not value or value == "none":
        return []
    return [item.strip() for item in value.split("|") if item.strip()]


def _parse_int(raw: Optional[str]) -> Optional[int]:
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None
