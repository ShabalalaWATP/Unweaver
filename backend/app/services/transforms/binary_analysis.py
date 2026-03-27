"""
Helpers for identifying binary payloads that are flowing through the text-only
pipeline, especially PE/.NET assemblies uploaded as Latin-1 text.
"""

from __future__ import annotations

import os
from typing import Final

_PE_HEADER_POINTER_OFFSET: Final[int] = 0x3C


def binary_text_to_bytes(code: str) -> bytes:
    if not code:
        return b""
    try:
        return code.encode("latin-1")
    except UnicodeEncodeError:
        return code.encode("latin-1", "ignore")


def looks_like_pe_binary_bytes(data: bytes) -> bool:
    if len(data) < 0x100 or not data.startswith(b"MZ"):
        return False
    if len(data) <= _PE_HEADER_POINTER_OFFSET + 4:
        return False
    pe_offset = int.from_bytes(
        data[_PE_HEADER_POINTER_OFFSET:_PE_HEADER_POINTER_OFFSET + 4],
        "little",
        signed=False,
    )
    if pe_offset <= 0 or pe_offset + 4 > len(data):
        return False
    return data[pe_offset:pe_offset + 4] == b"PE\x00\x00"


def looks_like_dotnet_assembly_bytes(data: bytes) -> bool:
    if not looks_like_pe_binary_bytes(data):
        return False
    lowered = data.lower()
    return (
        b"bsjb" in lowered
        or b"mscoree.dll" in lowered
        or b"system.runtime" in lowered
    )


def looks_like_binary_blob_text(code: str) -> bool:
    data = binary_text_to_bytes(code)
    if looks_like_dotnet_assembly_bytes(data) or looks_like_pe_binary_bytes(data):
        return True
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample[:1024]:
        return True
    control_count = sum(
        1
        for byte in sample
        if byte < 32 and byte not in (9, 10, 13)
    )
    return control_count / max(len(sample), 1) >= 0.18


def detect_upload_content_kind(filename: str, data: bytes) -> str:
    lower_name = os.path.basename(filename or "").lower()
    if looks_like_dotnet_assembly_bytes(data):
        return "dotnet_binary"
    if looks_like_pe_binary_bytes(data):
        return "pe_binary"
    if lower_name.endswith((".dll", ".exe")):
        return "binary"
    return "text"


def binary_preview_text(filename: str, kind: str, size: int) -> str:
    lines = [
        f"// Binary sample uploaded: {os.path.basename(filename or 'sample.bin')}",
        f"// Content kind: {kind}",
        f"// Size: {size} bytes",
        "// Raw bytes are preserved on disk and fed directly to the binary analysis worker.",
    ]
    if kind == "dotnet_binary":
        lines.append("// This sample will be analyzed as a .NET assembly rather than decoded as text.")
    return "\n".join(lines) + "\n"
