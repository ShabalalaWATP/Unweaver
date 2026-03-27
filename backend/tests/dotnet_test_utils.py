from __future__ import annotations

import functools
import shutil
import subprocess
import tempfile
import textwrap
from html import escape
from pathlib import Path
from typing import Mapping


@functools.lru_cache(maxsize=8)
def build_test_dotnet_assembly(source: str, assembly_name: str = "UnweaverTestAssembly") -> bytes:
    return _build_test_dotnet_assembly(source, assembly_name, embedded_resources=None)


def build_test_dotnet_assembly_with_resources(
    source: str,
    assembly_name: str,
    embedded_resources: Mapping[str, str | bytes],
) -> bytes:
    return _build_test_dotnet_assembly(source, assembly_name, embedded_resources=embedded_resources)


def build_resx(entries: Mapping[str, str]) -> str:
    items = "\n".join(
        textwrap.dedent(
            f"""\
            <data name="{escape(name, quote=True)}" xml:space="preserve">
              <value>{escape(value)}</value>
            </data>
            """
        ).strip()
        for name, value in entries.items()
    )
    return textwrap.dedent(
        f"""\
<?xml version="1.0" encoding="utf-8"?>
<root>
  <resheader name="resmimetype">
    <value>text/microsoft-resx</value>
  </resheader>
  <resheader name="version">
    <value>2.0</value>
  </resheader>
  <resheader name="reader">
    <value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
  </resheader>
  <resheader name="writer">
    <value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
  </resheader>
  {items}
</root>
"""
    ).strip() + "\n"


def _build_test_dotnet_assembly(
    source: str,
    assembly_name: str,
    embedded_resources: Mapping[str, str | bytes] | None,
) -> bytes:
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        raise RuntimeError("dotnet_unavailable")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        embedded_resources = embedded_resources or {}
        item_group = ""
        if embedded_resources:
            lines = "\n".join(
                f"    <EmbeddedResource Include=\"{name}\" />"
                for name in embedded_resources
            )
            item_group = f"  <ItemGroup>\n{lines}\n  </ItemGroup>\n"
        (root / f"{assembly_name}.csproj").write_text(
            textwrap.dedent(
                f"""\
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net8.0</TargetFramework>
                    <OutputType>Library</OutputType>
                    <AssemblyName>{assembly_name}</AssemblyName>
                    <EnableDefaultEmbeddedResourceItems>false</EnableDefaultEmbeddedResourceItems>
                    <ImplicitUsings>enable</ImplicitUsings>
                    <Nullable>enable</Nullable>
                  </PropertyGroup>
                {item_group}</Project>
                """
            ),
            encoding="utf-8",
        )
        (root / "Sample.cs").write_text(textwrap.dedent(source), encoding="utf-8")
        for name, content in embedded_resources.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")

        completed = subprocess.run(
            [dotnet, "build", "-c", "Release", "--nologo", "-v", "q"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "dotnet_build_failed").strip()
            raise RuntimeError(message[:500])

        dll_path = root / "bin" / "Release" / "net8.0" / f"{assembly_name}.dll"
        if not dll_path.exists():
            raise RuntimeError("compiled_dll_missing")
        return dll_path.read_bytes()
