from __future__ import annotations

from app.services.ingest.workspace_bundle import parse_workspace_bundle
from app.services.transforms.workspace_file_deobfuscator import WorkspaceFileDeobfuscator
from app.services.transforms.workspace_profiler import WorkspaceProfiler


class TestWorkspaceFileDeobfuscator:
    def test_deobfuscates_prioritized_files_and_preserves_bundle(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 3\n"
            "omitted_files: 0\n"
            "languages: javascript=1, python=1, json=1\n"
            "entry_points: src/main.js\n"
            "suspicious_files: tools/payload.py\n"
            "manifest_files: package.json\n"
            "root_dirs: src | tools\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=70>>>\n'
            "const msg = String.fromCharCode(72, 105);\n"
            "console.log(msg);\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="tools/payload.py" language="python" priority="suspicious" size=80>>>\n'
            "import base64\n"
            "exec(base64.b64decode('cHJpbnQoImhpIik='))\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="package.json" language="json" priority="manifest" size=30>>>\n'
            '{\"name\":\"demo\"}\n'
            "<<<END FILE>>>\n"
        )

        profile = WorkspaceProfiler().apply(bundle, "workspace", {})
        result = WorkspaceFileDeobfuscator().apply(
            bundle,
            "workspace",
            {"workspace_context": profile.details["workspace_context"]},
        )

        assert result.success is True
        assert 'console.log("Hi");' in result.output
        assert '# DECODED (exec+b64):\nprint("hi")' in result.output
        assert set(result.details["deobfuscated_files"]) == {"src/main.js", "tools/payload.py"}
        assert result.details["workspace_validation"]["accepted"] is True
        assert len(parse_workspace_bundle(result.output)) == 3
