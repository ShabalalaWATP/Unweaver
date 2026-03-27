from __future__ import annotations

from unittest.mock import patch

import app.services.transforms.javascript_bundle_deobfuscator as javascript_bundle_deobfuscator_module
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

    def test_materializes_bundle_modules_into_workspace_bundle(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 1\n"
            "omitted_files: 0\n"
            "languages: javascript=1\n"
            "entry_points: dist/app.bundle.js\n"
            "suspicious_files: dist/app.bundle.js\n"
            "manifest_files: none\n"
            "root_dirs: dist\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="dist/app.bundle.js" language="javascript" priority="entrypoint,bundle,suspicious" size=130>>>\n'
            "(()=>{var __webpack_modules__={1:(module)=>{module.exports='ok'}};"
            "function __webpack_require__(id){return __webpack_modules__[id](module={exports:{}}),module.exports;}"
            "console.log(__webpack_require__(1));})();\n"
            "<<<END FILE>>>\n"
        )

        with patch.object(
            javascript_bundle_deobfuscator_module,
            "javascript_bundle_tooling_available",
            return_value=True,
        ), patch.object(
            javascript_bundle_deobfuscator_module,
            "run_webcrack",
            return_value={
                "ok": True,
                "output": "function __webpack_require__(id) {\n  return id;\n}\nconsole.log(__webpack_require__(1));\n",
                "bundle": {
                    "type": "webpack",
                    "entryId": "1",
                    "moduleCount": 2,
                    "modules": [
                        {
                            "id": "1",
                            "path": "src/index.js",
                            "isEntry": True,
                            "code": "console.log('entry');\n",
                        },
                        {
                            "id": "2",
                            "path": "src/utils.js",
                            "isEntry": False,
                            "code": "export const value = 1;\n",
                        },
                    ],
                },
                "heuristics": {"bundleLike": True},
            },
        ), patch.object(
            javascript_bundle_deobfuscator_module,
            "validate_javascript_source",
            return_value={"ok": True},
        ):
            result = WorkspaceFileDeobfuscator().apply(
                bundle,
                "workspace",
                {
                    "workspace_context": {
                        "entry_points": ["dist/app.bundle.js"],
                        "suspicious_files": ["dist/app.bundle.js"],
                    }
                },
            )

        rebuilt_files = parse_workspace_bundle(result.output)
        rebuilt_paths = {item.path for item in rebuilt_files}

        assert result.success is True
        assert "dist/app.bundle.js.__webcrack__/src/index.js" in rebuilt_paths
        assert "dist/app.bundle.js.__webcrack__/src/utils.js" in rebuilt_paths
        assert len(rebuilt_files) == 3
        assert "dist/app.bundle.js.__webcrack__/src/index.js" in result.details["added_files_to_bundle"]
