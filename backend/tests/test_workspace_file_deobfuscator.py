from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import app.services.transforms.javascript_bundle_deobfuscator as javascript_bundle_deobfuscator_module
import app.services.transforms.semantic_verifier as semantic_verifier_module
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
        assert result.details["workspace_context"]["targeted_supported_ratio"] == 1.0
        assert result.details["workspace_context"]["recovered_target_ratio"] == 1.0
        assert result.details["file_transform_summary"][0]["final_verification"]["safe"] is True
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

    def test_rejects_destructive_structural_candidates(self):
        validation = WorkspaceFileDeobfuscator()._candidate_validation_summary(
            language="javascript",
            before=(
                "import tool from './tool';\n"
                "function first(){ return tool(); }\n"
                "function second(){ return first(); }\n"
            ),
            after="console.log('trimmed');\n",
        )

        assert validation["safe"] is False
        assert "import_surface_removed" in validation["reasons"]
        assert "function_surface_removed" in validation["reasons"]

    def test_rejects_javascript_export_surface_change_without_structural_loss(self):
        def _id(name: str) -> SimpleNamespace:
            return SimpleNamespace(type="Identifier", name=name)

        before_program = SimpleNamespace(
            type="Program",
            body=[
                SimpleNamespace(
                    type="ImportDeclaration",
                    source=SimpleNamespace(type="Literal", value="./tool"),
                ),
                SimpleNamespace(
                    type="ExportNamedDeclaration",
                    declaration=None,
                    specifiers=[
                        SimpleNamespace(
                            type="ExportSpecifier",
                            local=_id("run"),
                            exported=_id("run"),
                        )
                    ],
                    source=None,
                ),
                SimpleNamespace(
                    type="FunctionDeclaration",
                    id=_id("run"),
                    body=SimpleNamespace(type="BlockStatement", body=[]),
                ),
            ],
        )
        after_program = SimpleNamespace(
            type="Program",
            body=[
                SimpleNamespace(
                    type="ImportDeclaration",
                    source=SimpleNamespace(type="Literal", value="./tool"),
                ),
                SimpleNamespace(
                    type="FunctionDeclaration",
                    id=_id("run"),
                    body=SimpleNamespace(type="BlockStatement", body=[]),
                ),
            ],
        )

        with patch.object(
            semantic_verifier_module,
            "parse_javascript_ast",
            side_effect=lambda code, language="javascript": (
                before_program if "export { run }" in code else after_program
            ),
        ):
            validation = WorkspaceFileDeobfuscator()._candidate_validation_summary(
                language="javascript",
                before=(
                    "import tool from './tool';\n"
                    "export { run };\n"
                    "function run(){ return tool(); }\n"
                ),
                after=(
                    "import tool from './tool';\n"
                    "function run(){ return tool(); }\n"
                ),
            )

        assert validation["safe"] is False
        assert "export_surface_changed" in validation["reasons"]
        assert validation["semantic"]["available"] is True
        assert validation["semantic"]["missing_exports"] == ["run"]

    def test_rejects_python_entrypoint_call_surface_change(self):
        validation = WorkspaceFileDeobfuscator()._candidate_validation_summary(
            language="python",
            before=(
                "def run():\n"
                "    return 1\n\n"
                "if __name__ == '__main__':\n"
                "    run()\n"
            ),
            after=(
                "def run():\n"
                "    return 1\n\n"
                "if __name__ == '__main__':\n"
                "    pass\n"
            ),
        )

        assert validation["safe"] is False
        assert "entrypoint_call_surface_removed" in validation["reasons"]
        assert validation["semantic"]["available"] is True
        assert validation["semantic"]["missing_top_level_calls"] == ["local_call"]

    def test_rejects_powershell_export_surface_change(self):
        validation = WorkspaceFileDeobfuscator()._candidate_validation_summary(
            language="powershell",
            before=(
                "function Invoke-Task {\n"
                "  Write-Host 'x'\n"
                "}\n"
                "Export-ModuleMember -Function Invoke-Task\n"
            ),
            after=(
                "function Invoke-Task {\n"
                "  Write-Host 'x'\n"
                "}\n"
            ),
        )

        assert validation["safe"] is False
        assert "export_surface_changed" in validation["reasons"]
        assert validation["semantic"]["available"] is True
        assert validation["semantic"]["missing_exports"] == ["Invoke-Task"]

    def test_advances_workspace_coverage_across_batches_even_without_new_rewrites(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 4\n"
            "omitted_files: 0\n"
            "languages: javascript=4\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/decode.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=60>>>\n'
            "const msg = String.fromCharCode(72, 105);\n"
            "console.log(msg);\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=60>>>\n'
            "const msg = String.fromCharCode(66, 121, 101);\n"
            "console.log(msg);\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/utils.js" language="javascript" priority="normal" size=48>>>\n'
            "export function keep(){ return 'steady'; }\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/worker.js" language="javascript" priority="normal" size=44>>>\n'
            "export const value = 7;\n"
            "<<<END FILE>>>\n"
        )

        profile = WorkspaceProfiler().apply(bundle, "workspace", {})
        deobfuscator = WorkspaceFileDeobfuscator()

        with patch.object(WorkspaceFileDeobfuscator, "_MAX_TARGET_FILES", 2), patch.object(
            WorkspaceFileDeobfuscator,
            "_MAX_BUNDLE_ADDITIONS",
            2,
        ):
            first = deobfuscator.apply(
                bundle,
                "workspace",
                {"workspace_context": profile.details["workspace_context"]},
            )
            second = deobfuscator.apply(
                first.output,
                "workspace",
                {"workspace_context": first.details["workspace_context"]},
            )

        assert first.success is True
        assert 'console.log("Hi");' in first.output
        assert first.details["workspace_context"]["targeted_file_count"] == 2
        assert first.details["workspace_context"]["remaining_supported_file_count"] == 2
        assert first.details["workspace_context"]["workspace_pass_index"] == 1

        assert second.success is True
        assert second.output == first.output
        assert second.details["coverage_advanced"] is True
        assert second.details["workspace_context"]["latest_targeted_file_count"] == 2
        assert second.details["workspace_context"]["targeted_file_count"] == 4
        assert second.details["workspace_context"]["remaining_supported_file_count"] == 0
        assert second.details["workspace_context"]["workspace_pass_index"] == 2
