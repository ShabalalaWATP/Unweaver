from __future__ import annotations

from app.services.analysis.orchestrator import _build_action_space
from app.services.transforms.literal_propagator import LiteralPropagator
from app.services.transforms.workspace_file_deobfuscator import WorkspaceFileDeobfuscator
from app.services.transforms.workspace_profiler import WorkspaceProfiler


class TestLiteralPropagator:
    def test_javascript_propagates_literals_and_prunes_dead_branch(self):
        code = (
            'const enabled = false;\n'
            'const payload = "decoded-run";\n'
            "const alias = payload;\n"
            "if (enabled) {\n"
            '  console.log("dead");\n'
            "} else {\n"
            "  console.log(alias);\n"
            "}\n"
        )

        result = LiteralPropagator().apply(code, "javascript", {})

        assert result.success is True
        assert 'console.log("decoded-run");' in result.output
        assert "if (enabled)" not in result.output
        assert "dead_branch_pruning" in result.details["detected_techniques"]

    def test_python_propagates_literals_and_prunes_dead_branch(self):
        code = (
            "enabled = False\n"
            'prefix = "de"\n'
            'suffix = "coded"\n'
            "message = prefix + suffix\n"
            "if enabled:\n"
            '    print("dead")\n'
            "else:\n"
            "    print(message)\n"
        )

        result = LiteralPropagator().apply(code, "python", {})

        assert result.success is True
        assert "if enabled" not in result.output
        assert "print('decoded')" in result.output or 'print("decoded")' in result.output
        assert "dead_branch_pruning" in result.details["detected_techniques"]

    def test_recover_literals_action_uses_literal_propagator(self):
        space = _build_action_space()

        assert "recover_literals" in space
        assert isinstance(space["recover_literals"], LiteralPropagator)

    def test_javascript_uses_imported_literals_without_rewriting_imports(self):
        code = (
            'import payload from "./cfg";\n'
            'import { enabled } from "./flags";\n'
            "if (enabled) {\n"
            '  console.log("dead");\n'
            "} else {\n"
            "  console.log(payload);\n"
            "}\n"
        )

        result = LiteralPropagator().apply(
            code,
            "javascript",
            {"imported_literals": {"payload": "decoded-run", "enabled": False}},
        )

        assert result.success is True
        assert 'import payload from "./cfg";' in result.output
        assert 'import { enabled } from "./flags";' in result.output
        assert 'console.log("decoded-run");' in result.output
        assert "if (enabled)" not in result.output
        assert "cross_file_literal_propagation" in result.details["detected_techniques"]

    def test_javascript_ast_preserves_shadowed_function_parameters(self):
        code = (
            'const payload = "decoded-run";\n'
            "function run(payload) {\n"
            "  console.log(payload);\n"
            "}\n"
            "console.log(payload);\n"
        )

        result = LiteralPropagator().apply(code, "javascript", {})

        assert result.success is True
        assert 'function run(payload) {\n  console.log(payload);\n}' in result.output
        assert 'console.log("decoded-run");' in result.output
        assert "javascript_ast_literal_propagation" in result.details["detected_techniques"]

    def test_javascript_does_not_strip_exported_const_declarations(self):
        code = 'export const payload = "decoded-run";\n'

        result = LiteralPropagator().apply(code, "javascript", {})

        assert result.output == code
        assert result.success is False


class TestWorkspaceLiteralPropagation:
    def test_workspace_pipeline_applies_literal_propagation_to_hotspot_files(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: javascript=2\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/decode.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=60>>>\n'
            'import { run } from "./decode";\n'
            "run();\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=160>>>\n'
            "export function run() {\n"
            "  const enabled = false;\n"
            '  const payload = "decoded-run";\n'
            "  const alias = payload;\n"
            "  if (enabled) {\n"
            "    eval(alias);\n"
            "  } else {\n"
            "    console.log(alias);\n"
            "  }\n"
            "}\n"
            "<<<END FILE>>>\n"
        )

        profile = WorkspaceProfiler().apply(bundle, "workspace", {})
        result = WorkspaceFileDeobfuscator().apply(
            bundle,
            "workspace",
            {"workspace_context": profile.details["workspace_context"]},
        )

        assert result.success is True
        assert 'console.log("decoded-run");' in result.output
        assert "if (enabled)" not in result.output
        assert "literal_propagation" in result.details["detected_techniques"]

    def test_workspace_pipeline_propagates_exported_literals_across_javascript_files(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 3\n"
            "omitted_files: 0\n"
            "languages: javascript=3\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/main.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint,suspicious" size=120>>>\n'
            'import payload from "./config";\n'
            'import { enabled } from "./flags";\n'
            "if (enabled) {\n"
            '  console.log("dead");\n'
            "} else {\n"
            "  console.log(payload);\n"
            "}\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/config.js" language="javascript" priority="normal" size=40>>>\n'
            'export default "decoded-run";\n'
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/flags.js" language="javascript" priority="normal" size=32>>>\n'
            "export const enabled = false;\n"
            "<<<END FILE>>>\n"
        )

        profile = WorkspaceProfiler().apply(bundle, "workspace", {})
        result = WorkspaceFileDeobfuscator().apply(
            bundle,
            "workspace",
            {"workspace_context": profile.details["workspace_context"]},
        )

        assert result.success is True
        assert 'console.log("decoded-run");' in result.output
        assert "if (enabled)" not in result.output
        assert "cross_file_literal_propagation" in result.details["detected_techniques"]
        assert result.details["workspace_context"]["symbol_literal_files"]

    def test_workspace_pipeline_propagates_exported_literals_across_python_files(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: python=2\n"
            "entry_points: src/runner.py\n"
            "suspicious_files: src/runner.py\n"
            "manifest_files: pyproject.toml\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/constants.py" language="python" priority="normal" size=40>>>\n'
            "FLAG = False\n"
            'MESSAGE = "decoded-run"\n'
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/runner.py" language="python" priority="entrypoint,suspicious" size=120>>>\n'
            "from .constants import FLAG, MESSAGE\n"
            "if FLAG:\n"
            '    print("dead")\n'
            "else:\n"
            "    print(MESSAGE)\n"
            "<<<END FILE>>>\n"
        )

        profile = WorkspaceProfiler().apply(bundle, "workspace", {})
        result = WorkspaceFileDeobfuscator().apply(
            bundle,
            "workspace",
            {"workspace_context": profile.details["workspace_context"]},
        )

        assert result.success is True
        assert "if FLAG" not in result.output
        assert "print('decoded-run')" in result.output or 'print("decoded-run")' in result.output
        assert "cross_file_literal_propagation" in result.details["detected_techniques"]

    def test_workspace_pipeline_preserves_shadowed_javascript_parameters(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: javascript=2\n"
            "entry_points: src/runner.js\n"
            "suspicious_files: src/runner.js\n"
            "manifest_files: package.json\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/config.js" language="javascript" priority="normal" size=70>>>\n'
            'export const enabled = false;\n'
            'export const payload = "decoded-run";\n'
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/runner.js" language="javascript" priority="entrypoint,suspicious" size=220>>>\n'
            'import { enabled, payload } from "./config";\n'
            "export function run(payload) {\n"
            "  if (enabled) {\n"
            '    console.log("dead");\n'
            "  } else {\n"
            "    console.log(payload);\n"
            "  }\n"
            "}\n"
            "console.log(payload);\n"
            "<<<END FILE>>>\n"
        )

        profile = WorkspaceProfiler().apply(bundle, "workspace", {})
        result = WorkspaceFileDeobfuscator().apply(
            bundle,
            "workspace",
            {"workspace_context": profile.details["workspace_context"]},
        )

        assert result.success is True
        assert 'console.log("decoded-run");' in result.output
        assert 'console.log(payload);' in result.output
        assert "javascript_ast_literal_propagation" in result.details["detected_techniques"]
