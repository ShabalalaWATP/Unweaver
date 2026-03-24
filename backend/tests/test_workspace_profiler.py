from __future__ import annotations

from app.services.transforms.workspace_profiler import WorkspaceProfiler


class TestWorkspaceProfiler:
    def test_extracts_imports_entrypoints_and_workspace_context(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: typescript=2\n"
            "entry_points: apps/web/src/main.tsx\n"
            "suspicious_files: packages/api/src/decode.ts\n"
            "manifest_files: package.json\n"
            "root_dirs: apps | packages\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="apps/web/src/main.tsx" language="typescript" priority="entrypoint" size=80>>>\n'
            'import { decode } from "../../packages/api/src/decode";\n'
            "const main = () => decode('test');\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="packages/api/src/decode.ts" language="typescript" priority="suspicious" size=80>>>\n'
            "export const decode = (value: string) => eval(value);\n"
            "<<<END FILE>>>\n"
        )

        result = WorkspaceProfiler().apply(bundle, "workspace", {})

        assert result.success is True
        assert "workspace_bundle" in result.details["detected_techniques"]
        assert "monorepo_bundle" in result.details["detected_techniques"]
        assert any("apps/web/src/main.tsx -> ../../packages/api/src/decode" in item for item in result.details["imports"])
        assert any("packages/api/src/decode.ts::decode" in item for item in result.details["functions"])
        assert result.details["workspace_context"]["entry_points"] == ["apps/web/src/main.tsx"]
        assert result.details["workspace_context"]["local_dependency_count"] == 1
        assert result.details["workspace_context"]["cross_file_call_count"] == 1
        assert result.details["workspace_context"]["dependency_hotspots"][:2] == [
            "packages/api/src/decode.ts",
            "apps/web/src/main.tsx",
        ]
        assert result.details["workspace_context"]["symbol_hotspots"][:2] == [
            "packages/api/src/decode.ts",
            "apps/web/src/main.tsx",
        ]
        assert result.details["workspace_context"]["execution_paths"] == [
            "apps/web/src/main.tsx -> packages/api/src/decode.ts::decode"
        ]
        assert result.details["workspace_context"]["prioritized_files"][0]["path"] == "packages/api/src/decode.ts"
        assert result.details["workspace_context"]["prioritized_files"][0]["cross_file_call_in"] == 1
        assert result.details["import_edges"][0]["kind"] == "local"
        assert result.details["import_edges"][0]["resolved"] == "packages/api/src/decode.ts"
