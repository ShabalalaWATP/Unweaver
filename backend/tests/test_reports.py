from __future__ import annotations

from datetime import datetime, timezone

from app.services.reports.json_report import generate_json_report
from app.services.reports.markdown import generate_markdown_report


class TestWorkspaceReports:
    def test_json_report_includes_workspace_graph_context(self):
        report = generate_json_report(
            sample_id="sample-1",
            filename="repo.zip",
            language="workspace",
            status="completed",
            original_text=(
                "UNWEAVER_WORKSPACE_BUNDLE v1\n"
                "archive_name: repo.zip\n"
                "included_files: 1\n"
                "omitted_files: 0\n"
                "languages: javascript=1\n"
                "entry_points: src/main.js\n"
                "suspicious_files: src/main.js\n"
                "manifest_files: package.json\n"
                "root_dirs: src\n"
                "bundle_note: preserve markers.\n\n"
                '<<<FILE path="src/main.js" language="javascript" priority="entrypoint,suspicious" size=20>>>\n'
                "console.log('hi');\n"
                "<<<END FILE>>>\n"
            ),
            recovered_text=None,
            analyst_notes=None,
            created_at=datetime.now(timezone.utc),
            transforms=[],
            strings=[],
            iocs=[],
            findings=[],
            iteration_states=[
                {
                    "state_json": (
                        '{"workspace_context": {'
                        '"dependency_hotspots": ["src/main.js"], '
                        '"symbol_hotspots": ["src/main.js"], '
                        '"execution_paths": ["src/main.js -> src/lib.js::decode"], '
                        '"graph_summary": {"cross_file_calls": 1, "execution_paths": 1}'
                        '}}'
                    )
                }
            ],
        )

        assert report["workspace"]["dependency_hotspots"] == ["src/main.js"]
        assert report["workspace"]["execution_paths"] == ["src/main.js -> src/lib.js::decode"]
        assert report["workspace"]["graph_summary"]["cross_file_calls"] == 1

    def test_markdown_report_mentions_execution_paths(self):
        report = generate_markdown_report(
            sample_id="sample-1",
            filename="repo.zip",
            language="workspace",
            status="completed",
            original_text=(
                "UNWEAVER_WORKSPACE_BUNDLE v1\n"
                "archive_name: repo.zip\n"
                "included_files: 1\n"
                "omitted_files: 0\n"
                "languages: javascript=1\n"
                "entry_points: src/main.js\n"
                "suspicious_files: src/main.js\n"
                "manifest_files: package.json\n"
                "root_dirs: src\n"
                "bundle_note: preserve markers.\n\n"
                '<<<FILE path="src/main.js" language="javascript" priority="entrypoint,suspicious" size=20>>>\n'
                "console.log('hi');\n"
                "<<<END FILE>>>\n"
            ),
            recovered_text=None,
            analyst_notes=None,
            created_at=datetime.now(timezone.utc),
            transforms=[],
            strings=[],
            iocs=[],
            findings=[],
            iteration_states=[
                {
                    "state_json": (
                        '{"workspace_context": {'
                        '"dependency_hotspots": ["src/main.js"], '
                        '"execution_paths": ["src/main.js -> src/lib.js::decode"], '
                        '"graph_summary": {"cross_file_calls": 1, "execution_paths": 1}'
                        '}}'
                    )
                }
            ],
        )

        assert "Cross-file calls: 1" in report
        assert "Execution paths: 1" in report
        assert "`src/main.js -> src/lib.js::decode`" in report
