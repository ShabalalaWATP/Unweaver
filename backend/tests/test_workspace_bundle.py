from __future__ import annotations

import io
import zipfile

from app.services.ingest.workspace_bundle import (
    build_workspace_bundle,
    extract_workspace_context,
    parse_workspace_bundle,
    pick_workspace_bundle_text,
    rebuild_workspace_bundle,
    truncate_workspace_bundle,
    validate_workspace_bundle_candidate,
)


class TestWorkspaceBundle:
    def test_build_bundle_prioritizes_entrypoints_and_suspicious_files(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w") as archive:
            archive.writestr(
                "apps/web/src/main.tsx",
                'const payload = atob("aGVsbG8=");\nconsole.log(payload);\n',
            )
            archive.writestr(
                "packages/api/src/decode.ts",
                "export const decode = (value: string) => eval(value);\n",
            )
            archive.writestr(
                "docs/readme.txt",
                "plain documentation",
            )

        result = build_workspace_bundle(
            filename="repo.zip",
            content_bytes=archive_bytes.getvalue(),
            max_bundle_chars=20_000,
            max_member_bytes=200_000,
            max_files=10,
        )

        context = extract_workspace_context(result.bundle_text)
        assert context is not None
        assert context["archive_name"] == "repo.zip"
        assert "apps/web/src/main.tsx" in context["entry_points"]
        assert "packages/api/src/decode.ts" in context["suspicious_files"]

    def test_truncate_bundle_keeps_manifest_and_file_markers(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w") as archive:
            archive.writestr("apps/web/src/main.tsx", "console.log('hello');\n" * 40)
            archive.writestr("packages/api/src/index.ts", "export const run = true;\n" * 40)
            archive.writestr("packages/api/src/worker.ts", "export const worker = true;\n" * 40)

        result = build_workspace_bundle(
            filename="repo.zip",
            content_bytes=archive_bytes.getvalue(),
            max_bundle_chars=30_000,
            max_member_bytes=200_000,
            max_files=10,
        )

        truncated = truncate_workspace_bundle(result.bundle_text, 500)
        assert truncated.startswith("UNWEAVER_WORKSPACE_BUNDLE v1")
        assert '<<<FILE path="' in truncated
        assert "additional bundled file(s) omitted" in truncated

    def test_validate_candidate_rejects_missing_file_blocks(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w") as archive:
            archive.writestr("apps/web/src/main.tsx", "console.log('hello');\n")
            archive.writestr("packages/api/src/index.ts", "export const run = true;\n")

        result = build_workspace_bundle(
            filename="repo.zip",
            content_bytes=archive_bytes.getvalue(),
            max_bundle_chars=30_000,
            max_member_bytes=200_000,
            max_files=10,
        )

        original_files = parse_workspace_bundle(result.bundle_text)
        candidate = rebuild_workspace_bundle(result.bundle_text, original_files[:1])
        validation = validate_workspace_bundle_candidate(result.bundle_text, candidate)

        assert validation["accepted"] is False
        assert "workspace_file_blocks_missing" in validation["issues"]
        assert "packages/api/src/index.ts" in validation["missing_paths"]

    def test_pick_workspace_bundle_text_skips_invalid_candidate(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w") as archive:
            archive.writestr("apps/web/src/main.tsx", "console.log('hello');\n")
            archive.writestr("packages/api/src/index.ts", "export const run = true;\n")

        result = build_workspace_bundle(
            filename="repo.zip",
            content_bytes=archive_bytes.getvalue(),
            max_bundle_chars=30_000,
            max_member_bytes=200_000,
            max_files=10,
        )

        invalid_candidate = rebuild_workspace_bundle(
            result.bundle_text,
            parse_workspace_bundle(result.bundle_text)[:1],
        )

        assert pick_workspace_bundle_text(invalid_candidate, result.bundle_text) == result.bundle_text
