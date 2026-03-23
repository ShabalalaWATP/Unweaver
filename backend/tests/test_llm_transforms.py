from __future__ import annotations

import json

from app.services.transforms.llm_deobfuscator import LLMDeobfuscator
from app.services.transforms.llm_multilayer import LLMMultiLayerUnwrapper
from app.services.transforms.llm_renamer import LLMRenamer


class TestLLMRenamer:
    def test_does_not_rename_inside_strings_or_comments(self):
        code = 'var _0x1 = 1; console.log("_0x1"); // _0x1 should stay\n'
        reply = json.dumps({"_0x1": "decodedValue"})

        result = LLMRenamer().parse_response(reply, code, "javascript", {})

        assert result.success is True
        assert "var decodedValue = 1;" in result.output
        assert '"_0x1"' in result.output
        assert "// _0x1 should stay" in result.output

    def test_workspace_renames_do_not_touch_file_paths(self):
        code = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 1\n"
            "omitted_files: 0\n"
            "languages: javascript=1\n"
            "entry_points: src/_0x1.js\n"
            "suspicious_files: none\n"
            "manifest_files: none\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/_0x1.js" language="javascript" priority="entrypoint" size=48>>>\n'
            "const _0x1 = 1;\nconsole.log(_0x1);\n"
            "<<<END FILE>>>\n"
        )
        reply = json.dumps({"_0x1": "decodedValue"})

        result = LLMRenamer().parse_response(reply, code, "workspace", {})

        assert result.success is True
        assert 'path="src/_0x1.js"' in result.output
        assert "const decodedValue = 1;" in result.output
        assert "console.log(decodedValue);" in result.output


class TestLLMDeobfuscator:
    def test_rejects_structurally_unsafe_candidate(self):
        reply = json.dumps(
            {
                "cleaned_code": "function decodePayload( {",
                "confidence": 0.9,
            }
        )

        result = LLMDeobfuscator().parse_response(
            reply,
            "function decodePayload(){ return 1; }",
            "javascript",
            {},
        )

        assert result.success is False
        assert "validation" in result.details
        assert "unbalanced_delimiters" in result.details["validation"]["issues"]

    def test_accepts_structured_json_result(self):
        reply = json.dumps(
            {
                "cleaned_code": 'var decodedMessage = "hello";',
                "decoded_artifacts": ["hello"],
                "renames": {"_0x1": "decodedMessage"},
                "remaining_uncertainties": ["exact origin of blob"],
                "confidence": 0.82,
            }
        )

        result = LLMDeobfuscator().parse_response(
            reply,
            'var _0x1 = atob("aGVsbG8=");',
            "javascript",
            {},
        )

        assert result.success is True
        assert result.output == 'var decodedMessage = "hello";'
        assert result.details["decoded_artifacts"] == ["hello"]
        assert result.details["renames"]["_0x1"] == "decodedMessage"

    def test_rejects_workspace_candidate_that_drops_file_blocks(self):
        original = (
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
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=36>>>\n'
            "const run = () => console.log('ok');\n"
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=42>>>\n'
            "const decode = (value) => eval(value);\n"
            "<<<END FILE>>>\n"
        )
        reply = json.dumps(
            {
                "cleaned_code": (
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
                    '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=36>>>\n'
                    "const run = () => console.log('ok');\n"
                    "<<<END FILE>>>\n"
                ),
                "confidence": 0.8,
            }
        )

        result = LLMDeobfuscator().parse_response(reply, original, "workspace", {})

        assert result.success is False
        assert "workspace_file_blocks_missing" in result.details["validation"]["issues"]

    def test_truncate_code_keeps_workspace_header_and_file_markers(self):
        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 3\n"
            "omitted_files: 0\n"
            "languages: typescript=3\n"
            "entry_points: apps/web/src/main.tsx\n"
            "suspicious_files: packages/api/src/decode.ts\n"
            "manifest_files: package.json\n"
            "root_dirs: apps | packages\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="apps/web/src/main.tsx" language="typescript" priority="entrypoint" size=120>>>\n'
            + ("const x = atob('aGVsbG8=');\n" * 20)
            + "<<<END FILE>>>\n\n"
            + '<<<FILE path="packages/api/src/decode.ts" language="typescript" priority="suspicious" size=120>>>\n'
            + ("export const decode = (v) => eval(v);\n" * 20)
            + "<<<END FILE>>>\n"
        )

        truncated = LLMDeobfuscator.truncate_code(bundle, max_chars=500)

        assert truncated.startswith("UNWEAVER_WORKSPACE_BUNDLE v1")
        assert '<<<FILE path="apps/web/src/main.tsx"' in truncated


class TestLLMMultiLayerUnwrapper:
    def test_keeps_partial_result_when_unwrapped_code_is_unsafe(self):
        reply = json.dumps(
            {
                "layers_detected": [
                    {"layer": 1, "type": "base64", "description": "outer wrapper"}
                ],
                "unwrapped_code": "function brokenPayload( {",
                "hidden_payloads": ["http://example.test/payload"],
                "confidence": 0.7,
                "notes": "Recovered only part of the layer stack",
            }
        )

        original = 'var data = atob("aGVsbG8=");'
        result = LLMMultiLayerUnwrapper().parse_response(
            reply,
            original,
            "javascript",
            {},
        )

        assert result.success is True
        assert result.output == original
        assert result.details["fully_unwrapped"] is False
        assert result.details["validation"]["accepted"] is False
