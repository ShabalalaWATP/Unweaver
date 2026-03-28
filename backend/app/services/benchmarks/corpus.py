from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple


CORPUS_NAME = "js_recovery"
CORPUS_VERSION = "js-corpus-v2"


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    name: str
    description: str
    language: str
    obfuscated_code: str
    ground_truth_code: str
    expected_markers: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    max_iterations: int | None = None
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    pass_threshold: float = 0.75


def load_js_benchmark_corpus(*, limit: int | None = None) -> List[BenchmarkCase]:
    cases: Sequence[BenchmarkCase] = (
        BenchmarkCase(
            case_id="js-atob-console",
            name="Base64 String Decode",
            description="Simple atob wrapper should recover the literal and preserve the call surface.",
            language="javascript",
            obfuscated_code=(
                'var _0x1 = atob("aGVsbG8gd29ybGQ=");\n'
                "console.log(_0x1);\n"
            ),
            ground_truth_code=(
                'const message = "hello world";\n'
                "console.log(message);\n"
            ),
            expected_markers=("hello world", "console.log"),
            tags=("single_file", "base64", "strings"),
        ),
        BenchmarkCase(
            case_id="js-string-array",
            name="Array Resolver",
            description="String table wrappers should resolve to the underlying literal.",
            language="javascript",
            obfuscated_code=(
                'const _0x59d2 = ["http://evil.test/payload"];\n'
                "function _0x1f(index) {\n"
                "  return _0x59d2[index];\n"
                "}\n"
                "console.log(_0x1f(0));\n"
            ),
            ground_truth_code=(
                'const payloadUrl = "http://evil.test/payload";\n'
                "console.log(payloadUrl);\n"
            ),
            expected_markers=("http://evil.test/payload", "console.log"),
            tags=("single_file", "array_resolver", "iocs"),
        ),
        BenchmarkCase(
            case_id="js-esm-import-preservation",
            name="ESM Import Preservation",
            description="The recovered code should decode the literal without breaking imports, exports, or entrypoints.",
            language="javascript",
            obfuscated_code=(
                'import { decode as _0xdec } from "./codec";\n'
                "export function run() {\n"
                '  return _0xdec(atob("aGk="));\n'
                "}\n\n"
                "run();\n"
            ),
            ground_truth_code=(
                'import { decode } from "./codec";\n'
                "export function run() {\n"
                '  return decode("hi");\n'
                "}\n\n"
                "run();\n"
            ),
            expected_markers=("./codec", "export function run", "hi", "run();"),
            tags=("single_file", "module_surface", "base64"),
        ),
        BenchmarkCase(
            case_id="workspace-cross-file-base64",
            name="Workspace Cross-file Decode",
            description="A small workspace bundle should recover the decoded helper while preserving cross-file imports.",
            language="workspace",
            obfuscated_code=(
                "UNWEAVER_WORKSPACE_BUNDLE v1\n"
                "archive_name: benchmark.zip\n"
                "included_files: 2\n"
                "omitted_files: 0\n"
                "languages: javascript=2\n"
                "entry_points: src/main.js\n"
                "suspicious_files: src/decode.js\n"
                "manifest_files: none\n"
                "root_dirs: src\n"
                "bundle_note: benchmark bundle.\n\n"
                '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=55>>>\n'
                "export function decodeValue() {\n"
                '  return atob("aGk=");\n'
                "}\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=76>>>\n'
                "import { decodeValue } from './decode.js';\n"
                "console.log(decodeValue());\n"
                "<<<END FILE>>>\n"
            ),
            ground_truth_code=(
                "UNWEAVER_WORKSPACE_BUNDLE v1\n"
                "archive_name: benchmark.zip\n"
                "included_files: 2\n"
                "omitted_files: 0\n"
                "languages: javascript=2\n"
                "entry_points: src/main.js\n"
                "suspicious_files: src/decode.js\n"
                "manifest_files: none\n"
                "root_dirs: src\n"
                "bundle_note: benchmark bundle.\n\n"
                '<<<FILE path="src/decode.js" language="javascript" priority="suspicious" size=54>>>\n'
                "export function decodeValue() {\n"
                '  return "hi";\n'
                "}\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=76>>>\n'
                "import { decodeValue } from './decode.js';\n"
                "console.log(decodeValue());\n"
                "<<<END FILE>>>\n"
            ),
            expected_markers=("src/decode.js", "hi", "src/main.js", "decodeValue"),
            tags=("workspace", "cross_file", "base64"),
            max_iterations=12,
            analysis_metadata={"content_kind": "archive_bundle", "filename": "benchmark.zip"},
            pass_threshold=0.7,
        ),
        BenchmarkCase(
            case_id="workspace-monorepo-package-graph",
            name="Monorepo Package Graph Decode",
            description="A JS monorepo workspace should recover a shared package helper without breaking package manifests or app imports.",
            language="workspace",
            obfuscated_code=(
                "UNWEAVER_WORKSPACE_BUNDLE v1\n"
                "archive_name: monorepo.zip\n"
                "included_files: 6\n"
                "omitted_files: 0\n"
                "languages: javascript=4, json=2\n"
                "entry_points: apps/web/src/main.js\n"
                "suspicious_files: packages/shared/src/decode.js\n"
                "manifest_files: apps/web/package.json | packages/shared/package.json\n"
                "root_dirs: apps | packages\n"
                "package_roots: apps/web | packages/shared\n"
                "bundle_note: benchmark bundle.\n\n"
                '<<<FILE path="apps/web/package.json" language="json" priority="manifest" size=70>>>\n'
                '{"name":"@repo/web","dependencies":{"@repo/shared":"workspace:*"}}\n'
                "<<<END FILE>>>\n\n"
                '<<<FILE path="apps/web/src/main.js" language="javascript" priority="entrypoint" size=88>>>\n'
                'import { decodeValue } from "@repo/shared";\n'
                "console.log(decodeValue());\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="apps/web/src/view.js" language="javascript" priority="normal" size=42>>>\n'
                "export const page = 'web';\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="packages/shared/package.json" language="json" priority="manifest" size=52>>>\n'
                '{"name":"@repo/shared","main":"src/index.js"}\n'
                "<<<END FILE>>>\n\n"
                '<<<FILE path="packages/shared/src/index.js" language="javascript" priority="normal" size=72>>>\n'
                "export { decodeValue } from './decode.js';\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="packages/shared/src/decode.js" language="javascript" priority="suspicious" size=76>>>\n'
                "export function decodeValue(){\n"
                '  return atob("aGk=");\n'
                "}\n"
                "<<<END FILE>>>\n"
            ),
            ground_truth_code=(
                "UNWEAVER_WORKSPACE_BUNDLE v1\n"
                "archive_name: monorepo.zip\n"
                "included_files: 6\n"
                "omitted_files: 0\n"
                "languages: javascript=4, json=2\n"
                "entry_points: apps/web/src/main.js\n"
                "suspicious_files: packages/shared/src/decode.js\n"
                "manifest_files: apps/web/package.json | packages/shared/package.json\n"
                "root_dirs: apps | packages\n"
                "package_roots: apps/web | packages/shared\n"
                "bundle_note: benchmark bundle.\n\n"
                '<<<FILE path="apps/web/package.json" language="json" priority="manifest" size=70>>>\n'
                '{"name":"@repo/web","dependencies":{"@repo/shared":"workspace:*"}}\n'
                "<<<END FILE>>>\n\n"
                '<<<FILE path="apps/web/src/main.js" language="javascript" priority="entrypoint" size=88>>>\n'
                'import { decodeValue } from "@repo/shared";\n'
                "console.log(decodeValue());\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="apps/web/src/view.js" language="javascript" priority="normal" size=42>>>\n'
                "export const page = 'web';\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="packages/shared/package.json" language="json" priority="manifest" size=52>>>\n'
                '{"name":"@repo/shared","main":"src/index.js"}\n'
                "<<<END FILE>>>\n\n"
                '<<<FILE path="packages/shared/src/index.js" language="javascript" priority="normal" size=72>>>\n'
                "export { decodeValue } from './decode.js';\n"
                "<<<END FILE>>>\n\n"
                '<<<FILE path="packages/shared/src/decode.js" language="javascript" priority="suspicious" size=72>>>\n'
                "export function decodeValue(){\n"
                '  return "hi";\n'
                "}\n"
                "<<<END FILE>>>\n"
            ),
            expected_markers=(
                "@repo/shared",
                "packages/shared/src/decode.js",
                "apps/web/src/main.js",
                '"hi"',
            ),
            tags=("workspace", "monorepo", "package_graph", "base64"),
            max_iterations=14,
            analysis_metadata={"content_kind": "archive_bundle", "filename": "monorepo.zip"},
            pass_threshold=0.72,
        ),
    )
    materialized = list(cases)
    if limit is not None and limit > 0:
        return materialized[:limit]
    return materialized
