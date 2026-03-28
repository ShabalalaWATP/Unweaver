from __future__ import annotations

from app.services.analysis.orchestrator import AnalysisResult
from app.services.benchmarks.corpus import load_js_benchmark_corpus
from app.services.benchmarks.runner import (
    score_benchmark_case,
    summarize_benchmark_results,
)


class TestBenchmarkScoring:
    def test_scores_matching_single_file_case_highly(self):
        case = load_js_benchmark_corpus(limit=1)[0]
        result = AnalysisResult(
            sample_id="bench-case-1",
            success=True,
            original_code=case.obfuscated_code,
            deobfuscated_code=case.ground_truth_code,
            language=case.language,
            iterations=4,
            confidence=0.91,
            stop_reason="Completed normally.",
        )

        scored = score_benchmark_case(case, result)

        assert scored["passed"] is True
        assert scored["overall_score"] >= 0.9
        assert scored["metrics"]["marker_score"] == 1.0
        assert scored["metrics"]["surface"]["score"] >= 0.9

    def test_scores_workspace_case_lower_when_expected_file_is_missing(self):
        case = load_js_benchmark_corpus(limit=4)[-1]
        recovered = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: benchmark.zip\n"
            "included_files: 1\n"
            "omitted_files: 1\n"
            "languages: javascript=1\n"
            "entry_points: src/main.js\n"
            "suspicious_files: src/decode.js\n"
            "manifest_files: none\n"
            "root_dirs: src\n"
            "bundle_note: benchmark bundle.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=76>>>\n'
            "import { decodeValue } from './decode.js';\n"
            "console.log(decodeValue());\n"
            "<<<END FILE>>>\n"
        )
        result = AnalysisResult(
            sample_id="bench-case-2",
            success=False,
            original_code=case.obfuscated_code,
            deobfuscated_code=recovered,
            language=case.language,
            iterations=7,
            confidence=0.42,
            stop_reason="Action queue exhausted; no more transforms to try.",
        )

        scored = score_benchmark_case(case, result)

        assert scored["passed"] is False
        assert scored["overall_score"] < case.pass_threshold
        assert "Missing expected files" in " ".join(scored["notes"])
        assert scored["metrics"]["file_presence_score"] < 1.0

    def test_summary_collects_strengths_and_recommendations(self):
        corpus = load_js_benchmark_corpus(limit=2)
        good = score_benchmark_case(
            corpus[0],
            AnalysisResult(
                sample_id="bench-good",
                success=True,
                original_code=corpus[0].obfuscated_code,
                deobfuscated_code=corpus[0].ground_truth_code,
                language=corpus[0].language,
                iterations=3,
                confidence=0.88,
                stop_reason="Completed normally.",
            ),
        )
        poor = score_benchmark_case(
            corpus[1],
            AnalysisResult(
                sample_id="bench-poor",
                success=False,
                original_code=corpus[1].obfuscated_code,
                deobfuscated_code="",
                language=corpus[1].language,
                iterations=5,
                confidence=0.2,
                stop_reason="Too many consecutive failures (3).",
            ),
        )

        summary = summarize_benchmark_results([good, poor], llm_enabled=True)

        assert summary["case_count"] == 2
        assert summary["failed_cases"] == 1
        assert isinstance(summary["recommendations"], list)
        assert summary["recommendations"]

    def test_scores_matching_monorepo_workspace_case_highly(self):
        case = next(
            item
            for item in load_js_benchmark_corpus()
            if item.case_id == "workspace-monorepo-package-graph"
        )
        result = AnalysisResult(
            sample_id="bench-monorepo",
            success=True,
            original_code=case.obfuscated_code,
            deobfuscated_code=case.ground_truth_code,
            language=case.language,
            iterations=6,
            confidence=0.9,
            stop_reason="Completed normally.",
        )

        scored = score_benchmark_case(case, result)

        assert scored["passed"] is True
        assert scored["overall_score"] >= case.pass_threshold
        assert scored["metrics"]["syntax_ok"] is True
        assert scored["metrics"]["missing_paths"] == []
