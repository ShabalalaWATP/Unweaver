from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import decrypt_value
from app.core.database import async_session
from app.models.db_models import BenchmarkRun, ProviderConfig
from app.services.analysis.orchestrator import AnalysisResult, Orchestrator
from app.services.benchmarks.corpus import (
    CORPUS_NAME,
    CORPUS_VERSION,
    BenchmarkCase,
    load_js_benchmark_corpus,
)
from app.services.ingest.workspace_bundle import parse_workspace_bundle
from app.services.llm.client import LLMClient, _MAX_TOKENS_MAP
from app.services.transforms.js_tooling import validate_javascript_source
from app.services.transforms.readability_scorer import compute_readability_score
from app.services.transforms.semantic_verifier import semantic_signature

logger = logging.getLogger(__name__)

_RUNNING_BENCHMARKS: Dict[str, asyncio.Task[None]] = {}
_STARTUP_SCHEDULER_TASK: Optional[asyncio.Task[None]] = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(value)))


def _normalized_code(text: str) -> str:
    return "".join(str(text or "").split())


def _similarity_ratio(expected: str, recovered: str) -> float:
    return round(
        SequenceMatcher(
            None,
            _normalized_code(expected),
            _normalized_code(recovered),
        ).ratio(),
        4,
    )


def _set_overlap_score(expected: List[str], recovered: List[str]) -> float:
    left = {str(item).strip() for item in expected if str(item).strip()}
    right = {str(item).strip() for item in recovered if str(item).strip()}
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return round(len(left & right) / len(left | right), 4)


def _marker_score(markers: Tuple[str, ...], recovered: str) -> Tuple[float, List[str]]:
    if not markers:
        return 1.0, []
    lowered = str(recovered or "").lower()
    missing = [marker for marker in markers if marker.lower() not in lowered]
    score = (len(markers) - len(missing)) / max(len(markers), 1)
    return round(score, 4), missing


def _syntax_ok(code: str, *, language: str = "javascript") -> bool:
    if not code or not code.strip():
        return False
    lang = str(language or "javascript").lower()
    if lang == "json":
        try:
            json.loads(code)
            return True
        except (json.JSONDecodeError, TypeError, ValueError):
            return False
    if lang not in {"javascript", "typescript", "jsx", "tsx", "js", "ts"}:
        return True
    validation = validate_javascript_source(code, language=language)
    if validation.get("ok") is True:
        return True
    return validation.get("error") in {"node_unavailable", "worker_missing", "tooling_unavailable"}


def _surface_score(expected_code: str, recovered_code: str, language: str) -> Dict[str, Any]:
    expected_sig = semantic_signature(language, expected_code)
    recovered_sig = semantic_signature(language, recovered_code)
    if not expected_sig.get("available") or not recovered_sig.get("available"):
        return {
            "available": False,
            "score": 0.0,
            "expected": expected_sig,
            "recovered": recovered_sig,
        }

    parts = {
        "imports": _set_overlap_score(
            list(expected_sig.get("imports", [])),
            list(recovered_sig.get("imports", [])),
        ),
        "import_bindings": _set_overlap_score(
            list(expected_sig.get("import_bindings", [])),
            list(recovered_sig.get("import_bindings", [])),
        ),
        "exports": _set_overlap_score(
            list(expected_sig.get("exports", [])),
            list(recovered_sig.get("exports", [])),
        ),
        "top_level_calls": _set_overlap_score(
            list(expected_sig.get("top_level_calls", [])),
            list(recovered_sig.get("top_level_calls", [])),
        ),
        "module_kind": 1.0
        if str(expected_sig.get("module_kind") or "script")
        == str(recovered_sig.get("module_kind") or "script")
        else 0.0,
    }
    score = sum(parts.values()) / max(len(parts), 1)
    return {
        "available": True,
        "score": round(score, 4),
        "parts": parts,
        "expected": expected_sig,
        "recovered": recovered_sig,
    }


def _score_single_file_case(
    *,
    case: BenchmarkCase,
    recovered_code: str,
) -> Dict[str, Any]:
    language = str(case.language or "javascript")
    syntax_ok = _syntax_ok(recovered_code, language=language)
    surface = _surface_score(case.ground_truth_code, recovered_code, language)
    marker_score, missing_markers = _marker_score(case.expected_markers, recovered_code)
    similarity = _similarity_ratio(case.ground_truth_code, recovered_code)

    read_before, _ = compute_readability_score(case.obfuscated_code)
    read_after, _ = compute_readability_score(recovered_code)
    readability_gain = round(read_after - read_before, 2)

    weighted_parts = [
        (0.2, 1.0 if syntax_ok else 0.0),
        (0.25, marker_score),
        (0.15, similarity),
    ]
    if surface.get("available"):
        weighted_parts.append((0.4, float(surface.get("score") or 0.0)))
    active_weight = sum(weight for weight, _ in weighted_parts) or 1.0
    overall = round(
        _clamp(
            sum(weight * score for weight, score in weighted_parts) / active_weight
        ),
        4,
    )
    return {
        "syntax_ok": syntax_ok,
        "surface": surface,
        "marker_score": marker_score,
        "missing_markers": missing_markers,
        "similarity": similarity,
        "readability_gain": readability_gain,
        "overall_score": overall,
    }


def _score_workspace_case(
    *,
    case: BenchmarkCase,
    recovered_code: str,
) -> Dict[str, Any]:
    expected_files = {item.path: item for item in parse_workspace_bundle(case.ground_truth_code)}
    obfuscated_files = {item.path: item for item in parse_workspace_bundle(case.obfuscated_code)}
    recovered_files = {item.path: item for item in parse_workspace_bundle(recovered_code)}
    if not expected_files:
        return {
            "syntax_ok": False,
            "surface": {"available": False, "score": 0.0},
            "marker_score": 0.0,
            "missing_markers": list(case.expected_markers),
            "similarity": 0.0,
            "readability_gain": 0.0,
            "overall_score": 0.0,
            "file_results": [],
            "missing_paths": [],
        }

    marker_score, missing_markers = _marker_score(case.expected_markers, recovered_code)
    missing_paths = [path for path in expected_files if path not in recovered_files]
    file_presence = (len(expected_files) - len(missing_paths)) / max(len(expected_files), 1)

    file_results: List[Dict[str, Any]] = []
    total_file_score = 0.0
    syntax_hits = 0
    similarity_hits = 0.0
    readability_gain = 0.0

    for path, expected_file in expected_files.items():
        recovered_file = recovered_files.get(path)
        obfuscated_file = obfuscated_files.get(path)
        if recovered_file is None:
            file_results.append(
                {
                    "path": path,
                    "language": expected_file.language,
                    "missing": True,
                    "overall_score": 0.0,
                }
            )
            continue

        file_score = _score_single_file_case(
            case=BenchmarkCase(
                case_id=f"{case.case_id}:{path}",
                name=path,
                description=case.description,
                language=expected_file.language,
                obfuscated_code=obfuscated_file.text if obfuscated_file else expected_file.text,
                ground_truth_code=expected_file.text,
                expected_markers=(),
            ),
            recovered_code=recovered_file.text,
        )
        file_results.append(
            {
                "path": path,
                "language": expected_file.language,
                "missing": False,
                **file_score,
            }
        )
        total_file_score += float(file_score["overall_score"])
        syntax_hits += 1 if file_score["syntax_ok"] else 0
        similarity_hits += float(file_score["similarity"])
        readability_gain += float(file_score["readability_gain"])

    average_file_score = total_file_score / max(len(expected_files), 1)
    overall = (
        0.15 * (1.0 if recovered_files else 0.0)
        + 0.2 * file_presence
        + 0.5 * average_file_score
        + 0.15 * marker_score
    )
    return {
        "syntax_ok": syntax_hits == len(expected_files),
        "surface": {
            "available": True,
            "score": round(average_file_score, 4),
        },
        "marker_score": round(marker_score, 4),
        "missing_markers": missing_markers,
        "similarity": round(similarity_hits / max(len(expected_files), 1), 4),
        "readability_gain": round(readability_gain / max(len(expected_files), 1), 2),
        "overall_score": round(_clamp(overall), 4),
        "file_results": file_results,
        "missing_paths": missing_paths,
        "file_presence_score": round(file_presence, 4),
    }


def score_benchmark_case(
    case: BenchmarkCase,
    analysis_result: AnalysisResult,
) -> Dict[str, Any]:
    recovered_code = analysis_result.deobfuscated_code or ""
    iter_state = (
        analysis_result.state.iteration_state
        if analysis_result.state is not None
        and isinstance(analysis_result.state.iteration_state, dict)
        else {}
    )
    if case.language == "workspace":
        metrics = _score_workspace_case(case=case, recovered_code=recovered_code)
    else:
        metrics = _score_single_file_case(case=case, recovered_code=recovered_code)

    passed = bool(metrics.get("overall_score", 0.0) >= case.pass_threshold)
    notes: List[str] = []
    if not metrics.get("syntax_ok"):
        notes.append("Recovered output is not syntactically healthy.")
    missing_markers = metrics.get("missing_markers", [])
    if missing_markers:
        notes.append(
            "Missing expected markers: " + ", ".join(str(item) for item in missing_markers[:6])
        )
    if case.language == "workspace" and metrics.get("missing_paths"):
        notes.append(
            "Missing expected files: " + ", ".join(str(item) for item in metrics["missing_paths"][:6])
        )

    return {
        "case_id": case.case_id,
        "name": case.name,
        "description": case.description,
        "language": case.language,
        "tags": list(case.tags),
        "iterations": analysis_result.iterations,
        "analysis_success": bool(analysis_result.success),
        "result_kind": str(iter_state.get("result_kind") or ""),
        "best_effort": bool(iter_state.get("best_effort")),
        "confidence": round(float(analysis_result.confidence or 0.0), 4),
        "stop_reason": str(analysis_result.stop_reason or "")[:220],
        "elapsed_seconds": round(float(analysis_result.elapsed_seconds or 0.0), 3),
        "overall_score": metrics["overall_score"],
        "pass_threshold": case.pass_threshold,
        "passed": passed,
        "metrics": metrics,
        "notes": notes,
    }


def summarize_benchmark_results(
    case_results: List[Dict[str, Any]],
    *,
    llm_enabled: bool,
) -> Dict[str, Any]:
    case_count = len(case_results)
    overall_score = (
        sum(float(item.get("overall_score") or 0.0) for item in case_results) / max(case_count, 1)
    )
    passed_cases = [item for item in case_results if item.get("passed")]
    pass_rate = len(passed_cases) / max(case_count, 1)
    failed_cases = [item for item in case_results if not item.get("passed")]

    strengths: List[str] = []
    recommendations: List[str] = []
    average_marker = (
        sum(float(item.get("metrics", {}).get("marker_score") or 0.0) for item in case_results)
        / max(case_count, 1)
    )
    average_surface = (
        sum(
            float(item.get("metrics", {}).get("surface", {}).get("score") or 0.0)
            for item in case_results
        )
        / max(case_count, 1)
    )
    syntax_failures = [
        item["case_id"]
        for item in case_results
        if not bool(item.get("metrics", {}).get("syntax_ok"))
    ]

    if average_marker >= 0.85:
        strengths.append("Recovered literals and expected markers are being retained consistently.")
    if average_surface >= 0.8:
        strengths.append("Import/export and entrypoint surfaces are being preserved well.")
    if not syntax_failures:
        strengths.append("Recovered outputs remained syntactically healthy across the corpus.")

    if average_surface < 0.75:
        recommendations.append("Improve semantic preservation around imports, exports, and top-level call flow.")
    if average_marker < 0.8:
        recommendations.append("Increase literal and IOC recovery fidelity before readability-only cleanups.")
    if syntax_failures:
        recommendations.append("Tighten structural validation; some recovered outputs still fail syntax checks.")
    if failed_cases:
        recommendations.append(
            "Review the lowest-scoring cases first: "
            + ", ".join(str(item["case_id"]) for item in failed_cases[:4])
            + "."
        )

    return {
        "corpus_name": CORPUS_NAME,
        "corpus_version": CORPUS_VERSION,
        "llm_enabled": llm_enabled,
        "case_count": case_count,
        "passed_cases": len(passed_cases),
        "failed_cases": len(failed_cases),
        "overall_score": round(overall_score, 4),
        "pass_rate": round(pass_rate, 4),
        "strengths": strengths,
        "recommendations": recommendations,
    }


async def run_benchmark_corpus(
    *,
    llm_client: Optional[LLMClient],
    max_cases: Optional[int] = None,
) -> Dict[str, Any]:
    corpus = load_js_benchmark_corpus(limit=max_cases or settings.BENCHMARK_MAX_CASES)
    case_results: List[Dict[str, Any]] = []

    for case in corpus:
        if case.max_iterations is not None:
            max_iterations = case.max_iterations
        elif case.language == "workspace":
            max_iterations = int(settings.BENCHMARK_MAX_WORKSPACE_ITERATIONS)
        else:
            max_iterations = int(settings.BENCHMARK_MAX_ITERATIONS)
        orchestrator = Orchestrator(
            sample_id=f"benchmark-{case.case_id}-{uuid.uuid4().hex[:8]}",
            original_code=case.obfuscated_code,
            language=case.language,
            llm_client=llm_client,
            analysis_metadata={
                **case.analysis_metadata,
                "benchmark_case_id": case.case_id,
                "benchmark_corpus_version": CORPUS_VERSION,
            },
        )
        try:
            result = await orchestrator.run(
                auto_approve_threshold=settings.AUTO_APPROVE_THRESHOLD,
                min_confidence=settings.MIN_CONFIDENCE_THRESHOLD,
                max_iterations=max_iterations,
                stall_limit=settings.STALL_THRESHOLD,
            )
        except Exception as exc:
            logger.exception("Benchmark case %s failed during orchestration", case.case_id)
            case_results.append(
                {
                    "case_id": case.case_id,
                    "name": case.name,
                    "description": case.description,
                    "language": case.language,
                    "tags": list(case.tags),
                    "iterations": 0,
                    "analysis_success": False,
                    "result_kind": "benchmark_error",
                    "best_effort": True,
                    "confidence": 0.0,
                    "stop_reason": str(exc)[:220],
                    "elapsed_seconds": 0.0,
                    "overall_score": 0.0,
                    "pass_threshold": case.pass_threshold,
                    "passed": False,
                    "metrics": {
                        "syntax_ok": False,
                        "surface": {"available": False, "score": 0.0},
                        "marker_score": 0.0,
                        "missing_markers": list(case.expected_markers),
                        "similarity": 0.0,
                        "readability_gain": 0.0,
                        "overall_score": 0.0,
                    },
                    "notes": [f"Benchmark orchestration failed: {exc}"],
                }
            )
            continue
        case_results.append(score_benchmark_case(case, result))

    summary = summarize_benchmark_results(
        case_results,
        llm_enabled=llm_client is not None,
    )
    return {
        "summary": summary,
        "results": case_results,
    }


def _build_client_for_provider(provider: ProviderConfig) -> LLMClient:
    context_window = _MAX_TOKENS_MAP.get(provider.max_tokens_preset, 131_072)
    return LLMClient(
        base_url=provider.base_url,
        api_key=decrypt_value(provider.api_key_encrypted),
        model=provider.model_name,
        max_tokens=4096,
        context_window=context_window,
        cert_bundle=provider.cert_bundle_path,
        use_system_trust=provider.use_system_trust,
    )


async def get_latest_benchmark_run(
    provider_id: str,
    *,
    db_session: Any = None,
) -> Optional[BenchmarkRun]:
    if db_session is not None:
        result = await db_session.execute(
            select(BenchmarkRun)
            .where(BenchmarkRun.provider_id == provider_id)
            .order_by(BenchmarkRun.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async with async_session() as db:
        result = await db.execute(
            select(BenchmarkRun)
            .where(BenchmarkRun.provider_id == provider_id)
            .order_by(BenchmarkRun.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


def serialize_benchmark_run(run: BenchmarkRun) -> Dict[str, Any]:
    return {
        "id": run.id,
        "provider_id": run.provider_id,
        "provider_name": run.provider_name,
        "provider_model": run.provider_model,
        "trigger_reason": run.trigger_reason,
        "corpus_name": run.corpus_name,
        "corpus_version": run.corpus_version,
        "status": run.status,
        "llm_enabled": run.llm_enabled,
        "case_count": run.case_count,
        "completed_case_count": run.completed_case_count,
        "overall_score": run.overall_score,
        "pass_rate": run.pass_rate,
        "summary": run.summary_json or {},
        "results": run.results_json or [],
        "error_text": run.error_text,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "created_at": run.created_at,
    }


async def schedule_provider_benchmark(
    provider_id: str,
    *,
    reason: str,
    force: bool = False,
) -> bool:
    if not provider_id:
        return False

    existing_task = _RUNNING_BENCHMARKS.get(provider_id)
    if existing_task is not None and not existing_task.done() and not force:
        return False

    if not force:
        latest = await get_latest_benchmark_run(provider_id)
        if latest is not None:
            if latest.status == "running":
                return False
            if latest.completed_at is not None:
                age = _utcnow() - latest.completed_at
                if age < timedelta(hours=max(int(settings.BENCHMARK_MIN_RERUN_HOURS), 1)):
                    return False

    async def _runner() -> None:
        await _run_provider_benchmark(provider_id, reason=reason)

    task = asyncio.create_task(_runner())
    _RUNNING_BENCHMARKS[provider_id] = task

    def _cleanup(finished: asyncio.Task[None]) -> None:
        current = _RUNNING_BENCHMARKS.get(provider_id)
        if current is finished:
            _RUNNING_BENCHMARKS.pop(provider_id, None)
        try:
            finished.result()
        except Exception:
            logger.exception("Background benchmark task failed for provider %s", provider_id)

    task.add_done_callback(_cleanup)
    return True


async def schedule_startup_benchmarks() -> None:
    global _STARTUP_SCHEDULER_TASK

    if not bool(getattr(settings, "BENCHMARK_AUTO_RUN_ON_STARTUP", True)):
        return
    if _STARTUP_SCHEDULER_TASK is not None and not _STARTUP_SCHEDULER_TASK.done():
        return

    async def _startup_runner() -> None:
        async with async_session() as db:
            result = await db.execute(
                select(ProviderConfig)
                .where(ProviderConfig.is_active == True)  # noqa: E712
                .order_by(ProviderConfig.created_at.desc())
            )
            providers = result.scalars().all()
        for provider in providers:
            try:
                await schedule_provider_benchmark(
                    provider.id,
                    reason="startup_auto",
                    force=False,
                )
            except Exception:
                logger.exception(
                    "Failed to schedule startup benchmark for provider %s",
                    provider.id,
                )

    _STARTUP_SCHEDULER_TASK = asyncio.create_task(_startup_runner())


async def _run_provider_benchmark(provider_id: str, *, reason: str) -> None:
    async with async_session() as db:
        provider = await db.get(ProviderConfig, provider_id)
        if provider is None:
            logger.warning("Skipping benchmark for missing provider %s", provider_id)
            return

        benchmark_run = BenchmarkRun(
            provider_id=provider.id,
            provider_name=provider.name,
            provider_model=provider.model_name,
            trigger_reason=reason,
            corpus_name=CORPUS_NAME,
            corpus_version=CORPUS_VERSION,
            status="running",
            llm_enabled=True,
            case_count=min(
                len(load_js_benchmark_corpus()),
                max(int(settings.BENCHMARK_MAX_CASES or 0), 1),
            ),
            completed_case_count=0,
            started_at=_utcnow(),
        )
        db.add(benchmark_run)
        await db.commit()
        run_id = benchmark_run.id

    try:
        client = _build_client_for_provider(provider)
        payload = await run_benchmark_corpus(
            llm_client=client,
            max_cases=settings.BENCHMARK_MAX_CASES,
        )
        summary = payload["summary"]
        results = payload["results"]
        status_text = "completed"
        error_text = None
    except Exception as exc:
        logger.exception("Provider benchmark failed for %s", provider_id)
        summary = {
            "corpus_name": CORPUS_NAME,
            "corpus_version": CORPUS_VERSION,
            "llm_enabled": True,
            "case_count": 0,
            "passed_cases": 0,
            "failed_cases": 0,
            "overall_score": 0.0,
            "pass_rate": 0.0,
            "strengths": [],
            "recommendations": [],
        }
        results = []
        status_text = "failed"
        error_text = str(exc)[:2000]

    async with async_session() as db:
        run = await db.get(BenchmarkRun, run_id)
        if run is None:
            return
        run.status = status_text
        run.case_count = int(summary.get("case_count") or len(results))
        run.completed_case_count = len(results)
        run.overall_score = float(summary.get("overall_score") or 0.0)
        run.pass_rate = float(summary.get("pass_rate") or 0.0)
        run.summary_json = summary
        run.results_json = results
        run.error_text = error_text
        run.completed_at = _utcnow()
        await db.commit()
