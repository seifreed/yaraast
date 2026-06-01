"""Performance CLI services (logic without IO)."""

from __future__ import annotations

from collections.abc import Iterable
from os import PathLike, fspath
from pathlib import Path
import time
from typing import Any

from yaraast.performance.batch_processor import BatchOperation, BatchProcessor
from yaraast.performance.memory_optimizer import MemoryOptimizer
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.streaming_parser import StreamingParser
from yaraast.shared.file_patterns import FilePatterns, iter_matching_files
from yaraast.shared.numeric_validation import (
    validate_non_negative_int_setting,
    validate_positive_int_setting,
    validate_positive_number_setting,
)

BATCH_OPERATION_MAP = {
    "parse": BatchOperation.PARSE,
    "complexity": BatchOperation.COMPLEXITY,
    "dependency_graph": BatchOperation.DEPENDENCY_GRAPH,
    "html_tree": BatchOperation.HTML_TREE,
    "serialize": BatchOperation.SERIALIZE,
    "validate": BatchOperation.VALIDATE,
}
BATCH_OPERATION_CHOICES = tuple(BATCH_OPERATION_MAP)


def convert_operations(operations: Iterable[object]) -> list[BatchOperation]:
    if isinstance(operations, str | bytes) or not isinstance(operations, Iterable):
        raise TypeError("batch operations must be an iterable of strings")
    converted = []
    for operation in operations:
        converted.append(_require_batch_operation(operation))
    return converted


def _require_batch_operation(operation: object) -> BatchOperation:
    if not isinstance(operation, str):
        raise TypeError("batch operation must be a string")
    if operation not in BATCH_OPERATION_MAP:
        valid = ", ".join(sorted(BATCH_OPERATION_MAP))
        raise ValueError(f"batch operation must be one of: {valid}")
    return BATCH_OPERATION_MAP[operation]


def run_batch_processing(
    input_path: Path,
    output_dir: Path,
    batch_operations: list[BatchOperation],
    processor: BatchProcessor,
    pattern: FilePatterns,
    recursive: bool,
) -> tuple[dict, float]:
    start_time = time.time()
    if input_path.is_file():
        results = processor.process_large_file(
            input_path,
            batch_operations,
            output_dir,
        )
    else:
        results = processor.process_directory(
            input_path,
            batch_operations,
            output_dir,
            pattern,
            recursive,
        )
    total_time = time.time() - start_time
    return results, total_time


def build_batch_results_data(results: dict) -> dict[str, Any]:
    return {
        operation.value: {
            "input_count": result.input_count,
            "successful_count": result.successful_count,
            "failed_count": result.failed_count,
            "success_rate": result.success_rate,
            "total_time": result.total_time,
            "output_files": result.output_files,
            "errors": result.errors,
            "summary": result.summary,
        }
        for operation, result in results.items()
    }


def _require_collect_input_path(raw_path: object) -> Path:
    if isinstance(raw_path, bytes) or not isinstance(raw_path, str | PathLike):
        msg = "input path must be a string or path-like object"
        raise TypeError(msg)
    path_text = fspath(raw_path)
    if not path_text:
        msg = "input path must not be empty"
        raise ValueError(msg)
    return Path(path_text)


def get_parse_iterator(
    parser: StreamingParser,
    input_path: Path,
    split_rules: bool,
    pattern: FilePatterns,
    recursive: bool,
):
    if input_path.is_file():
        if split_rules:
            return parser.parse_rules_from_file(input_path)
        return parser.parse_files([input_path])
    return parser.parse_directory(input_path, pattern, recursive)


def summarize_stream_results(results: list) -> dict[str, Any]:
    successful = [r for r in results if r.status.value == "success"]
    failed = [r for r in results if r.status.value == "error"]
    return {
        "successful": successful,
        "failed": failed,
    }


def build_stream_output_data(
    results: list,
    successful: list,
    failed: list,
    total_time: float,
    parser_stats: dict[str, Any],
) -> dict[str, Any]:
    return {
        "summary": {
            "total_processed": len(results),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": len(successful) / len(results) * 100 if results else 0.0,
            "total_time": total_time,
            "parser_stats": parser_stats,
        },
        "results": [
            {
                "file_path": r.file_path,
                "rule_name": r.rule_name,
                "status": r.status.value,
                "error": r.error,
                "parse_time": r.parse_time,
                "rule_count": r.rule_count,
                "import_count": r.import_count,
            }
            for r in results
        ],
    }


def collect_file_paths(input_paths: tuple) -> list[Path]:
    file_paths = []
    seen: set[Path] = set()
    for raw_path in input_paths:
        path = _require_collect_input_path(raw_path)
        candidates: Iterable[Path]
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = iter_matching_files(path, recursive=True)
        else:
            candidates = []
        for candidate in candidates:
            canonical_candidate = candidate.resolve()
            if canonical_candidate in seen:
                continue
            seen.add(canonical_candidate)
            file_paths.append(candidate)
    return file_paths


def extract_successful_asts(parse_jobs, file_paths: list[Path], chunk_size: int):
    successful_asts = []
    file_names = []

    for job_index, job in enumerate(parse_jobs):
        if _has_successful_parse_results(job):
            asts, names = _process_job_results(job, job_index, file_paths, chunk_size)
            successful_asts.extend(asts)
            file_names.extend(names)

    return successful_asts, file_names


def _has_successful_parse_results(job) -> bool:
    """Return whether a parse job can contribute successful ASTs."""
    if not job.result:
        return False
    if job.status.value == "completed":
        return True
    return getattr(job, "job_type", None) == "parse_files" and any(
        hasattr(ast, "_parse_error") for ast in job.result
    )


def _process_job_results(job, job_index: int, file_paths: list[Path], chunk_size: int):
    asts = []
    names = []

    for i, ast in enumerate(job.result):
        if not hasattr(ast, "_parse_error"):
            asts.append(ast)
            file_name = _get_corresponding_file_name(job_index, i, file_paths, chunk_size)
            if file_name:
                names.append(file_name)

    return asts, names


def _get_corresponding_file_name(
    job_index: int,
    ast_index: int,
    file_paths: list[Path],
    chunk_size: int,
) -> str | None:
    start_idx = job_index * chunk_size
    file_idx = start_idx + ast_index
    return str(file_paths[file_idx]) if file_idx < len(file_paths) else None


def run_parallel_analysis(
    file_paths: list[Path],
    max_workers: int | None,
    chunk_size: int,
    analysis_type: str,
    output_dir: Path,
    timeout: float | None = None,
) -> tuple[dict[str, Any], float]:
    _validate_timeout(timeout)
    start_time = time.time()
    with ParallelAnalyzer(max_workers=max_workers) as analyzer:
        parse_jobs = analyzer.parse_files_parallel(file_paths, chunk_size)
        _raise_if_analysis_timed_out(start_time, timeout, "parsing")
        successful_asts, file_names = extract_successful_asts(
            parse_jobs,
            file_paths,
            chunk_size,
        )

        if analysis_type in ["complexity", "all"]:
            complexity_jobs = analyzer.analyze_complexity_parallel(successful_asts, max_workers)
            complexity_results = [
                job.result for job in complexity_jobs if job.status.value == "completed"
            ]
            _raise_if_analysis_timed_out(start_time, timeout, "complexity analysis")
        else:
            complexity_results = []

        if analysis_type in ["dependency", "all"]:
            graph_jobs = analyzer.generate_graphs_parallel(
                successful_asts,
                output_dir / "graphs",
                ["full", "rules"],
            )
            dependency_graphs = [job for job in graph_jobs if job.status.value == "completed"]
            _raise_if_analysis_timed_out(start_time, timeout, "dependency graph generation")
        else:
            dependency_graphs = []

        analyzer_stats = analyzer.get_statistics()

    total_time = time.time() - start_time
    return {
        "successful_asts": successful_asts,
        "file_names": file_names,
        "complexity_results": complexity_results,
        "dependency_graphs": dependency_graphs,
        "analyzer_stats": analyzer_stats,
    }, total_time


def _validate_timeout(timeout: float | None) -> None:
    if timeout is not None:
        validate_positive_number_setting(timeout, "timeout")


def _raise_if_analysis_timed_out(
    start_time: float,
    timeout: float | None,
    stage: str,
) -> None:
    if timeout is None:
        return

    elapsed = time.time() - start_time
    if elapsed > timeout:
        msg = f"parallel analysis timed out after {timeout:g} seconds during {stage}"
        raise TimeoutError(msg)


def build_parallel_summary(
    file_paths: list[Path],
    successful_asts: list,
    analyzer_stats: dict[str, Any],
    total_time: float,
) -> dict[str, Any]:
    avg_job_time = analyzer_stats.get("avg_job_time", analyzer_stats.get("avg_time_per_rule", 0.0))
    jobs_completed = analyzer_stats.get("jobs_completed", 0)
    speedup = 1.0
    if jobs_completed > 0 and total_time > 0:
        # Estimate sequential time as sum of individual job times
        sequential_estimate = avg_job_time * jobs_completed
        speedup = sequential_estimate / total_time if sequential_estimate > 0 else 1.0

    return {
        "files_processed": len(file_paths),
        "successful": len(successful_asts),
        "jobs_submitted": analyzer_stats.get("jobs_submitted", 0),
        "jobs_completed": analyzer_stats.get("jobs_completed", 0),
        "jobs_failed": analyzer_stats.get("jobs_failed", 0),
        "avg_job_time": avg_job_time,
        "workers_used": analyzer_stats.get("workers_created", analyzer_stats.get("max_workers", 0)),
        "speedup": speedup,
    }


def build_optimize_recommendations(collection_size: int) -> dict[str, Any]:
    optimizer = MemoryOptimizer()
    return optimizer.optimize_for_large_collection(collection_size)


def build_optimization_plan(
    collection_size: int,
    memory_mb: int | None,
    target_time: int | None,
) -> dict[str, Any]:
    validate_non_negative_int_setting(collection_size, "collection_size")
    if memory_mb is not None:
        validate_positive_int_setting(memory_mb, "memory_mb")
    if target_time is not None:
        validate_positive_int_setting(target_time, "target_time")

    recommendations = build_optimize_recommendations(collection_size)
    strategy = _build_strategy_messages(collection_size)
    memory_plan = _build_memory_plan(collection_size, memory_mb, recommendations)
    time_plan = _build_time_plan(collection_size, target_time)
    examples = _build_command_examples(collection_size, recommendations)
    return {
        "collection_size": collection_size,
        "recommendations": recommendations,
        "strategy": strategy,
        "memory_plan": memory_plan,
        "time_plan": time_plan,
        "examples": examples,
    }


def _build_strategy_messages(collection_size: int) -> list[str]:
    if collection_size < 100:
        return [
            "Use standard parallel processing",
            "Memory optimization not critical",
        ]
    if collection_size < 1000:
        return [
            "Use batch processing with moderate parallelism",
            "Enable object pooling",
            "Monitor memory usage",
        ]
    return [
        "Use streaming parser with small batches",
        "Enable aggressive memory management",
        "Consider distributed processing",
    ]


def _build_memory_plan(
    collection_size: int,
    memory_mb: int | None,
    recommendations: dict[str, Any],
) -> dict[str, Any] | None:
    if memory_mb is None:
        return None

    estimated_memory = collection_size * 0.5
    memory_limit = recommendations.get("memory_limit_mb")
    sufficient = estimated_memory <= memory_mb
    suggested_batch = max(1, (memory_mb * 2) // collection_size) if collection_size else 1
    return {
        "available_mb": memory_mb,
        "estimated_mb": estimated_memory,
        "sufficient": sufficient,
        "suggested_batch_size": suggested_batch,
        "memory_limit_mb": memory_limit,
    }


def _build_time_plan(collection_size: int, target_time: int | None) -> dict[str, Any] | None:
    if target_time is None:
        return None

    estimated_time_sequential = collection_size * 0.1
    max_workers = 8
    estimated_time_parallel = (
        estimated_time_sequential / max_workers if max_workers > 0 else estimated_time_sequential
    )
    needed_workers = int(estimated_time_sequential / target_time) if target_time > 0 else 0
    return {
        "target_time": target_time,
        "estimated_time_parallel": estimated_time_parallel,
        "needed_workers": needed_workers,
        "max_workers": max_workers,
    }


def _build_command_examples(
    collection_size: int,
    recommendations: dict[str, Any],
) -> dict[str, Any]:
    batch_size = recommendations.get("batch_size")
    memory_limit = recommendations.get("memory_limit_mb")
    max_workers = min(8, max(2, collection_size // 100)) if collection_size else 2
    return {
        "batch": {
            "batch_size": batch_size,
            "memory_limit_mb": memory_limit,
            "max_workers": max_workers,
        },
        "stream": {
            "memory_limit_mb": memory_limit // 2 if isinstance(memory_limit, int) else memory_limit,
        },
    }
