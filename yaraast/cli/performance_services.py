"""Performance CLI services (logic without IO)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import time
from typing import Any

from yaraast.performance.batch_processor import BatchOperation, BatchProcessor
from yaraast.performance.memory_optimizer import MemoryOptimizer
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.streaming_parser import StreamingParser


def convert_operations(operations: Iterable[str]) -> list[BatchOperation]:
    operation_map = {
        "parse": BatchOperation.PARSE,
        "complexity": BatchOperation.COMPLEXITY,
        "dependency_graph": BatchOperation.DEPENDENCY_GRAPH,
        "html_tree": BatchOperation.HTML_TREE,
        "serialize": BatchOperation.SERIALIZE,
    }
    return [operation_map[op] for op in operations if op in operation_map]


def run_batch_processing(
    input_path: Path,
    output_dir: Path,
    batch_operations: list[BatchOperation],
    processor: BatchProcessor,
    pattern: str,
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


def get_parse_iterator(
    parser: StreamingParser,
    input_path: Path,
    split_rules: bool,
    pattern: str,
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
    for path in input_paths:
        path = Path(path)
        if path.is_file():
            file_paths.append(path)
        elif path.is_dir():
            file_paths.extend(path.rglob("*.yar"))
    return file_paths


def extract_successful_asts(parse_jobs, file_paths: list[Path], chunk_size: int):
    successful_asts = []
    file_names = []

    for job_index, job in enumerate(parse_jobs):
        if job.status.value == "completed" and job.result:
            asts, names = _process_job_results(job, job_index, file_paths, chunk_size)
            successful_asts.extend(asts)
            file_names.extend(names)

    return successful_asts, file_names


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
) -> tuple[dict[str, Any], float]:
    start_time = time.time()
    with ParallelAnalyzer(max_workers=max_workers) as analyzer:
        parse_jobs = analyzer.parse_files_parallel(file_paths, chunk_size)
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
        else:
            complexity_results = []

        if analysis_type in ["dependency", "all"]:
            graph_jobs = analyzer.generate_graphs_parallel(
                successful_asts,
                output_dir / "graphs",
                ["full", "rules"],
            )
            dependency_graphs = [job for job in graph_jobs if job.status.value == "completed"]
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
