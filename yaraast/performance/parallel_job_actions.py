"""Job-oriented helpers for ParallelAnalyzer."""

from __future__ import annotations

from functools import partial
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import YaraFile
from yaraast.performance.parallel_job_helpers import (
    complete_job,
    export_graph_files,
    fail_job,
    parse_file_chunks,
    process_items,
    start_job,
    validate_yara_file_sequence,
)
from yaraast.performance.parallel_models import Job, JobStatus
from yaraast.performance.timeout_helpers import run_with_timeout

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from yaraast.performance.parallel_analyzer import ParallelAnalyzer


def analyze_complexity_parallel(
    analyzer: ParallelAnalyzer,
    asts: Sequence[YaraFile],
    max_workers: int | None = None,
    file_timeout: float | None = None,
    suppress_internal_errors: bool = True,
) -> list[Job]:
    """Create tracked complexity jobs for ASTs."""
    jobs: list[Job] = []
    ast_items = validate_yara_file_sequence(asts)
    for index, ast in enumerate(ast_items):
        job = start_job("complexity")
        jobs.append(job)
        analyzer._stats["jobs_submitted"] += 1
        if not isinstance(ast, YaraFile):
            fail_job(job, "complexity analysis input must be a YaraFile")
            analyzer._stats["jobs_failed"] += 1
            continue
        try:
            analyze_job = partial(analyzer.analyze_file, ast, max_workers)
            analysis = run_with_timeout(
                f"complexity analysis for AST {index}",
                file_timeout,
                analyze_job,
            )
            analysis["metrics"] = analysis.get("stats", {})
            error_rate = analysis["stats"].get("errors", 0) / max(
                analysis["stats"].get("total_rules", 1),
                1,
            )
            analysis["quality_score"] = max(0, 100 - (error_rate * 100))
            complete_job(job, analysis)
            analyzer._stats["jobs_completed"] += 1
        except Exception as exc:
            if not suppress_internal_errors:
                raise
            fail_job(job, exc)
            analyzer._stats["jobs_failed"] += 1
    return jobs


def generate_graphs_parallel(
    analyzer: ParallelAnalyzer,
    asts: Sequence[YaraFile],
    output_dir: str | PathLike[str],
    graph_types: Sequence[str] | None = None,
    file_timeout: float | None = None,
) -> list[Job]:
    """Generate dependency graph export jobs and update analyzer stats."""
    jobs = export_graph_files(asts, output_dir, graph_types, file_timeout)
    for job in jobs:
        analyzer._stats["jobs_submitted"] += 1
        if job.status == JobStatus.COMPLETED:
            analyzer._stats["jobs_completed"] += 1
        elif job.status == JobStatus.FAILED:
            analyzer._stats["jobs_failed"] += 1
    return jobs


def parse_files_parallel(
    analyzer: ParallelAnalyzer,
    file_paths: Sequence[str | Path],
    chunk_size: int = 10,
    file_timeout: float | None = None,
) -> list[Job]:
    """Parse file chunks into tracked jobs."""
    jobs = parse_file_chunks(file_paths, chunk_size, file_timeout)
    for job in jobs:
        analyzer._stats["jobs_submitted"] += 1
        if job.status == JobStatus.COMPLETED:
            analyzer._stats["jobs_completed"] += 1
        elif job.status == JobStatus.FAILED:
            analyzer._stats["jobs_failed"] += 1
    return jobs


def process_batch(
    analyzer: ParallelAnalyzer,
    items: list[Any],
    worker_func: Callable[[Any, dict[str, Any]], Any],
    job_type: str = "batch",
    parameters: dict[str, Any] | None = None,
) -> list[Job]:
    """Process arbitrary items through tracked job helpers."""
    jobs = process_items(items, worker_func, job_type=job_type, parameters=parameters)
    for job in jobs:
        analyzer._stats["jobs_submitted"] += 1
        if job.status == JobStatus.COMPLETED:
            analyzer._stats["jobs_completed"] += 1
        elif job.status == JobStatus.FAILED:
            analyzer._stats["jobs_failed"] += 1
    return jobs
