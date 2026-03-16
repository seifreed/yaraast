"""Job-oriented helpers for ParallelAnalyzer."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.performance.parallel_job_helpers import (
    complete_job,
    export_graph_files,
    fail_job,
    parse_file_chunks,
    process_items,
    start_job,
)
from yaraast.performance.parallel_models import Job, JobStatus

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.base import YaraFile
    from yaraast.performance.parallel_analyzer import ParallelAnalyzer


def analyze_complexity_parallel(
    analyzer: ParallelAnalyzer,
    asts: list[YaraFile],
    max_workers: int | None = None,
) -> list[Job]:
    """Create tracked complexity jobs for ASTs."""
    jobs = []
    for ast in asts:
        job = start_job("complexity")
        jobs.append(job)
        analyzer._stats["jobs_submitted"] += 1
        try:
            analysis = analyzer.analyze_file(ast, max_workers)
            analysis["metrics"] = analysis.get("stats", {})
            error_rate = analysis["stats"].get("errors", 0) / max(
                analysis["stats"].get("total_rules", 1),
                1,
            )
            analysis["quality_score"] = max(0, 100 - (error_rate * 100))
            complete_job(job, analysis)
            analyzer._stats["jobs_completed"] += 1
        except Exception as exc:
            fail_job(job, exc)
    return jobs


def generate_graphs_parallel(
    analyzer: ParallelAnalyzer,
    asts: list[YaraFile],
    output_dir: str | Path,
    graph_types: list[str] | None = None,
) -> list[Job]:
    """Generate dependency graph export jobs and update analyzer stats."""
    jobs = export_graph_files(asts, output_dir, graph_types)
    for job in jobs:
        analyzer._stats["jobs_submitted"] += 1
        if job.status == JobStatus.COMPLETED:
            analyzer._stats["jobs_completed"] += 1
    return jobs


def parse_files_parallel(
    analyzer: ParallelAnalyzer,
    file_paths: list,
    chunk_size: int = 10,
) -> list[Job]:
    """Parse file chunks into tracked jobs."""
    jobs = parse_file_chunks(file_paths, chunk_size)
    for job in jobs:
        analyzer._stats["jobs_submitted"] += 1
        if job.status == JobStatus.COMPLETED:
            analyzer._stats["jobs_completed"] += 1
    return jobs


def process_batch(
    analyzer: ParallelAnalyzer,
    items: list,
    worker_func: Callable,
    job_type: str = "batch",
    parameters: dict | None = None,
) -> list[Job]:
    """Process arbitrary items through tracked job helpers."""
    return process_items(items, worker_func, job_type=job_type, parameters=parameters)
