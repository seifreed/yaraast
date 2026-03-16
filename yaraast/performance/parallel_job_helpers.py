"""Job and statistics helpers for the parallel analyzer."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from yaraast.performance.parallel_models import Job, JobStatus


def default_parallel_stats() -> dict[str, float | int]:
    """Return the default statistics shape for ParallelAnalyzer."""
    return {
        "rules_analyzed": 0,
        "total_time": 0.0,
        "errors": 0,
        "jobs_submitted": 0,
        "jobs_completed": 0,
    }


def resettable_parallel_stats() -> dict[str, float | int]:
    """Return the minimal reset statistics shape expected by tests."""
    return {
        "rules_analyzed": 0,
        "total_time": 0.0,
        "errors": 0,
    }


def start_job(job_type: str) -> Job:
    """Create a running job with a generated id."""
    return Job(job_id=str(uuid.uuid4()), job_type=job_type, status=JobStatus.RUNNING)


def complete_job(job: Job, result) -> Job:
    """Mark a job as completed with result payload."""
    job.result = result
    job.status = JobStatus.COMPLETED
    job.end_time = time.time()
    return job


def fail_job(job: Job, error: Exception | str) -> Job:
    """Mark a job as failed with an error message."""
    job.error = str(error)
    job.status = JobStatus.FAILED
    job.end_time = time.time()
    return job


def analyze_file_path(path: str, analyzer) -> dict:
    """Parse and analyze a file path using a provided analyzer instance."""
    from yaraast.parser.parser import Parser

    parser = Parser()
    with open(path) as f:
        content = f.read()

    yara_file = parser.parse(content)
    analysis = analyzer.analyze_file(yara_file)
    analysis["file"] = path
    return analysis


def export_graph_files(
    asts, output_dir: str | Path, graph_types: list[str] | None = None
) -> list[Job]:
    """Generate dependency graph export jobs for ASTs."""
    from yaraast.metrics.dependency_graph_utils import (
        build_dependency_graph,
        export_dependency_graph,
    )

    graph_types = graph_types or ["full"]
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    jobs: list[Job] = []

    for index, ast in enumerate(asts):
        job = start_job("dependency_graph")
        jobs.append(job)
        try:
            graph = build_dependency_graph(ast)
            rule_name = ast.rules[0].name if getattr(ast, "rules", None) else f"ast_{index}"
            output_files = []
            for graph_type in graph_types:
                output_path = output_dir / f"{rule_name}_{graph_type}.json"
                export_dependency_graph(graph, output_path, format="json")
                output_files.append(str(output_path))
            complete_job(job, output_files)
        except Exception as e:
            fail_job(job, e)
    return jobs


def parse_file_chunks(file_paths: list, chunk_size: int = 10) -> list[Job]:
    """Parse file paths in chunks and return job objects."""
    from yaraast.parser.parser import Parser

    chunks = [file_paths[i : i + chunk_size] for i in range(0, len(file_paths), chunk_size)]
    jobs: list[Job] = []

    for chunk in chunks:
        job = start_job("parse_files")
        jobs.append(job)
        try:
            parser = Parser()
            results = []
            for file_path in chunk:
                content = Path(file_path).read_text()
                ast = parser.parse(content)
                results.append(ast)
            complete_job(job, results)
        except Exception as e:
            fail_job(job, e)
    return jobs


def process_items(
    items: list, worker_func, job_type: str = "batch", parameters: dict | None = None
) -> list[Job]:
    """Process items via a worker function and return tracked jobs."""
    jobs: list[Job] = []
    parameters = parameters or {}
    for item in items:
        job = start_job(job_type)
        jobs.append(job)
        try:
            complete_job(job, worker_func(item, parameters))
        except Exception as e:
            fail_job(job, e)
    return jobs
