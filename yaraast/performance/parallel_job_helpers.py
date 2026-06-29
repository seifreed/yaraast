"""Job and statistics helpers for the parallel analyzer."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from functools import partial
from os import PathLike, fspath
from pathlib import Path
import time
from typing import Any, cast
import uuid

from yaraast.ast.base import YaraFile
from yaraast.errors import YaraASTError
from yaraast.performance.parallel_models import Job, JobStatus, ParseErrorMarker
from yaraast.performance.timeout_helpers import run_with_timeout
from yaraast.performance.validation import (
    path_exists_and_is_dir,
    path_exists_and_not_dir,
    validate_file_path_sequence,
    validate_positive_int_setting,
)
from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink

_EXPECTED_PARSE_ERRORS = (OSError, UnicodeDecodeError, ValueError, YaraASTError)
GRAPH_TYPES_TYPE_ERROR = "graph_types must be a sequence of strings"
GRAPH_TYPE_ENTRY_ERROR = "graph_types must contain non-empty strings"
GRAPH_TYPE_VALUE_ERROR = "graph_types entries must contain only letters and numbers"
YARA_FILE_SEQUENCE_TYPE_ERROR = "asts must be a sequence of YaraFile objects"
OUTPUT_DIR_TYPE_ERROR = "output_dir must be a directory path"
FILE_PATH_TYPE_ERROR = "file_path must be a file path"


def default_parallel_stats() -> dict[str, float | int]:
    """Return the default statistics shape for ParallelAnalyzer."""
    return {
        "rules_analyzed": 0,
        "total_time": 0.0,
        "errors": 0,
        "jobs_submitted": 0,
        "jobs_completed": 0,
        "jobs_failed": 0,
    }


def start_job(job_type: str) -> Job:
    """Create a running job with a generated id."""
    return Job(job_id=str(uuid.uuid4()), job_type=job_type, status=JobStatus.RUNNING)


def complete_job(job: Job, result: Any) -> Job:
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


def validate_graph_types(graph_types: object) -> list[str]:
    """Normalize graph export type names."""
    if graph_types is None:
        return ["full"]
    if isinstance(graph_types, (str, bytes)) or not isinstance(graph_types, Sequence):
        raise TypeError(GRAPH_TYPES_TYPE_ERROR)
    normalized: list[str] = []
    for graph_type in graph_types:
        if not isinstance(graph_type, str) or not graph_type.strip():
            raise TypeError(GRAPH_TYPE_ENTRY_ERROR)
        if not graph_type.isalnum():
            raise ValueError(GRAPH_TYPE_VALUE_ERROR)
        normalized.append(graph_type)
    return normalized


def validate_yara_file_sequence(asts: object) -> list[object]:
    """Reject scalar values before treating AST inputs as a job sequence."""
    if isinstance(asts, (str, bytes)) or not isinstance(asts, Sequence):
        raise TypeError(YARA_FILE_SEQUENCE_TYPE_ERROR)
    return list(asts)


def require_output_dir_path(output_dir: object) -> Path:
    """Normalize a graph export output directory path."""
    if isinstance(output_dir, bool | bytes) or not isinstance(output_dir, str | PathLike):
        raise TypeError(OUTPUT_DIR_TYPE_ERROR)
    raw_path = fspath(output_dir)
    if not isinstance(raw_path, str):
        raise TypeError(OUTPUT_DIR_TYPE_ERROR)
    if not raw_path.strip():
        msg = "output_dir must not be empty"
        raise ValueError(msg)
    if "\x00" in raw_path:
        msg = "output_dir must not contain null bytes"
        raise ValueError(msg)
    path = Path(raw_path)
    if path_exists_and_not_dir(path):
        msg = "output_dir must not be a file"
        raise ValueError(msg)
    if path_is_symlink(path) or path_has_symlink_ancestor(path):
        msg = "output_dir must not traverse a symlink"
        raise ValueError(msg)
    return path


def _require_file_path(path: object) -> Path:
    if isinstance(path, bool | bytes) or not isinstance(path, str | PathLike):
        raise TypeError(FILE_PATH_TYPE_ERROR)
    raw_path = fspath(path)
    if not isinstance(raw_path, str):
        raise TypeError(FILE_PATH_TYPE_ERROR)
    if not raw_path.strip():
        msg = "file_path must not be empty"
        raise ValueError(msg)
    if "\x00" in raw_path:
        msg = "file_path must not contain null bytes"
        raise ValueError(msg)
    path_obj = Path(raw_path)
    if path_exists_and_is_dir(path_obj):
        msg = "file_path must not be a directory"
        raise ValueError(msg)
    if path_is_symlink(path_obj) or path_has_symlink_ancestor(path_obj):
        msg = "file_path must not traverse a symlink"
        raise ValueError(msg)
    return path_obj


def _read_yara_text_file(path: object) -> str:
    path_obj = _require_file_path(path)
    try:
        return path_obj.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def analyze_file_path(path: object, analyzer: Any) -> dict[str, Any]:
    """Parse and analyze a file path using a provided analyzer instance."""
    path_obj = _require_file_path(path)
    content = _read_yara_text_file(path_obj)
    from importlib import import_module

    parser_source = import_module("yaraast.parser.source")
    parse_yara_source = cast(Callable[[str], YaraFile], parser_source.parse_yara_source)

    yara_file = parse_yara_source(content)
    analysis: dict[str, Any] = dict(analyzer.analyze_file(yara_file))
    analysis["file"] = str(path_obj)
    return analysis


def _parse_yara_source_with_timeout(
    file_path: object,
    timeout: float | None,
) -> YaraFile:
    content = _read_yara_text_file(file_path)
    from importlib import import_module

    parser_source = import_module("yaraast.parser.source")
    parse_yara_source = cast(Callable[[str], YaraFile], parser_source.parse_yara_source)

    def _parse_file() -> YaraFile:
        return parse_yara_source(content)

    return run_with_timeout(f"parsing {file_path}", timeout, _parse_file)


def _generate_dependency_graph_exports(
    ast_item: YaraFile,
    index: int,
    graph_types: Sequence[str],
    output_dir: Path,
) -> list[str]:
    from yaraast.metrics.dependency_graph_utils import (
        build_dependency_graph,
        export_dependency_graph,
    )

    graph = build_dependency_graph(ast_item)
    rule_name = ast_item.rules[0].name if getattr(ast_item, "rules", None) else f"ast_{index}"
    output_files: list[str] = []
    for graph_type in graph_types:
        output_path = output_dir / f"{rule_name}_{graph_type}.json"
        export_dependency_graph(graph, output_path, format="json")
        output_files.append(str(output_path))
    return output_files


def export_graph_files(
    asts: Sequence[YaraFile],
    output_dir: str | PathLike[str],
    graph_types: Sequence[str] | None = None,
    file_timeout: float | None = None,
) -> list[Job]:
    """Generate dependency graph export jobs for ASTs."""
    graph_types = validate_graph_types(graph_types)
    ast_items = validate_yara_file_sequence(asts)
    output_dir = require_output_dir_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    jobs: list[Job] = []

    for index, ast in enumerate(ast_items):
        job = start_job("dependency_graph")
        jobs.append(job)
        if not isinstance(ast, YaraFile):
            fail_job(job, "dependency graph input must be a YaraFile")
            continue
        try:
            output_files = run_with_timeout(
                f"dependency graph generation for ast index {index}",
                file_timeout,
                partial(
                    _generate_dependency_graph_exports,
                    ast,
                    index,
                    graph_types,
                    output_dir,
                ),
            )
            complete_job(job, output_files)
        except (OSError, ValueError, YaraASTError) as e:
            fail_job(job, e)
        except TimeoutError as e:
            fail_job(job, e)
    return jobs


def parse_file_chunks(
    file_paths: Sequence[str | Path],
    chunk_size: int = 10,
    file_timeout: float | None = None,
) -> list[Job]:
    """Parse file paths in chunks and return job objects."""
    normalized_file_paths = validate_file_path_sequence(file_paths)
    validate_positive_int_setting(chunk_size, "chunk_size")

    chunks = [
        normalized_file_paths[i : i + chunk_size]
        for i in range(0, len(normalized_file_paths), chunk_size)
    ]
    jobs: list[Job] = []

    for chunk in chunks:
        job = start_job("parse_files")
        jobs.append(job)
        results: list[YaraFile | ParseErrorMarker] = []
        errors: list[str] = []
        for file_path in chunk:
            try:
                ast = _parse_yara_source_with_timeout(file_path, file_timeout)
                results.append(ast)
            except (*_EXPECTED_PARSE_ERRORS, TimeoutError) as e:
                results.append(ParseErrorMarker(str(file_path), str(e)))
                errors.append(f"{file_path}: {e}")
        if errors:
            job.result = results
            fail_job(job, "; ".join(errors))
        else:
            complete_job(job, results)
    return jobs


def process_items(
    items: list[Any],
    worker_func: Callable[[Any, dict[str, Any]], Any],
    job_type: str = "batch",
    parameters: dict[str, Any] | None = None,
) -> list[Job]:
    """Process items via a worker function and return tracked jobs."""
    jobs: list[Job] = []
    if parameters is None:
        parameters = {}
    elif not isinstance(parameters, dict):
        msg = "parameters must be a dictionary"
        raise TypeError(msg)
    for item in items:
        job = start_job(job_type)
        jobs.append(job)
        try:
            complete_job(job, worker_func(item, parameters))
        except Exception as e:
            fail_job(job, e)
    return jobs
