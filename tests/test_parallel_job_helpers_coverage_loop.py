# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in parallel_job_helpers.

Missing-line audit (full-suite baseline 15.42% / targeted baseline 94.53%):
  44            -- start_job body: uuid generation and RUNNING status
  49-52         -- complete_job body: result/status/end_time assignment
  57-60         -- fail_job body: error/status/end_time assignment
  65-74         -- validate_graph_types: all branches (None, bad type, loop)
  79-81         -- validate_yara_file_sequence: sequence/scalar rejection
  86-98         -- require_output_dir_path: all type/value guards + Path case
  102-114       -- _require_file_path: all type/value guards + dir rejection
  118-123       -- _read_yara_text_file: success path + UnicodeDecodeError path
  128-135       -- analyze_file_path: real parse + analyze + file key
  144-172       -- export_graph_files: YaraFile success, non-YaraFile failure,
                   empty-rules fallback name, multiple graph_types
  177-210       -- parse_file_chunks: complete success, mixed errors
                   (partial fail path), multi-chunk, empty path list

  NOTE lines 207-209 (outer except _EXPECTED_PARSE_ERRORS in parse_file_chunks):
  Structurally unreachable via the public API. The inner per-file handler
  absorbs all _EXPECTED_PARSE_ERRORS; no code path in the chunk loop body can
  raise these exceptions outside of that guard. Reported here as dead code.

  220-233       -- process_items: success, per-item failure, empty list,
                   invalid parameters dict guard
"""

from __future__ import annotations

import os
from pathlib import Path
import time
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.parser import Parser
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.parallel_job_helpers import (
    FILE_PATH_TYPE_ERROR,
    GRAPH_TYPE_ENTRY_ERROR,
    GRAPH_TYPES_TYPE_ERROR,
    OUTPUT_DIR_TYPE_ERROR,
    _read_yara_text_file,
    _require_file_path,
    analyze_file_path,
    complete_job,
    default_parallel_stats,
    export_graph_files,
    fail_job,
    parse_file_chunks,
    process_items,
    require_output_dir_path,
    start_job,
    validate_graph_types,
    validate_yara_file_sequence,
)
from yaraast.performance.parallel_models import JobStatus, ParseErrorMarker

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _yara_source(name: str = "r") -> str:
    return f"rule {name} {{ condition: true }}"


def _parsed_ast(name: str = "r") -> YaraFile:
    return Parser().parse(_yara_source(name))


def _write_yara_file(path: Path, name: str = "r") -> None:
    path.write_text(_yara_source(name), encoding="utf-8")


# ---------------------------------------------------------------------------
# default_parallel_stats
# ---------------------------------------------------------------------------


def test_default_parallel_stats_returns_zero_initialized_dict() -> None:
    """default_parallel_stats must return the canonical zero-value statistics shape."""
    stats = default_parallel_stats()

    assert stats["rules_analyzed"] == 0
    assert stats["total_time"] == 0.0
    assert stats["errors"] == 0
    assert stats["jobs_submitted"] == 0
    assert stats["jobs_completed"] == 0
    assert stats["jobs_failed"] == 0
    assert len(stats) == 6


# ---------------------------------------------------------------------------
# start_job / complete_job / fail_job
# ---------------------------------------------------------------------------


def test_start_job_creates_running_job_with_unique_ids() -> None:
    """start_job must return a Job in RUNNING status with a non-empty UUID string."""
    j1 = start_job("parse_files")
    j2 = start_job("parse_files")

    assert j1.status is JobStatus.RUNNING
    assert j2.status is JobStatus.RUNNING
    assert j1.job_type == "parse_files"
    assert isinstance(j1.job_id, str)
    assert len(j1.job_id) > 0
    # UUIDs must be unique across calls
    assert j1.job_id != j2.job_id


def test_complete_job_sets_result_status_and_end_time() -> None:
    """complete_job must stamp the job as COMPLETED and record the result payload."""
    before = time.time()
    job = start_job("scan")
    payload = {"key": "value", "count": 42}

    returned = complete_job(job, payload)

    assert returned is job
    assert job.status is JobStatus.COMPLETED
    assert job.result == payload
    assert job.end_time is not None
    assert job.end_time >= before


def test_fail_job_with_exception_sets_error_string_status_and_end_time() -> None:
    """fail_job must convert the exception to a string, set FAILED status, and end_time."""
    before = time.time()
    job = start_job("batch")
    exc = ValueError("something went wrong")

    returned = fail_job(job, exc)

    assert returned is job
    assert job.status is JobStatus.FAILED
    assert "something went wrong" in (job.error or "")
    assert job.end_time is not None
    assert job.end_time >= before


def test_fail_job_with_string_message() -> None:
    """fail_job must accept a plain string error message."""
    job = start_job("batch")
    fail_job(job, "explicit string error")

    assert job.error == "explicit string error"
    assert job.status is JobStatus.FAILED


# ---------------------------------------------------------------------------
# validate_graph_types
# ---------------------------------------------------------------------------


def test_validate_graph_types_none_returns_full_default() -> None:
    """validate_graph_types(None) must return ['full']."""
    assert validate_graph_types(None) == ["full"]


def test_validate_graph_types_valid_list_returns_same_entries() -> None:
    """validate_graph_types normalizes a list of non-empty strings."""
    result = validate_graph_types(["full", "dot", "json"])
    assert result == ["full", "dot", "json"]


def test_validate_graph_types_rejects_plain_string() -> None:
    """A bare string is not a valid sequence of type names."""
    with pytest.raises(TypeError, match=GRAPH_TYPES_TYPE_ERROR):
        validate_graph_types("full")


def test_validate_graph_types_rejects_bytes() -> None:
    """bytes is not a valid input sequence."""
    with pytest.raises(TypeError, match=GRAPH_TYPES_TYPE_ERROR):
        validate_graph_types(b"full")


def test_validate_graph_types_rejects_non_sequence() -> None:
    """An integer is not a valid graph_types argument."""
    with pytest.raises(TypeError, match=GRAPH_TYPES_TYPE_ERROR):
        validate_graph_types(42)


def test_validate_graph_types_rejects_empty_string_entry() -> None:
    """An empty string inside the list must be rejected."""
    with pytest.raises(TypeError, match=GRAPH_TYPE_ENTRY_ERROR):
        validate_graph_types(["full", ""])


def test_validate_graph_types_rejects_whitespace_only_entry() -> None:
    """A whitespace-only string entry must be rejected."""
    with pytest.raises(TypeError, match=GRAPH_TYPE_ENTRY_ERROR):
        validate_graph_types(["   "])


def test_validate_graph_types_rejects_non_string_entry() -> None:
    """A non-string item inside the list must be rejected."""
    with pytest.raises(TypeError, match=GRAPH_TYPE_ENTRY_ERROR):
        validate_graph_types([123])


# ---------------------------------------------------------------------------
# validate_yara_file_sequence
# ---------------------------------------------------------------------------


def test_validate_yara_file_sequence_accepts_empty_list() -> None:
    """An empty list is a valid (empty) sequence of ASTs."""
    assert validate_yara_file_sequence([]) == []


def test_validate_yara_file_sequence_accepts_list_of_yara_files() -> None:
    """A list of YaraFile objects must be returned as a plain list."""
    ast = _parsed_ast()
    result = validate_yara_file_sequence([ast])
    assert result == [ast]


def test_validate_yara_file_sequence_rejects_plain_string() -> None:
    """A string must be rejected (it is iterable but not a sequence of ASTs)."""
    from yaraast.performance.parallel_job_helpers import YARA_FILE_SEQUENCE_TYPE_ERROR

    with pytest.raises(TypeError, match=YARA_FILE_SEQUENCE_TYPE_ERROR):
        validate_yara_file_sequence("rule r { condition: true }")


def test_validate_yara_file_sequence_rejects_bytes() -> None:
    """bytes must be rejected."""
    from yaraast.performance.parallel_job_helpers import YARA_FILE_SEQUENCE_TYPE_ERROR

    with pytest.raises(TypeError, match=YARA_FILE_SEQUENCE_TYPE_ERROR):
        validate_yara_file_sequence(b"data")


def test_validate_yara_file_sequence_rejects_non_sequence() -> None:
    """An integer must be rejected (not iterable as an AST sequence)."""
    from yaraast.performance.parallel_job_helpers import YARA_FILE_SEQUENCE_TYPE_ERROR

    with pytest.raises(TypeError, match=YARA_FILE_SEQUENCE_TYPE_ERROR):
        validate_yara_file_sequence(999)


# ---------------------------------------------------------------------------
# require_output_dir_path
# ---------------------------------------------------------------------------


def test_require_output_dir_path_accepts_string(tmp_path: Path) -> None:
    """A valid directory path string must be returned as a Path object."""
    result = require_output_dir_path(str(tmp_path))
    assert result == tmp_path


def test_require_output_dir_path_accepts_path_object(tmp_path: Path) -> None:
    """A pathlib.Path argument must be accepted and returned as a Path."""
    result = require_output_dir_path(tmp_path)
    assert result == tmp_path


def test_require_output_dir_path_rejects_bool() -> None:
    """bool is excluded even though it subclasses int."""
    with pytest.raises(TypeError, match=OUTPUT_DIR_TYPE_ERROR):
        require_output_dir_path(True)


def test_require_output_dir_path_rejects_bytes() -> None:
    """bytes must be rejected."""
    with pytest.raises(TypeError, match=OUTPUT_DIR_TYPE_ERROR):
        require_output_dir_path(b"/tmp")


def test_require_output_dir_path_rejects_integer() -> None:
    """An integer must be rejected."""
    with pytest.raises(TypeError, match=OUTPUT_DIR_TYPE_ERROR):
        require_output_dir_path(42)


def test_require_output_dir_path_rejects_empty_string() -> None:
    """An empty or whitespace-only string must be rejected."""
    with pytest.raises(ValueError, match="output_dir must not be empty"):
        require_output_dir_path("   ")


def test_require_output_dir_path_rejects_existing_file(tmp_path: Path) -> None:
    """A path that resolves to an existing regular file must be rejected."""
    file_path = tmp_path / "existing.txt"
    file_path.write_text("data", encoding="utf-8")

    with pytest.raises(ValueError, match="output_dir must not be a file"):
        require_output_dir_path(str(file_path))


def test_require_output_dir_path_rejects_pathlike_returning_bytes() -> None:
    """A PathLike whose __fspath__ returns bytes must be rejected."""

    class BytesPathLike:
        def __fspath__(self) -> bytes:
            return b"/tmp/bytes_path"

    with pytest.raises(TypeError, match=OUTPUT_DIR_TYPE_ERROR):
        require_output_dir_path(BytesPathLike())


# ---------------------------------------------------------------------------
# _require_file_path
# ---------------------------------------------------------------------------


def test_require_file_path_accepts_string_to_nonexistent_file() -> None:
    """A string path that is not a directory must be accepted (file need not exist)."""
    path = _require_file_path("/nonexistent/file.yar")
    assert path == Path("/nonexistent/file.yar")


def test_require_file_path_accepts_path_object_for_nonexistent_file() -> None:
    """A pathlib.Path argument must be accepted."""
    path = _require_file_path(Path("/nonexistent/file.yar"))
    assert path == Path("/nonexistent/file.yar")


def test_require_file_path_rejects_bool() -> None:
    """bool must be rejected."""
    with pytest.raises(TypeError, match=FILE_PATH_TYPE_ERROR):
        _require_file_path(False)


def test_require_file_path_rejects_bytes() -> None:
    """bytes must be rejected."""
    with pytest.raises(TypeError, match=FILE_PATH_TYPE_ERROR):
        _require_file_path(b"/tmp/file.yar")


def test_require_file_path_rejects_empty_string() -> None:
    """An empty or whitespace-only string must be rejected."""
    with pytest.raises(ValueError, match="file_path must not be empty"):
        _require_file_path("   ")


def test_require_file_path_rejects_directory(tmp_path: Path) -> None:
    """A path that points to an existing directory must be rejected."""
    with pytest.raises(ValueError, match="file_path must not be a directory"):
        _require_file_path(str(tmp_path))


def test_require_file_path_rejects_pathlike_returning_bytes() -> None:
    """A PathLike whose __fspath__ returns bytes must be rejected."""

    class BytesPathLike:
        def __fspath__(self) -> bytes:
            return b"/tmp/bytes.yar"

    with pytest.raises(TypeError, match=FILE_PATH_TYPE_ERROR):
        _require_file_path(BytesPathLike())


# ---------------------------------------------------------------------------
# _read_yara_text_file
# ---------------------------------------------------------------------------


def test_read_yara_text_file_returns_file_contents(tmp_path: Path) -> None:
    """_read_yara_text_file must return the UTF-8 text content of a YARA source file."""
    source = _yara_source("read_test")
    yar = tmp_path / "read_test.yar"
    yar.write_text(source, encoding="utf-8")

    content = _read_yara_text_file(str(yar))

    assert content == source


def test_read_yara_text_file_raises_on_non_utf8_binary(tmp_path: Path) -> None:
    """_read_yara_text_file must raise ValueError when the file is not valid UTF-8."""
    binary_file = tmp_path / "bad.bin"
    binary_file.write_bytes(b"\xff\xfe\x00\x01")

    with pytest.raises(ValueError, match="YARA file must contain valid UTF-8 text"):
        _read_yara_text_file(str(binary_file))


# ---------------------------------------------------------------------------
# analyze_file_path
# ---------------------------------------------------------------------------


def test_analyze_file_path_returns_full_analysis_dict(tmp_path: Path) -> None:
    """analyze_file_path must parse the file and run a real analysis, returning file key."""
    yar = tmp_path / "a.yar"
    _write_yara_file(yar, "a")
    analyzer = ParallelAnalyzer(max_workers=1)

    result = analyze_file_path(str(yar), analyzer)

    assert result["file"] == str(yar)
    assert "rules" in result
    assert "stats" in result
    assert result["stats"]["total_rules"] == 1


def test_analyze_file_path_accepts_path_object(tmp_path: Path) -> None:
    """analyze_file_path must accept a pathlib.Path as the path argument."""
    yar = tmp_path / "b.yar"
    _write_yara_file(yar, "b")
    analyzer = ParallelAnalyzer(max_workers=1)

    result = analyze_file_path(yar, analyzer)

    assert result["file"] == str(yar)


# ---------------------------------------------------------------------------
# export_graph_files
# ---------------------------------------------------------------------------


def test_export_graph_files_single_ast_single_type(tmp_path: Path) -> None:
    """export_graph_files must produce one completed job with an output file list."""
    ast = _parsed_ast("ex1")

    jobs = export_graph_files([ast], tmp_path, ["full"])

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.COMPLETED
    assert isinstance(job.result, list)
    assert len(job.result) == 1
    assert job.result[0].endswith("_full.json")
    assert Path(job.result[0]).exists()


def test_export_graph_files_multiple_graph_types(tmp_path: Path) -> None:
    """Each graph_type entry must produce a separate output file per AST."""
    ast = _parsed_ast("multi")

    jobs = export_graph_files([ast], tmp_path, ["full", "summary"])

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.COMPLETED
    assert isinstance(job.result, list)
    assert len(job.result) == 2


def test_export_graph_files_defaults_to_full_graph_type(tmp_path: Path) -> None:
    """graph_types=None must default to ['full'] and produce the expected output."""
    ast = _parsed_ast("default_type")

    jobs = export_graph_files([ast], tmp_path, None)

    assert len(jobs) == 1
    assert jobs[0].status is JobStatus.COMPLETED
    output_files = jobs[0].result
    assert len(output_files) == 1
    assert "_full.json" in output_files[0]


def test_export_graph_files_non_yara_file_input_fails_job(tmp_path: Path) -> None:
    """An item that is not a YaraFile must produce a FAILED job."""
    jobs = export_graph_files(cast(Any, ["not_a_yara_file"]), tmp_path)

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.FAILED
    assert job.error is not None
    assert "YaraFile" in job.error


def test_export_graph_files_ast_with_no_rules_uses_index_fallback_name(
    tmp_path: Path,
) -> None:
    """An AST with an empty rules list must name the output file ast_0_<type>.json."""
    empty_ast = YaraFile(imports=[], includes=[], rules=[])

    jobs = export_graph_files([empty_ast], tmp_path, ["full"])

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.COMPLETED
    output_files = job.result
    assert len(output_files) == 1
    assert "ast_0_full.json" in output_files[0]


def test_export_graph_files_creates_output_dir_if_missing(tmp_path: Path) -> None:
    """export_graph_files must create the output directory when it does not yet exist."""
    new_dir = tmp_path / "subdir" / "graphs"
    assert not new_dir.exists()
    ast = _parsed_ast("mkdir_test")

    jobs = export_graph_files([ast], new_dir, ["full"])

    assert new_dir.exists()
    assert len(jobs) == 1
    assert jobs[0].status is JobStatus.COMPLETED


def test_export_graph_files_mixed_valid_and_invalid(tmp_path: Path) -> None:
    """A list with both YaraFile and non-YaraFile items must produce mixed job statuses."""
    ast = _parsed_ast("valid")

    jobs = export_graph_files(cast(Any, [ast, "invalid"]), tmp_path, ["full"])

    assert len(jobs) == 2
    statuses = {j.status for j in jobs}
    assert JobStatus.COMPLETED in statuses
    assert JobStatus.FAILED in statuses


def test_export_graph_files_ioerror_during_write_fails_job(tmp_path: Path) -> None:
    """An OSError during graph export must fail the job via the except handler."""
    import stat

    ast = _parsed_ast("ioerror_test")
    output_dir = tmp_path / "readonly"
    output_dir.mkdir()

    original_mode = output_dir.stat().st_mode
    try:
        os.chmod(output_dir, stat.S_IRUSR | stat.S_IXUSR)
        jobs = export_graph_files([ast], output_dir, ["full"])
    finally:
        os.chmod(output_dir, original_mode)

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.FAILED
    assert job.error is not None


# ---------------------------------------------------------------------------
# parse_file_chunks
# ---------------------------------------------------------------------------


def test_parse_file_chunks_single_file_single_chunk(tmp_path: Path) -> None:
    """A single valid YARA file in one chunk must produce one completed job."""
    yar = tmp_path / "single.yar"
    _write_yara_file(yar, "single")

    jobs = parse_file_chunks([str(yar)], chunk_size=1)

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.COMPLETED
    assert isinstance(job.result, list)
    assert len(job.result) == 1
    assert isinstance(job.result[0], YaraFile)


def test_parse_file_chunks_multiple_files_single_chunk(tmp_path: Path) -> None:
    """Multiple valid files within chunk_size must produce one job with all ASTs."""
    files = []
    for i in range(3):
        yar = tmp_path / f"f{i}.yar"
        _write_yara_file(yar, f"rule{i}")
        files.append(str(yar))

    jobs = parse_file_chunks(files, chunk_size=10)

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.COMPLETED
    assert len(job.result) == 3


def test_parse_file_chunks_multiple_chunks(tmp_path: Path) -> None:
    """Files exceeding chunk_size must produce multiple jobs, one per chunk."""
    files = []
    for i in range(3):
        yar = tmp_path / f"chunk{i}.yar"
        _write_yara_file(yar, f"chunkrule{i}")
        files.append(str(yar))

    jobs = parse_file_chunks(files, chunk_size=1)

    assert len(jobs) == 3
    assert all(j.status is JobStatus.COMPLETED for j in jobs)


def test_parse_file_chunks_non_utf8_file_fails_job(tmp_path: Path) -> None:
    """A non-UTF-8 file in a chunk must produce a FAILED job with a ParseErrorMarker."""
    bad_file = tmp_path / "bad.bin"
    bad_file.write_bytes(b"\xff\xfe\x00\x01")

    jobs = parse_file_chunks([str(bad_file)], chunk_size=1)

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.FAILED
    assert job.error is not None


def test_parse_file_chunks_mixed_valid_and_invalid_in_same_chunk(tmp_path: Path) -> None:
    """A chunk containing both valid and invalid files must be FAILED with partial results."""
    good1 = tmp_path / "good1.yar"
    good2 = tmp_path / "good2.yar"
    bad = tmp_path / "bad.bin"
    _write_yara_file(good1, "good1")
    _write_yara_file(good2, "good2")
    bad.write_bytes(b"\xff\xfe\x00\x01")

    jobs = parse_file_chunks([str(good1), str(bad), str(good2)], chunk_size=10)

    assert len(jobs) == 1
    job = jobs[0]
    # Partial failures cause the job to be FAILED but result still populated
    assert job.status is JobStatus.FAILED
    assert job.result is not None
    # Three entries: two YaraFile, one ParseErrorMarker
    assert len(job.result) == 3
    markers = [r for r in job.result if isinstance(r, ParseErrorMarker)]
    assert len(markers) == 1
    assert str(bad) in markers[0].file_path


def test_parse_file_chunks_syntax_error_file_in_chunk(tmp_path: Path) -> None:
    """A YARA file with a parse error must produce a FAILED job with a ParseErrorMarker."""
    broken = tmp_path / "broken.yar"
    broken.write_text("this is not valid yara syntax !!!", encoding="utf-8")

    jobs = parse_file_chunks([str(broken)], chunk_size=1)

    assert len(jobs) == 1
    job = jobs[0]
    assert job.status is JobStatus.FAILED
    assert isinstance(job.result, list)
    assert len(job.result) == 1
    assert isinstance(job.result[0], ParseErrorMarker)


# ---------------------------------------------------------------------------
# process_items
# ---------------------------------------------------------------------------


def test_process_items_all_succeed_produces_completed_jobs() -> None:
    """process_items must produce COMPLETED jobs when the worker always succeeds."""

    def double(item: int, params: dict[str, Any]) -> int:
        return item * 2

    jobs = process_items([1, 2, 3], double, "double", parameters={})

    assert len(jobs) == 3
    assert all(j.status is JobStatus.COMPLETED for j in jobs)
    assert [j.result for j in jobs] == [2, 4, 6]


def test_process_items_worker_failure_produces_failed_job() -> None:
    """process_items must catch worker exceptions and mark that job as FAILED."""

    def failing_on_two(item: int, params: dict[str, Any]) -> int:
        if item == 2:
            msg = "bad item"
            raise ValueError(msg)
        return item

    jobs = process_items([1, 2, 3], failing_on_two, "mixed")

    statuses = [j.status for j in jobs]
    assert statuses[0] is JobStatus.COMPLETED
    assert statuses[1] is JobStatus.FAILED
    assert statuses[2] is JobStatus.COMPLETED
    assert jobs[1].error is not None
    assert "bad item" in jobs[1].error


def test_process_items_empty_list_returns_no_jobs() -> None:
    """process_items on an empty list must return an empty job list."""
    jobs = process_items([], lambda i, p: i, "empty")
    assert jobs == []


def test_process_items_none_parameters_defaults_to_empty_dict() -> None:
    """parameters=None must be treated as an empty dict without raising."""
    received: list[dict[str, Any]] = []

    def capture_params(item: int, params: dict[str, Any]) -> int:
        received.append(dict(params))
        return item

    jobs = process_items([7], capture_params, "capture", parameters=None)

    assert len(jobs) == 1
    assert jobs[0].status is JobStatus.COMPLETED
    assert received == [{}]


def test_process_items_custom_parameters_passed_to_worker() -> None:
    """process_items must forward the parameters dict to the worker function."""
    captured: list[dict[str, Any]] = []

    def capture_params(item: int, params: dict[str, Any]) -> int:
        captured.append(dict(params))
        return item

    params = {"threshold": 10, "mode": "strict"}
    jobs = process_items([1, 2], capture_params, "param_check", parameters=params)

    assert len(jobs) == 2
    assert all(j.status is JobStatus.COMPLETED for j in jobs)
    assert captured == [params, params]


def test_process_items_rejects_non_dict_parameters() -> None:
    """process_items must raise TypeError when parameters is not a dict."""
    with pytest.raises(TypeError, match="parameters must be a dictionary"):
        process_items([1], lambda i, p: i, parameters=cast(Any, "not-a-dict"))


def test_process_items_uses_custom_job_type_label() -> None:
    """The job_type string must appear on every produced Job."""
    jobs = process_items([1, 2], lambda i, p: i, "custom_label")

    assert all(j.job_type == "custom_label" for j in jobs)


# ---------------------------------------------------------------------------
# Integration: export_graph_files via ParallelAnalyzer.generate_graphs_parallel
# ---------------------------------------------------------------------------


def test_generate_graphs_parallel_updates_analyzer_stats(tmp_path: Path) -> None:
    """generate_graphs_parallel must update ParallelAnalyzer stats for each job."""
    ast = _parsed_ast("stats_test")
    analyzer = ParallelAnalyzer(max_workers=1)

    jobs = analyzer.generate_graphs_parallel([ast], tmp_path, ["full"])

    stats = analyzer.get_statistics()
    assert stats["jobs_submitted"] >= 1
    assert stats["jobs_completed"] >= 1
    assert len(jobs) == 1
    assert jobs[0].status is JobStatus.COMPLETED


def test_generate_graphs_parallel_failed_job_increments_failed_stat(
    tmp_path: Path,
) -> None:
    """A non-YaraFile input must increment jobs_failed in analyzer stats."""
    analyzer = ParallelAnalyzer(max_workers=1)

    jobs = analyzer.generate_graphs_parallel(cast(Any, ["not_a_yara_file"]), tmp_path)

    stats = analyzer.get_statistics()
    assert stats["jobs_failed"] >= 1
    assert jobs[0].status is JobStatus.FAILED


# ---------------------------------------------------------------------------
# Integration: parse_file_chunks via ParallelAnalyzer.parse_files_parallel
# ---------------------------------------------------------------------------


def test_parse_files_parallel_updates_analyzer_stats(tmp_path: Path) -> None:
    """parse_files_parallel must update analyzer stats reflecting completed jobs."""
    yar = tmp_path / "stats.yar"
    _write_yara_file(yar, "stats_rule")
    analyzer = ParallelAnalyzer(max_workers=1)

    jobs = analyzer.parse_files_parallel([str(yar)], chunk_size=1)

    stats = analyzer.get_statistics()
    assert stats["jobs_submitted"] >= 1
    assert stats["jobs_completed"] >= 1
    assert len(jobs) == 1


# ---------------------------------------------------------------------------
# Integration: process_items via ParallelAnalyzer.process_batch
# ---------------------------------------------------------------------------


def test_process_batch_via_analyzer_success(tmp_path: Path) -> None:
    """process_batch must complete jobs and update analyzer stats on worker success."""
    analyzer = ParallelAnalyzer(max_workers=1)

    def worker(item: int, params: dict[str, Any]) -> int:
        return item + 1

    jobs = analyzer.process_batch([10, 20], worker, job_type="add_one")

    assert len(jobs) == 2
    assert all(j.status is JobStatus.COMPLETED for j in jobs)
    results = [j.result for j in jobs]
    assert results == [11, 21]
    stats = analyzer.get_statistics()
    assert stats["jobs_completed"] >= 2


def test_process_batch_via_analyzer_failure_increments_failed_stat() -> None:
    """process_batch must update jobs_failed when the worker raises."""
    analyzer = ParallelAnalyzer(max_workers=1)

    def always_fail(item: int, params: dict[str, Any]) -> int:
        msg = "always fails"
        raise RuntimeError(msg)

    jobs = analyzer.process_batch([1], always_fail)

    assert jobs[0].status is JobStatus.FAILED
    stats = analyzer.get_statistics()
    assert stats["jobs_failed"] >= 1
