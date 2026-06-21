"""Coverage tests for direct_helpers, runtime_workspace, and parallel_job_actions.

Copyright (c) 2026 Marc Rivero Lopez
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Targets:
  yaraast.libyara.direct_helpers        - compile_source_with_file_context branches
  yaraast.lsp.runtime_workspace         - _uncached_workspace_symbol_records exception + filter
  yaraast.performance.parallel_job_actions - FAILED job stat paths and exception handler
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from yaraast.libyara.direct_helpers import (
    compile_source_with_file_context,
)
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import RuntimeConfig, SymbolRecord
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.runtime_workspace import (
    _uncached_workspace_symbol_records,
    workspace_symbol_records,
    workspace_symbols,
)
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.parallel_job_actions import (
    analyze_complexity_parallel,
    generate_graphs_parallel,
    parse_files_parallel,
    process_batch,
)
from yaraast.performance.parallel_models import JobStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_rule(name: str = "test_rule") -> str:
    return f"rule {name} {{ condition: true }}"


def _uncached_runtime() -> LspRuntime:
    """Return an LspRuntime configured with cache_workspace disabled."""
    config = RuntimeConfig(cache_workspace=False)
    return LspRuntime(config=config)


# ---------------------------------------------------------------------------
# direct_helpers.py - compile_source_with_file_context
# ---------------------------------------------------------------------------


class TestCompileSourceWithFileContext:
    """Direct calls to compile_source_with_file_context exercising all branches."""

    def test_happy_path_compiles_rule_and_cleans_up(self, tmp_path: Path) -> None:
        """Arrange: valid source and real writable directory.

        The function writes a temporary file in source_dir, compiles it with
        libyara, then removes the temporary file in the finally block.
        """
        source = _minimal_rule("happy_path_rule")
        source_path = str(tmp_path / "input.yar")

        result = compile_source_with_file_context(source, {}, source_path, False)

        assert result.success is True
        assert result.errors == []
        assert result.compiled_rules is not None
        # Verify the cleanup: no .yar temp files remain in the directory
        remaining = [f for f in os.listdir(tmp_path) if f.endswith(".yar")]
        assert remaining == []

    def test_happy_path_returns_directcompilationresult(self, tmp_path: Path) -> None:
        """The return value must be a DirectCompilationResult with warnings."""
        from yaraast.libyara.direct_models import DirectCompilationResult

        source = _minimal_rule("result_type_rule")
        source_path = tmp_path / "check.yar"

        result = compile_source_with_file_context(source, {}, source_path, False)

        assert isinstance(result, DirectCompilationResult)
        assert isinstance(result.warnings, list)

    def test_accepts_pathlike_source_path(self, tmp_path: Path) -> None:
        """Accepts a pathlib.Path object (PathLike) as source_path."""
        source = _minimal_rule("pathlike_rule")
        source_path = tmp_path / "rules.yar"

        result = compile_source_with_file_context(source, {}, source_path, False)

        assert result.success is True

    def test_rejects_pathlike_with_bytes_fspath_result(self) -> None:
        """A PathLike whose __fspath__() returns bytes passes the first isinstance
        guard but then fails the 'isinstance(raw_path, str)' check on line 58-60.

        Branch: not isinstance(raw_path, str) → TypeError at lines 59-60.
        """

        class _BytesFsPathLike:
            """PathLike that returns bytes instead of str from __fspath__."""

            def __fspath__(self) -> bytes:
                return b"/tmp/rules.yar"

        source = _minimal_rule()
        with pytest.raises(TypeError, match="source_path must be a string or path-like object"):
            compile_source_with_file_context(source, {}, _BytesFsPathLike(), False)

    def test_rejects_bool_source_path(self, tmp_path: Path) -> None:
        """bool is excluded even though bool is a subclass of int, not str.

        Branch: isinstance(source_path, bool | bytes) at line 54 → TypeError.
        """
        source = _minimal_rule()
        with pytest.raises(TypeError, match="source_path must be a string or path-like object"):
            compile_source_with_file_context(source, {}, True, False)

    def test_rejects_bytes_source_path(self, tmp_path: Path) -> None:
        """bytes is rejected even though bytes supports __fspath__ conceptually.

        Branch: isinstance(source_path, bool | bytes) at line 54 → TypeError.
        """
        source = _minimal_rule()
        with pytest.raises(TypeError, match="source_path must be a string or path-like object"):
            compile_source_with_file_context(source, {}, b"/tmp/test.yar", False)

    def test_rejects_integer_source_path(self) -> None:
        """An integer is not str or PathLike; triggers the second isinstance check.

        Branch: not isinstance(source_path, str | PathLike) at line 54 → TypeError.
        """
        source = _minimal_rule()
        with pytest.raises(TypeError, match="source_path must be a string or path-like object"):
            compile_source_with_file_context(source, {}, 42, False)

    def test_rejects_none_source_path(self) -> None:
        """None is not str or PathLike.

        Branch: not isinstance(source_path, str | PathLike) → TypeError.
        """
        source = _minimal_rule()
        with pytest.raises(TypeError, match="source_path must be a string or path-like object"):
            compile_source_with_file_context(source, {}, None, False)

    def test_rejects_empty_string_source_path(self) -> None:
        """An empty string passes isinstance checks but fails the strip() guard.

        Branch: not raw_path.strip() at line 61 → ValueError.
        """
        source = _minimal_rule()
        with pytest.raises(ValueError, match="source_path must not be empty"):
            compile_source_with_file_context(source, {}, "", False)

    def test_rejects_whitespace_only_source_path(self) -> None:
        """Whitespace-only string fails the strip() guard.

        Branch: not raw_path.strip() at line 61 → ValueError.
        """
        source = _minimal_rule()
        with pytest.raises(ValueError, match="source_path must not be empty"):
            compile_source_with_file_context(source, {}, "   ", False)

    def test_compile_failure_reported_not_raised(self, tmp_path: Path) -> None:
        """Invalid YARA source yields a failed DirectCompilationResult, not an exception."""
        source = "this is not valid yara syntax {"
        source_path = str(tmp_path / "bad.yar")

        result = compile_source_with_file_context(source, {}, source_path, False)

        assert result.success is False
        assert len(result.errors) > 0

    def test_cleanup_occurs_even_when_compile_fails(self, tmp_path: Path) -> None:
        """The finally block removes the temp file even when compilation fails."""
        source = "bad syntax"
        source_path = str(tmp_path / "fail.yar")

        compile_source_with_file_context(source, {}, source_path, False)

        remaining = [f for f in os.listdir(tmp_path) if f.endswith(".yar")]
        assert remaining == []

    def test_externals_passed_through(self, tmp_path: Path) -> None:
        """External variables provided to compile_source_with_file_context are forwarded."""
        source = 'rule ext_rule { condition: my_var == "hello" }'
        source_path = str(tmp_path / "ext.yar")
        externals = {"my_var": "hello"}

        result = compile_source_with_file_context(source, externals, source_path, False)

        assert result.success is True


# ---------------------------------------------------------------------------
# runtime_workspace.py - _uncached_workspace_symbol_records
# ---------------------------------------------------------------------------


class _FailingSymbolsDocument(DocumentContext):
    """A real DocumentContext subclass whose symbols() always raises.

    This exercises the exception-swallowing branch at lines 67-69 of
    _uncached_workspace_symbol_records without replacing any production code.
    """

    def symbols(self) -> list[SymbolRecord]:
        raise RuntimeError("symbols() intentionally broken for coverage")


class TestUncachedWorkspaceSymbolRecords:
    """Real calls to _uncached_workspace_symbol_records covering all branches."""

    def test_exception_in_symbols_is_swallowed_and_doc_skipped(self) -> None:
        """Arrange: a DocumentContext subclass that raises from symbols().

        Branch: except Exception at line 67 → logger.debug + continue (lines 68-69).
        The function must return an empty list and not propagate the exception.
        """
        runtime = _uncached_runtime()
        uri = "file:///tmp/broken_doc.yar"
        broken = _FailingSymbolsDocument(uri, _minimal_rule("broken"))
        runtime.documents[uri] = broken

        records = _uncached_workspace_symbol_records(runtime, "")

        assert records == []

    def test_exception_does_not_prevent_other_docs_from_being_processed(self) -> None:
        """A broken document is skipped; subsequent documents are still processed.

        This validates the continue after the except block actually skips only
        the offending document and the loop proceeds.
        """
        runtime = _uncached_runtime()

        broken_uri = "file:///tmp/broken_second.yar"
        runtime.documents[broken_uri] = _FailingSymbolsDocument(
            broken_uri, _minimal_rule("broken_second")
        )

        good_uri = "file:///tmp/good_doc.yar"
        runtime.documents[good_uri] = DocumentContext(good_uri, _minimal_rule("good_rule"))

        records = _uncached_workspace_symbol_records(runtime, "")

        names = {r.name for r in records}
        assert "good_rule" in names

    def test_query_filter_skips_non_matching_records(self) -> None:
        """A non-empty query causes non-matching symbol names to be skipped.

        Branch: if query and query_lower not in record.name.lower(): continue
        at line 73-74. The query 'zzznonexistent' matches nothing in alpha_rule,
        so the result must be empty.
        """
        runtime = _uncached_runtime()
        uri = "file:///tmp/query_filter_doc.yar"
        runtime.documents[uri] = DocumentContext(uri, _minimal_rule("alpha_rule"))

        records = _uncached_workspace_symbol_records(runtime, "zzznonexistent")

        assert records == []

    def test_query_filter_returns_matching_records(self) -> None:
        """A matching query prefix returns the corresponding symbol record.

        This validates the branch is taken as False (match found, record appended).
        """
        runtime = _uncached_runtime()
        uri = "file:///tmp/matching_doc.yar"
        runtime.documents[uri] = DocumentContext(uri, _minimal_rule("delta_rule"))

        records = _uncached_workspace_symbol_records(runtime, "delta")

        names = [r.name for r in records]
        assert "delta_rule" in names

    def test_empty_query_returns_all_non_hidden_records(self) -> None:
        """An empty query string bypasses the name filter and returns everything."""
        runtime = _uncached_runtime()
        uri = "file:///tmp/all_records.yar"
        runtime.documents[uri] = DocumentContext(uri, _minimal_rule("omega_rule"))

        records = _uncached_workspace_symbol_records(runtime, "")

        names = {r.name for r in records}
        assert "omega_rule" in names

    def test_hidden_kinds_are_excluded(self) -> None:
        """Records with kinds 'rule_block' or 'section_header' must not appear."""
        runtime = _uncached_runtime()
        uri = "file:///tmp/hidden_kinds.yar"
        runtime.documents[uri] = DocumentContext(uri, _minimal_rule("visible_rule"))

        records = _uncached_workspace_symbol_records(runtime, "")

        hidden = {r.name for r in records if r.kind in {"rule_block", "section_header"}}
        assert hidden == set()

    def test_workspace_symbols_public_api_with_cache_disabled(self, tmp_path: Path) -> None:
        """workspace_symbols (the public API) routes through _uncached when cache is off."""
        yar = tmp_path / "pub.yar"
        yar.write_text(_minimal_rule("pub_api_rule"), encoding="utf-8")

        config = RuntimeConfig(cache_workspace=False)
        runtime = LspRuntime(config=config)
        runtime.set_workspace_folders([str(tmp_path)])

        uri = f"file://{yar}"
        runtime.open_document(uri, yar.read_text(encoding="utf-8"))

        results = workspace_symbols(runtime, "")

        rule_names = {s.name for s in results if s.name}
        assert "pub_api_rule" in rule_names

    def test_workspace_symbol_records_public_api_with_cache_disabled(self, tmp_path: Path) -> None:
        """workspace_symbol_records routes through _uncached path when cache is off."""
        yar = tmp_path / "rec.yar"
        yar.write_text(_minimal_rule("record_api_rule"), encoding="utf-8")

        config = RuntimeConfig(cache_workspace=False)
        runtime = LspRuntime(config=config)
        runtime.set_workspace_folders([str(tmp_path)])
        uri = f"file://{yar}"
        runtime.open_document(uri, yar.read_text(encoding="utf-8"))

        records = workspace_symbol_records(runtime, "")

        names = {r.name for r in records}
        assert "record_api_rule" in names


# ---------------------------------------------------------------------------
# parallel_job_actions.py - FAILED job stat tracking and exception handler
# ---------------------------------------------------------------------------


class _ExceptionOnAnalyzeFile(ParallelAnalyzer):
    """ParallelAnalyzer subclass that raises ValueError from analyze_file.

    This exercises lines 54-56 of analyze_complexity_parallel: the
    'except (ValueError, YaraASTError)' branch that records the failure and
    increments jobs_failed without re-raising.
    """

    def analyze_file(self, yara_file: Any, max_workers: int | None = None) -> dict[str, Any]:
        raise ValueError("forced analyze_file failure for branch coverage")


class TestAnalyzeComplexityParallelExceptionBranch:
    """Lines 54-56 of parallel_job_actions.py: exception handler in analyze_complexity_parallel."""

    def test_exception_in_analyze_file_marks_job_failed(self) -> None:
        """Arrange: analyzer whose analyze_file raises ValueError.

        Act: analyze_complexity_parallel processes a valid YaraFile.
        Assert: the returned job is FAILED and stats reflect the failure.
        """
        from yaraast.ast.base import YaraFile
        from yaraast.parser import Parser

        analyzer = _ExceptionOnAnalyzeFile(max_workers=1)
        source = _minimal_rule("exc_rule")
        ast = Parser().parse(source)
        assert isinstance(ast, YaraFile)

        jobs = analyze_complexity_parallel(analyzer, [ast])

        assert len(jobs) == 1
        assert jobs[0].status == JobStatus.FAILED
        assert "forced analyze_file failure" in str(jobs[0].error)
        assert analyzer._stats["jobs_submitted"] == 1
        assert analyzer._stats["jobs_failed"] == 1
        assert analyzer._stats["jobs_completed"] == 0

    def test_exception_in_analyze_file_multiple_asts_all_counted(self) -> None:
        """Multiple ASTs all produce failed jobs and stats accumulate correctly."""
        from yaraast.parser import Parser

        analyzer = _ExceptionOnAnalyzeFile(max_workers=1)
        asts = [Parser().parse(_minimal_rule(f"exc_rule_{i}")) for i in range(3)]

        jobs = analyze_complexity_parallel(analyzer, asts)

        assert all(j.status == JobStatus.FAILED for j in jobs)
        assert analyzer._stats["jobs_submitted"] == 3
        assert analyzer._stats["jobs_failed"] == 3

    def test_non_yarafile_in_sequence_uses_fast_fail_path(self) -> None:
        """A non-YaraFile item takes the fast-fail branch (lines 40-43), not the exception path.

        This confirms that lines 41-43 cover the separate fail_job call for type mismatches,
        distinct from the exception-based failure at lines 54-56.
        """
        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = analyze_complexity_parallel(analyzer, ["not_a_yara_file"])  # type: ignore[list-item]

        assert jobs[0].status == JobStatus.FAILED
        assert "complexity analysis input must be a YaraFile" in str(jobs[0].error)


class TestGenerateGraphsParallelFailedJobStats:
    """Branch 72->68 in generate_graphs_parallel: FAILED job increments jobs_failed."""

    def test_non_yarafile_produces_failed_job_and_increments_stats(self, tmp_path: Path) -> None:
        """Arrange: pass a non-YaraFile in the sequence so export_graph_files marks it failed.

        Branch: job.status == JobStatus.FAILED → elif taken (line 72->68 = True path).
        """
        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = generate_graphs_parallel(
            analyzer, ["not_a_yara_file"], str(tmp_path)  # type: ignore[list-item]
        )

        assert len(jobs) == 1
        assert jobs[0].status == JobStatus.FAILED
        assert analyzer._stats["jobs_submitted"] == 1
        assert analyzer._stats["jobs_failed"] == 1
        assert analyzer._stats["jobs_completed"] == 0

    def test_mixed_valid_and_invalid_asts_counts_both_job_states(self, tmp_path: Path) -> None:
        """One valid YaraFile and one non-YaraFile produce one COMPLETED and one FAILED job."""
        from yaraast.parser import Parser

        analyzer = ParallelAnalyzer(max_workers=1)
        valid_ast = Parser().parse(_minimal_rule("graph_rule"))

        jobs = generate_graphs_parallel(
            analyzer,
            [valid_ast, "not_a_yara_file"],  # type: ignore[list-item]
            str(tmp_path),
        )

        statuses = {j.status for j in jobs}
        assert JobStatus.COMPLETED in statuses
        assert JobStatus.FAILED in statuses
        assert analyzer._stats["jobs_completed"] == 1
        assert analyzer._stats["jobs_failed"] == 1


class TestParseFilesParallelFailedJobStats:
    """Branch 88->84 in parse_files_parallel: FAILED job increments jobs_failed."""

    def test_nonexistent_file_produces_failed_job_and_increments_stats(self) -> None:
        """Arrange: a file path that does not exist.

        parse_file_chunks reads the file and catches OSError, marking the job FAILED.
        Branch: job.status == JobStatus.FAILED → elif taken (line 88->84 = True path).
        """
        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = parse_files_parallel(
            analyzer, ["/absolutely/nonexistent/path/rules.yar"], chunk_size=1
        )

        assert len(jobs) == 1
        assert jobs[0].status == JobStatus.FAILED
        assert analyzer._stats["jobs_submitted"] == 1
        assert analyzer._stats["jobs_failed"] == 1
        assert analyzer._stats["jobs_completed"] == 0

    def test_valid_file_path_produces_completed_job(self, tmp_path: Path) -> None:
        """A real parseable YARA file produces a COMPLETED job.

        Validates the non-FAILED branch (jobs_completed incremented).
        """
        yar = tmp_path / "valid.yar"
        yar.write_text(_minimal_rule("parse_valid"), encoding="utf-8")

        analyzer = ParallelAnalyzer(max_workers=1)
        jobs = parse_files_parallel(analyzer, [str(yar)], chunk_size=1)

        assert len(jobs) == 1
        assert jobs[0].status == JobStatus.COMPLETED
        assert analyzer._stats["jobs_completed"] == 1
        assert analyzer._stats["jobs_failed"] == 0

    def test_mixed_paths_increment_both_counters(self, tmp_path: Path) -> None:
        """One valid and one nonexistent file in separate chunks increment each counter."""
        yar = tmp_path / "ok.yar"
        yar.write_text(_minimal_rule("ok_rule"), encoding="utf-8")

        analyzer = ParallelAnalyzer(max_workers=1)
        jobs = parse_files_parallel(
            analyzer,
            [str(yar), "/no/such/file.yar"],
            chunk_size=1,
        )

        statuses = {j.status for j in jobs}
        assert JobStatus.COMPLETED in statuses
        assert JobStatus.FAILED in statuses


class TestProcessBatchFailedJobStats:
    """Branch 106->102 in process_batch: FAILED job increments jobs_failed."""

    def test_failing_worker_produces_failed_job_and_increments_stats(self) -> None:
        """Arrange: worker_func that always raises ValueError.

        process_items catches the exception, marks the job FAILED.
        Branch: job.status == JobStatus.FAILED → elif taken (line 106->102 = True path).
        """

        def _always_fail(item: Any, params: dict[str, Any]) -> None:
            raise ValueError(f"intentional failure on {item}")

        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = process_batch(analyzer, ["item_a", "item_b"], _always_fail)

        assert len(jobs) == 2
        assert all(j.status == JobStatus.FAILED for j in jobs)
        assert analyzer._stats["jobs_submitted"] == 2
        assert analyzer._stats["jobs_failed"] == 2
        assert analyzer._stats["jobs_completed"] == 0

    def test_successful_worker_produces_completed_job_and_increments_stats(self) -> None:
        """A worker that succeeds produces COMPLETED jobs and increments jobs_completed."""

        def _succeed(item: Any, params: dict[str, Any]) -> str:
            return f"processed:{item}"

        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = process_batch(analyzer, ["x", "y"], _succeed)

        assert all(j.status == JobStatus.COMPLETED for j in jobs)
        assert analyzer._stats["jobs_completed"] == 2
        assert analyzer._stats["jobs_failed"] == 0

    def test_mixed_worker_results_increment_both_counters(self) -> None:
        """Some items succeed, others fail; both counters are incremented correctly."""

        def _conditional_fail(item: Any, params: dict[str, Any]) -> str:
            if item == "bad":
                raise RuntimeError("bad item")
            return str(item)

        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = process_batch(analyzer, ["good", "bad", "good2"], _conditional_fail)

        completed = sum(1 for j in jobs if j.status == JobStatus.COMPLETED)
        failed = sum(1 for j in jobs if j.status == JobStatus.FAILED)
        assert completed == 2
        assert failed == 1
        assert analyzer._stats["jobs_completed"] == 2
        assert analyzer._stats["jobs_failed"] == 1

    def test_stats_accumulate_across_successive_process_batch_calls(self) -> None:
        """Stats persist across multiple calls to process_batch on the same analyzer."""

        def _good(item: Any, params: dict[str, Any]) -> str:
            return "ok"

        def _bad(item: Any, params: dict[str, Any]) -> None:
            raise ValueError("bad")

        analyzer = ParallelAnalyzer(max_workers=1)

        process_batch(analyzer, ["a", "b"], _good)
        process_batch(analyzer, ["c"], _bad)

        assert analyzer._stats["jobs_submitted"] == 3
        assert analyzer._stats["jobs_completed"] == 2
        assert analyzer._stats["jobs_failed"] == 1
