# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in batch_processor_ops.

Missing-line audit (baseline 80 %):
  65              -- _rule_summary_key duplicate-name branch
  135-140         -- _process_large_html_tree body
  151-152         -- _process_large_validate not-split + is_valid=False
  155-163         -- _process_large_validate split_rules=True loop
  172-184         -- _process_dependency_graph body
  205             -- require_output_dir_path PathLike returning bytes from fspath
  240             -- process_files_single COMPLEXITY (no previous success path)
  251             -- process_files_single DEPENDENCY_GRAPH
  287             -- process_large_file output_dir=None raises TypeError
  304             -- process_large_file COMPLEXITY split_rules=True success-count line
  307-309         -- process_large_file HTML_TREE and DEPENDENCY_GRAPH operation branches
  312             -- process_large_file progress_callback invocation

"""

from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
from typing import Any

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.parser.source import parse_yara_source
from yaraast.performance.batch_processor import BatchOperation, BatchProcessor, BatchResult
from yaraast.performance.batch_processor_ops import (
    OUTPUT_DIR_TYPE_ERROR,
    _add_complexity_summaries,
    _process_dependency_graph,
    _process_large_html_tree,
    _process_large_validate,
    _rule_summary_key,
    process_files_single,
    process_large_file,
    require_output_dir_path,
)

# ---------------------------------------------------------------------------
# Shared YARA source fixtures
# ---------------------------------------------------------------------------

_SINGLE_RULE_SRC = "rule single_rule { condition: true }"
_TWO_RULE_SRC = "rule rule_a { condition: true }\nrule rule_b { condition: false }"


def _write_yara(path: Path, src: str) -> Path:
    path.write_text(src, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Line 65 - _rule_summary_key duplicate-name branch
# ---------------------------------------------------------------------------


def test_rule_summary_key_returns_numbered_suffix_when_name_appears_more_than_once() -> None:
    """_rule_summary_key must append #N when the same rule name occurs multiple times.

    Arrange: Counter showing 'alpha' appears twice.
    Act: call _rule_summary_key for both occurrences.
    Assert: first call returns 'alpha#1', second returns 'alpha#2'.
    """
    counts: Counter[str] = Counter({"alpha": 2})

    first_key = _rule_summary_key("alpha", 1, counts)
    second_key = _rule_summary_key("alpha", 2, counts)

    assert first_key == "alpha#1"
    assert second_key == "alpha#2"


def test_add_complexity_summaries_disambiguates_duplicate_rule_objects() -> None:
    """_add_complexity_summaries must produce #N keys when the same Rule appears twice.

    The parser rejects YARA files with duplicate names, but the ops helper accepts
    any list[Rule].  This test exercises that path by reusing the same parsed Rule
    object twice, which reproduces the duplicate-key scenario without fabrication.

    Arrange: parse a single-rule file; place the Rule object in the list twice.
    Act: call _add_complexity_summaries.
    Assert: summary contains both 'single_rule#1' and 'single_rule#2'.
    """
    parsed = parse_yara_source(_SINGLE_RULE_SRC)
    rule = parsed.rules[0]

    summary: dict[str, Any] = {}
    _add_complexity_summaries(summary, [rule, rule])

    assert "single_rule#1" in summary
    assert "single_rule#2" in summary
    assert "single_rule" not in summary


# ---------------------------------------------------------------------------
# Lines 135-140 - _process_large_html_tree body
# ---------------------------------------------------------------------------


def test_process_large_html_tree_writes_html_for_single_combined_ast(tmp_path: Path) -> None:
    """_process_large_html_tree must write one HTML file when split_rules=False.

    Arrange: parse two rules; create a BatchResult and an output directory.
    Act: call _process_large_html_tree with split_rules=False.
    Assert: one output file exists, successful_count is 1, file ends with .html.
    """
    file_path = _write_yara(tmp_path / "multi.yar", _TWO_RULE_SRC)
    parsed = parse_yara_source(_TWO_RULE_SRC)
    out_dir = tmp_path / "html_out"
    out_dir.mkdir()
    result = BatchResult(operation=BatchOperation.HTML_TREE, input_count=1)

    _process_large_html_tree(file_path, parsed, out_dir, split_rules=False, result=result)

    assert result.successful_count == 1
    assert len(result.output_files) == 1
    assert result.output_files[0].endswith(".html")
    assert Path(result.output_files[0]).exists()


def test_process_large_html_tree_writes_one_html_file_per_rule_when_split(tmp_path: Path) -> None:
    """_process_large_html_tree must produce one HTML file per rule when split_rules=True.

    Arrange: parse two rules; create a BatchResult and an output directory.
    Act: call _process_large_html_tree with split_rules=True.
    Assert: two output files exist, successful_count is 2.
    """
    file_path = _write_yara(tmp_path / "split.yar", _TWO_RULE_SRC)
    parsed = parse_yara_source(_TWO_RULE_SRC)
    out_dir = tmp_path / "html_split"
    out_dir.mkdir()
    result = BatchResult(operation=BatchOperation.HTML_TREE, input_count=2)

    _process_large_html_tree(file_path, parsed, out_dir, split_rules=True, result=result)

    assert result.successful_count == 2
    assert len(result.output_files) == 2
    assert all(f.endswith(".html") for f in result.output_files)
    assert all(Path(f).exists() for f in result.output_files)


# ---------------------------------------------------------------------------
# Lines 151-152 - _process_large_validate not-split + is_valid=False
# ---------------------------------------------------------------------------


def test_process_large_validate_not_split_records_failure_for_invalid_rule() -> None:
    """_process_large_validate must record a failure when a rule has an empty name.

    validate_item returns False when bool(rule.name) is False.  A Rule with name=''
    is a legitimate construction (Rule is a dataclass) even though the parser never
    produces one; the helper must handle it correctly.

    Arrange: YaraFile containing one Rule with name=''; split_rules=False.
    Act: call _process_large_validate.
    Assert: failed_count=1, errors=['Validation failed'], successful_count=0.
    """
    invalid_rule = Rule(name="")
    parsed = YaraFile(imports=[], includes=[], rules=[invalid_rule])
    result = BatchResult(operation=BatchOperation.VALIDATE, input_count=1)

    _process_large_validate(parsed, split_rules=False, result=result)

    assert result.failed_count == 1
    assert result.successful_count == 0
    assert result.errors == ["Validation failed"]
    assert result.summary["valid"] is False
    assert result.summary["rule_count"] == 1


def test_process_large_validate_not_split_records_success_for_valid_rules() -> None:
    """_process_large_validate must record success when all rules pass validation.

    Arrange: YaraFile with two parser-produced rules; split_rules=False.
    Act: call _process_large_validate.
    Assert: successful_count=1, failed_count=0, summary['valid']=True.
    """
    parsed = parse_yara_source(_TWO_RULE_SRC)
    result = BatchResult(operation=BatchOperation.VALIDATE, input_count=1)

    _process_large_validate(parsed, split_rules=False, result=result)

    assert result.successful_count == 1
    assert result.failed_count == 0
    assert result.summary["valid"] is True
    assert result.summary["rule_count"] == 2


# ---------------------------------------------------------------------------
# Lines 155-163 - _process_large_validate split_rules=True loop
# ---------------------------------------------------------------------------


def test_process_large_validate_split_counts_each_rule_independently() -> None:
    """_process_large_validate must evaluate each rule separately when split_rules=True.

    Arrange: YaraFile with one valid (parser-produced) rule and one invalid rule
             (name='').  split_rules=True.
    Act: call _process_large_validate.
    Assert: successful_count=1, failed_count=1, one error, two summary entries.
    """
    valid_parsed = parse_yara_source(_SINGLE_RULE_SRC)
    valid_rule = valid_parsed.rules[0]
    invalid_rule = Rule(name="")

    parsed = YaraFile(imports=[], includes=[], rules=[valid_rule, invalid_rule])
    result = BatchResult(operation=BatchOperation.VALIDATE, input_count=2)

    _process_large_validate(parsed, split_rules=True, result=result)

    assert result.successful_count == 1
    assert result.failed_count == 1
    assert len(result.errors) == 1
    assert "Validation failed for rule" in result.errors[0]
    # valid rule is keyed by its name; invalid rule falls back to "rule_2"
    assert result.summary["single_rule"] is True
    assert result.summary["rule_2"] is False


def test_process_large_validate_split_all_valid_increments_each_rule() -> None:
    """_process_large_validate split must succeed for every rule in a clean file.

    Arrange: parse a two-rule file; split_rules=True.
    Act: call _process_large_validate.
    Assert: successful_count=2, failed_count=0, all summary entries are True.
    """
    parsed = parse_yara_source(_TWO_RULE_SRC)
    result = BatchResult(operation=BatchOperation.VALIDATE, input_count=2)

    _process_large_validate(parsed, split_rules=True, result=result)

    assert result.successful_count == 2
    assert result.failed_count == 0
    assert result.errors == []
    assert all(result.summary[k] is True for k in result.summary)


# ---------------------------------------------------------------------------
# Lines 172-184 - _process_dependency_graph body
# ---------------------------------------------------------------------------


def test_process_dependency_graph_writes_json_and_dot_files(tmp_path: Path) -> None:
    """_process_dependency_graph must create both JSON and DOT dependency exports.

    Arrange: parse a single-rule file; prepare output directory and BatchResult.
    Act: call _process_dependency_graph.
    Assert: two output files written (one .json, one .dot); summary populated.
    """
    file_path = _write_yara(tmp_path / "dep.yar", _SINGLE_RULE_SRC)
    parsed = parse_yara_source(_SINGLE_RULE_SRC)
    out_dir = tmp_path / "dep_out"
    out_dir.mkdir()
    result = BatchResult(operation=BatchOperation.DEPENDENCY_GRAPH, input_count=1)

    _process_dependency_graph(file_path, parsed, out_dir, result)

    assert len(result.output_files) == 2
    json_files = [f for f in result.output_files if f.endswith(".json")]
    dot_files = [f for f in result.output_files if f.endswith(".dot")]
    assert len(json_files) == 1
    assert len(dot_files) == 1
    assert Path(json_files[0]).exists()
    assert Path(dot_files[0]).exists()
    assert file_path.name in result.summary


# ---------------------------------------------------------------------------
# Line 205 - require_output_dir_path PathLike returning bytes from __fspath__
# ---------------------------------------------------------------------------


class _BytesFspathLike(os.PathLike):  # type: ignore[type-arg]
    """PathLike whose __fspath__ returns bytes instead of str."""

    def __fspath__(self) -> bytes:
        return b"/tmp/bytes_path"


def test_require_output_dir_path_rejects_pathlike_with_bytes_fspath() -> None:
    """require_output_dir_path must raise TypeError when fspath() returns bytes.

    os.fspath() can return either str or bytes depending on the PathLike
    implementation.  The function must reject the bytes case explicitly.

    Arrange: a PathLike whose __fspath__ returns bytes.
    Act: call require_output_dir_path with that object.
    Assert: TypeError raised with the expected message.
    """
    bad_pathlike = _BytesFspathLike()

    with pytest.raises(TypeError, match=OUTPUT_DIR_TYPE_ERROR):
        require_output_dir_path(bad_pathlike)


def test_require_output_dir_path_rejects_null_byte_string() -> None:
    with pytest.raises(ValueError, match="output_dir must not contain null bytes"):
        require_output_dir_path("\x00broken")


def test_require_output_dir_path_rejects_symlink_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="output_dir must not traverse a symlink"):
        require_output_dir_path(str(link))


def test_require_output_dir_path_rejects_symlink_ancestors(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="output_dir must not traverse a symlink"):
        require_output_dir_path(str(link / "child"))


def test_batch_processor_rejects_symlink_temp_dir(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="temp_dir must not traverse a symlink"):
        BatchProcessor(temp_dir=link)


def test_batch_processor_rejects_symlink_ancestor_temp_dir(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    nested = link / "nested"
    nested.mkdir()

    with pytest.raises(ValueError, match="temp_dir must not traverse a symlink"):
        BatchProcessor(temp_dir=nested)


# ---------------------------------------------------------------------------
# Line 240 - process_files_single COMPLEXITY with a successfully-parsed file
# ---------------------------------------------------------------------------


def test_process_files_single_complexity_populates_summary_for_valid_file(tmp_path: Path) -> None:
    """process_files_single with COMPLEXITY must populate summary for a parseable file.

    The existing test suite only calls process_files([...], COMPLEXITY) with a
    file containing duplicate rule names, which fails to parse.  This test uses
    a clean file so the _add_complexity_summaries branch (line 240) executes.

    Arrange: write a single-rule YARA file; no output_dir needed for COMPLEXITY.
    Act: call process_files_single with BatchOperation.COMPLEXITY.
    Assert: successful_count=1, summary contains the rule name as a key.
    """
    file_path = _write_yara(tmp_path / "comp.yar", _SINGLE_RULE_SRC)
    processor = BatchProcessor()

    result = process_files_single(processor, [file_path], BatchOperation.COMPLEXITY)

    assert result.successful_count == 1
    assert result.failed_count == 0
    assert "single_rule" in result.summary
    assert isinstance(result.summary["single_rule"], dict)


# ---------------------------------------------------------------------------
# Line 251 - process_files_single DEPENDENCY_GRAPH
# ---------------------------------------------------------------------------


def test_process_files_single_dependency_graph_writes_both_output_files(tmp_path: Path) -> None:
    """process_files_single with DEPENDENCY_GRAPH must call _process_dependency_graph.

    Arrange: write a single-rule YARA file; provide an output directory.
    Act: call process_files_single with BatchOperation.DEPENDENCY_GRAPH.
    Assert: two output files created, successful_count=1, no errors.
    """
    file_path = _write_yara(tmp_path / "dep_single.yar", _SINGLE_RULE_SRC)
    out_dir = tmp_path / "dep_single_out"
    processor = BatchProcessor()

    result = process_files_single(
        processor, [file_path], BatchOperation.DEPENDENCY_GRAPH, output_dir=out_dir
    )

    assert result.successful_count == 1
    assert result.failed_count == 0
    assert len(result.output_files) == 2
    assert any(f.endswith("_dependencies.json") for f in result.output_files)
    assert any(f.endswith("_dependencies.dot") for f in result.output_files)


# ---------------------------------------------------------------------------
# Line 287 - process_large_file output_dir=None raises TypeError
# ---------------------------------------------------------------------------


def test_process_large_file_raises_type_error_when_output_dir_is_none(tmp_path: Path) -> None:
    """process_large_file must raise TypeError immediately when output_dir is None.

    require_output_dir_path(None) returns None, and the subsequent guard raises
    TypeError before any file I/O or parsing happens.

    Arrange: a BatchProcessor; output_dir=None passed explicitly.
    Act: call process_large_file.
    Assert: TypeError raised with the expected message.
    """
    file_path = tmp_path / "irrelevant.yar"
    processor = BatchProcessor()

    with pytest.raises(TypeError, match=OUTPUT_DIR_TYPE_ERROR):
        process_large_file(
            processor,
            file_path,
            operations=[BatchOperation.PARSE],
            output_dir=None,  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Line 300 - process_large_file COMPLEXITY split_rules=True success-count
# ---------------------------------------------------------------------------


def test_process_large_file_complexity_split_sets_successful_count_to_rule_count(
    tmp_path: Path,
) -> None:
    """process_large_file with COMPLEXITY and split_rules=True must set successful_count.

    Line 300: result.successful_count = len(parsed.rules) if split_rules else 1

    Arrange: write a two-rule file; use split_rules=True.
    Act: call process_large_file with BatchOperation.COMPLEXITY.
    Assert: successful_count equals the number of rules in the file.
    """
    file_path = _write_yara(tmp_path / "complexity_split.yar", _TWO_RULE_SRC)
    out_dir = tmp_path / "cplx_out"
    processor = BatchProcessor()

    results = process_large_file(
        processor,
        file_path,
        operations=[BatchOperation.COMPLEXITY],
        output_dir=out_dir,
        split_rules=True,
    )

    result = results[BatchOperation.COMPLEXITY]
    assert result.successful_count == 2
    assert "rule_a" in result.summary
    assert "rule_b" in result.summary


# ---------------------------------------------------------------------------
# Lines 303-304 - process_large_file HTML_TREE operation branch
# ---------------------------------------------------------------------------


def test_process_large_file_html_tree_writes_output_file(tmp_path: Path) -> None:
    """process_large_file with HTML_TREE must delegate to _process_large_html_tree.

    Arrange: write a single-rule file; provide an output directory.
    Act: call process_large_file with BatchOperation.HTML_TREE.
    Assert: result contains at least one .html output file; successful_count >= 1.
    """
    file_path = _write_yara(tmp_path / "html_large.yar", _SINGLE_RULE_SRC)
    out_dir = tmp_path / "html_large_out"
    processor = BatchProcessor()

    results = process_large_file(
        processor,
        file_path,
        operations=[BatchOperation.HTML_TREE],
        output_dir=out_dir,
    )

    result = results[BatchOperation.HTML_TREE]
    assert result.successful_count >= 1
    assert any(f.endswith(".html") for f in result.output_files)
    assert Path(result.output_files[0]).exists()


def test_process_large_file_html_tree_split_produces_per_rule_files(tmp_path: Path) -> None:
    """process_large_file HTML_TREE with split_rules=True must write one file per rule.

    Arrange: write a two-rule file; split_rules=True.
    Act: call process_large_file with BatchOperation.HTML_TREE.
    Assert: two .html files written; successful_count=2.
    """
    file_path = _write_yara(tmp_path / "html_split.yar", _TWO_RULE_SRC)
    out_dir = tmp_path / "html_split_out"
    processor = BatchProcessor()

    results = process_large_file(
        processor,
        file_path,
        operations=[BatchOperation.HTML_TREE],
        output_dir=out_dir,
        split_rules=True,
    )

    result = results[BatchOperation.HTML_TREE]
    assert result.successful_count == 2
    assert len(result.output_files) == 2
    assert all(f.endswith(".html") for f in result.output_files)


# ---------------------------------------------------------------------------
# Lines 307-309 - process_large_file DEPENDENCY_GRAPH branch
# ---------------------------------------------------------------------------


def test_process_large_file_dependency_graph_writes_json_and_dot_and_sets_success(
    tmp_path: Path,
) -> None:
    """process_large_file with DEPENDENCY_GRAPH must call _process_dependency_graph.

    This branch (lines 307-309) is distinct from process_files_single's DEPENDENCY_GRAPH
    path.  It is reached only through process_large_file.

    Arrange: write a single-rule YARA file; provide an output directory.
    Act: call process_large_file with BatchOperation.DEPENDENCY_GRAPH.
    Assert: two output files created (.json + .dot); successful_count=1.
    """
    file_path = _write_yara(tmp_path / "dep_large.yar", _SINGLE_RULE_SRC)
    out_dir = tmp_path / "dep_large_out"
    processor = BatchProcessor()

    results = process_large_file(
        processor,
        file_path,
        operations=[BatchOperation.DEPENDENCY_GRAPH],
        output_dir=out_dir,
    )

    result = results[BatchOperation.DEPENDENCY_GRAPH]
    assert result.successful_count == 1
    assert result.failed_count == 0
    assert any(f.endswith("_dependencies.json") for f in result.output_files)
    assert any(f.endswith("_dependencies.dot") for f in result.output_files)


# ---------------------------------------------------------------------------
# Line 312 - process_large_file progress_callback invocation
# ---------------------------------------------------------------------------


def test_process_large_file_invokes_progress_callback_for_each_operation(tmp_path: Path) -> None:
    """process_large_file must call the progress_callback once per operation.

    Arrange: register a progress callback; process two operations in one call.
    Act: call process_large_file with PARSE and COMPLEXITY.
    Assert: callback invoked twice; call arguments match operation labels and counts.
    """
    file_path = _write_yara(tmp_path / "progress.yar", _SINGLE_RULE_SRC)
    out_dir = tmp_path / "progress_out"

    calls: list[tuple[str, int, int]] = []

    def record_progress(stage: str, done: int, total: int) -> None:
        calls.append((stage, done, total))

    processor = BatchProcessor(progress_callback=record_progress)

    results = process_large_file(
        processor,
        file_path,
        operations=[BatchOperation.PARSE, BatchOperation.COMPLEXITY],
        output_dir=out_dir,
    )

    assert len(calls) == 2
    assert calls[0] == ("Processing parse", 1, 2)
    assert calls[1] == ("Processing complexity", 2, 2)
    assert results[BatchOperation.PARSE].successful_count == 1
    assert results[BatchOperation.COMPLEXITY].successful_count == 1
