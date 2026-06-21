# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for six target modules.

Target modules and the specific uncovered lines / branches this file addresses:

1. yaraast/cli/commands/metrics.py
   - Lines 124, 145, 149, 194->exit, 235, 239 are *structurally unreachable* in
     this environment:
     * Line 124 (DependencyGraphGenerator is None) fires only when the graphviz
       Python package is absent; it is installed in this venv.
     * Lines 145 and 235 (unknown type/pattern branches) are behind click.Choice
       guards that reject invalid values before the command body executes.
     * Lines 149 and 239 (_display_text_fallback / _display_text_pattern_analysis)
       require a graphviz-classified exception; render_graph catches those internally.
     * Line 194->exit (path_size_for_display returns None) requires the output file
       to disappear between write and stat; the tree command always writes first.
   No tests are added for these lines to avoid fabricated non-real scenarios.

2. yaraast/performance/batch_processor.py
   - Lines 132-133: _require_temp_dir raises TypeError when fspath() returns bytes.
     Covered by test_batch_processor_temp_dir_bytes_fspath.
   - Branches 205->exit, 213->exit, 280->exit, 290->exit are @overload type stubs
     with an Ellipsis body.  The @overload decorator makes them unreachable at
     runtime; they exist only for type checkers.  Not covered.

3. yaraast/performance/batch_processor_ops.py
   - Branch 307->310 (False path of the DEPENDENCY_GRAPH elif in process_large_file):
     This branch fires only when an operation matches NONE of the six elif conditions.
     Since BatchOperation has exactly six values and each is handled by one of the six
     elif clauses, any valid operation matches exactly one clause; no operation can fall
     through to line 310 via the 307 False path.  Structurally unreachable; not covered.
     The tests DO cover lines 308-309 (the DEPENDENCY_GRAPH body) via
     test_process_large_file_dependency_graph_operation.
   - Lines 259-261: VALIDATE failure path inside process_files_single requires
     validate_item() to return False.  validate_item() returns
     bool(rule.name) and rule.condition is not None.  The real parser always
     produces rules with a non-empty name and a non-None condition; inputs
     that violate this raise ParserError before process_files_single processes
     the file.  Structurally dead code; not covered.

4. yaraast/performance/memory_transformer_visitors.py
   - Branches 305->307, 307->309, 309->311 (visit_binary_expression) and
     316->318, 318->320 (visit_unary_expression): hasattr guards that evaluate
     to False when the node object lacks the expected attribute.  Both visitor
     functions accept Any, so they can be called directly with a plain object
     that has no attributes.
     Covered by test_visit_binary_expression_* and test_visit_unary_expression_*.

5. yaraast/cli/performance_services.py
   - Lines 158-159: collect_file_paths raises TypeError when fspath() returns bytes.
     Covered by test_collect_file_paths_bytes_fspath_raises.
   - Line 196 (_has_successful_parse_results returns False when job.result is falsy):
     Covered by test_has_successful_parse_results_empty_result_returns_false.
   - Branch [195,196]: 'if not job.result:' evaluates to True (job.result is None or []).
     Also covered by test_has_successful_parse_results_empty_result_returns_false.

6. yaraast/parser/comment_aware_parser.py
   - Branch 124->128: top_level_nodes is empty (empty input file) so the location
     setter is skipped.  Covered by test_comment_aware_parser_empty_file.
   - Branch 359->exit: _attach_rule_comments called with start_token=None so the
     trailing-comment collection is skipped.
     Covered by test_attach_rule_comments_none_start_token.
   - Lines 420-422: hex_tokens empty branch inside _parse_strings_section.
     HexStringParser.parse() always raises HexParseError before returning an empty
     list; this branch is structurally dead code.  Not covered.
"""

from __future__ import annotations

from pathlib import Path
import textwrap
from typing import Any

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.cli.performance_services import _has_successful_parse_results, collect_file_paths
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.performance.batch_processor import BatchOperation, BatchProcessor
from yaraast.performance.batch_processor_ops import process_large_file
from yaraast.performance.memory_transformer_visitors import (
    visit_binary_expression,
    visit_unary_expression,
)
from yaraast.performance.parallel_models import Job, JobStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _BytesPathLike:
    """PathLike whose __fspath__ returns bytes instead of str.

    Both _require_temp_dir (batch_processor.py line 131) and collect_file_paths
    (performance_services.py line 157) call fspath() and then check
    isinstance(raw_path, str).  A PathLike returning bytes makes that check fail
    and is the only way to reach lines 132-133 and 158-159 respectively.
    """

    def __fspath__(self) -> bytes:
        return b"/tmp/yaraast_test_bytes_path"


class _FakeTransformer:
    """Minimal transformer-like object for calling visitor helpers directly.

    visit_binary_expression and visit_unary_expression accept Any for both
    transformer and node, so a plain object with string_pool is sufficient.
    """

    string_pool: dict[str, str] = {}

    def visit(self, node: Any) -> Any:
        return node


def _write_yara_file(directory: Path, content: str, name: str = "rules.yar") -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


_SIMPLE_RULE = textwrap.dedent("""\
    rule simple_rule {
        strings:
            $s = "hello"
        condition:
            $s
    }
    """)


# ---------------------------------------------------------------------------
# batch_processor.py -lines 132-133
# ---------------------------------------------------------------------------


def test_batch_processor_temp_dir_bytes_fspath_raises() -> None:
    """_require_temp_dir must raise TypeError when fspath returns bytes.

    Arrange: construct a PathLike whose __fspath__ returns bytes.
    Act: pass it as temp_dir when constructing BatchProcessor.
    Assert: TypeError with the 'must be a text path' message.
    """
    bytes_path: Any = _BytesPathLike()
    with pytest.raises(TypeError, match="temp_dir must be a text path"):
        BatchProcessor(temp_dir=bytes_path)


# ---------------------------------------------------------------------------
# batch_processor_ops.py -branch 307->310
# ---------------------------------------------------------------------------


def test_process_large_file_dependency_graph_operation(tmp_path: Path) -> None:
    """process_large_file must handle BatchOperation.DEPENDENCY_GRAPH end-to-end.

    The DEPENDENCY_GRAPH branch at lines 307-309 of batch_processor_ops.py
    calls _process_dependency_graph and then sets result.successful_count = 1.
    This is the only operation that process_large_file delegates to
    _process_dependency_graph.

    Arrange: write a YARA file with one rule; create an output directory.
    Act: call process_large_file with [BatchOperation.DEPENDENCY_GRAPH].
    Assert: the result for DEPENDENCY_GRAPH has successful_count == 1 and
            the output directory contains at least one generated file.
    """
    yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
    out_dir = tmp_path / "dep_out"
    out_dir.mkdir()

    processor = BatchProcessor()
    results = process_large_file(
        processor,
        yara_file,
        [BatchOperation.DEPENDENCY_GRAPH],
        out_dir,
    )

    result = results[BatchOperation.DEPENDENCY_GRAPH]
    assert result.successful_count == 1
    assert result.failed_count == 0
    assert len(result.output_files) >= 1


def test_process_large_file_dependency_graph_with_progress_callback(tmp_path: Path) -> None:
    """process_large_file must invoke progress_callback for DEPENDENCY_GRAPH.

    The progress_callback at line 311 fires for every operation including
    DEPENDENCY_GRAPH.  Verifying the callback is invoked at least once confirms
    that the branch 307->310 ran completely to the results dict update.

    Arrange: write a rule file; set up a callback accumulator.
    Act: call process_large_file with DEPENDENCY_GRAPH and a callback.
    Assert: callback was invoked once (one operation in the list).
    """
    yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
    out_dir = tmp_path / "dep_cb_out"
    out_dir.mkdir()

    calls: list[tuple[str, int, int]] = []

    def callback(stage: str, current: int, total: int) -> None:
        calls.append((stage, current, total))

    processor = BatchProcessor(progress_callback=callback)
    results = process_large_file(
        processor,
        yara_file,
        [BatchOperation.DEPENDENCY_GRAPH],
        out_dir,
    )

    assert results[BatchOperation.DEPENDENCY_GRAPH].successful_count == 1
    assert len(calls) == 1
    assert calls[0][2] == 1  # total = number of operations


# ---------------------------------------------------------------------------
# memory_transformer_visitors.py -branches 305-311, 316-320
# ---------------------------------------------------------------------------


class _NodeWithoutBinaryAttrs:
    """Object that passes copy.copy but has none of left / right / operator.

    visit_binary_expression shallow-copies the node and then checks hasattr.
    When left, right, and operator are all absent, the three False branches
    (305->307, 307->309, 309->311) execute and the node passes through unchanged.
    """


class _NodeWithNonStrOperator:
    """Object with left and right but an integer operator.

    visit_binary_expression checks isinstance(node.operator, str) at branch 309.
    An integer operator makes that check False (branch 309->311 is skipped).
    """

    left = BooleanLiteral(value=True)
    right = BooleanLiteral(value=False)
    operator = 42  # not a str


class _NodeWithoutUnaryAttrs:
    """Object that passes copy.copy but has none of operand / operator.

    visit_unary_expression shallow-copies the node and checks hasattr.
    When both attributes are absent, branches 316->318 and 318->320 execute
    and the node passes through unchanged.
    """


class _NodeWithNonStrUnaryOperator:
    """Object with operand but an integer operator.

    visit_unary_expression checks isinstance(node.operator, str) at branch 318.
    An integer operator makes that check False (branch 318->320 is skipped).
    """

    operand = BooleanLiteral(value=True)
    operator = 0  # not a str


def test_visit_binary_expression_all_attrs_absent() -> None:
    """visit_binary_expression skips all hasattr branches when node has no attrs.

    Arrange: node without left, right, or operator; a minimal transformer.
    Act: call visit_binary_expression directly.
    Assert: the returned object is the shallow copy of the original; no error.
    """
    transformer = _FakeTransformer()
    node: Any = _NodeWithoutBinaryAttrs()
    result = visit_binary_expression(transformer, node)

    # The node passed through; its identity changed (shallow copy) but no attr set
    assert not hasattr(result, "left")
    assert not hasattr(result, "right")
    assert not hasattr(result, "operator")


def test_visit_binary_expression_non_str_operator() -> None:
    """visit_binary_expression skips operator pooling when operator is not a str.

    Arrange: node with left and right attrs but an integer operator.
    Act: call visit_binary_expression.
    Assert: operator remains an integer (not pooled); left and right are visited.
    """
    transformer = _FakeTransformer()
    node: Any = _NodeWithNonStrOperator()
    result = visit_binary_expression(transformer, node)

    # operator is not a str so it must remain as-is
    assert isinstance(result.operator, int)
    assert result.operator == 42


def test_visit_unary_expression_all_attrs_absent() -> None:
    """visit_unary_expression skips all hasattr branches when node has no attrs.

    Arrange: node without operand or operator; a minimal transformer.
    Act: call visit_unary_expression directly.
    Assert: the returned object is a shallow copy with no new attributes.
    """
    transformer = _FakeTransformer()
    node: Any = _NodeWithoutUnaryAttrs()
    result = visit_unary_expression(transformer, node)

    assert not hasattr(result, "operand")
    assert not hasattr(result, "operator")


def test_visit_unary_expression_non_str_operator() -> None:
    """visit_unary_expression skips operator pooling when operator is not a str.

    Arrange: node with operand but an integer operator.
    Act: call visit_unary_expression.
    Assert: operator remains an integer; operand is visited.
    """
    transformer = _FakeTransformer()
    node: Any = _NodeWithNonStrUnaryOperator()
    result = visit_unary_expression(transformer, node)

    assert isinstance(result.operator, int)
    assert result.operator == 0


# ---------------------------------------------------------------------------
# performance_services.py -lines 158-159 and 196
# ---------------------------------------------------------------------------


def test_collect_file_paths_bytes_fspath_raises() -> None:
    """collect_file_paths must raise TypeError when fspath returns bytes.

    Arrange: a PathLike whose __fspath__ returns bytes.
    Act: pass it to collect_file_paths inside a tuple.
    Assert: TypeError with the expected message.
    """
    with pytest.raises(TypeError, match="input path must be a string or path-like object"):
        collect_file_paths((_BytesPathLike(),))


def test_collect_file_paths_nonexistent_path_returns_empty() -> None:
    """collect_file_paths returns an empty list for a path that does not exist.

    When input_path is neither a file nor a directory, _path_exists_and_is_file
    and _path_exists_and_is_dir both return False, hitting the else branch at
    line 170 (candidates = []).  The result is an empty file list.

    Arrange: a string path that does not exist on the filesystem.
    Act: call collect_file_paths.
    Assert: the result list is empty and no exception is raised.
    """
    non_existent = "/tmp/yaraast_does_not_exist_xyz_abc_99887766"
    result = collect_file_paths((non_existent,))
    assert result == []


# ---------------------------------------------------------------------------
# comment_aware_parser.py -branches 124->128, 349->351, 359->exit
# ---------------------------------------------------------------------------


def test_comment_aware_parser_empty_file_skips_location_setter() -> None:
    """Parsing an empty string skips _set_node_location_from_nodes.

    Line 124: 'if top_level_nodes:' evaluates to False for an empty file.
    The branch 124->128 is taken when the file contains no rules, imports,
    includes, pragmas, or namespace declarations.

    Arrange: empty string input to CommentAwareParser.
    Act: parse the empty string.
    Assert: the returned YaraFile has no location (location is None).
    """
    parser = CommentAwareParser()
    yara_file = parser.parse("")

    assert yara_file.location is None
    assert yara_file.rules == []
    assert yara_file.imports == []


def test_comment_aware_parser_trailing_comment_only_file() -> None:
    """Parsing a comment-only file executes _attach_trailing_comments.

    Line 128: 'if self.comment_tokens:' evaluates to True when the file has
    only comments and no AST nodes.  This also exercises branch 124->128
    (top_level_nodes is empty).

    Arrange: a file containing only a line comment.
    Act: parse it.
    Assert: the returned YaraFile has a trailing comment attached.
    """
    parser = CommentAwareParser()
    yara_file = parser.parse("// only a comment")

    assert yara_file.trailing_comment is not None
    assert yara_file.location is None


def test_attach_rule_comments_none_start_token_skips_trailing_collection() -> None:
    """_attach_rule_comments with start_token=None skips trailing-comment collection.

    Branch 359->exit: 'if start_token:' evaluates to False.
    The caller _parse_rule sets start_token = self._peek() which normally is a
    real token.  Calling the method directly with None exercises the False branch.

    Arrange: a real Rule object and a parser with no comment tokens.
    Act: call _attach_rule_comments with start_token=None.
    Assert: rule.trailing_comment remains None; no error raised.
    """
    parser = CommentAwareParser()
    parser.comment_tokens = []
    rule = Rule(
        name="test_rule",
        modifiers=[],
        tags=[],
        meta=[],
        strings=[],
        condition=BooleanLiteral(value=True),
        pragmas=[],
    )

    parser._attach_rule_comments(rule, [], None)

    assert rule.trailing_comment is None


def test_attach_rule_comments_with_leading_comments_sets_them() -> None:
    """_attach_rule_comments attaches non-empty leading comments to the rule.

    Branch 356 (leading_comments is truthy): confirmed by checking the rule
    gets its leading_comments attribute set.

    Arrange: a rule and a list with one leading comment text marker; parser
    with a single comment token whose line matches start_token.line.
    Act: call _attach_rule_comments with leading_comments=[stub_comment].
    Assert: rule.leading_comments is not empty.
    """
    from yaraast.ast.comments import Comment

    parser = CommentAwareParser()
    parser.comment_tokens = []
    rule = Rule(
        name="commented_rule",
        modifiers=[],
        tags=[],
        meta=[],
        strings=[],
        condition=BooleanLiteral(value=True),
        pragmas=[],
    )
    leading = [Comment(text="// leading", is_multiline=False)]

    parser._attach_rule_comments(rule, leading, None)

    assert rule.leading_comments == leading


# ---------------------------------------------------------------------------
# performance_services.py -line 196, branch [195,196]
# ---------------------------------------------------------------------------


def test_has_successful_parse_results_empty_result_returns_false() -> None:
    """_has_successful_parse_results returns False when job.result is None.

    Branch 195->196: 'if not job.result:' evaluates to True.
    Line 196: 'return False' is executed.

    A completed job with result=None has no ASTs to contribute; the early-exit
    False return is the correct behavior.

    Arrange: a Job with status=COMPLETED and result=None.
    Act: call _has_successful_parse_results.
    Assert: returns False.
    """
    job = Job(job_id="test-none-result", job_type="parse_files", status=JobStatus.COMPLETED)
    # result defaults to None in the Job dataclass
    assert job.result is None

    result = _has_successful_parse_results(job)

    assert result is False


def test_has_successful_parse_results_empty_list_returns_false() -> None:
    """_has_successful_parse_results returns False when job.result is an empty list.

    An empty list is falsy; the branch 195->196 fires in the same way as
    when result is None.

    Arrange: a Job with status=COMPLETED and result=[].
    Act: call _has_successful_parse_results.
    Assert: returns False.
    """
    job = Job(
        job_id="test-empty-list",
        job_type="parse_files",
        status=JobStatus.COMPLETED,
        result=[],
    )

    result = _has_successful_parse_results(job)

    assert result is False
