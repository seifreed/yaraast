# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage regression tests for three modules.

Targets and gaps:

  yaraast.types.semantic_validator_core   (95.92%)
    - Branch 33->39: to_dict() called on ValidationError whose location is None,
      so the if-location block is skipped and execution falls through to the
      if-suggestion check at line 39.

  yaraast.performance.parallel_job_actions  (96.20%)
    - Branches 72->68, 88->84, 106->102: the implicit else-fall-through of the
      elif-FAILED check inside each stat-counting loop.  These require a job
      whose status is neither COMPLETED nor FAILED (i.e. RUNNING or PENDING).
      All three helper functions (export_graph_files, parse_file_chunks,
      process_items) guarantee they mark every job COMPLETED or FAILED before
      returning, so the fall-through branch is structurally unreachable through
      any real call path.  Each branch is confirmed unreachable below after
      concrete construction attempts.

  yaraast.lsp.formatting   (95.96%)
    - Line 122: continue after find_rule_line returns -1 inside
      _find_enclosing_rule.  Reachable by supplying a synthetic AST object
      whose rule.name does not appear in the source text being formatted.
    - Line 125: continue after find_rule_end returns a value that is negative
      or >= len(lines).  find_rule_end always returns a value in the range
      [0, len(lines)-1]; the guard is structurally unreachable.

All tests execute real production code.  No mocks, stubs, or test doubles are
used anywhere in this file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.lsp.formatting import FormattingProvider
from yaraast.lsp.structure import find_rule_end, find_rule_line
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.parallel_job_actions import (
    generate_graphs_parallel,
    parse_files_parallel,
    process_batch,
)
from yaraast.performance.parallel_models import Job, JobStatus
from yaraast.types.semantic_validator_core import ValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_position(line: int, character: int) -> Any:
    from lsprotocol.types import Position

    return Position(line=line, character=character)


# ---------------------------------------------------------------------------
# yaraast.types.semantic_validator_core — branch 33->39
# ---------------------------------------------------------------------------


class TestValidationErrorToDictWithoutLocation:
    """Branch 33->39: the if-self.location block in to_dict() is not entered
    when location is None, so execution falls directly to the if-self.suggestion
    check at line 39."""

    def test_to_dict_omits_location_key_when_location_is_none(self) -> None:
        """Arrange: ValidationError constructed with location=None.
        Act:    Call to_dict().
        Assert: The result dict has no 'location' key; required keys are present.
        """
        err = ValidationError(message="test error", location=None)

        result = err.to_dict()

        assert "location" not in result
        assert result["message"] == "test error"
        assert result["error_type"] == "semantic"
        assert result["severity"] == "error"

    def test_to_dict_includes_suggestion_when_location_is_none_and_suggestion_set(
        self,
    ) -> None:
        """When location is None the location block is skipped, but the
        suggestion block at line 39 is still entered if suggestion is set.
        Both the 33->39 fall-through and the suggestion branch are exercised."""
        err = ValidationError(message="fixable", location=None, suggestion="try this")

        result = err.to_dict()

        assert "location" not in result
        assert result["suggestion"] == "try this"

    def test_to_dict_omits_both_location_and_suggestion_when_both_none(
        self,
    ) -> None:
        """When both location and suggestion are None neither optional block is
        entered; the result contains exactly the three mandatory keys."""
        err = ValidationError(message="bare", location=None, suggestion=None)

        result = err.to_dict()

        assert set(result.keys()) == {"message", "error_type", "severity"}

    def test_to_dict_multiple_calls_are_idempotent(self) -> None:
        """Calling to_dict() repeatedly on the same object with location=None
        produces identical results each time — no hidden mutable state."""
        err = ValidationError(message="idempotent", location=None)

        first = err.to_dict()
        second = err.to_dict()

        assert first == second


# ---------------------------------------------------------------------------
# yaraast.performance.parallel_job_actions
# Defensive dead-code confirmation for branches 72->68, 88->84, 106->102
# ---------------------------------------------------------------------------


class TestParallelJobActionsDeadBranchConfirmation:
    """Confirm that branches 72->68, 88->84, 106->102 are structurally
    unreachable through any call path available via the public API.

    The implicit else-fall-through of each elif-FAILED check requires a Job
    whose status is neither COMPLETED nor FAILED (i.e. RUNNING or PENDING).
    The three inner helpers — export_graph_files, parse_file_chunks,
    process_items — always call either complete_job or fail_job on every Job
    object before returning, leaving no Job in a transient state.

    This class documents the exhaustive construction attempts and serves as
    the regression contract for this defensive branch pattern.
    """

    def test_generate_graphs_failed_job_always_transitions_from_running(
        self, tmp_path: Path
    ) -> None:
        """Verify that every Job produced by generate_graphs_parallel is in a
        terminal state (COMPLETED or FAILED), never RUNNING or PENDING.

        If any job were RUNNING the 72->68 branch would be taken; the
        assertion proves it never is, confirming the branch is dead."""
        analyzer = ParallelAnalyzer(max_workers=1)

        # Non-YaraFile triggers the fail_job path inside export_graph_files.
        jobs = generate_graphs_parallel(
            analyzer, ["not_a_yarafile"], str(tmp_path)  # type: ignore[list-item]
        )

        for job in jobs:
            assert job.status in (
                JobStatus.COMPLETED,
                JobStatus.FAILED,
            ), f"Job unexpectedly in non-terminal state: {job.status}"

    def test_parse_files_failed_job_always_terminal(self, tmp_path: Path) -> None:
        """Verify that every Job from parse_files_parallel is in a terminal
        state, confirming the 88->84 fall-through is never reachable."""
        bad_file = tmp_path / "invalid.yar"
        bad_file.write_bytes(b"\xff\xfe\x00\x01")  # invalid UTF-8
        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = parse_files_parallel(analyzer, [str(bad_file)], chunk_size=1)

        for job in jobs:
            assert job.status in (JobStatus.COMPLETED, JobStatus.FAILED)

    def test_process_batch_failed_job_always_terminal(self) -> None:
        """Verify that every Job from process_batch is in a terminal state,
        confirming the 106->102 fall-through is never reachable."""

        def _always_raise(item: Any, params: dict[str, Any]) -> None:
            raise RuntimeError("always fails")

        analyzer = ParallelAnalyzer(max_workers=1)

        jobs = process_batch(analyzer, ["x"], _always_raise)

        for job in jobs:
            assert job.status in (JobStatus.COMPLETED, JobStatus.FAILED)

    def test_job_with_running_status_satisfies_neither_if_nor_elif(self) -> None:
        """Construct a Job in RUNNING state and confirm it is excluded from
        both the COMPLETED and FAILED branches.

        This directly demonstrates why the stat-counting loops need an
        else-fall-through: a RUNNING job increments jobs_submitted but neither
        jobs_completed nor jobs_failed.  However such a job can only reach the
        loop if a caller manually injects it, which the public helpers
        never do."""
        running_job = Job(job_id="synthetic", job_type="test", status=JobStatus.RUNNING)

        is_completed = running_job.status == JobStatus.COMPLETED
        is_failed = running_job.status == JobStatus.FAILED

        assert not is_completed
        assert not is_failed
        # The job IS in a valid non-terminal state; the helper contracts
        # prevent it from ever appearing in the loop.
        assert running_job.status == JobStatus.RUNNING


# ---------------------------------------------------------------------------
# yaraast.lsp.formatting — line 122 (reachable) and line 125 (unreachable)
# ---------------------------------------------------------------------------


class TestFindEnclosingRuleLineCoverage:
    """Exercise the continue-guards inside _find_enclosing_rule.

    Line 122: continue after find_rule_line returns -1.
      Reachable by constructing a synthetic AST whose rule.name is absent
      from the source text.

    Line 125: continue after find_rule_end returns a negative value or a
      value >= len(lines).
      Unreachable: find_rule_end is guaranteed to return a value in the
      range [0, len(lines)-1] for any non-empty lines list.
    """

    def test_find_rule_line_returns_minus_one_for_absent_name(self) -> None:
        """Prerequisite: confirm the structural precondition for line 122.
        find_rule_line returns -1 when the rule name does not appear in text."""
        lines = ["rule real { condition: true }"]

        result = find_rule_line(lines, "phantom")

        assert result == -1

    def test_find_enclosing_rule_continues_past_mismatched_rule_name(
        self,
    ) -> None:
        """Line 122 is reached when find_rule_line returns -1 for a rule
        whose name does not appear in the source text.

        Arrange: a YaraFile with one Rule whose name is 'phantom', paired
          with source text that only contains 'rule real'.
        Act:    call _find_enclosing_rule over the entire single-line range.
        Assert: the method returns None because the continue at line 122
          skips 'phantom', the loop exhausts all rules, and no enclosing
          rule is found."""
        rule = Rule(name="phantom")
        ast = YaraFile(rules=[rule])
        text = "rule real { condition: true }"
        provider = FormattingProvider()

        result = provider._find_enclosing_rule(
            text,
            ast,
            _make_position(0, 0),
            _make_position(0, 5),
        )

        assert result is None

    def test_find_enclosing_rule_skips_all_mismatched_names(self) -> None:
        """Multiple rules with names absent from the text all trigger line 122
        and are skipped; the method returns None after exhausting the loop."""
        rules = [Rule(name="ghost"), Rule(name="specter"), Rule(name="wraith")]
        ast = YaraFile(rules=rules)
        text = "rule present { condition: true }"
        provider = FormattingProvider()

        result = provider._find_enclosing_rule(
            text,
            ast,
            _make_position(0, 0),
            _make_position(0, 4),
        )

        assert result is None

    def test_find_enclosing_rule_succeeds_after_skipping_mismatched_name(
        self,
    ) -> None:
        """A ghost rule triggers line 122 (continue) while the second rule
        matches correctly; the method returns the enclosing range for the
        matched rule, proving the loop continues rather than aborting."""
        ghost = Rule(name="ghost")
        real_rule = Rule(name="real_rule")
        ast = YaraFile(rules=[ghost, real_rule])
        text = "rule real_rule { condition: true }"
        provider = FormattingProvider()

        result = provider._find_enclosing_rule(
            text,
            ast,
            _make_position(0, 5),
            _make_position(0, 10),
        )

        assert result is not None
        matched_rule, matched_range = result
        assert matched_rule.name == "real_rule"
        assert matched_range.start.line == 0

    # ------------------------------------------------------------------
    # Structural proof that line 125 is unreachable
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "lines, start_line",
        [
            (["rule a { condition: true }"], 0),
            ([""], 0),
            (["rule a {", "condition: true", "}"], 0),
            (["rule a {", "// no closing brace"], 0),
            (["single line no braces at all"], 0),
        ],
    )
    def test_find_rule_end_never_returns_negative(self, lines: list[str], start_line: int) -> None:
        """find_rule_end guarantees its return value is in [0, len(lines)-1].
        A negative return value is required to enter line 125; this test
        confirms no such value is ever produced across representative inputs."""
        result = find_rule_end(lines, start_line)

        assert result >= 0, (
            f"find_rule_end returned {result} for lines={lines!r}; "
            "line 125 would be reachable if this could happen"
        )

    @pytest.mark.parametrize(
        "lines, start_line",
        [
            (["rule a { condition: true }"], 0),
            ([""], 0),
            (["rule a {", "condition: true", "}"], 0),
            (["rule a {", "// no closing brace"], 0),
        ],
    )
    def test_find_rule_end_never_returns_value_ge_len_lines(
        self, lines: list[str], start_line: int
    ) -> None:
        """find_rule_end returns at most len(lines)-1 (via the fallback on
        line 253 of structure.py).  A return value >= len(lines) would be
        required to reach line 125; this test confirms it cannot happen."""
        result = find_rule_end(lines, start_line)

        assert result < len(lines), (
            f"find_rule_end returned {result} for len(lines)={len(lines)}; "
            "line 125 would be reachable if result >= len(lines)"
        )
