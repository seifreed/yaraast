"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Regression tests targeting uncovered lines in yaraast/cli/commands/metrics.py.

Missing lines after the existing suite:
  93-94  : complexity command quality-gate failure branch  -- COVERED by this file
  124    : DependencyGraphGenerator is None guard          -- UNREACHABLE (graphviz installed)
  145    : graph command dead else-raise                   -- UNREACHABLE (click validates choices)
  147-151: graph except block, graphviz error path        -- UNREACHABLE (render_graph absorbs)
  194->exit: tree size-is-None branch                     -- UNREACHABLE (file always exists)
  235    : patterns dead else-raise                       -- UNREACHABLE (click validates choices)
  237-241: patterns except block, graphviz error path     -- UNREACHABLE (render_graph absorbs)

Unreachability rationale:
- graphviz is installed: DependencyGraphGenerator is not None, so line 124 cannot execute.
- click Choice validation rejects invalid --type and --engine values at argument parsing
  time, before the command body executes; the else-raise branches at lines 145 and 235
  are dead code under the real CLI.
- render_graph() in dependency_graph_helpers.py catches ExecutableNotFound and CalledProcessError
  internally and produces a dot-format fallback; those errors never propagate to the
  except blocks at lines 147-151 and 237-241 in the CLI handler.
- The tree command always writes the HTML file before calling path_size_for_display; the
  function returns None only on OSError or if the path does not exist, neither of which
  occurs in normal operation, making the 194->exit (size is None) branch unreachable.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
import pytest

from yaraast.cli.commands.metrics import metrics

# ---------------------------------------------------------------------------
# YARA fixture helpers
# ---------------------------------------------------------------------------

_DEEPLY_NESTED_RULE = """\
rule deeply_nested_coverage_test {
    strings:
        $a = "aaa"
        $b = "bbb"
        $c = "ccc"
        $d = "ddd"
        $e = "eee"
        $f = "fff"
        $g = "ggg"
        $h = "hhh"
        $i = "iii"
        $j = "jjj"
    condition:
        ($a and ($b or ($c and ($d or ($e and ($f or ($g and ($h or ($i and $j)))))))))
        or all of them
}
"""

_SIMPLE_RULE = """\
rule simple_for_coverage {
    strings:
        $a = "hello"
    condition:
        $a
}
"""


def _write_yara(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Tests covering lines 93-94: quality-gate failure in complexity command
#
# The deeply-nested rule produces max_condition_depth=10 which triggers
# CRITICAL_DEPTH_PENALTY=20 and complex_rules=['deeply_nested_coverage_test']
# which adds COMPLEX_RULE_PENALTY_PER_ITEM=10, yielding quality_score=70.
# Passing --quality-gate above 70 makes quality_score < quality_gate True
# and exercises:
#   line 93: click.echo(message, err=True)
#   line 94: raise SystemExit(1)
# ---------------------------------------------------------------------------


def test_complexity_quality_gate_failure_exits_nonzero(tmp_path: Path) -> None:
    """
    Quality gate set above the computed score of 70 must cause a non-zero exit.
    Lines 93-94 are exercised: the warning is printed and SystemExit(1) is raised.
    """
    yara_path = _write_yara(tmp_path, "nested.yar", _DEEPLY_NESTED_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--quality-gate", "75"],
    )

    assert result.exit_code != 0
    assert "Quality gate warning" in result.output
    assert "70.0" in result.output
    assert "75" in result.output


def test_complexity_quality_gate_failure_message_contains_score_and_gate(
    tmp_path: Path,
) -> None:
    """
    The message produced on line 93 must include both the computed quality
    score and the configured gate value, confirming that complexity_quality_message
    was called with the real analysed score.
    """
    yara_path = _write_yara(tmp_path, "nested2.yar", _DEEPLY_NESTED_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--quality-gate", "80"],
    )

    assert result.exit_code != 0
    assert "Quality gate warning" in result.output
    assert "70.0" in result.output
    assert "80" in result.output
    assert "<" in result.output


def test_complexity_quality_gate_at_boundary_passes(tmp_path: Path) -> None:
    """
    When the gate equals the computed score exactly (70 == 70), the condition
    quality_score < quality_gate is False and the ok branch (line 91) runs.
    Lines 93-94 must NOT execute, confirming the boundary is exclusive on the
    failure side.
    """
    yara_path = _write_yara(tmp_path, "boundary.yar", _DEEPLY_NESTED_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--quality-gate", "70"],
    )

    assert result.exit_code == 0
    assert "Quality gate passed" in result.output
    assert "70.0" in result.output


def test_complexity_quality_gate_failure_no_traceback(tmp_path: Path) -> None:
    """
    Lines 93-94 raise SystemExit(1), not an unhandled exception.
    The CliRunner must capture a clean SystemExit; no Python traceback may
    appear in the output.
    """
    yara_path = _write_yara(tmp_path, "notrace.yar", _DEEPLY_NESTED_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--quality-gate", "75"],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output


def test_complexity_quality_gate_failure_with_json_format(tmp_path: Path) -> None:
    """
    Quality gate evaluation happens after formatting.  With --format json the
    JSON report is printed first, then lines 93-94 fire and the exit code is 1.
    """
    yara_path = _write_yara(tmp_path, "json_gate.yar", _DEEPLY_NESTED_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--format", "json", "--quality-gate", "75"],
    )

    assert result.exit_code != 0
    assert "quality_score" in result.output
    assert "Quality gate warning" in result.output


def test_complexity_quality_gate_failure_with_output_file(tmp_path: Path) -> None:
    """
    When --output is specified, the report is written to disk first and then
    lines 93-94 still fire if the score is below the threshold.  Both the file
    write and the gate failure must occur.
    """
    yara_path = _write_yara(tmp_path, "file_gate.yar", _DEEPLY_NESTED_RULE)
    output_file = tmp_path / "complexity_report.txt"
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        [
            "complexity",
            str(yara_path),
            "--output",
            str(output_file),
            "--quality-gate",
            "75",
        ],
    )

    assert result.exit_code != 0
    assert output_file.exists()
    assert "Quality gate warning" in result.output


def test_complexity_high_quality_gate_on_simple_rule(tmp_path: Path) -> None:
    """
    A simple rule scores 100.  Passing --quality-gate 100 exercises the ok
    branch (line 91), confirming that lines 93-94 are NOT reached when the
    score satisfies the gate.
    """
    yara_path = _write_yara(tmp_path, "simple.yar", _SIMPLE_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--quality-gate", "100"],
    )

    assert result.exit_code == 0
    assert "Quality gate passed" in result.output


@pytest.mark.parametrize("gate", [71, 75, 79, 100])
def test_complexity_quality_gate_failure_parametric(tmp_path: Path, gate: int) -> None:
    """
    The deeply-nested rule scores 70.  Every gate value strictly above 70
    must trigger lines 93-94 and yield a non-zero exit code.
    """
    yara_path = _write_yara(tmp_path, f"nested_gate{gate}.yar", _DEEPLY_NESTED_RULE)
    runner = CliRunner()

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "--quality-gate", str(gate)],
    )

    assert (
        result.exit_code != 0
    ), f"Expected quality gate failure for gate={gate} but command exited with 0"
    assert "Quality gate warning" in result.output
