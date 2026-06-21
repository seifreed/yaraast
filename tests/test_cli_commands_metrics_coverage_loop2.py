"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Regression tests extending coverage of yaraast/cli/commands/metrics.py.

This file targets lines that the prior file (test_cli_commands_metrics_coverage_loop.py)
correctly identified as a group but left unattempted because render_graph was assumed
to absorb all errors.

The prior analysis was correct that render_graph absorbs graphviz ExecutableNotFound
inside its inner try/except.  However, it does NOT protect the write_text call at
line 85 of dependency_graph_helpers.py (dot format, non-binary path):

    if format == "dot":
        output_path_obj.write_text(dot.source, encoding="utf-8")   # <-- no try/except
        return str(output_path_obj)

A PermissionError writing to an unwritable directory propagates uncaught through
render_graph and up into the 'except Exception as e' blocks in the graph and
patterns CLI commands.  'is_graphviz_error(PermissionError)' evaluates to False,
so the 'else: raise' branch at lines 150-151 and 240-241 executes.

Lines newly covered by this file:
  147: except Exception as e  (graph command, reached via PermissionError)
  148: if is_graphviz_error(e)  (evaluates to False for PermissionError)
  150: else:
  151: raise
  237: except Exception as e  (patterns command, same mechanism)
  238: if is_graphviz_error(e)
  240: else:
  241: raise

Lines that remain unreachable in this environment and are NOT attempted:
  124: DependencyGraphGenerator is None — only when graphviz Python package is absent;
       the package is installed in this venv, so the guard never fires.
  145: Unknown graph type else-raise — click.Choice rejects invalid values before the
       command body executes; no invocation can reach this branch.
  149: _display_text_fallback inside graph except — requires a graphviz-classified
       error to escape render_graph; render_graph catches ExecutableNotFound internally
       and writes a dot fallback, so no graphviz error ever propagates to line 149.
  194->exit: path_size_for_display returns None — only if the HTML file does not exist
       or stat raises OSError; the tree command writes the file unconditionally before
       calling path_size_for_display, so size is always an int, not None.
  235: Unknown pattern type else-raise — same click.Choice argument as line 145.
  239: _display_text_pattern_analysis inside patterns except — same argument as 149.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from click.testing import CliRunner
import pytest

from yaraast.cli.commands.metrics import metrics

# ---------------------------------------------------------------------------
# YARA content helpers
# ---------------------------------------------------------------------------

_SIMPLE_RULE = """\
rule simple_rule_for_graph_error_test {
    strings:
        $a = "hello"
    condition:
        $a
}
"""

_STRING_PATTERN_RULE = """\
rule string_pattern_for_error_test {
    strings:
        $plain = "hello world"
        $hex = {4D 5A 90 00}
    condition:
        $plain or $hex
}
"""


def _write_yara(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Fixture: a temporary directory where the current user cannot write.
# Cleanup restores write permission so pytest can remove the directory.
# ---------------------------------------------------------------------------


class _ReadOnlyDir:
    """Context manager that creates a non-writable directory."""

    def __init__(self, parent: Path) -> None:
        self._path = parent / "readonly_sub"
        self._path.mkdir()

    def __enter__(self) -> Path:
        os.chmod(self._path, stat.S_IRUSR | stat.S_IXUSR)
        return self._path

    def __exit__(self, *_: object) -> None:
        # Restore so pytest's tmp_path cleanup can remove the tree.
        os.chmod(self._path, stat.S_IRWXU)


# ---------------------------------------------------------------------------
# Tests for lines 147-151: graph command except block, else-raise path
#
# Strategy: invoke 'metrics graph' with --format dot and an --output path
# inside a read-only directory.  render_graph writes the dot source with
# write_text() which is NOT wrapped in any try/except.  The PermissionError
# propagates through generate_graph → graph command's except Exception.
# is_graphviz_error(PermissionError) is False → else: raise executes.
# Lines 147, 148, 150, 151 are all hit.
# ---------------------------------------------------------------------------


def test_graph_dot_format_unwritable_output_propagates_permission_error(
    tmp_path: Path,
) -> None:
    """
    A PermissionError writing a .dot file to an unwritable directory must
    propagate through the graph command's except block (line 147), evaluate
    is_graphviz_error to False (line 148), and re-raise (lines 150-151),
    producing a non-zero exit code and a captured PermissionError exception.
    """
    yara_path = _write_yara(tmp_path, "simple.yar", _SIMPLE_RULE)
    with _ReadOnlyDir(tmp_path) as ro_dir:
        out_path = ro_dir / "graph.dot"
        runner = CliRunner()
        result = runner.invoke(
            metrics,
            ["graph", str(yara_path), "--format", "dot", "--output", str(out_path)],
        )

    assert result.exit_code != 0
    assert isinstance(result.exception, PermissionError)


def test_graph_dot_format_unwritable_output_does_not_produce_graphviz_text(
    tmp_path: Path,
) -> None:
    """
    When the PermissionError fires, is_graphviz_error returns False so the
    text fallback at line 149 (_display_text_fallback) must NOT be called.
    The fallback message 'Graphviz not installed' must be absent from output.
    """
    yara_path = _write_yara(tmp_path, "simple2.yar", _SIMPLE_RULE)
    with _ReadOnlyDir(tmp_path) as ro_dir:
        out_path = ro_dir / "graph2.dot"
        runner = CliRunner()
        result = runner.invoke(
            metrics,
            ["graph", str(yara_path), "--format", "dot", "--output", str(out_path)],
        )

    assert "Graphviz not installed" not in result.output
    assert isinstance(result.exception, PermissionError)


@pytest.mark.parametrize("graph_type", ["full", "rules", "modules", "complexity"])
def test_graph_dot_all_types_unwritable_output_reraises(tmp_path: Path, graph_type: str) -> None:
    """
    Every branch inside the graph command's try block ultimately calls
    render_graph which performs the unprotected write_text.  Verify that
    for every valid --type value the PermissionError re-raise path is
    exercised, not the graphviz fallback.
    """
    yara_path = _write_yara(tmp_path, f"simple_{graph_type}.yar", _SIMPLE_RULE)
    with _ReadOnlyDir(tmp_path) as ro_dir:
        out_path = ro_dir / f"output_{graph_type}.dot"
        runner = CliRunner()
        result = runner.invoke(
            metrics,
            [
                "graph",
                str(yara_path),
                "--format",
                "dot",
                "--type",
                graph_type,
                "--output",
                str(out_path),
            ],
        )

    assert result.exit_code != 0
    assert isinstance(result.exception, PermissionError)


# ---------------------------------------------------------------------------
# Tests for lines 237-241: patterns command except block, else-raise path
#
# Same mechanism: --format dot with an unwritable output directory causes
# write_text() to raise PermissionError, which is not a graphviz error,
# so lines 237, 238, 240, 241 execute and the exception re-raises.
# ---------------------------------------------------------------------------


def test_patterns_dot_format_unwritable_output_propagates_permission_error(
    tmp_path: Path,
) -> None:
    """
    A PermissionError when writing a .dot pattern diagram must propagate
    through the patterns command's except block (lines 237-238), evaluate
    is_graphviz_error to False, and re-raise (lines 240-241).
    """
    yara_path = _write_yara(tmp_path, "patterns.yar", _STRING_PATTERN_RULE)
    with _ReadOnlyDir(tmp_path) as ro_dir:
        out_path = ro_dir / "patterns.dot"
        runner = CliRunner()
        result = runner.invoke(
            metrics,
            [
                "patterns",
                str(yara_path),
                "--format",
                "dot",
                "--output",
                str(out_path),
            ],
        )

    assert result.exit_code != 0
    assert isinstance(result.exception, PermissionError)


def test_patterns_dot_format_unwritable_output_no_text_analysis_fallback(
    tmp_path: Path,
) -> None:
    """
    When PermissionError fires in the patterns except block, is_graphviz_error
    is False so _display_text_pattern_analysis at line 239 must NOT execute.
    The text analysis header must be absent.
    """
    yara_path = _write_yara(tmp_path, "patterns2.yar", _STRING_PATTERN_RULE)
    with _ReadOnlyDir(tmp_path) as ro_dir:
        out_path = ro_dir / "patterns2.dot"
        runner = CliRunner()
        result = runner.invoke(
            metrics,
            [
                "patterns",
                str(yara_path),
                "--format",
                "dot",
                "--output",
                str(out_path),
            ],
        )

    assert "Pattern Analysis" not in result.output
    assert isinstance(result.exception, PermissionError)


@pytest.mark.parametrize("pattern_type", ["flow", "complexity", "similarity", "hex"])
def test_patterns_dot_all_types_unwritable_output_reraises(
    tmp_path: Path, pattern_type: str
) -> None:
    """
    Every branch inside the patterns command's try block calls render_graph.
    Verify that for all valid --type values the PermissionError re-raise path
    executes rather than the graphviz text fallback.
    """
    yara_path = _write_yara(tmp_path, f"patterns_{pattern_type}.yar", _STRING_PATTERN_RULE)
    with _ReadOnlyDir(tmp_path) as ro_dir:
        out_path = ro_dir / f"output_{pattern_type}.dot"
        runner = CliRunner()
        result = runner.invoke(
            metrics,
            [
                "patterns",
                str(yara_path),
                "--format",
                "dot",
                "--type",
                pattern_type,
                "--output",
                str(out_path),
            ],
        )

    assert result.exit_code != 0
    assert isinstance(result.exception, PermissionError)
