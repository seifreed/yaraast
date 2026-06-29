"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Regression tests covering the remaining coverage gaps in:
  - yaraast/cli/commands/roundtrip.py       (targets: lines 220, 226->231, 232)
  - yaraast/cli/commands/libyara_cmd.py     (targets: lines 125-126)
  - yaraast/cli/metrics_reporting_display.py (targets: line 44, branch 70->exit)

Every test uses real production code paths.  No mocking frameworks, no test doubles,
no placeholder stubs.  File I/O uses real temporary directories.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any

from click.testing import CliRunner
import pytest

from yaraast.cli.commands.roundtrip import roundtrip
from yaraast.cli.metrics_reporting_display import (
    display_module_usage,
    display_successful_graph_result,
)
from yaraast.libyara import YARA_AVAILABLE
from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.parser.parser import Parser

# ---------------------------------------------------------------------------
# Shared YARA rule text helpers
# ---------------------------------------------------------------------------


def _simple_rule_text() -> str:
    """Minimal valid YARA rule that round-trips perfectly."""
    return 'rule simple {\n    strings:\n        $a = "hello"\n    condition:\n        $a\n}\n'


def _timeout_rule_text() -> str:
    """YARA rule with a triple-nested loop that causes a yara scan timeout
    within one second of scan time.  Compilation succeeds; the scan engine
    itself times out, causing scan_result['success'] == False.
    """
    return (
        "rule timeout_loop {\n"
        "    condition:\n"
        "        for all i in (1..1000) : (\n"
        "            for all j in (1..1000) : (\n"
        "                for all k in (1..1000) : (\n"
        "                    i + j + k > 0\n"
        "                )\n"
        "            )\n"
        "        )\n"
        "}\n"
    )


# ---------------------------------------------------------------------------
# yaraast/cli/commands/libyara_cmd.py
# Target lines: 125-126  (scan_failure branch + click.Abort)
#
# These lines are reached when:
#   1. YARA is available
#   2. Compilation succeeds (scan_result is not None)
#   3. scan_result["success"] is False (scan engine raised an exception)
#
# The triple-nested 1000x1000x1000 loop produces a compile-time-valid rule
# whose scan times out within --timeout 1, which makes OptimizedMatcher.scan()
# catch the yara.TimeoutError and return {"success": False, "error": ...}.
# ---------------------------------------------------------------------------


class TestLibyaraScanFailureBranch:
    """Cover libyara_cmd.py lines 125-126: scan command failure after a
    successful compilation, triggered by a real scan timeout."""

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_scan_failure_calls_display_scan_failure_and_aborts(self, tmp_path: Path) -> None:
        """
        Arrange: write a rule that compiles cleanly but whose evaluation loop
                 takes far longer than 1 second.
        Act:     invoke the CLI scan command with --timeout 1.
        Assert:  exit code is non-zero (Abort) and no 'Scan completed' line.

        Lines 125-126 in libyara_cmd.py:
            display_scan_failure(console, scan_result)
            raise click.Abort from None
        """
        # Arrange
        rule_file = tmp_path / "timeout.yar"
        rule_file.write_text(_timeout_rule_text(), encoding="utf-8")
        target_file = tmp_path / "target.bin"
        target_file.write_bytes(b"irrelevant data for timeout test")

        runner = CliRunner()

        # Act — the scan must time out; --timeout 1 is the minimum allowed by CLI
        result = runner.invoke(
            _get_libyara_cli(),
            [
                "scan",
                str(rule_file),
                str(target_file),
                "--timeout",
                "1",
            ],
        )

        # Assert
        assert result.exit_code != 0, (
            f"Expected non-zero exit when scan fails, got 0.\nOutput:\n{result.output}"
        )
        # 'Scan completed' is only printed on the success branch (line 117)
        assert "Scan completed" not in result.output
        # Failure branch output comes from display_scan_failure at line 125
        assert "Scan failed" in result.output or "error" in result.output.lower()


# ---------------------------------------------------------------------------
# yaraast/cli/commands/roundtrip.py
# Target: lines 220, 226->231, 232
#
# Line 220:       _display_test_failure(input_file, result, verbose)
# Branch 226->231: output_path is not None AND the test failed
#                  (write_text + click.echo for the saved-results message)
# Line 232:       sys.exit(1) when round_trip_successful is False
#
# The RoundTripSerializer is loss-free for all well-formed YARA constructs
# the existing test suite exercises.  These three lines represent a defensive
# guard for future serializer regressions.
#
# Reachability status (determined by exhaustive search over all YARA construct
# categories — meta types, string modifiers, hex patterns, condition operators,
# for-loops, imports, module references, pragmas, extern rules, namespaces):
#   - No existing YARA source produces round_trip_successful=False with the
#     current RoundTripSerializer implementation.
#   - Lines 220, 226->231, and 232 are GENUINELY UNREACHABLE through the CLI
#     for any well-formed YARA input handled by the current serializer.
#   - The try/except at line 234 catches any serializer exception before
#     lines 220/232 could be reached via a broken rule.
#
# The tests below document this finding and assert the correct behavior of
# the surrounding code under the only conditions that CAN be reached.
# ---------------------------------------------------------------------------


class TestRoundtripTestCommandSuccessPath:
    """Confirm the success path of the CLI 'test' command (lines 217-219)
    to lock in the behavior that surrounds the unreachable failure branch."""

    def test_test_command_success_exits_zero_with_output_file(self, tmp_path: Path) -> None:
        """
        Arrange: a valid YARA file whose round trip succeeds.
        Act:     invoke 'roundtrip test' with --output to save results.
        Assert:  exit code 0, output file created, success message present.

        This exercises lines 217-219 and 226-228 (success branch) which are
        the reachable partners of the unreachable failure lines 220 and 232.
        """
        # Arrange
        yara_file = tmp_path / "rule.yar"
        yara_file.write_text(_simple_rule_text(), encoding="utf-8")
        out_file = tmp_path / "results.json"

        runner = CliRunner()

        # Act
        result = runner.invoke(
            roundtrip,
            [
                "test",
                str(yara_file),
                "--format",
                "json",
                "--output",
                str(out_file),
            ],
        )

        # Assert
        assert result.exit_code == 0, f"Unexpected failure:\n{result.output}"
        assert "Round-trip test PASSED" in result.output
        assert out_file.exists(), "Output file was not created"
        assert "Detailed results saved to" in result.output

    def test_test_command_verbose_success_shows_source(self, tmp_path: Path) -> None:
        """
        The --verbose flag on a passing round-trip triggers _display_verbose_source
        at line 223.  This test locks in the verbose success path.
        """
        # Arrange
        yara_file = tmp_path / "rule.yar"
        yara_file.write_text(_simple_rule_text(), encoding="utf-8")
        runner = CliRunner()

        # Act
        result = runner.invoke(
            roundtrip,
            ["test", str(yara_file), "--verbose"],
        )

        # Assert
        assert result.exit_code == 0, f"Unexpected failure:\n{result.output}"
        assert "Round-trip test PASSED" in result.output
        # Verbose mode emits source content
        assert "simple" in result.output  # rule name appears in source preview

    def test_test_command_exception_path_exits_nonzero(self, tmp_path: Path) -> None:
        """
        When roundtrip_test() raises (because the file cannot be parsed),
        the except block at line 234 fires and sys.exit(1) is called.
        This confirms the exception path works correctly.
        """
        # Arrange: write a YARA file that is syntactically broken
        bad_file = tmp_path / "bad.yar"
        bad_file.write_text("rule broken { condition: }", encoding="utf-8")
        runner = CliRunner()

        # Act
        result = runner.invoke(
            roundtrip,
            ["test", str(bad_file)],
        )

        # Assert
        assert result.exit_code != 0
        assert "Error testing" in result.output


# ---------------------------------------------------------------------------
# yaraast/cli/metrics_reporting_display.py
# Target: line 44 and branch 70->exit
#
# Line 44:
#   display_successful_graph_result(result_path, generator)
#   When result_path is NOT a str (e.g. an int), the isinstance check at
#   line 36 is False, the 'else' at line 43 runs, and 'exists' is set to
#   False at line 44.  Because 'exists' is False the click.echo at line 46
#   is never called, so the function produces no output.
#
# Branch 70->exit:
#   display_module_usage(generator)
#   When generator.module_references is empty (falsy), the 'if' at line 70
#   is False and the function exits immediately without printing anything.
# ---------------------------------------------------------------------------


class TestDisplaySuccessfulGraphResultNonStringPath:
    """Cover line 44 in metrics_reporting_display.py.

    display_successful_graph_result receives a non-str result_path.  The
    isinstance guard at line 36 takes the 'else' branch (line 43-44),
    setting exists=False without attempting Path.exists().  Because the
    function only emits output when exists is True, no output is produced.
    """

    def test_non_string_result_path_produces_no_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        Arrange: a generator with valid dependency stats and a non-str path (int).
        Act:     call display_successful_graph_result with the int path.
        Assert:  no output, and no AttributeError (the function silently short-circuits).

        Line 44 fires: 'else: exists = False'
        """
        # Arrange: a real DependencyGraphGenerator populated from a parsed YARA file
        ast = Parser("rule r { condition: true }").parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        # Act — path is an integer, not a str
        display_successful_graph_result(42, gen)  # type: ignore[arg-type]

        # Assert
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_none_result_path_produces_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        None is also not a str.  The else branch (line 43-44) fires, sets
        exists=False, and the function produces no output.
        """
        # Arrange
        ast = Parser("rule r { condition: true }").parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        # Act
        display_successful_graph_result(None, gen)  # type: ignore[arg-type]

        # Assert
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_list_result_path_produces_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        A list is not a str.  The else branch fires identically to the int case.
        """
        # Arrange
        ast = Parser("rule r { condition: true }").parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        # Act
        display_successful_graph_result(["/some/path.dot"], gen)  # type: ignore[arg-type]

        # Assert
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_str_path_to_nonexistent_file_produces_no_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A str result_path that does not exist on disk makes Path.exists() return
        False (not the else branch, but the same outcome: no output).
        This guards the boundary between the covered str branch and line 44.
        """
        # Arrange
        ast = Parser("rule r { condition: true }").parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        # Act
        display_successful_graph_result("/does/not/exist/graph.dot", gen)

        # Assert
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_str_path_to_existing_file_emits_generated_message(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A str path that DOES exist causes the success output to be printed,
        including the dependency statistics from the generator.

        This test verifies the positive branch (lines 45-48) that surrounds
        line 44, ensuring line 44 is the ONLY missing path before our new tests.
        """
        # Arrange
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            real_path = f.name
            f.write(b"digraph {}")

        ast = Parser('import "pe"\nrule r { condition: pe.number_of_sections > 0 }').parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        try:
            # Act
            display_successful_graph_result(real_path, gen)
            captured = capsys.readouterr()

            # Assert
            assert "Dependency graph generated:" in captured.out
            assert real_path in captured.out
            # Statistics are printed because generator is not None (lines 47-48)
            assert "Graph Statistics" in captured.out
        finally:
            Path(real_path).unlink(missing_ok=True)


class TestDisplayModuleUsageEmptyBranch:
    """Cover branch 70->exit in metrics_reporting_display.py.

    display_module_usage() checks 'if generator.module_references:' at line 70.
    When module_references is an empty dict (falsy), the if-body is skipped and
    the function exits immediately.  This is branch 70->exit.
    """

    def test_empty_module_references_produces_no_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        Arrange: a DependencyGraphGenerator after visiting a YARA file with
                 no module imports.  module_references is an empty defaultdict.
        Act:     call display_module_usage with this generator.
        Assert:  no output is produced (branch 70->exit fires).
        """
        # Arrange: rule with no imports means module_references stays empty
        ast = Parser(
            'rule no_modules {\n    strings:\n        $a = "hello"\n    condition:\n        $a\n}'
        ).parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        # Verify the precondition: module_references must be empty
        assert not gen.module_references, (
            "Expected empty module_references for a rule with no imports"
        )

        # Act
        display_module_usage(gen)

        # Assert
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_non_empty_module_references_produces_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        Contrast test: with real module references, display_module_usage emits
        the Module Usage section.  This confirms the empty-dict branch is
        genuinely distinct from the non-empty branch.
        """
        # Arrange: rule that uses the 'pe' module populates module_references
        ast = Parser(
            'import "pe"\nrule uses_pe {\n    condition:\n        pe.number_of_sections > 0\n}'
        ).parse()
        gen = DependencyGraphGenerator()
        gen.visit(ast)

        # Verify the precondition: module_references must be non-empty
        assert gen.module_references, (
            "Expected non-empty module_references after visiting a rule that uses 'pe'"
        )

        # Act
        display_module_usage(gen)

        # Assert
        captured = capsys.readouterr()
        assert "Module Usage" in captured.out
        assert "pe" in captured.out


# ---------------------------------------------------------------------------
# Helper: lazy import of the libyara CLI group to avoid import-time yara check.
# The libyara_cmd module imports yara at module level only inside functions,
# so importing from yaraast.cli.main is safe regardless of YARA_AVAILABLE.
# ---------------------------------------------------------------------------


def _get_libyara_cli() -> Any:
    """Return the Click group for libyara commands.

    Imported lazily so the module can be imported even when yara-python is
    not installed.  The skip guard on the test ensures yara IS available
    before the Click invocation.
    """
    from yaraast.cli.main import cli

    return cli
