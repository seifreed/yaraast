# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Third coverage-loop pass for yaraast.cli.commands.metrics and
yaraast.lsp.authoring_actions_sorting.

Lines newly covered by this file
---------------------------------
metrics.py
  52-54  : _parse_or_fail error path — ParserError is caught, message printed to
           stderr, SystemExit(1) raised.  Reached via `metrics complexity` and
           `metrics strings` with syntactically invalid YARA content.
  153-154: graph command `else` clause — executes when the try block completes
           without raising; prints "Graph source:" and the result path.  Reached
           via a successful `metrics graph --format dot` invocation.
  177-195: tree command body — generate_html / generate_interactive_html,
           output-path defaulting, no-metadata and collapsible flags, file-size
           reporting.  Reached via `metrics tree` with various flag combinations.
  243-244: patterns --stats flag — _display_pattern_statistics called after a
           successful diagram generation.  Reached via `metrics patterns --stats`.
  264-312: report command body — build_report, write_complexity_report_files,
           write_report_summary, all echo statements including file-count summary.
           Reached via `metrics report` with and without --output-dir.
  327-333: strings command body — _analyze_string_patterns, format/output
           routing.  Reached via `metrics strings` with text and json formats.

authoring_actions_sorting.py
  41     : sort_strings_by_identifier — `if ast is None: return None`.  Reached
           by passing a rule body that require_rule_context accepts (contains the
           "rule" keyword) but the YARA parser cannot fully parse (truncated
           condition).

Lines confirmed genuinely unreachable (not attempted in this file)
------------------------------------------------------------------
metrics.py
  124    : `if DependencyGraphGenerator is None` — the graphviz Python package is
           installed in this venv so the guard evaluates to False on every call.
  145-146: `else: raise click.ClickException(f"Unknown graph type: {type}")` —
           click.Choice validates the --type argument before the command body
           executes; no value that bypasses click validation can reach this branch.
  149    : `_display_text_fallback(...)` inside `except` — is_graphviz_error() is
           True only for graphviz.backend.execute.ExecutableNotFound and
           CalledProcessError; render_graph() catches those internally and writes a
           dot fallback, so no graphviz-classified error ever propagates to this
           branch.
  235-236: `else: raise click.ClickException(f"Unknown pattern type: {type}")` —
           same click.Choice argument as lines 145-146.
  239    : `_display_text_pattern_analysis(...)` inside patterns `except` — same
           argument as line 149.
  194->  : `if size is not None` false branch — tree always writes the HTML file
           before calling path_size_for_display, so stat() succeeds and size is
           always an int.

authoring_actions_sorting.py
  147    : `if regenerated_ast is None` in canonicalize_rule_structure — requires
           _safe_parse to fail after a correct generator has produced valid YARA.
           A working CodeGenerator always outputs syntactically valid YARA; there
           is no code path that produces non-parseable output without first
           failing _safe_generate.
  149    : `if len(regenerated_ast.rules) != 1` in canonicalize_rule_structure —
           same argument: correct generation from a single rule always yields a
           single-rule file after re-parsing.
  152    : `if diff.logical_changes or ...` in canonicalize_rule_structure —
           ASTDiffer reports no changes after a correct identity round-trip; this
           guard would only fire if the generator introduced semantic mutations,
           which constitutes a generator bug not a reachable runtime scenario.
  178, 180, 183 : mirror of 147/149/152 for pretty_print_rule / _safe_format_ast.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from lsprotocol.types import Position, Range
import pytest

from yaraast.cli.commands.metrics import metrics
from yaraast.lsp.authoring import AuthoringActions
from yaraast.lsp.authoring_actions_sorting import sort_strings_by_identifier

# ---------------------------------------------------------------------------
# Shared YARA fixture content
# ---------------------------------------------------------------------------

_SIMPLE_RULE = """\
rule simple_test_rule {
    strings:
        $a = "hello world"
    condition:
        $a
}
"""

_MULTI_STRING_RULE = """\
rule multi_string_rule {
    meta:
        author = "test"
        description = "multi-string rule for coverage"
    strings:
        $plain = "hello world"
        $hex = {4D 5A 90 00}
        $re = /pattern[0-9]+/
    condition:
        $plain or $hex or $re
}
"""

_TAGGED_RULE = """\
rule tagged_rule : malware exploit {
    strings:
        $a = "payload"
        $b = "shellcode"
    condition:
        $a and $b
}
"""

# A syntactically incomplete rule body: require_rule_context finds the "rule"
# keyword and returns a RuleContext, but the parser cannot complete the parse
# because there is no closing brace or condition body.
_MALFORMED_RULE_TEXT = "rule malformed { condition:"

# Content that is entirely invalid YARA (no rule keyword at all).
_INVALID_YARA_CONTENT = "this is not valid yara content at all 12345"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yara_file(tmp_path: Path, content: str) -> Path:
    """Write YARA content to a temporary file and return the path."""
    yara_file = tmp_path / "test_rule.yar"
    yara_file.write_text(content, encoding="utf-8")
    return yara_file


def _sel(line: int = 0) -> Range:
    return Range(
        start=Position(line=line, character=0),
        end=Position(line=line, character=0),
    )


# ---------------------------------------------------------------------------
# metrics.py — _parse_or_fail error path (lines 52-54)
# ---------------------------------------------------------------------------


class TestParseOrFailErrorPath:
    """Exercises the ParserError handling in _parse_or_fail.

    Both `complexity` and `strings` use _parse_or_fail, so each provides
    an independent path to lines 52-54.
    """

    def test_complexity_with_invalid_yara_exits_nonzero(self, tmp_path: Path) -> None:
        """
        Arrange: write content that is syntactically invalid YARA.
        Act: invoke `metrics complexity` with that file.
        Assert: exit code is 1 (SystemExit raised by _parse_or_fail).
        """
        yara_file = _write_yara_file(tmp_path, _INVALID_YARA_CONTENT)
        runner = CliRunner()
        result = runner.invoke(metrics, ["complexity", str(yara_file)])
        assert result.exit_code == 1

    def test_complexity_with_invalid_yara_prints_failed_to_parse(self, tmp_path: Path) -> None:
        """
        Arrange: write content that is syntactically invalid YARA.
        Act: invoke `metrics complexity`.
        Assert: output contains the "Failed to parse" prefix.  CliRunner by
        default mixes stderr into result.output, so the assertion checks there.
        """
        yara_file = _write_yara_file(tmp_path, _INVALID_YARA_CONTENT)
        runner = CliRunner()
        result = runner.invoke(metrics, ["complexity", str(yara_file)])
        assert "Failed to parse" in result.output

    def test_strings_with_invalid_yara_exits_nonzero(self, tmp_path: Path) -> None:
        """
        Arrange: write content that is syntactically invalid YARA.
        Act: invoke `metrics strings` with that file.
        Assert: exit code is 1.
        """
        yara_file = _write_yara_file(tmp_path, _INVALID_YARA_CONTENT)
        runner = CliRunner()
        result = runner.invoke(metrics, ["strings", str(yara_file)])
        assert result.exit_code == 1

    def test_strings_with_invalid_yara_prints_filename_in_error(self, tmp_path: Path) -> None:
        """
        Arrange: write invalid YARA content.
        Act: invoke `metrics strings`.
        Assert: the error output (mixed into result.output by default) names the
        file path.
        """
        yara_file = _write_yara_file(tmp_path, _INVALID_YARA_CONTENT)
        runner = CliRunner()
        result = runner.invoke(metrics, ["strings", str(yara_file)])
        assert str(yara_file) in result.output


# ---------------------------------------------------------------------------
# metrics.py — graph command else clause (lines 153-154)
# ---------------------------------------------------------------------------


class TestGraphCommandSuccessElseClause:
    """Exercises the else: clause of the try/except/else block in the graph command.

    The else clause (lines 153-154) runs only when the try block completes
    without raising.  A successful `graph --format dot` invocation triggers it.
    """

    def test_graph_dot_success_prints_graph_source_header(self, tmp_path: Path) -> None:
        """
        Arrange: write a valid YARA rule; use dot format so no graphviz render occurs.
        Act: invoke `metrics graph --format dot`.
        Assert: output contains "Graph source:" (line 153).
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["graph", str(yara_file), "--format", "dot"])
        assert result.exit_code == 0
        assert "Graph source:" in result.output

    def test_graph_dot_success_prints_result_path(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; dot format.
        Act: invoke `metrics graph --format dot`.
        Assert: output contains the generated file path (line 154).
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["graph", str(yara_file), "--format", "dot"])
        assert result.exit_code == 0
        assert ".dot" in result.output

    @pytest.mark.parametrize("graph_type", ["full", "rules", "modules", "complexity"])
    def test_graph_all_types_dot_reach_else_clause(self, tmp_path: Path, graph_type: str) -> None:
        """
        Arrange: valid multi-string YARA rule; dot format; parametric graph type.
        Act: invoke `metrics graph --type <type> --format dot`.
        Assert: "Graph source:" appears in output (else clause executed).
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                metrics,
                ["graph", str(yara_file), "--type", graph_type, "--format", "dot"],
            )
        assert result.exit_code == 0
        assert "Graph source:" in result.output


# ---------------------------------------------------------------------------
# metrics.py — tree command body (lines 177-195)
# ---------------------------------------------------------------------------


class TestTreeCommand:
    """Exercises the tree subcommand body.

    Lines 177-195 are the entire body of the tree command, including output-path
    defaulting, flag handling (--interactive, --no-metadata, --collapsible,
    --title), file-size reporting, and HtmlTreeGenerator invocations.
    """

    def test_tree_default_output_path_uses_stem_tree_suffix(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule file; no --output flag.
        Act: invoke `metrics tree`.
        Assert: output reports a file named <stem>_tree.html and exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["tree", str(yara_file)])
        assert result.exit_code == 0
        assert "_tree.html" in result.output

    def test_tree_default_output_reports_file_size(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule.
        Act: invoke `metrics tree`.
        Assert: output contains "File size:" with a byte count.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["tree", str(yara_file)])
        assert result.exit_code == 0
        assert "File size:" in result.output

    def test_tree_interactive_flag_uses_interactive_suffix(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; --interactive flag.
        Act: invoke `metrics tree --interactive`.
        Assert: output reports a file named <stem>_interactive.html and exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["tree", str(yara_file), "--interactive"])
        assert result.exit_code == 0
        assert "_interactive.html" in result.output

    def test_tree_with_explicit_output_path(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; explicit --output path inside isolated fs.
        Act: invoke `metrics tree --output my_vis.html`.
        Assert: output announces the specified filename.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["tree", str(yara_file), "--output", "my_vis.html"])
        assert result.exit_code == 0
        assert "my_vis.html" in result.output

    def test_tree_no_metadata_flag_exits_zero(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule with a meta section; --no-metadata flag.
        Act: invoke `metrics tree --no-metadata`.
        Assert: exits 0 (HtmlTreeGenerator(include_metadata=False) succeeds).
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["tree", str(yara_file), "--no-metadata"])
        assert result.exit_code == 0

    def test_tree_collapsible_flag_exits_zero(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; --collapsible flag.
        Act: invoke `metrics tree --collapsible`.
        Assert: exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["tree", str(yara_file), "--collapsible"])
        assert result.exit_code == 0

    def test_tree_interactive_with_custom_title(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; --interactive --title flags.
        Act: invoke `metrics tree --interactive --title "My Rules"`.
        Assert: exits 0 (generate_interactive_html uses the title parameter).
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                metrics,
                ["tree", str(yara_file), "--interactive", "--title", "My Rules"],
            )
        assert result.exit_code == 0
        assert "_interactive.html" in result.output

    def test_tree_generates_html_file_on_disk(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; explicit --output path.
        Act: invoke `metrics tree --output out.html`.
        Assert: the file exists on disk after invocation.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as isolated:
            result = runner.invoke(metrics, ["tree", str(yara_file), "--output", "out.html"])
            assert result.exit_code == 0
            assert Path(isolated, "out.html").exists()


# ---------------------------------------------------------------------------
# metrics.py — patterns --stats flag (lines 243-244)
# ---------------------------------------------------------------------------


class TestPatternsStatsFlag:
    """Exercises the --stats flag in the patterns subcommand (lines 243-244).

    _display_pattern_statistics is called only when the --stats flag is present
    and the try block completed without an exception.
    """

    def test_patterns_stats_prints_statistics_section(self, tmp_path: Path) -> None:
        """
        Arrange: valid multi-string YARA rule; dot format (no render needed).
        Act: invoke `metrics patterns --format dot --stats`.
        Assert: output contains "Pattern Statistics:" section.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                metrics, ["patterns", str(yara_file), "--format", "dot", "--stats"]
            )
        assert result.exit_code == 0
        assert "Pattern Statistics:" in result.output

    def test_patterns_stats_shows_total_patterns(self, tmp_path: Path) -> None:
        """
        Arrange: valid multi-string YARA rule.
        Act: invoke `metrics patterns --format dot --stats`.
        Assert: output includes "Total patterns:" with a count.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                metrics, ["patterns", str(yara_file), "--format", "dot", "--stats"]
            )
        assert result.exit_code == 0
        assert "Total patterns:" in result.output

    @pytest.mark.parametrize("diagram_type", ["flow", "complexity", "similarity", "hex"])
    def test_patterns_stats_all_diagram_types(self, tmp_path: Path, diagram_type: str) -> None:
        """
        Arrange: valid multi-string YARA rule; parametric diagram type; dot format.
        Act: invoke `metrics patterns --type <type> --format dot --stats`.
        Assert: "Pattern Statistics:" in output and exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                metrics,
                [
                    "patterns",
                    str(yara_file),
                    "--type",
                    diagram_type,
                    "--format",
                    "dot",
                    "--stats",
                ],
            )
        assert result.exit_code == 0
        assert "Pattern Statistics:" in result.output


# ---------------------------------------------------------------------------
# metrics.py — report command body (lines 264-312)
# ---------------------------------------------------------------------------


class TestReportCommand:
    """Exercises the comprehensive report subcommand (lines 264-312).

    The report command orchestrates build_report, write_complexity_report_files,
    write_report_summary, and multiple click.echo calls including the final
    quality score and generated-file count summary.
    """

    def test_report_default_output_dir_exits_zero(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; no --output-dir flag.
        Act: invoke `metrics report`.
        Assert: exits 0 (full report generation succeeded).
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["report", str(yara_file)])
        assert result.exit_code == 0

    def test_report_default_output_dir_name_derived_from_stem(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule written as 'test_rule.yar'.
        Act: invoke `metrics report`.
        Assert: output announces 'test_rule_metrics_report/' directory.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["report", str(yara_file)])
        assert "test_rule_metrics_report" in result.output

    def test_report_with_explicit_output_dir(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; explicit --output-dir path.
        Act: invoke `metrics report --output-dir myreport`.
        Assert: output references myreport/ and exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["report", str(yara_file), "--output-dir", "myreport"])
        assert result.exit_code == 0
        assert "myreport" in result.output

    def test_report_prints_quality_score(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule.
        Act: invoke `metrics report`.
        Assert: output contains "Quality Score:" (line ~310).
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["report", str(yara_file)])
        assert "Quality Score:" in result.output

    def test_report_prints_generated_files_count(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule.
        Act: invoke `metrics report`.
        Assert: output contains "Generated" and "files" to confirm the summary line.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["report", str(yara_file)])
        assert "Generated" in result.output
        assert "files" in result.output

    def test_report_creates_output_directory(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; explicit output dir that does not yet exist.
        Act: invoke `metrics report --output-dir newdir`.
        Assert: the output directory is created on disk.
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as isolated:
            result = runner.invoke(metrics, ["report", str(yara_file), "--output-dir", "newdir"])
        assert result.exit_code == 0
        assert Path(isolated, "newdir").is_dir()

    def test_report_png_format_exits_zero(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; --format png.
        Act: invoke `metrics report --format png`.
        Assert: exits 0 (png is a valid choice for the report image format).
        """
        yara_file = _write_yara_file(tmp_path, _SIMPLE_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(metrics, ["report", str(yara_file), "--format", "png"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# metrics.py — strings command body (lines 327-333)
# ---------------------------------------------------------------------------


class TestStringsCommand:
    """Exercises the strings subcommand body (lines 327-333).

    _parse_or_fail, _analyze_string_patterns, _format_string_analysis_output,
    and _output_string_analysis_results are all called unconditionally.
    """

    def test_strings_text_format_exits_zero(self, tmp_path: Path) -> None:
        """
        Arrange: valid multi-string YARA rule.
        Act: invoke `metrics strings` (default text format).
        Assert: exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        result = runner.invoke(metrics, ["strings", str(yara_file)])
        assert result.exit_code == 0

    def test_strings_text_format_reports_total_strings(self, tmp_path: Path) -> None:
        """
        Arrange: YARA rule with 3 strings.
        Act: invoke `metrics strings`.
        Assert: output contains "Total strings: 3".
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        result = runner.invoke(metrics, ["strings", str(yara_file)])
        assert result.exit_code == 0
        assert "Total strings: 3" in result.output

    def test_strings_json_format_produces_valid_json_structure(self, tmp_path: Path) -> None:
        """
        Arrange: valid multi-string YARA rule.
        Act: invoke `metrics strings --format json`.
        Assert: output begins with '{' (JSON object) and exits 0.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        result = runner.invoke(metrics, ["strings", str(yara_file), "--format", "json"])
        assert result.exit_code == 0
        assert result.output.strip().startswith("{")

    def test_strings_with_output_file_writes_file(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; --output flag pointing to a file in isolated fs.
        Act: invoke `metrics strings --output analysis.txt`.
        Assert: the output file is created on disk.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as isolated:
            result = runner.invoke(metrics, ["strings", str(yara_file), "--output", "analysis.txt"])
        assert result.exit_code == 0
        assert Path(isolated, "analysis.txt").exists()

    def test_strings_json_with_output_file_writes_file(self, tmp_path: Path) -> None:
        """
        Arrange: valid YARA rule; --format json --output flag.
        Act: invoke `metrics strings --format json --output analysis.json`.
        Assert: the output file is created on disk.
        """
        yara_file = _write_yara_file(tmp_path, _MULTI_STRING_RULE)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as isolated:
            result = runner.invoke(
                metrics,
                ["strings", str(yara_file), "--format", "json", "--output", "analysis.json"],
            )
        assert result.exit_code == 0
        assert Path(isolated, "analysis.json").exists()

    def test_strings_rule_with_no_strings_exits_zero(self, tmp_path: Path) -> None:
        """
        Arrange: YARA rule with no strings section (condition-only rule).
        Act: invoke `metrics strings`.
        Assert: exits 0 (empty string analysis is valid).
        """
        condition_only = "rule no_strings { condition: true }\n"
        yara_file = _write_yara_file(tmp_path, condition_only)
        runner = CliRunner()
        result = runner.invoke(metrics, ["strings", str(yara_file)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# authoring_actions_sorting.py — sort_strings_by_identifier line 41
# ---------------------------------------------------------------------------


class TestSortStringsByIdentifierParseReturnsNone:
    """Covers authoring_actions_sorting.py line 41: `if ast is None: return None`.

    _safe_parse wraps lsp_safe_handler.  When the wrapped parser.parse() raises
    an exception, lsp_safe_handler catches it and returns None.  This happens
    when require_rule_context accepts the text (it finds the "rule" keyword) but
    the YARA parser cannot complete the parse due to a truncated rule body.
    """

    def test_malformed_rule_body_returns_none(self) -> None:
        """
        Arrange: a rule text that require_rule_context accepts but the parser
                 cannot parse (no closing brace, incomplete condition).
        Act: call sort_strings_by_identifier with that text.
        Assert: the function returns None (line 41 executed).
        """
        authoring = AuthoringActions()
        result = sort_strings_by_identifier(authoring, _MALFORMED_RULE_TEXT, _sel(0))
        assert result is None

    def test_empty_string_body_returns_none(self) -> None:
        """
        Arrange: a rule keyword followed by an empty body that the parser rejects.
        Act: call sort_strings_by_identifier.
        Assert: returns None.
        """
        authoring = AuthoringActions()
        # "rule r {" has the keyword and opening brace but no closing brace or
        # condition; require_rule_context should accept it while the parser rejects it.
        result = sort_strings_by_identifier(authoring, "rule r {", _sel(0))
        assert result is None

    def test_truncated_strings_section_returns_none(self) -> None:
        """
        Arrange: a rule with a strings section but truncated before condition.
        Act: call sort_strings_by_identifier.
        Assert: returns None.
        """
        authoring = AuthoringActions()
        truncated = 'rule r { strings: $a = "x" $b = "y"'
        result = sort_strings_by_identifier(authoring, truncated, _sel(0))
        assert result is None
