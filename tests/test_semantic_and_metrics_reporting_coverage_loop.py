"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Regression tests covering the remaining branch gaps in:
  - yaraast/cli/semantic_reporting.py
  - yaraast/cli/metrics_reporting.py

Each test exercises real production code paths using real data structures.
No mocks, stubs, or artificial test doubles are used.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.ast.strings import (
    PlainString,
    StringDefinition,
)
from yaraast.cli import metrics_reporting as mr, semantic_reporting as sr
from yaraast.metrics import StringDiagramGenerator
from yaraast.parser.parser import Parser
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _parse(yara_text: str) -> YaraFile:
    """Parse YARA source into a real YaraFile via the production parser."""
    return Parser(yara_text).parse()


def _build_minimal_analysis(
    *,
    modifiers: dict[str, int] | None = None,
    short_strings: int = 0,
    hex_patterns: int = 0,
) -> dict[str, object]:
    """Build a real string-analysis dict that _format_strings_text accepts."""
    return {
        "total_strings": 1,
        "type_distribution": {"plain": 1, "hex": 0, "regex": 0},
        "length_stats": {"min": 5, "max": 5, "avg": 5.0},
        "modifiers": modifiers if modifiers is not None else {},
        "patterns": {
            "short_strings": short_strings,
            "hex_patterns": hex_patterns,
        },
    }


# ---------------------------------------------------------------------------
# semantic_reporting.py — missing branch coverage
# ---------------------------------------------------------------------------


class TestDisplayValidationStartQuietBranch:
    """Cover line 16->exit: display_validation_start with quiet=True."""

    def test_quiet_true_produces_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        When quiet=True the guard 'if not quiet' is False and the function
        exits immediately without calling click.echo.
        """
        sr.display_validation_start(Path("rule.yar"), quiet=True)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""


class TestDisplayTextResultsNonSuggestionBranches:
    """
    Cover lines 34->32, 40->38, and 45->exit:
    - error with suggestion=None while show_suggestions=True
    - warning with suggestion=None while show_suggestions=True
    - quiet=True silences the summary line
    """

    def _result_with_error_no_suggestion(self) -> ValidationResult:
        result = ValidationResult(is_valid=False)
        result.errors.append(ValidationError("bare error message", location=None, suggestion=None))
        return result

    def _result_with_warning_no_suggestion(self) -> ValidationResult:
        result = ValidationResult(is_valid=True)
        result.warnings.append(
            ValidationError(
                "bare warning message",
                location=None,
                severity="warning",
                suggestion=None,
            )
        )
        return result

    def test_error_with_no_suggestion_skips_suggestion_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        An error with suggestion=None must not emit a 'Suggestion:' line even
        when show_suggestions=True.  Branch 34->32 (falsy suggestion) fires.
        """
        sr.display_text_results(
            Path("t.yar"),
            self._result_with_error_no_suggestion(),
            show_warnings=False,
            show_suggestions=True,
            quiet=False,
        )
        captured = capsys.readouterr()
        assert "bare error message" in captured.err
        assert "Suggestion:" not in captured.out
        assert "Suggestion:" not in captured.err

    def test_warning_with_no_suggestion_skips_suggestion_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A warning with suggestion=None must not emit a 'Suggestion:' line even
        when show_suggestions=True.  Branch 40->38 (falsy suggestion) fires.
        """
        sr.display_text_results(
            Path("t.yar"),
            self._result_with_warning_no_suggestion(),
            show_warnings=True,
            show_suggestions=True,
            quiet=False,
        )
        captured = capsys.readouterr()
        assert "bare warning message" in captured.out
        assert "Suggestion:" not in captured.out

    def test_quiet_true_suppresses_summary_line(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        When quiet=True, 'if not quiet' at line 45 is False so the entire
        summary block (valid/invalid/warnings) is skipped.  Branch 45->exit.
        """
        result = ValidationResult(is_valid=True)
        sr.display_text_results(
            Path("t.yar"),
            result,
            show_warnings=False,
            show_suggestions=False,
            quiet=True,
        )
        captured = capsys.readouterr()
        # No valid/invalid status line emitted
        assert "All checks passed" not in captured.out
        assert "errors" not in captured.out
        assert captured.out == ""


class TestDisplaySummaryAllBranches:
    """
    Cover lines 65->68, 68->71, and 72:
    - zero errors skips the error count line
    - zero warnings skips the warning count line
    - both zero emits the 'All files passed' success message
    """

    def test_zero_errors_zero_warnings_emits_success(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        With total_errors=0 and total_warnings=0 both conditional branches
        (lines 65->68 and 68->71) are not taken and line 72 body executes.
        """
        sr.display_summary(total_files=5, total_errors=0, total_warnings=0)
        captured = capsys.readouterr()
        assert "All files passed validation" in captured.out
        assert "errors" not in captured.out
        assert "warnings" not in captured.out
        assert "Validated 5 file(s)" in captured.out

    def test_zero_errors_with_warnings_skips_error_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        With total_errors=0 the branch at line 65 is not taken (65->68).
        The warning line at 68 is taken since total_warnings > 0.
        """
        sr.display_summary(total_files=2, total_errors=0, total_warnings=3)
        captured = capsys.readouterr()
        assert "Found 3 warnings" in captured.out
        assert "errors" not in captured.out

    def test_zero_warnings_with_errors_skips_warning_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        With total_warnings=0 the branch at line 68 is not taken (68->71).
        The error line at 65 is taken since total_errors > 0.
        """
        sr.display_summary(total_files=1, total_errors=2, total_warnings=0)
        captured = capsys.readouterr()
        assert "Found 2 errors" in captured.out
        assert "warnings" not in captured.out


class TestWriteOutputFileMissingBranches:
    """
    Cover branches 99->105, 105->97, 110->116, 116->108:
    write_output_file text format with errors/warnings that lack location
    or suggestion fields (the 'if error.get(...)' guards evaluate False).
    """

    def test_error_without_location_or_suggestion(self, tmp_path: Path) -> None:
        """
        An error dict with no 'location' key (99->105) and no 'suggestion'
        key (105->97) must render only the ERROR line without Location or
        Suggestion sub-lines.
        """
        results = [
            {
                "file": "check.yar",
                "is_valid": False,
                "errors": [{"message": "undeclared identifier"}],
                "warnings": [],
            }
        ]
        out = tmp_path / "out.txt"
        sr.write_output_file(out, results, format="text")
        content = out.read_text(encoding="utf-8")
        assert "ERROR: undeclared identifier" in content
        assert "Location:" not in content
        assert "Suggestion:" not in content

    def test_error_with_location_but_no_suggestion(self, tmp_path: Path) -> None:
        """
        An error dict with a 'location' key but no 'suggestion' must render
        Location but skip Suggestion (branch 105->97 fires).
        """
        results = [
            {
                "file": "check.yar",
                "is_valid": False,
                "errors": [
                    {
                        "message": "duplicate rule",
                        "location": {"file": "check.yar", "line": 4, "column": 1},
                    }
                ],
                "warnings": [],
            }
        ]
        out = tmp_path / "out2.txt"
        sr.write_output_file(out, results, format="text")
        content = out.read_text(encoding="utf-8")
        assert "ERROR: duplicate rule" in content
        assert "Location: check.yar:4:1" in content
        assert "Suggestion:" not in content

    def test_warning_without_location_or_suggestion(self, tmp_path: Path) -> None:
        """
        A warning dict with no 'location' key (110->116) and no 'suggestion'
        key (116->108) must render only the WARNING line.
        """
        results = [
            {
                "file": "check.yar",
                "is_valid": True,
                "errors": [],
                "warnings": [{"message": "unused string $a"}],
            }
        ]
        out = tmp_path / "out3.txt"
        sr.write_output_file(out, results, format="text")
        content = out.read_text(encoding="utf-8")
        assert "WARNING: unused string $a" in content
        assert "Location:" not in content
        assert "Suggestion:" not in content

    def test_warning_with_location_but_no_suggestion(self, tmp_path: Path) -> None:
        """
        A warning dict with 'location' but no 'suggestion' must render
        Location but omit Suggestion (branch 116->108 fires).
        """
        results = [
            {
                "file": "check.yar",
                "is_valid": True,
                "errors": [],
                "warnings": [
                    {
                        "message": "condition always true",
                        "location": {"file": "check.yar", "line": 8, "column": 5},
                    }
                ],
            }
        ]
        out = tmp_path / "out4.txt"
        sr.write_output_file(out, results, format="text")
        content = out.read_text(encoding="utf-8")
        assert "WARNING: condition always true" in content
        assert "Location: check.yar:8:5" in content
        assert "Suggestion:" not in content


# ---------------------------------------------------------------------------
# metrics_reporting.py — missing branch coverage
# ---------------------------------------------------------------------------


class TestDisplayPatternResultBranches:
    """
    Cover lines 59-62, 66-67:
    - OSError from Path.exists() sets exists=False (line 59-60)
    - non-string argument takes the else branch (line 61-62: exists=False)
    - non-existing string path outputs 'Diagram source:' (line 66-67)
    - existing file outputs 'Pattern diagram generated:' (line 64)
    """

    def test_non_string_argument_shows_diagram_source(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A non-string result_path (e.g. an integer) takes the else-branch at
        line 61 (exists=False) and outputs 'Diagram source:' with the value.
        """
        mr._display_pattern_result(42)  # type: ignore[arg-type]
        captured = capsys.readouterr()
        assert "Diagram source:" in captured.out
        assert "42" in captured.out

    def test_nonexistent_string_path_shows_diagram_source(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A valid string path that does not exist on disk: Path.exists() returns
        False, so line 66-67 ('Diagram source:') is emitted.
        """
        mr._display_pattern_result("/does/not/exist/output.dot")
        captured = capsys.readouterr()
        assert "Diagram source:" in captured.out
        assert "/does/not/exist/output.dot" in captured.out

    def test_os_error_from_overlong_path_shows_diagram_source(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A string whose final component exceeds NAME_MAX (255 bytes on POSIX)
        causes Path.exists() to raise OSError (ENAMETOOLONG).  The except
        branch at line 59 catches it, sets exists=False, and line 66-67
        ('Diagram source:') is emitted.
        """
        # On macOS and Linux a filename component > 255 chars raises OSError
        # from the OS stat syscall, which Path.exists() propagates.
        overlong = "/tmp/" + "a" * 300
        mr._display_pattern_result(overlong)
        captured = capsys.readouterr()
        assert "Diagram source:" in captured.out

    def test_existing_file_shows_generated_message(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        When result_path points to an existing file, Path.exists() returns
        True and line 64 ('Pattern diagram generated:') is emitted.
        """
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            fname = f.name
        try:
            mr._display_pattern_result(fname)
            captured = capsys.readouterr()
            assert "Pattern diagram generated:" in captured.out
            assert fname in captured.out
        finally:
            os.unlink(fname)


class TestDisplayTextPatternAnalysisBranches:
    """
    Cover branches within _display_text_pattern_analysis:
    - line 82->81: rule with empty strings list (if rule.strings is False)
    - line 102-103: StringDefinition base class instance (continue)
    - line 88-89: PlainString.value is bytes (decode branch)
    - line 92: long string value truncation (>30 chars)
    """

    def _gen_and_run(self, yara_file: YaraFile, capsys: pytest.CaptureFixture[str]) -> str:
        """Run _display_text_pattern_analysis with a fresh generator and return stdout."""
        gen = StringDiagramGenerator()
        gen._analyze_patterns(yara_file)
        mr._display_text_pattern_analysis(gen, yara_file)
        return capsys.readouterr().out

    def test_rule_with_no_strings_skips_string_block(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A rule with an empty strings list makes 'if rule.strings' False at
        line 82 (branch 82->81: skip inner loop body).  The summary still
        shows zero counts.
        """
        yara_file = _parse("rule empty_rule { condition: true }")
        assert yara_file.rules[0].strings == []

        output = self._gen_and_run(yara_file, capsys)
        assert "Total strings: 0" in output
        # The rule block header must NOT appear since strings is empty
        assert "Rule: empty_rule" not in output

    def test_base_string_definition_triggers_continue(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A raw StringDefinition (not Plain/Hex/Regex) is inserted into a rule's
        strings list.  The elif at line 102 matches and 'continue' executes
        (line 103), keeping counts at zero.
        """
        rule = Rule(name="test_base_sd")
        rule.strings.append(StringDefinition(identifier="$x"))
        yara_file = YaraFile(rules=[rule])

        gen = StringDiagramGenerator()
        gen._analyze_patterns(yara_file)
        mr._display_text_pattern_analysis(gen, yara_file)
        output = capsys.readouterr().out
        assert "Total strings: 0" in output

    def test_plain_string_with_bytes_value_is_decoded(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A PlainString whose .value is bytes triggers the decode branch at
        lines 88-89.  The displayed value must be the decoded text.
        """
        rule = Rule(name="bytes_rule")
        rule.strings.append(PlainString(identifier="$b", value=b"hello bytes"))
        yara_file = YaraFile(rules=[rule])

        gen = StringDiagramGenerator()
        gen._analyze_patterns(yara_file)
        mr._display_text_pattern_analysis(gen, yara_file)
        output = capsys.readouterr().out
        assert "hello bytes" in output
        assert "Plain strings: 1" in output

    def test_long_plain_string_is_truncated(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        A PlainString value longer than 30 characters is truncated with '...'
        appended (line 92 truthy branch).
        """
        long_value = "x" * 35
        rule = Rule(name="long_rule")
        rule.strings.append(PlainString(identifier="$long", value=long_value))
        yara_file = YaraFile(rules=[rule])

        gen = StringDiagramGenerator()
        gen._analyze_patterns(yara_file)
        mr._display_text_pattern_analysis(gen, yara_file)
        output = capsys.readouterr().out
        assert '..."' in output
        assert long_value not in output  # full value must not appear

    def test_all_string_types_together(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        A YaraFile with plain, hex, and regex strings in one rule exercises
        all three isinstance branches and produces correct summary counts.
        """
        yara_file = _parse(
            'rule mixed {  strings: $p = "hello" $h = {4D 5A} $r = /world/   condition: $p}'
        )
        output = self._gen_and_run(yara_file, capsys)
        assert "Plain strings: 1" in output
        assert "Hex patterns: 1" in output
        assert "Regex patterns: 1" in output
        assert "Total strings: 3" in output

    def test_unknown_string_type_falls_through_all_elif_branches(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        Cover branch 102->84: an object in rule.strings that is not an
        instance of PlainString, HexString, RegexString, or StringDefinition
        causes all four isinstance guards to be False.  The for-loop
        continues to the next iteration without incrementing any counter.

        The object must carry a 'modifiers' attribute (a list) because
        _display_text_pattern_analysis calls generator._analyze_patterns(ast)
        at line 76 which accesses string_def.modifiers during its scan.
        """

        class UnknownStringLike:
            """
            Minimal stand-in that satisfies _analyze_patterns requirements
            (identifier + modifiers) while being none of the known subtypes.
            """

            identifier: str = "$unknown"
            modifiers: list[object] = []

        rule = Rule(name="unknown_type_rule")
        rule.strings.append(UnknownStringLike())  # type: ignore[arg-type]
        yara_file = YaraFile(rules=[rule])

        gen = StringDiagramGenerator()
        mr._display_text_pattern_analysis(gen, yara_file)
        output = capsys.readouterr().out
        # Rule header is printed (rule.strings is truthy)
        assert "Rule: unknown_type_rule" in output
        # No counts incremented since all isinstance checks failed
        assert "Total strings: 0" in output


class TestDisplayPatternStatisticsBranches:
    """
    Cover lines 116->exit and 122->exit:
    - empty dict from get_pattern_statistics() skips the entire block
    - populated dict without 'pattern_lengths' skips the length stats sub-block
    """

    def test_empty_statistics_skips_all_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """
        When get_pattern_statistics() returns an empty dict (falsy), the 'if
        pattern_stats' guard at line 116 is False (branch 116->exit) and no
        statistics output is produced.
        """

        class EmptyStatsGenerator:
            def get_pattern_statistics(self) -> dict[str, object]:
                return {}

        mr._display_pattern_statistics(EmptyStatsGenerator())
        captured = capsys.readouterr()
        assert "Pattern Statistics" not in captured.out

    def test_statistics_without_pattern_lengths_skips_length_block(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        When get_pattern_statistics() returns a populated dict that omits the
        'pattern_lengths' key, the inner guard at line 122 is False (branch
        122->exit) and no 'Length stats' line appears.
        """

        class NoLengthsGenerator:
            def get_pattern_statistics(self) -> dict[str, object]:
                return {
                    "total_patterns": 2,
                    "by_type": {"plain": 2},
                    "complexity_distribution": {"low": 2, "medium": 0, "high": 0},
                }

        mr._display_pattern_statistics(NoLengthsGenerator())
        captured = capsys.readouterr()
        assert "Pattern Statistics" in captured.out
        assert "Total patterns: 2" in captured.out
        assert "Length stats:" not in captured.out

    def test_statistics_with_pattern_lengths_shows_length_block(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        When get_pattern_statistics() returns a dict that includes
        'pattern_lengths', the inner block at lines 123-126 executes.
        """
        gen = StringDiagramGenerator()
        yara_file = _parse('rule check {  strings: $a = "hello" $b = {4D 5A}   condition: $a}')
        gen._analyze_patterns(yara_file)
        mr._display_pattern_statistics(gen)
        captured = capsys.readouterr()
        assert "Length stats:" in captured.out


class TestRequireStringOutputFormatGuards:
    """
    Cover lines 131, 133-134:
    - non-string format raises TypeError
    - unknown string format raises ValueError
    """

    def test_non_string_format_raises_type_error(self) -> None:
        """Line 131: _require_string_output_format rejects non-string input."""
        with pytest.raises(TypeError, match="string analysis output format must be a string"):
            mr._require_string_output_format(None)

    def test_integer_format_raises_type_error(self) -> None:
        """Line 131: integer is not a string."""
        with pytest.raises(TypeError, match="string analysis output format must be a string"):
            mr._require_string_output_format(42)

    def test_unknown_string_format_raises_value_error(self) -> None:
        """Lines 133-134: _require_string_output_format rejects unknown formats."""
        with pytest.raises(
            ValueError, match="string analysis output format must be one of: json, text"
        ):
            mr._require_string_output_format("xml")

    def test_empty_string_format_raises_value_error(self) -> None:
        """Lines 133-134: empty string is not a valid format."""
        with pytest.raises(
            ValueError, match="string analysis output format must be one of: json, text"
        ):
            mr._require_string_output_format("")


class TestRequireStringAnalysisGuard:
    """Cover line 140: _require_string_analysis rejects non-dict input."""

    def test_string_input_raises_type_error(self) -> None:
        """Line 140: a plain string is not a dict."""
        with pytest.raises(TypeError, match="string analysis must be a dictionary"):
            mr._require_string_analysis("not a dict")

    def test_list_input_raises_type_error(self) -> None:
        """Line 140: a list is not a dict."""
        with pytest.raises(TypeError, match="string analysis must be a dictionary"):
            mr._require_string_analysis([1, 2, 3])

    def test_none_input_raises_type_error(self) -> None:
        """Line 140: None is not a dict."""
        with pytest.raises(TypeError, match="string analysis must be a dictionary"):
            mr._require_string_analysis(None)


class TestFormatStringTextBranches:
    """
    Cover lines 175 and 183->186:
    - line 175: modifiers dict is non-empty (truthy) -> extend lines
    - line 183->186: short_strings == 0 (False branch skips short-strings line)
    """

    def test_non_empty_modifiers_renders_modifier_section(self) -> None:
        """Line 175 truthy branch: non-empty modifiers dict generates 'Modifiers:' section."""
        analysis = _build_minimal_analysis(modifiers={"nocase": 3, "wide": 1})
        result = mr._format_strings_text(analysis)
        assert "Modifiers:" in result
        assert "nocase: 3" in result
        assert "wide: 1" in result

    def test_zero_short_strings_skips_short_strings_line(self) -> None:
        """
        Line 183->186: when short_strings == 0 the condition is False and
        'Short strings' is never appended to the output.
        """
        analysis = _build_minimal_analysis(short_strings=0, hex_patterns=0)
        result = mr._format_strings_text(analysis)
        assert "Short strings" not in result
        assert "Hex patterns" not in result

    def test_positive_short_strings_renders_short_strings_line(self) -> None:
        """Line 183 truthy branch: short_strings > 0 appends the short-strings count line."""
        analysis = _build_minimal_analysis(short_strings=5)
        result = mr._format_strings_text(analysis)
        assert "Short strings (<4 chars): 5" in result

    def test_positive_hex_patterns_renders_hex_patterns_line(self) -> None:
        """Line 186 truthy branch: hex_patterns > 0 appends the hex-patterns count line."""
        analysis = _build_minimal_analysis(hex_patterns=2)
        result = mr._format_strings_text(analysis)
        assert "Hex patterns: 2" in result

    def test_format_string_analysis_output_delegates_text(self) -> None:
        """_format_string_analysis_output with format='text' calls _format_strings_text."""
        analysis = _build_minimal_analysis()
        result = mr._format_string_analysis_output(analysis, "text")
        assert "YARA String Analysis" in result

    def test_format_string_analysis_output_delegates_json(self) -> None:
        """_format_string_analysis_output with format='json' returns JSON."""
        analysis = _build_minimal_analysis()
        result = mr._format_string_analysis_output(analysis, "json")
        assert '"total_strings"' in result
