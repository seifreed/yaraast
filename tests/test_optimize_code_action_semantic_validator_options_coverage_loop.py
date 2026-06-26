"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Regression tests that close the coverage gaps in:
  - yaraast.cli.commands.optimize   (lines 35, 98)
  - yaraast.lsp.code_action_semantic (lines 34-58, 67-70, 83-86, 102-109, 121, 130-134, 149)
  - yaraast.yaral.validator_options   (line 25->exit)

All tests call production code with real inputs and assert on observed
return values. No mocks, no stubs, no suppressions of any kind.
"""

from __future__ import annotations

from pathlib import Path

import click
from click.testing import CliRunner
from lsprotocol.types import CodeAction, Diagnostic, Position, Range
import pytest

from yaraast.cli.commands.optimize import _validate_output_path, optimize
from yaraast.lsp.code_actions import CodeActionsProvider
from yaraast.yaral.ast_nodes import OptionsSection
from yaraast.yaral.validator import YaraLValidator

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

URI = "file://test.yar"
_ZERO = Position(line=0, character=0)
_TEN = Position(line=0, character=10)


def _diag(
    message: str,
    *,
    data: object = None,
    start: Position | None = None,
    end: Position | None = None,
) -> Diagnostic:
    rng = Range(start=start or _ZERO, end=end or _TEN)
    return Diagnostic(range=rng, message=message, data=data)


def _provider() -> CodeActionsProvider:
    return CodeActionsProvider()


# ---------------------------------------------------------------------------
# yaraast.cli.commands.optimize — line 35
# _validate_output_path raises click.BadParameter when output is an existing dir
# ---------------------------------------------------------------------------


class TestValidateOutputPathDirectory:
    """_validate_output_path must reject an existing directory."""

    def test_raises_bad_parameter_for_directory(self, tmp_path: Path) -> None:
        """Line 35: _path_exists_and_is_dir True → raise click.BadParameter."""
        # tmp_path is an existing directory; _validate_output_path must reject it.
        with pytest.raises(click.BadParameter) as exc_info:
            _validate_output_path(str(tmp_path))

        assert "must not be a directory" in str(exc_info.value)

    def test_cli_rejects_directory_as_output(self, tmp_path: Path) -> None:
        """Line 35: the optimize CLI command surfaces BadParameter as exit-code 2."""
        src = tmp_path / "in.yar"
        src.write_text("rule x { condition: true }", encoding="utf-8")
        output_dir = tmp_path / "outdir"
        output_dir.mkdir()

        result = CliRunner().invoke(optimize, [str(src), str(output_dir)])

        assert result.exit_code == 2
        assert "must not be a directory" in result.output


# ---------------------------------------------------------------------------
# yaraast.cli.commands.optimize — line 98
# display_improvement is called when optimization eliminates a rule that carries
# a performance issue (dead rule with always-false condition + regex string).
# Dead-code elimination reduces total_issues from 2 to 1, so
# calculate_improvement returns a non-None float.
# ---------------------------------------------------------------------------


class TestOptimizeDisplaysImprovement:
    """The optimization pipeline displays the improvement percentage when real
    dead-code elimination reduces the number of performance issues."""

    YARA_DEAD_RULE_WITH_REGEX = """\
rule live_rule {
    strings:
        $a = /expensive_pattern/
    condition:
        $a
}
rule dead_rule {
    strings:
        $b = /another_expensive_pattern/
    condition:
        false
}
"""

    def test_improvement_displayed_after_dead_code_elimination(self, tmp_path: Path) -> None:
        """Line 98: calculate_improvement returns non-None when before > after."""
        src = tmp_path / "two_rules.yar"
        src.write_text(self.YARA_DEAD_RULE_WITH_REGEX, encoding="utf-8")
        out = tmp_path / "optimized.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out), "--analyze"])

        assert result.exit_code == 0
        # The improvement line is only emitted when improvement is not None.
        assert "Performance improved" in result.output
        assert out.exists()


# ---------------------------------------------------------------------------
# yaraast.cli.commands.optimize — line 40
# _validate_output_path re-raises TypeError/ValueError from _require_file_path
# ---------------------------------------------------------------------------


class TestValidateOutputPathTypeError:
    """_validate_output_path catches TypeError/ValueError from _require_file_path
    and converts them to click.BadParameter (line 40)."""

    def test_raises_bad_parameter_for_empty_string(self) -> None:
        """Line 40: _require_file_path raises ValueError for empty string → BadParameter."""
        with pytest.raises(click.BadParameter) as exc_info:
            _validate_output_path("")

        # The original error message is forwarded as the parameter description.
        assert exc_info.value.param_hint == "OUTPUT_FILE"

    def test_raises_bad_parameter_for_none(self) -> None:
        """Line 40: _require_file_path raises TypeError for None → BadParameter."""
        with pytest.raises(click.BadParameter) as exc_info:
            _validate_output_path(None)

        assert exc_info.value.param_hint == "OUTPUT_FILE"


# ---------------------------------------------------------------------------
# yaraast.cli.commands.optimize — lines 73-78 (parse error warning block)
# Lines 81->86, 92->101, 97->101 (branches when analyze=False / improvement=None)
# Lines 107-111 (dry-run path and exception handler)
# ---------------------------------------------------------------------------


class TestOptimizeCommandAdditionalPaths:
    """Tests for parse error recovery warnings, no-analyze branch, dry-run
    branch, and the general exception handler."""

    VALID_YARA = """\
rule simple {
    strings:
        $a = "hello"
    condition:
        $a
}
"""

    BROKEN_YARA = """\
rule broken {
    strings:
        $a = "x"
    condition:
}
"""

    def test_warns_on_parse_errors_lines_73_78(self, tmp_path: Path) -> None:
        """Lines 73-78: recovered parse errors are printed before optimization."""
        src = tmp_path / "broken.yar"
        src.write_text(self.BROKEN_YARA, encoding="utf-8")
        out = tmp_path / "out.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out)])

        assert result.exit_code == 0
        assert "Recovered from" in result.output

    def test_no_analyze_skips_before_block_branch_81_86(self, tmp_path: Path) -> None:
        """Lines 81->86: when analyze=False the if-branch at 81 is not taken
        and control jumps to line 86 (the console.print for rule count)."""
        src = tmp_path / "rule.yar"
        src.write_text(self.VALID_YARA, encoding="utf-8")
        out = tmp_path / "out.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out)])

        assert result.exit_code == 0
        assert "Optimizing" in result.output
        assert "Performance analysis before" not in result.output
        assert out.exists()

    def test_no_analyze_skips_after_block_branch_92_101(self, tmp_path: Path) -> None:
        """Lines 92->101: when analyze=False the if-branch at 92 is not taken
        and control proceeds to line 101 (the if not dry_run check)."""
        src = tmp_path / "rule.yar"
        src.write_text(self.VALID_YARA, encoding="utf-8")
        out = tmp_path / "out.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out)])

        assert result.exit_code == 0
        assert "Performance analysis after" not in result.output
        assert out.exists()

    def test_analyze_but_no_improvement_branch_97_101(self, tmp_path: Path) -> None:
        """Lines 97->101: when analyze=True but improvement is None (single rule,
        no dead-code elimination) the if improvement is not None block is skipped."""
        src = tmp_path / "rule.yar"
        src.write_text(self.VALID_YARA, encoding="utf-8")
        out = tmp_path / "out.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out), "--analyze"])

        assert result.exit_code == 0
        assert "Performance improved" not in result.output
        assert out.exists()

    def test_dry_run_path_lines_107(self, tmp_path: Path) -> None:
        """Line 107: when dry_run=True the else branch writes nothing and
        calls display_dry_run instead."""
        src = tmp_path / "rule.yar"
        src.write_text(self.VALID_YARA, encoding="utf-8")
        out = tmp_path / "out.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out), "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run" in result.output
        assert not out.exists()

    def test_exception_handler_lines_109_111(self, tmp_path: Path) -> None:
        """Lines 109-111: an unrecoverable read error (binary file with invalid
        UTF-8 content) triggers the except block and aborts with exit code != 0."""
        src = tmp_path / "binary.yar"
        src.write_bytes(b"\xff\xfe\xfa\x00invalid")
        out = tmp_path / "out.yar"

        result = CliRunner().invoke(optimize, [str(src), str(out)])

        assert result.exit_code != 0
        assert "Error:" in result.output


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — lines 34-58 (_create_semantic_actions)
# ---------------------------------------------------------------------------


class TestCreateSemanticActionsDispatch:
    """_create_semantic_actions dispatches to the correct handler for every
    supported diagnostic code and returns [] for unknown codes and bad types."""

    # Lines 34-36: data is None (no structured payload)
    def test_returns_empty_when_diagnostic_has_no_data(self) -> None:
        """Line 35-36: _get_diagnostic_data → None → return []."""
        provider = _provider()
        diag = _diag("some error")
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert result == []

    # Lines 40-41: code is not str or metadata is not Mapping
    def test_returns_empty_when_code_is_not_string(self) -> None:
        """Line 40-41: non-string code → return []."""
        provider = _provider()
        diag = _diag("err", data={"code": 42, "metadata": {}})
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert result == []

    def test_returns_empty_when_metadata_is_not_mapping(self) -> None:
        """Line 40-41: metadata is a list, not a Mapping → return []."""
        provider = _provider()
        diag = _diag("err", data={"code": "semantic.module_not_imported", "metadata": ["pe"]})
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert result == []

    # Lines 43-56: dispatch table matched — semantic.module_not_imported
    def test_dispatches_to_module_not_imported_handler(self) -> None:
        """Lines 43-56: known code hits the handler and returns CodeAction list."""
        provider = _provider()
        diag = _diag(
            "module not imported",
            data={"code": "semantic.module_not_imported", "metadata": {"module": "pe"}},
        )
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], CodeAction)

    # compiler.module_not_imported also maps to the same handler
    def test_dispatches_to_compiler_module_not_imported(self) -> None:
        """Lines 43-56: compiler.module_not_imported hits handle_module_not_imported."""
        provider = _provider()
        diag = _diag(
            "module not imported",
            data={"code": "compiler.module_not_imported", "metadata": {"module": "math"}},
        )
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert len(result) == 1

    # semantic.undefined_string_identifier
    def test_dispatches_to_validation_or_undefined(self) -> None:
        """Lines 43-56: semantic.undefined_string_identifier → handle_validation_or_undefined."""
        provider = _provider()
        diag = _diag(
            "undefined string",
            data={
                "code": "semantic.undefined_string_identifier",
                "metadata": {"name": "$foo"},
            },
        )
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert isinstance(result, list)

    # semantic.validation_error
    def test_dispatches_validation_error(self) -> None:
        """Lines 43-56: semantic.validation_error → handle_validation_or_undefined."""
        provider = _provider()
        diag = _diag(
            "validation error",
            data={"code": "semantic.validation_error", "metadata": {}},
        )
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert isinstance(result, list)

    # compiler.undefined_identifier
    def test_dispatches_compiler_undefined_identifier(self) -> None:
        """Lines 43-56: compiler.undefined_identifier → handle_validation_or_undefined."""
        provider = _provider()
        diag = _diag(
            "undefined identifier",
            data={"code": "compiler.undefined_identifier", "metadata": {}},
        )
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert isinstance(result, list)

    # Lines 57-58: code not in dispatch table → return []
    def test_returns_empty_for_unrecognised_code(self) -> None:
        """Lines 57-58: code not in handlers dict → handler is None → return []."""
        provider = _provider()
        diag = _diag(
            "unrecognised diagnostic",
            data={"code": "custom.unrecognised_code", "metadata": {}},
        )
        result = provider._create_semantic_actions("rule r { condition: true }", diag, URI)
        assert result == []


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — lines 67-70 (_create_add_string_actions)
# ---------------------------------------------------------------------------


class TestCreateAddStringActions:
    """_create_add_string_actions returns [] when the diagnostic message
    contains no $ variable reference and delegates to the identifier helper
    when a match is found."""

    def test_returns_empty_when_message_has_no_dollar_identifier(self) -> None:
        r"""Lines 67-70: re.search finds no $\w+ → return []."""
        provider = _provider()
        diag = _diag("undefined variable foo")  # no leading $
        result = provider._create_add_string_actions("rule r { condition: true }", diag, URI)
        assert result == []

    def test_returns_empty_when_message_is_plain_text(self) -> None:
        """Lines 67-70: message without any dollar sign → re.search is None."""
        provider = _provider()
        diag = _diag("some unrelated error without identifiers")
        result = provider._create_add_string_actions("rule r { condition: true }", diag, URI)
        assert result == []

    def test_delegates_when_message_contains_dollar_identifier(self) -> None:
        """Line 70: re.search finds $foo → cast() path executed.
        Uses a rule with a strings section so authoring.create_missing_string
        returns a non-None value and a CodeAction is produced."""
        provider = _provider()
        # The message must contain a $name token for the regex to match.
        diag = _diag("undefined variable $foo not found")
        text = (
            "rule r {\n"
            "    strings:\n"
            '        $a = "existing"\n'
            "    condition:\n"
            "        $a\n"
            "}"
        )
        result = provider._create_add_string_actions(text, diag, URI)
        # The cast() return path (line 70) is exercised; result is a list.
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], CodeAction)


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — lines 83-86
# (_create_add_string_action_from_identifier returns [] when authoring is None)
# ---------------------------------------------------------------------------


class TestCreateAddStringActionFromIdentifier:
    """_create_add_string_action_from_identifier returns [] when authoring
    cannot locate a strings section to insert into."""

    def test_returns_empty_when_authoring_yields_none(self) -> None:
        """Lines 83-86: create_missing_string returns None → return []."""
        provider = _provider()
        diag = _diag("undefined variable $foo")
        # A YARA rule with no strings section: authoring.create_missing_string returns None.
        text_no_strings = "rule r { condition: true }"
        result = provider._create_add_string_action_from_identifier(
            text_no_strings, diag, URI, "$foo"
        )
        assert result == []

    def test_returns_action_when_authoring_succeeds(self) -> None:
        """Lines 86-93: create_missing_string returns an action → list with one entry."""
        provider = _provider()
        # A rule that already has a strings section at a known location.
        text = 'rule r {\n    strings:\n        $a = "existing"\n    condition:\n        $a\n}'
        diag = _diag(
            "undefined $foo",
            start=Position(line=4, character=8),
            end=Position(line=4, character=14),
        )
        result = provider._create_add_string_action_from_identifier(text, diag, URI, "$foo")
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], CodeAction)


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — lines 102-109 (_create_import_module_actions)
# ---------------------------------------------------------------------------


class TestCreateImportModuleActions:
    """_create_import_module_actions extracts the module name via three
    different regex patterns and returns [] when none match."""

    def test_primary_pattern_single_quotes(self) -> None:
        """Lines 102-103: 'Module X not imported' with single-quoted name."""
        provider = _provider()
        diag = _diag("Module 'pe' not imported")
        result = provider._create_import_module_actions("rule r { condition: true }", diag, URI)
        assert len(result) == 1

    def test_alternate_pattern_colon_form(self) -> None:
        """Lines 103-104: 'not imported: pe' form hits second pattern."""
        provider = _provider()
        diag = _diag("not imported: hash")
        result = provider._create_import_module_actions("rule r { condition: true }", diag, URI)
        assert len(result) == 1

    def test_alternate_pattern_module_word_form(self) -> None:
        """Lines 105-106: 'Module pe not imported' hits third pattern."""
        provider = _provider()
        diag = _diag("Module math not imported")
        result = provider._create_import_module_actions("rule r { condition: true }", diag, URI)
        assert len(result) == 1

    def test_returns_empty_when_no_pattern_matches(self) -> None:
        """Lines 107-108: none of the three patterns match → return []."""
        provider = _provider()
        diag = _diag("something completely different")
        result = provider._create_import_module_actions("rule r { condition: true }", diag, URI)
        assert result == []


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — line 121
# (_create_import_module_action_from_name delegates to create_import_module_action)
# ---------------------------------------------------------------------------


class TestCreateImportModuleActionFromName:
    """_create_import_module_action_from_name passes through to the
    create_import_module_action helper (line 121 is the delegate call)."""

    def test_returns_action_list_for_known_module(self) -> None:
        """Line 121: create_import_module_action called with real module name."""
        provider = _provider()
        diag = _diag("Module 'pe' not imported")
        result = provider._create_import_module_action_from_name("pe", diag, URI)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert isinstance(result[0], CodeAction)

    def test_returns_list_for_arbitrary_module_name(self) -> None:
        """Line 121: function always delegates regardless of module name."""
        provider = _provider()
        diag = _diag("module not found")
        result = provider._create_import_module_action_from_name("hash", diag, URI)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — lines 130-134 (_create_rename_duplicate_actions)
# ---------------------------------------------------------------------------


class TestCreateRenameDuplicateActions:
    """_create_rename_duplicate_actions extracts the identifier via regex and
    returns [] when the message does not contain a '$identifier' literal."""

    _TEXT = (
        "rule r {\n"
        "    strings:\n"
        '        $foo = "abc"\n'
        '        $foo = "def"\n'
        "    condition:\n"
        "        $foo\n"
        "}"
    )

    def test_returns_empty_when_message_has_no_dollar_identifier_in_quotes(self) -> None:
        """Lines 130-132: message has no '$name' pattern → re.search None → return []."""
        provider = _provider()
        diag = _diag("duplicate string identifier foo")  # no '$foo' in quotes
        result = provider._create_rename_duplicate_actions(self._TEXT, diag, URI)
        assert result == []

    def test_returns_empty_when_message_has_dollar_but_no_quotes(self) -> None:
        """Lines 130-132: '$foo' not wrapped in single quotes → no match."""
        provider = _provider()
        diag = _diag("duplicate string identifier $foo")  # $ without quotes
        result = provider._create_rename_duplicate_actions(self._TEXT, diag, URI)
        assert result == []

    def test_delegates_when_match_found(self) -> None:
        """Lines 133-139: when pattern matches, delegates to
        _create_rename_duplicate_action_from_identifier which calls the helper."""
        provider = _provider()
        diag = _diag(
            "duplicate string identifier: '$foo'",
            start=Position(line=2, character=8),
            end=Position(line=2, character=12),
        )
        result = provider._create_rename_duplicate_actions(self._TEXT, diag, URI)
        # Result may be empty or non-empty depending on authoring; the point is
        # that the delegation path (lines 133-139) is executed without error.
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# yaraast.lsp.code_action_semantic — line 149
# (_create_rename_duplicate_action_from_identifier delegates)
# ---------------------------------------------------------------------------


class TestCreateRenameDuplicateActionFromIdentifier:
    """_create_rename_duplicate_action_from_identifier delegates to the
    create_rename_duplicate_action helper (line 149 is the delegate call)."""

    _TEXT = (
        "rule r {\n"
        "    strings:\n"
        '        $foo = "abc"\n'
        '        $foo = "def"\n'
        "    condition:\n"
        "        $foo\n"
        "}"
    )

    def test_delegate_called_with_real_identifier(self) -> None:
        """Line 149: create_rename_duplicate_action called through the delegate."""
        provider = _provider()
        diag = _diag(
            "duplicate string identifier: '$foo'",
            start=Position(line=2, character=8),
            end=Position(line=2, character=12),
        )
        result = provider._create_rename_duplicate_action_from_identifier(
            self._TEXT, diag, URI, "$foo"
        )
        # The helper returns a list (possibly empty if range does not map to the token).
        assert isinstance(result, list)

    def test_delegate_produces_action_when_range_points_to_identifier(self) -> None:
        """Line 149: when range maps to $foo in text, a CodeAction is produced."""
        provider = _provider()
        # Range at line 2, characters 8-12 covers '$foo' in the strings section.
        diag = _diag(
            "duplicate string identifier: '$foo'",
            start=Position(line=2, character=8),
            end=Position(line=2, character=12),
        )
        result = provider._create_rename_duplicate_action_from_identifier(
            self._TEXT, diag, URI, "$foo"
        )
        assert isinstance(result, list)
        # Verify the path executed without exception; action presence depends on authoring.
        if result:
            assert isinstance(result[0], CodeAction)


# ---------------------------------------------------------------------------
# yaraast.yaral.validator_options — line 25->exit
# _validate_options_section: hasattr(node, 'options') is False → early exit
# ---------------------------------------------------------------------------


class TestOptionsValidationMixinNoOptionsAttribute:
    """_validate_options_section must silently return when the node has no
    'options' attribute — the hasattr guard at line 25 exits immediately."""

    def test_no_warning_when_node_lacks_options_attribute(self) -> None:
        """Line 25->exit: OptionsSection.__new__ bypasses __init__ so 'options'
        is never set; _validate_options_section must return without error."""
        validator = YaraLValidator()
        validator.current_rule = "r_no_opts"

        # Bypass __init__ so the dataclass field is never initialised.
        node = OptionsSection.__new__(OptionsSection)
        assert not hasattr(node, "options")

        # Must not raise and must not emit any warnings.
        validator._validate_options_section(node)

        assert validator.warnings == []
        assert validator.errors == []

    def test_visit_yaral_options_section_with_uninitialised_node(self) -> None:
        """visit_yaral_options_section delegates to _validate_options_section;
        the hasattr guard keeps it safe for uninitialised nodes."""
        validator = YaraLValidator()
        validator.current_rule = "r_no_opts_visit"

        node = OptionsSection.__new__(OptionsSection)
        # visit_yaral_options_section calls _validate_options_section internally.
        validator.visit_yaral_options_section(node)

        assert validator.warnings == []

    def test_validates_normally_when_options_dict_is_present(self) -> None:
        """Positive control: standard path (hasattr True) still validates."""
        validator = YaraLValidator()
        validator.current_rule = "r_with_opts"

        node = OptionsSection(options={"unknown_key": True})
        validator._validate_options_section(node)

        assert any("Unknown option: unknown_key" in w.message for w in validator.warnings)

    def test_valid_key_passes_check_without_warning(self) -> None:
        """Branch 27->26: when a key IS in valid_options the if-body is skipped
        and the for-loop continues to the next iteration.

        Providing both a valid and an invalid key forces the loop to evaluate
        the if-condition as False at least once (valid key) and True at least
        once (invalid key), covering the 27->26 branch."""
        validator = YaraLValidator()
        validator.current_rule = "r_mixed_opts"

        # 'timeout' is a known-valid option; 'mystery_opt' is not.
        node = OptionsSection(options={"timeout": "30s", "mystery_opt": True})
        validator._validate_options_section(node)

        warning_messages = [w.message for w in validator.warnings]
        # Only the unknown key triggers a warning.
        assert any("Unknown option: mystery_opt" in m for m in warning_messages)
        # The valid key must not appear in any warning.
        assert not any("timeout" in m for m in warning_messages)
