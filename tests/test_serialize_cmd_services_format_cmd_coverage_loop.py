# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage regression tests for serialize CLI commands and format_cmd.

Targets three modules that had coverage gaps:
  - yaraast/cli/commands/serialize.py
  - yaraast/cli/serialize_command_services.py
  - yaraast/cli/commands/format_cmd.py

Every test executes real production code through the CLI API or by direct
function call where the CLI is not the entry point for the missing path.
No mocking of the modules under test; monkeypatching is used only where the
production code itself calls into an *external* module whose failure is the
scenario being exercised (e.g. diff_serialized raising ImportError).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import click
from click.testing import CliRunner
import pytest

from yaraast.cli.commands.format_cmd import (
    _validate_output_file,
    format_yara,
    validate_syntax,
)
import yaraast.cli.commands.serialize as ser_mod
from yaraast.cli.commands.serialize import serialize
from yaraast.cli.serialize_command_services import (
    build_diff_output_path,
    diff_serialized,
    validate_serialized_input,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_SIMPLE_RULE = "rule x { condition: true }"
_EXTRA_RULE = "rule y { condition: false }"


def _write_yara(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _export_json(runner: CliRunner, yar_path: Path, json_path: Path) -> None:
    result = runner.invoke(
        serialize,
        ["export", str(yar_path), "-f", "json", "-o", str(json_path)],
    )
    assert result.exit_code == 0, f"Export failed: {result.output}"


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — import command with -o output (line 102)
# ---------------------------------------------------------------------------


class TestSerializeImportWithOutputPath:
    """Cover the generate_yara_from_ast branch executed when -o is given."""

    def test_import_with_output_writes_yara_file(self, tmp_path: Path) -> None:
        """import -o must write a YARA file when output path is supplied."""
        # Arrange
        runner = CliRunner()
        yar_in = _write_yara(tmp_path / "src.yar", _SIMPLE_RULE)
        json_out = tmp_path / "src.json"
        yar_out = tmp_path / "restored.yar"
        _export_json(runner, yar_in, json_out)

        # Act
        result = runner.invoke(
            serialize,
            ["import", str(json_out), "-f", "json", "-o", str(yar_out)],
        )

        # Assert — exit 0, output file present, contains rule name
        assert result.exit_code == 0
        assert yar_out.exists()
        content = yar_out.read_text(encoding="utf-8")
        assert "rule x" in content

    def test_import_with_output_abort_on_invalid_serialized_file(self, tmp_path: Path) -> None:
        """import raises Abort (exit 1) when the serialized file is invalid JSON."""
        # Arrange
        runner = CliRunner()
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{corrupted}", encoding="utf-8")
        yar_out = tmp_path / "out.yar"

        # Act
        result = runner.invoke(
            serialize,
            ["import", str(bad_json), "-f", "json", "-o", str(yar_out)],
        )

        # Assert — non-zero exit, no output YARA file created
        assert result.exit_code != 0
        assert not yar_out.exists()


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — import exception path (lines 106-108)
# ---------------------------------------------------------------------------


class TestSerializeImportExceptionPath:
    """Cover the except-block in import_ast command (lines 106-108)."""

    def test_import_invalid_json_prints_error_and_aborts(self, tmp_path: Path) -> None:
        """import with unparseable JSON must print an error and abort."""
        # Arrange
        runner = CliRunner()
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json at all}", encoding="utf-8")

        # Act
        result = runner.invoke(
            serialize,
            ["import", str(bad), "-f", "json"],
        )

        # Assert
        assert result.exit_code != 0
        assert "Error" in result.output or "Invalid" in result.output


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — diff no-changes path (lines 149-150)
# ---------------------------------------------------------------------------


class TestSerializeDiffNoChanges:
    """Cover display_diff_no_changes + early return when files are identical."""

    def test_diff_identical_files_reports_no_changes(self, tmp_path: Path) -> None:
        """diff on two identical YARA files must exit 0 and report no differences."""
        # Arrange
        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE)

        # Act
        result = runner.invoke(serialize, ["diff", str(f1), str(f2)])

        # Assert
        assert result.exit_code == 0
        assert "No differences" in result.output or "identical" in result.output.lower()

    def test_diff_identical_files_does_not_write_output(self, tmp_path: Path) -> None:
        """diff with no changes must not create an output file even when -o is given."""
        # Arrange
        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE)
        out = tmp_path / "diff.json"

        # Act
        result = runner.invoke(serialize, ["diff", str(f1), str(f2), "-o", str(out)])

        # Assert — command succeeds and does NOT write the diff file (early return)
        assert result.exit_code == 0
        assert not out.exists()


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — diff with output / patch (lines 153-161)
# ---------------------------------------------------------------------------


class TestSerializeDiffOutputPaths:
    """Cover the output/patch branches in the diff command."""

    def test_diff_with_output_writes_json_diff(self, tmp_path: Path) -> None:
        """diff -o writes a JSON diff file when files differ."""
        # Arrange
        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)
        diff_out = tmp_path / "diff.json"

        # Act
        result = runner.invoke(
            serialize,
            ["diff", str(f1), str(f2), "-o", str(diff_out)],
        )

        # Assert
        assert result.exit_code == 0
        assert diff_out.exists()
        assert "Diff saved" in result.output or "saved" in result.output.lower()

    def test_diff_with_patch_flag_writes_patch_file(self, tmp_path: Path) -> None:
        """diff --patch writes a patch file containing patch_format key."""
        # Arrange
        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)
        patch_out = tmp_path / "patch.json"

        # Act
        result = runner.invoke(
            serialize,
            ["diff", str(f1), str(f2), "--patch", "-o", str(patch_out)],
        )

        # Assert
        import json

        assert result.exit_code == 0
        assert patch_out.exists()
        data = json.loads(patch_out.read_text(encoding="utf-8"))
        assert data.get("patch_format") == "yaraast-diff-v1"
        assert "Patch file created" in result.output or "Patch" in result.output

    def test_diff_with_patch_flag_without_output_uses_default_path(self, tmp_path: Path) -> None:
        """diff --patch without -o derives the patch path automatically."""
        # Arrange
        runner = CliRunner()
        f1 = _write_yara(tmp_path / "v1.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "v2.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)

        # Act — run from tmp_path so the generated file lands there
        import os

        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(serialize, ["diff", str(f1), str(f2), "--patch"])
        finally:
            os.chdir(cwd)

        # Assert
        assert result.exit_code == 0
        assert "Patch file created" in result.output or "Patch" in result.output


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — diff ImportError yaml path (lines 163-170)
# ---------------------------------------------------------------------------


class TestSerializeDiffImportErrorPaths:
    """Cover the ImportError handler and generic exception handler in diff."""

    def test_diff_yaml_import_error_prints_error_and_aborts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When yaml is missing and format=yaml, diff prints error and aborts."""

        # Arrange — make diff_serialized raise ImportError(name='yaml')
        def raise_yaml_import(*_args: Any, **_kwargs: Any) -> None:
            err = ImportError("No module named 'yaml'")
            err.name = "yaml"
            raise err

        monkeypatch.setattr(ser_mod, "diff_serialized", raise_yaml_import)

        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)
        out = tmp_path / "diff.yaml"

        # Act
        result = runner.invoke(
            serialize,
            ["diff", str(f1), str(f2), "-f", "yaml", "-o", str(out)],
        )

        # Assert
        assert result.exit_code != 0
        assert "Error" in result.output or "yaml" in result.output.lower()

    def test_diff_non_yaml_import_error_reraises(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ImportError with name='yaml' but format='json' must not be absorbed."""

        # Arrange — same ImportError but format mismatch triggers re-raise
        def raise_yaml_import(*_args: Any, **_kwargs: Any) -> None:
            err = ImportError("No module named 'yaml'")
            err.name = "yaml"
            raise err

        monkeypatch.setattr(ser_mod, "diff_serialized", raise_yaml_import)

        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)

        # Act
        result = runner.invoke(
            serialize,
            ["diff", str(f1), str(f2), "-f", "json", "-o", str(tmp_path / "out.json")],
        )

        # Assert — the ImportError propagates; Click wraps it as exit 1
        assert result.exit_code != 0
        assert isinstance(result.exception, ImportError)

    def test_diff_generic_exception_prints_error_and_aborts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Any non-ImportError from diff_serialized triggers the generic handler."""

        # Arrange
        def raise_runtime(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("unexpected failure")

        monkeypatch.setattr(ser_mod, "diff_serialized", raise_runtime)

        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)

        # Act
        result = runner.invoke(serialize, ["diff", str(f1), str(f2)])

        # Assert
        assert result.exit_code != 0
        assert "Error" in result.output or "unexpected failure" in result.output


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — validate exception path (lines 199-204)
# ---------------------------------------------------------------------------


class TestSerializeValidateExceptionPath:
    """Cover the except-block inside the validate command."""

    def test_validate_invalid_json_shows_error_panel(self, tmp_path: Path) -> None:
        """validate on a corrupt JSON file must show an error panel and abort."""
        # Arrange
        runner = CliRunner()
        bad = tmp_path / "bad.json"
        bad.write_text("{corrupted json}", encoding="utf-8")

        # Act
        result = runner.invoke(serialize, ["validate", str(bad), "-f", "json"])

        # Assert — exits non-zero and shows some validation result panel
        assert result.exit_code != 0
        assert "Validation Result" in result.output or "Invalid" in result.output


# ---------------------------------------------------------------------------
# yaraast/cli/commands/serialize.py  — info exception path (lines 224-226)
# ---------------------------------------------------------------------------


class TestSerializeInfoExceptionPath:
    """Cover the except-block inside the info command."""

    def test_info_on_broken_yara_prints_error_and_aborts(self, tmp_path: Path) -> None:
        """info on a syntactically broken YARA file must print an error and abort."""
        # Arrange
        runner = CliRunner()
        broken = tmp_path / "broken.yar"
        broken.write_text("rule broken_rule {", encoding="utf-8")

        # Act
        result = runner.invoke(serialize, ["info", str(broken)])

        # Assert
        assert result.exit_code != 0
        assert "Error" in result.output


# ---------------------------------------------------------------------------
# yaraast/cli/serialize_command_services.py  — diff_serialized no-changes (line 27)
# ---------------------------------------------------------------------------


class TestDiffSerializedNoChanges:
    """Cover the early-return path in diff_serialized when files are identical."""

    def test_diff_serialized_returns_early_on_identical_files(self, tmp_path: Path) -> None:
        """diff_serialized must return (differ, result, None) without calling display functions."""
        # Arrange
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE)

        # Act
        differ, diff_result, extra = diff_serialized(str(f1), str(f2), stats=False)

        # Assert — no changes, early return path
        assert not diff_result.has_changes
        assert extra is None
        assert differ is not None


# ---------------------------------------------------------------------------
# yaraast/cli/serialize_command_services.py  — stats=False branch (32->35)
# ---------------------------------------------------------------------------


class TestDiffSerializedStatsBranch:
    """Cover the stats branch in diff_serialized when stats=False."""

    def test_diff_serialized_with_changes_and_no_stats_skips_statistics(
        self, tmp_path: Path
    ) -> None:
        """When files differ but stats=False, statistics display is not called."""
        # Arrange
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)

        # Act
        differ, diff_result, extra = diff_serialized(str(f1), str(f2), stats=False)

        # Assert
        assert diff_result.has_changes
        assert extra is None
        assert differ is not None

    def test_diff_serialized_with_changes_and_stats_calls_statistics(self, tmp_path: Path) -> None:
        """When files differ and stats=True, statistics display is exercised."""
        # Arrange
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)

        # Act — stats=True covers the if-stats branch
        _differ, diff_result, extra = diff_serialized(str(f1), str(f2), stats=True)

        # Assert
        assert diff_result.has_changes
        assert extra is None


# ---------------------------------------------------------------------------
# yaraast/cli/serialize_command_services.py  — bytes __fspath__ guard (lines 51-52)
# ---------------------------------------------------------------------------


class TestBuildDiffOutputPathBytesGuard:
    """Cover defensive guards in build_diff_output_path."""

    def test_rejects_bytes_fspath(self) -> None:
        """A PathLike whose __fspath__ returns bytes must raise TypeError (lines 51-52)."""

        class BytesPathLike:
            def __fspath__(self) -> bytes:
                return b"some_bytes_path"

        with pytest.raises(TypeError, match="output path must be a file path"):
            build_diff_output_path("old.yar", "new.yar", cast(Any, BytesPathLike()), "json")

    def test_rejects_bool_output(self) -> None:
        """A bool output must raise TypeError (lines 47-48)."""
        with pytest.raises(TypeError, match="output path must be a file path"):
            build_diff_output_path("old.yar", "new.yar", cast(Any, True), "json")

    def test_rejects_integer_output(self) -> None:
        """A non-path integer output must raise TypeError (lines 47-48)."""
        with pytest.raises(TypeError, match="output path must be a file path"):
            build_diff_output_path("old.yar", "new.yar", cast(Any, 42), "json")

    def test_rejects_empty_string_output(self) -> None:
        """An empty string output must raise ValueError (lines 54-55)."""
        with pytest.raises(ValueError, match="output path must not be empty"):
            build_diff_output_path("old.yar", "new.yar", "", "json")

    def test_rejects_whitespace_string_output(self) -> None:
        """A whitespace-only string output must raise ValueError (lines 54-55)."""
        with pytest.raises(ValueError, match="output path must not be empty"):
            build_diff_output_path("old.yar", "new.yar", "   ", "json")

    def test_rejects_directory_output(self, tmp_path: Path) -> None:
        """An existing directory output must raise ValueError (lines 58-59)."""
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        with pytest.raises(ValueError, match="output path must not be a directory"):
            build_diff_output_path("old.yar", "new.yar", output_dir, "json")


# ---------------------------------------------------------------------------
# yaraast/cli/serialize_command_services.py  — validate_serialized_input (lines 64-66)
# ---------------------------------------------------------------------------


class TestValidateSerializedInput:
    """Cover validate_serialized_input success path."""

    def test_validate_serialized_input_returns_ast_and_panel(self, tmp_path: Path) -> None:
        """validate_serialized_input must return (YaraFile, Panel) on valid input."""
        # Arrange — export a valid YARA file to JSON first
        runner = CliRunner()
        yar = _write_yara(tmp_path / "rule.yar", _SIMPLE_RULE)
        json_out = tmp_path / "rule.json"
        _export_json(runner, yar, json_out)

        # Act — call directly without the CLI layer
        ast, panel = validate_serialized_input(str(json_out), "json")

        # Assert
        assert ast is not None
        assert hasattr(ast, "rules")
        # Panel must be a Rich Panel (has a title attribute)
        from rich.panel import Panel

        assert isinstance(panel, Panel)


# ---------------------------------------------------------------------------
# yaraast/cli/commands/format_cmd.py  — _validate_output_file directory (line 31)
# ---------------------------------------------------------------------------


class TestFormatCmdValidateOutputFile:
    """Cover the directory-rejection branch in _validate_output_file (line 31)."""

    def test_validate_output_file_raises_bad_parameter_for_directory(self, tmp_path: Path) -> None:
        """_validate_output_file must raise click.BadParameter when given a directory path."""
        # Arrange
        out_dir = tmp_path / "output_dir"
        out_dir.mkdir()

        # Act / Assert
        with pytest.raises(click.BadParameter, match="output path must not be a directory"):
            _validate_output_file(str(out_dir))

    def test_format_yara_command_rejects_directory_output_via_cli(self, tmp_path: Path) -> None:
        """format-yara command must exit 2 with a useful error when output is a directory."""
        # Arrange
        runner = CliRunner()
        inp = _write_yara(tmp_path / "in.yar", _SIMPLE_RULE)
        out_dir = tmp_path / "out_dir"
        out_dir.mkdir()

        # Act
        result = runner.invoke(format_yara, [str(inp), str(out_dir)])

        # Assert — Click converts BadParameter to exit code 2
        assert result.exit_code == 2
        assert "output path must not be a directory" in result.output
        assert "Formatted YARA file written" not in result.output


# ---------------------------------------------------------------------------
# format_cmd.py — validate_syntax full command path (lines 65-75)
# ---------------------------------------------------------------------------


class TestValidateSyntaxCommand:
    """Cover the validate-syntax command body (lines 65-75) end-to-end."""

    def test_validate_syntax_success_on_valid_file(self, tmp_path: Path) -> None:
        """validate-syntax must exit 0 and display a success panel."""
        # Arrange
        runner = CliRunner()
        valid = _write_yara(tmp_path / "valid.yar", _SIMPLE_RULE)

        # Act
        result = runner.invoke(validate_syntax, [str(valid)])

        # Assert
        assert result.exit_code == 0
        assert "Valid YARA file" in result.output

    def test_validate_syntax_error_on_broken_yara(self, tmp_path: Path) -> None:
        """validate-syntax must exit non-zero and display an error panel on bad YARA."""
        # Arrange
        runner = CliRunner()
        broken = _write_yara(tmp_path / "broken.yar", "rule broken {")

        # Act
        result = runner.invoke(validate_syntax, [str(broken)])

        # Assert
        assert result.exit_code != 0
        assert "Invalid YARA file" in result.output

    def test_validate_syntax_counts_rules_and_imports(self, tmp_path: Path) -> None:
        """validate-syntax reports rule and import counts from build_format_stats."""
        # Arrange
        runner = CliRunner()
        multi = _write_yara(
            tmp_path / "multi.yar",
            'import "pe"\nrule a { condition: true }\nrule b { condition: false }',
        )

        # Act
        result = runner.invoke(validate_syntax, [str(multi)])

        # Assert
        assert result.exit_code == 0
        assert "Rules: 2" in result.output
        assert "Imports: 1" in result.output


# ---------------------------------------------------------------------------
# format_cmd.py — _validate_output_file TypeError/ValueError re-raise (lines 35-36)
# ---------------------------------------------------------------------------


class TestFormatCmdValidateOutputFileTypeError:
    """Cover the except(TypeError, ValueError) re-raise in _validate_output_file."""

    def test_validate_output_file_raises_bad_parameter_for_empty_path(self) -> None:
        """_validate_output_file must convert ValueError(empty path) to BadParameter."""
        with pytest.raises(click.BadParameter, match="path must not be empty"):
            _validate_output_file("")

    def test_validate_output_file_returns_path_for_valid_nonexistent(self, tmp_path: Path) -> None:
        """_validate_output_file must return a Path for a valid non-directory output path."""
        # A path that does not exist yet is valid as a future output file
        result = _validate_output_file(str(tmp_path / "out.yar"))
        assert result == tmp_path / "out.yar"


# ---------------------------------------------------------------------------
# format_cmd.py — format_yara exception handler (lines 56-58)
# ---------------------------------------------------------------------------


class TestFormatYaraExceptionHandler:
    """Cover the except-block in format_yara (lines 56-58)."""

    def test_format_yara_abort_on_broken_yara(self, tmp_path: Path) -> None:
        """format-yara must exit non-zero when the input file cannot be parsed."""
        # Arrange
        runner = CliRunner()
        inp = _write_yara(tmp_path / "broken.yar", "rule broken {")
        out = tmp_path / "out.yar"

        # Act
        result = runner.invoke(format_yara, [str(inp), str(out)])

        # Assert
        assert result.exit_code != 0
        assert not out.exists()

    def test_format_yara_abort_on_invalid_utf8(self, tmp_path: Path) -> None:
        """format-yara must exit non-zero and report a UTF-8 error for binary input."""
        # Arrange
        runner = CliRunner()
        inp = tmp_path / "bad.yar"
        inp.write_bytes(b"\xff\xfe")
        out = tmp_path / "out.yar"

        # Act
        result = runner.invoke(format_yara, [str(inp), str(out)])

        # Assert
        assert result.exit_code != 0
        assert "Error" in result.output
        assert not out.exists()

    def test_format_yara_success_writes_formatted_file(self, tmp_path: Path) -> None:
        """format-yara must write the formatted YARA file on success."""
        # Arrange
        runner = CliRunner()
        inp = _write_yara(tmp_path / "in.yar", _SIMPLE_RULE)
        out = tmp_path / "out.yar"

        # Act
        result = runner.invoke(format_yara, [str(inp), str(out)])

        # Assert
        assert result.exit_code == 0
        assert out.exists()
        assert "rule x" in out.read_text(encoding="utf-8")
        assert "Formatted YARA file written" in result.output


# ---------------------------------------------------------------------------
# serialize.py — export exception handler (lines 74-76)
# ---------------------------------------------------------------------------


class TestSerializeExportExceptionHandler:
    """Cover the except-block in the export command (lines 74-76)."""

    def test_export_aborts_on_invalid_yara(self, tmp_path: Path) -> None:
        """export must exit non-zero when parsing the YARA input fails."""
        # Arrange
        runner = CliRunner()
        broken = _write_yara(tmp_path / "broken.yar", "rule broken {")

        # Act
        result = runner.invoke(serialize, ["export", str(broken), "-f", "json"])

        # Assert
        assert result.exit_code != 0
        assert "Error" in result.output

    def test_export_to_json_writes_output_file(self, tmp_path: Path) -> None:
        """export to JSON must write the serialized file and exit 0."""
        # Arrange
        runner = CliRunner()
        yar = _write_yara(tmp_path / "rule.yar", _SIMPLE_RULE)
        out = tmp_path / "rule.json"

        # Act
        result = runner.invoke(
            serialize,
            ["export", str(yar), "-f", "json", "-o", str(out)],
        )

        # Assert
        assert result.exit_code == 0
        assert out.exists()


# ---------------------------------------------------------------------------
# serialize.py — import without -o (branch 101->104: output is None)
# ---------------------------------------------------------------------------


class TestSerializeImportWithoutOutputPath:
    """Cover the False branch of 'if output is not None' in import_ast (101->104)."""

    def test_import_without_output_succeeds_and_displays_result(self, tmp_path: Path) -> None:
        """import without -o must exit 0 and display the import summary."""
        # Arrange — export first, then import without an output path
        runner = CliRunner()
        yar = _write_yara(tmp_path / "rule.yar", _SIMPLE_RULE)
        json_out = tmp_path / "rule.json"
        _export_json(runner, yar, json_out)

        # Act — no -o flag means output is None
        result = runner.invoke(
            serialize,
            ["import", str(json_out), "-f", "json"],
        )

        # Assert
        assert result.exit_code == 0
        assert "imported" in result.output.lower() or "Rules:" in result.output


# ---------------------------------------------------------------------------
# serialize.py — diff with changes but no output/patch (branch 152->exit)
# ---------------------------------------------------------------------------


class TestSerializeDiffWithChangesNoOutput:
    """Cover the branch where diff finds changes but no -o and no --patch."""

    def test_diff_with_changes_and_no_output_displays_summary(self, tmp_path: Path) -> None:
        """diff with changes but no -o or --patch must display the summary and exit 0."""
        # Arrange
        runner = CliRunner()
        f1 = _write_yara(tmp_path / "old.yar", _SIMPLE_RULE)
        f2 = _write_yara(tmp_path / "new.yar", _SIMPLE_RULE + "\n" + _EXTRA_RULE)

        # Act — no -o, no --patch: line 152 evaluates to False, execution falls through
        result = runner.invoke(serialize, ["diff", str(f1), str(f2)])

        # Assert
        assert result.exit_code == 0
        assert "AST Differences" in result.output or "Change" in result.output


# ---------------------------------------------------------------------------
# serialize.py — validate success path (line 195)
# ---------------------------------------------------------------------------


class TestSerializeValidateSuccessPath:
    """Cover the display_validation_result call on the success path (line 195)."""

    def test_validate_valid_json_export_exits_zero(self, tmp_path: Path) -> None:
        """validate with a well-formed serialized JSON must exit 0 and display a result."""
        # Arrange
        runner = CliRunner()
        yar = _write_yara(tmp_path / "rule.yar", _SIMPLE_RULE)
        json_out = tmp_path / "rule.json"
        _export_json(runner, yar, json_out)

        # Act
        result = runner.invoke(
            serialize,
            ["validate", str(json_out), "-f", "json"],
        )

        # Assert
        assert result.exit_code == 0
        assert "Validation Result" in result.output or "Valid" in result.output


# ---------------------------------------------------------------------------
# serialize.py — info success path (lines 220-222)
# ---------------------------------------------------------------------------


class TestSerializeInfoSuccessPath:
    """Cover the display_info call on the success path (lines 220-222)."""

    def test_info_valid_yara_displays_ast_structure(self, tmp_path: Path) -> None:
        """info on a valid YARA file must exit 0 and display rule count information."""
        # Arrange
        runner = CliRunner()
        yar = _write_yara(tmp_path / "rule.yar", _SIMPLE_RULE)

        # Act
        result = runner.invoke(serialize, ["info", str(yar)])

        # Assert
        assert result.exit_code == 0
        # The info display must mention the rule or rule count
        assert "rule" in result.output.lower() or "Rule" in result.output
