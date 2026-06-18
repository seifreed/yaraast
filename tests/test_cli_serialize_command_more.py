"""Additional CLI tests for serialize commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
import pytest

import yaraast.cli.commands.serialize as serialize_module
from yaraast.cli.commands.serialize import serialize


def _sample_rule() -> str:
    return """
rule sample_cli_serialize {
    strings:
        $a = "abc"
    condition:
        $a
}
"""


def test_serialize_diff_aborts_on_output_write_error(tmp_path: Path) -> None:
    runner = CliRunner()
    old_path = tmp_path / "old.yar"
    new_path = tmp_path / "new.yar"
    bad_output = tmp_path / "out_dir"
    bad_output.mkdir()

    old_path.write_text(_sample_rule(), encoding="utf-8")
    new_path.write_text(_sample_rule() + "\nrule extra { condition: true }\n", encoding="utf-8")

    result = runner.invoke(
        serialize,
        ["diff", str(old_path), str(new_path), "-o", str(bad_output), "-f", "json"],
    )

    assert result.exit_code != 0
    assert "Error:" in result.output


def test_serialize_export_escapes_error_markup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()
    source = tmp_path / "rule.yar"
    source.write_text(_sample_rule(), encoding="utf-8")

    def raise_markup_error(
        _input_file: str,
    ) -> object:
        raise ValueError("bad[/red][broken")

    monkeypatch.setattr(serialize_module, "parse_yara_file", raise_markup_error)

    result = runner.invoke(serialize, ["export", str(source), "-f", "json"])

    assert result.exit_code != 0
    assert "bad[/red][broken" in result.output
    assert "closing tag" not in result.output


def test_serialize_commands_reject_empty_output_path(tmp_path: Path) -> None:
    runner = CliRunner()
    old_path = tmp_path / "old.yar"
    new_path = tmp_path / "new.yar"
    json_path = tmp_path / "ast.json"

    old_path.write_text(_sample_rule(), encoding="utf-8")
    new_path.write_text(_sample_rule() + "\nrule extra { condition: true }\n", encoding="utf-8")

    exported = runner.invoke(
        serialize,
        ["export", str(old_path), "-o", str(json_path), "-f", "json"],
    )
    assert exported.exit_code == 0

    empty_export = runner.invoke(
        serialize,
        ["export", str(old_path), "-o", "", "-f", "json"],
    )
    assert empty_export.exit_code == 2
    assert "path must not be empty" in empty_export.output

    imported = runner.invoke(
        serialize,
        ["import", str(json_path), "-f", "json", "-o", ""],
    )
    assert imported.exit_code == 2
    assert "path must not be empty" in imported.output
    assert "AST imported" not in imported.output

    diffed = runner.invoke(
        serialize,
        ["diff", str(old_path), str(new_path), "-o", "", "-f", "json"],
    )
    assert diffed.exit_code == 2
    assert "path must not be empty" in diffed.output
    assert "AST Differences Summary" not in diffed.output
