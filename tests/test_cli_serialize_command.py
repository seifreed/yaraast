"""CLI tests for serialize commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

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


def test_serialize_export_import_validate_info(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    # export json
    json_path = tmp_path / "sample.json"
    result = runner.invoke(
        serialize,
        ["export", str(yara_path), "-f", "json", "-o", str(json_path)],
    )
    assert result.exit_code == 0
    assert json_path.exists()

    # validate json
    result = runner.invoke(
        serialize,
        ["validate", str(json_path), "-f", "json"],
    )
    assert result.exit_code == 0

    # import json
    result = runner.invoke(
        serialize,
        ["import-ast", str(json_path), "-f", "json"],
    )
    assert result.exit_code == 0

    # info
    result = runner.invoke(serialize, ["info", str(yara_path)])
    assert result.exit_code == 0


def test_serialize_diff(tmp_path: Path) -> None:
    runner = CliRunner()
    old_path = tmp_path / "old.yar"
    new_path = tmp_path / "new.yar"
    old_path.write_text(_sample_rule())
    new_path.write_text(_sample_rule() + "\nrule extra { condition: true }\n")

    result = runner.invoke(
        serialize,
        ["diff", str(old_path), str(new_path), "--stats"],
    )
    assert result.exit_code == 0


def test_serialize_import_invalid(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not-json}")

    result = runner.invoke(
        serialize,
        ["import-ast", str(bad_path), "-f", "json"],
    )
    assert result.exit_code != 0


def test_serialize_export_pretty(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    result = runner.invoke(
        serialize,
        ["export", str(yara_path), "-f", "json", "--pretty"],
    )
    assert result.exit_code == 0
