"""Additional CLI tests for serialize commands."""

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
