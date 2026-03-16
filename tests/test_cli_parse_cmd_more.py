from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.parse_cmd import parse


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_parse_cmd_writes_tree_output_and_handles_output_error(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "ok.yar"
    output_dir = tmp_path / "out_dir"
    output_dir.mkdir()

    _write(
        source,
        """
rule ok {
    condition:
        true
}
""",
    )

    tree_result = runner.invoke(parse, [str(source), "--format", "tree"])
    assert tree_result.exit_code == 0
    assert "ok" in tree_result.output

    error_result = runner.invoke(
        parse, [str(source), "--format", "json", "--output", str(output_dir)]
    )
    assert error_result.exit_code != 0
    assert "Error" in error_result.output
