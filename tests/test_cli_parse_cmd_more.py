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
    assert error_result.exit_code == 2
    assert "output path must not be a directory" in error_result.output

    for output_format in ("yara", "json", "yaml", "tree"):
        empty_output = runner.invoke(
            parse, [str(source), "--format", output_format, "--output", ""]
        )
        assert empty_output.exit_code == 2
        assert "path must not be empty" in empty_output.output
        assert "Rule: ok" not in empty_output.output


def test_parse_cmd_auto_yarax_outputs_extended_syntax(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "yarax.yar"

    _write(
        source,
        """
rule yarax_sample {
    condition:
        with xs = [1]: match xs { _ => true }
}
""",
    )

    yara_result = runner.invoke(parse, [str(source), "--dialect", "auto"])
    assert yara_result.exit_code == 0
    assert "Detected dialect: YARA_X" in yara_result.output
    assert "with xs = [1]" in yara_result.output
    assert "match xs" in yara_result.output

    json_result = runner.invoke(parse, [str(source), "--dialect", "yara-x", "--format", "json"])
    assert json_result.exit_code == 0
    assert '"type": "WithStatement"' in json_result.output
