from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.fmt_cmd import fmt


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


def test_fmt_cmd_check_and_diff_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    formatted = tmp_path / "formatted.yar"
    needs_format = tmp_path / "needs_format.yar"

    _write(
        formatted,
        """
rule ok {
    condition:
        true
}
""",
    )
    _write(needs_format, 'rule x { strings: $a = "x" condition: $a }')

    check_ok = runner.invoke(fmt, [str(formatted), "--check"])
    assert check_ok.exit_code == 0
    assert "already formatted" in check_ok.output

    check_fail = runner.invoke(fmt, [str(needs_format), "--check"])
    assert check_fail.exit_code != 0
    assert "needs formatting" in check_fail.output

    diff_result = runner.invoke(fmt, [str(needs_format), "--diff", "--style", "pretty"])
    assert diff_result.exit_code == 0
    assert (
        "Formatting changes for" in diff_result.output
        or "No formatting changes needed" in diff_result.output
    )


def test_fmt_cmd_check_fails_on_unparseable_file(tmp_path: Path) -> None:
    runner = CliRunner()
    invalid = tmp_path / "invalid.yar"
    _write(invalid, "rule broken { strings: $a =")

    result = runner.invoke(fmt, [str(invalid), "--check"])

    assert result.exit_code != 0
    assert "already formatted" not in result.output
    assert "Error" in result.output or "Expected" in result.output


def test_fmt_cmd_diff_and_format_fail_on_invalid_input(tmp_path: Path) -> None:
    runner = CliRunner()
    invalid = tmp_path / "invalid.yar"
    _write(invalid, "rule broken")

    diff_fail = runner.invoke(fmt, [str(invalid), "--diff"])
    assert diff_fail.exit_code != 0
    assert "Error" in diff_fail.output or "Expected" in diff_fail.output

    format_fail = runner.invoke(fmt, [str(invalid), "--style", "compact"])
    assert format_fail.exit_code != 0
    assert "Error" in format_fail.output or "Expected" in format_fail.output


def test_fmt_cmd_formats_to_separate_output(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.yar"
    output = tmp_path / "out.yar"
    _write(source, 'rule x { strings: $a = "x" condition: $a }')

    result = runner.invoke(fmt, [str(source), "--output", str(output), "--style", "verbose"])
    assert result.exit_code == 0
    assert output.exists()
    assert "Formatted file written" in result.output


def test_fmt_cmd_rejects_empty_output_without_overwriting_input(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.yar"
    original = 'rule x { strings: $a = "x" condition: $a }\n'
    source.write_text(original, encoding="utf-8")

    result = runner.invoke(fmt, [str(source), "--output", ""])

    assert result.exit_code == 2
    assert "path must not be empty" in result.output
    assert source.read_text(encoding="utf-8") == original


def test_fmt_cmd_rejects_directory_output(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.yar"
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    original = 'rule x { strings: $a = "x" condition: $a }\n'
    source.write_text(original, encoding="utf-8")

    result = runner.invoke(fmt, [str(source), "--output", str(output_dir)])

    assert result.exit_code == 2
    assert "output path must not be a directory" in result.output
    assert "Formatting error" not in result.output
    assert source.read_text(encoding="utf-8") == original


def test_fmt_cmd_rejects_directory_input(tmp_path: Path) -> None:
    runner = CliRunner()
    input_dir = tmp_path / "rules"
    input_dir.mkdir()

    result = runner.invoke(fmt, [str(input_dir), "--check"])

    assert result.exit_code == 2
    assert "is a directory" in result.output
    assert "already formatted" not in result.output


def test_fmt_cmd_formats_yarax(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "x.yar"
    output = tmp_path / "x_out.yar"
    _write(source, _yarax_rule())

    result = runner.invoke(fmt, [str(source), "--output", str(output), "--style", "pretty"])

    assert result.exit_code == 0
    assert output.exists()
    assert "match xs" in output.read_text(encoding="utf-8")
