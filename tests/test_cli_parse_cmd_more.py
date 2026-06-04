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


def test_parse_cmd_rejects_directory_input(tmp_path: Path) -> None:
    runner = CliRunner()
    input_dir = tmp_path / "rules"
    input_dir.mkdir()

    result = runner.invoke(parse, [str(input_dir)])

    assert result.exit_code == 2
    assert "is a directory" in result.output
    assert "Errno" not in result.output


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


def test_parse_cmd_tree_preserves_selective_extern_import_details(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "extern_import.yar"

    _write(
        source,
        """
import "external.rules" (A, B) as er

rule uses_external {
    condition:
        er.A
}
""",
    )

    result = runner.invoke(parse, [str(source), "--format", "tree"])

    assert result.exit_code == 0
    assert "extern import external.rules (A, B) as er" in result.output


def test_parse_cmd_tree_preserves_extern_rule_details(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "extern_rule.yar"

    _write(
        source,
        """
namespace corp
extern rule private corp.Nested

rule uses_external {
    condition:
        corp.Nested
}
""",
    )

    result = runner.invoke(parse, [str(source), "--format", "tree"])

    assert result.exit_code == 0
    assert "extern rule private corp.Nested" in result.output


def test_parse_cmd_json_reports_parse_errors_on_stderr(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "broken.yar"
    source.write_text("rule broken { strings: $a =\n", encoding="utf-8")

    result = runner.invoke(parse, [str(source), "--format", "json"])

    assert result.exit_code == 1
    assert "Parser Issues" in result.stderr
    assert 'rule "broken" has no condition' in result.stderr
