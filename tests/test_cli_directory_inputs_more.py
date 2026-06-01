from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.main import cli


def _write(path: Path, content: str) -> str:
    path.write_text(content.strip() + "\n", encoding="utf-8")
    return str(path)


def test_remaining_cli_file_arguments_reject_directories(tmp_path: Path) -> None:
    runner = CliRunner()
    input_dir = tmp_path / "input_dir"
    input_dir.mkdir()
    rule_file = _write(tmp_path / "rule.yar", "rule ok { condition: true }")
    sample_file = _write(tmp_path / "sample.bin", "sample")

    commands = (
        ["libyara", "compile", str(input_dir)],
        ["libyara", "scan", str(input_dir), sample_file],
        ["libyara", "scan", rule_file, str(input_dir)],
        ["libyara", "optimize", str(input_dir)],
        ["workspace", "resolve", str(input_dir)],
        ["yaral", "parse", str(input_dir)],
        ["yaral", "validate", str(input_dir)],
        ["yaral", "optimize", str(input_dir)],
        ["yaral", "generate", str(input_dir)],
        ["yaral", "compare", str(input_dir), rule_file],
        ["yaral", "compare", rule_file, str(input_dir)],
        ["yarax", "parse", str(input_dir)],
        ["yarax", "check", str(input_dir)],
        ["yarax", "convert", str(input_dir)],
        ["yarax", "playground", "--file", str(input_dir)],
        ["serialize", "export", str(input_dir)],
        ["serialize", "import", str(input_dir)],
        ["serialize", "diff", str(input_dir), rule_file],
        ["serialize", "diff", rule_file, str(input_dir)],
        ["serialize", "validate", str(input_dir)],
        ["serialize", "info", str(input_dir)],
        ["diff", str(input_dir), rule_file],
        ["diff", rule_file, str(input_dir)],
        ["validate", str(input_dir)],
        ["validate", "cross", str(input_dir), sample_file],
        ["validate", "cross", rule_file, str(input_dir)],
        ["validate", "roundtrip", str(input_dir)],
        ["validate", "roundtrip", rule_file, "--test-data", str(input_dir)],
        ["bench", str(input_dir)],
        ["optimize", str(input_dir), str(tmp_path / "optimized.yar")],
        ["performance-check", str(input_dir)],
        ["semantic", str(input_dir)],
        ["roundtrip", "serialize", str(input_dir)],
        ["roundtrip", "deserialize", str(input_dir)],
        ["roundtrip", "test", str(input_dir)],
        ["roundtrip", "pretty", str(input_dir)],
        ["roundtrip", "pipeline", str(input_dir)],
    )

    for command in commands:
        result = runner.invoke(cli, command)

        assert result.exit_code == 2, command
        assert "is a directory" in result.output, command
        assert "Errno" not in result.output, command
