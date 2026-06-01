from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.optimize import optimize


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_optimize_command_success_stdout_and_output(tmp_path: Path) -> None:
    runner = CliRunner()
    src = tmp_path / "rule.yar"
    out = tmp_path / "optimized.yar"
    _write(
        src,
        """
rule sample {
    strings:
        $a = "abc"
    condition:
        $a
}
""",
    )

    dry = runner.invoke(optimize, [str(src), str(out), "--dry-run"])
    assert dry.exit_code == 0
    assert "Dry run - no files were written" in dry.output
    assert not out.exists()

    real = runner.invoke(optimize, [str(src), str(out), "--analyze"])
    assert real.exit_code == 0
    assert out.exists()
    assert "Optimizing 1 rules" in real.output
    assert "Optimized YARA file written" in real.output


def test_optimize_command_preserves_yarax_output(tmp_path: Path) -> None:
    runner = CliRunner()
    src = tmp_path / "x.yar"
    out = tmp_path / "optimized.yar"
    _write(src, "rule x { condition: with xs = [1]: match xs { _ => true } }")

    result = runner.invoke(optimize, [str(src), str(out)])

    assert result.exit_code == 0
    output = out.read_text(encoding="utf-8")
    assert "with xs = [1]" in output
    assert "match xs" in output


def test_optimize_command_real_read_error(tmp_path: Path) -> None:
    runner = CliRunner()
    src = tmp_path / "rule.yar"
    out = tmp_path / "optimized.yar"
    src.write_bytes(b"\xff\xfe\xfa")

    result = runner.invoke(optimize, [str(src), str(out)])
    assert result.exit_code != 0
    assert "Error:" in result.output


def test_optimize_command_rejects_empty_output_path(tmp_path: Path) -> None:
    runner = CliRunner()
    src = tmp_path / "rule.yar"
    _write(
        src,
        """
rule sample {
    condition:
        true
}
""",
    )

    result = runner.invoke(optimize, [str(src), ""])

    assert result.exit_code == 2
    assert "path must not be empty" in result.output
    assert "Optimizing" not in result.output
