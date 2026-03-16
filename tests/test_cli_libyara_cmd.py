"""CLI libyara command tests (no mocks)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.main import cli
from yaraast.libyara import YARA_AVAILABLE


def _write_rule(tmp_path: Path) -> Path:
    rule_text = """
rule match_rule {
    strings:
        $a = "hello"
    condition:
        $a
}
"""
    rule_path = tmp_path / "match_rule.yar"
    rule_path.write_text(rule_text.strip())
    return rule_path


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")
    return target


def test_libyara_optimize_command(tmp_path: Path) -> None:
    if not YARA_AVAILABLE:
        import pytest

        pytest.skip("yara-python is not installed")

    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["libyara", "optimize", str(rule_path), "--show-optimizations"])

    assert result.exit_code == 0
    assert "Optimization completed" in result.output


def test_libyara_compile_and_scan(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    target = _write_target(tmp_path)
    runner = CliRunner()

    if not YARA_AVAILABLE:
        result = runner.invoke(cli, ["libyara", "compile", str(rule_path)])
        assert result.exit_code != 0
        assert "yara-python is not installed" in result.output

        result = runner.invoke(cli, ["libyara", "scan", str(rule_path), str(target)])
        assert result.exit_code != 0
        assert "yara-python is not installed" in result.output
        return

    compiled_path = tmp_path / "compiled.yarc"
    result = runner.invoke(
        cli,
        [
            "libyara",
            "compile",
            str(rule_path),
            "--output",
            str(compiled_path),
            "--stats",
        ],
    )

    assert result.exit_code == 0
    assert "Compilation successful" in result.output
    assert compiled_path.exists()

    result = runner.invoke(
        cli,
        [
            "libyara",
            "scan",
            str(rule_path),
            str(target),
            "--stats",
        ],
    )
    assert result.exit_code == 0
    assert "Scan completed" in result.output

    result = runner.invoke(
        cli,
        [
            "libyara",
            "compile",
            str(rule_path),
            "--optimize",
            "--debug",
        ],
    )
    assert result.exit_code == 0
    assert "Compilation successful" in result.output
