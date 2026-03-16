"""Additional real CLI tests for libyara scan handler."""

from __future__ import annotations

from pathlib import Path

import pytest
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


def _write_invalid_rule(tmp_path: Path) -> Path:
    rule_text = """
rule bad_rule {
    strings:
        $a = "one"
        $a = "two"
    condition:
        any of them
}
"""
    rule_path = tmp_path / "bad_rule.yar"
    rule_path.write_text(rule_text.strip())
    return rule_path


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")
    return target


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_scan_success_without_stats(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    target = _write_target(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["libyara", "scan", str(rule_path), str(target)])

    assert result.exit_code == 0
    assert "Scan completed" in result.output
    assert "Scan Statistics" not in result.output


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_scan_aborts_on_compile_failure(tmp_path: Path) -> None:
    rule_path = _write_invalid_rule(tmp_path)
    target = _write_target(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["libyara", "scan", str(rule_path), str(target)])

    assert result.exit_code != 0
    assert "Compilation failed" in result.output


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_scan_aborts_on_scan_failure(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["libyara", "scan", str(rule_path), str(tmp_path)])

    assert result.exit_code != 0
    assert "Scan failed:" in result.output
