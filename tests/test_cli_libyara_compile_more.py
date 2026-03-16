"""Additional real CLI tests for libyara compile handler."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from yaraast.cli.main import cli
from yaraast.libyara import YARA_AVAILABLE


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
    rule_path.write_text(rule_text.strip(), encoding="utf-8")
    return rule_path


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compile_aborts_on_compilation_failure(tmp_path: Path) -> None:
    rule_path = _write_invalid_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["libyara", "compile", str(rule_path)])

    assert result.exit_code != 0
    assert "Compilation failed" in result.output
