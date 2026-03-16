"""CLI semantic validation tests (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.main import cli


def test_semantic_cli_json(tmp_path: Path) -> None:
    rule_text = """
import "math"

rule sem_rule {
    condition:
        math.abs(1) == 1
}
"""
    rule_path = tmp_path / "sem.yar"
    rule_path.write_text(rule_text.strip())

    out_path = tmp_path / "out.json"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["semantic", str(rule_path), "--format", "json", "--output", str(out_path)],
    )

    assert result.exit_code == 0
    data = json.loads(out_path.read_text())
    assert isinstance(data, list)
    assert data[0]["is_valid"] is True
