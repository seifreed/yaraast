"""More tests for semantic CLI command (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.semantic import semantic


def test_semantic_command_json_output(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule a { condition: true }")

    output = tmp_path / "results.json"
    runner = CliRunner()
    result = runner.invoke(
        semantic,
        [str(rule_file), "--format", "json", "--output", str(output), "--quiet"],
    )

    assert result.exit_code == 0
    data = json.loads(output.read_text())
    assert data[0]["file"].endswith("sample.yar")
