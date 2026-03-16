"""Additional real CLI tests for semantic validation (no mocks)."""

from __future__ import annotations

import json
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.semantic import semantic


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def _sample_yara() -> str:
    return """
    rule semantic_ok {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """


def test_semantic_cli_json_output(tmp_path) -> None:
    file_path = _write(tmp_path, "rule.yar", _sample_yara())
    out_path = tmp_path / "results.json"
    runner = CliRunner()

    result = runner.invoke(
        semantic,
        [file_path, "--format", "json", "--output", str(out_path)],
    )

    assert result.exit_code == 0
    assert out_path.exists()

    payload = json.loads(out_path.read_text())
    assert len(payload) == 1
    assert payload[0]["file"].endswith("rule.yar")
    assert payload[0]["errors"] == []
