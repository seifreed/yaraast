"""Extra tests for semantic CLI command (no mocks)."""

from __future__ import annotations

import json
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.semantic import semantic


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def test_semantic_no_files() -> None:
    runner = CliRunner()
    result = runner.invoke(semantic, [])
    assert result.exit_code == 1
    assert "No files provided" in result.output


def test_semantic_strict_with_warning(tmp_path) -> None:
    # Unknown function should produce warning (not error)
    code = """
    rule warn_rule {
        condition:
            foo(1)
    }
    """
    file_path = _write(tmp_path, "warn.yar", code)

    runner = CliRunner()
    result = runner.invoke(semantic, [file_path, "--strict", "--format", "json", "--quiet"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload[0]["warnings"]


def test_semantic_text_output_file(tmp_path) -> None:
    code = """
    rule ok_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    file_path = _write(tmp_path, "ok.yar", code)
    out_path = tmp_path / "out.txt"

    runner = CliRunner()
    result = runner.invoke(
        semantic,
        [file_path, "--format", "text", "--output", str(out_path)],
    )

    assert result.exit_code == 0
    assert out_path.exists()
    content = out_path.read_text()
    assert "File:" in content
    assert "Valid:" in content
