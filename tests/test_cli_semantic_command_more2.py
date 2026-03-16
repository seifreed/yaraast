"""Additional real CLI tests for semantic command."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.semantic import semantic


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(dedent(content).strip(), encoding="utf-8")
    return path


def test_semantic_without_files_exits_with_error() -> None:
    runner = CliRunner()

    result = runner.invoke(semantic, [])

    assert result.exit_code != 0
    assert "No files provided" in result.output


def test_semantic_text_summary_and_processing_error(tmp_path: Path) -> None:
    runner = CliRunner()
    good_file = _write(
        tmp_path,
        "good.yar",
        """
        rule semantic_ok {
            strings:
                $a = "abc"
            condition:
                $a
        }
        """,
    )
    bad_input = tmp_path / "dir_as_file"
    bad_input.mkdir()

    result = runner.invoke(semantic, [str(good_file), str(bad_input)])

    assert result.exit_code == 0
    assert "Validating" in result.output
    assert "Validated 2 file(s)" in result.output
    assert "Error processing" in result.output


def test_semantic_json_stdout_emits_results(tmp_path: Path) -> None:
    runner = CliRunner()
    file_path = _write(
        tmp_path,
        "stdout_rule.yar",
        """
        rule semantic_ok {
            strings:
                $a = "abc"
            condition:
                $a
        }
        """,
    )

    result = runner.invoke(semantic, [str(file_path), "--format", "json", "--quiet"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert len(payload) == 1
    assert payload[0]["file"].endswith("stdout_rule.yar")
