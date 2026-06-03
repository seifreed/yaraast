"""Real tests for CLI validate command (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.validate import validate


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content), encoding="utf-8")
    return str(path)


def test_validate_default_file(tmp_path: Path) -> None:
    code = """
    rule ok {
        condition:
            true
    }
    """
    file_path = _write(tmp_path, "ok.yar", code)

    runner = CliRunner()
    result = runner.invoke(validate, [file_path])

    assert result.exit_code == 0
    assert "Valid YARA file" in result.output
