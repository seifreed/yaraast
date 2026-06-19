"""CLI tests for YARA-X commands."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

import yaraast.cli.commands.yarax as yarax_command
from yaraast.cli.commands.yarax import yarax


def _write_yarax(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")
    return str(path)


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def test_yarax_parse_show_features(tmp_path: Path) -> None:
    yarax_code = """
    rule yarax_demo {
        strings:
            $a = "test"

        condition:
            with $b = 1:
                $a and $b == 1
    }
    """
    yarax_path = _write_yarax(tmp_path, "demo.yarax", yarax_code)

    runner = CliRunner()
    result = runner.invoke(
        yarax,
        ["parse", yarax_path, "--show-features"],
    )
    assert result.exit_code == 0
    assert "YARA-X Features Used" in result.output
    assert "with statements" in result.output


def test_yarax_check_and_convert(tmp_path: Path) -> None:
    yara_code = """
    rule basic_rule {
        condition:
            true
    }
    """
    yara_path = _write_yarax(tmp_path, "basic.yar", yara_code)

    runner = CliRunner()
    result = runner.invoke(
        yarax,
        ["check", yara_path],
    )
    assert result.exit_code == 0
    assert "compatible" in result.output

    output_path = tmp_path / "converted.yarax"
    result = runner.invoke(
        yarax,
        ["convert", yara_path, "--target", "yarax", "--output", str(output_path)],
    )
    assert result.exit_code == 0
    assert "Converted to YARA-X format" in result.output
    assert output_path.exists()


def test_yarax_features_and_playground() -> None:
    runner = CliRunner()

    result = runner.invoke(yarax, ["features"])
    assert result.exit_code == 0
    assert "YARA-X New Features" in result.output

    result = runner.invoke(yarax, ["playground", "rule r { condition: true }"])
    assert result.exit_code == 0
    assert "Successfully parsed" in result.output


def test_yarax_parse_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yarax_path = _write_yarax(tmp_path, "demo.yarax", "rule r { condition: true }")
    sentinel = RuntimeError("parse sentinel")

    def fail_parse(_content: str) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(yarax_command, "parse_yarax_content", fail_parse)

    result = CliRunner().invoke(yarax, ["parse", yarax_path], standalone_mode=False)

    assert result.exit_code != 0
    assert "Error parsing YARA-X file: parse sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)


def test_yarax_check_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yarax_path = _write_yarax(tmp_path, "demo.yar", "rule r { condition: true }")
    sentinel = RuntimeError("check sentinel")

    def fail_parse_file(_file: str) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(yarax_command, "parse_yara_file", fail_parse_file)

    result = CliRunner().invoke(yarax, ["check", yarax_path], standalone_mode=False)

    assert result.exit_code != 0
    assert "Error checking YARA-X compatibility: check sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)


def test_yarax_convert_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yarax_path = _write_yarax(tmp_path, "demo.yar", "rule r { condition: true }")
    sentinel = RuntimeError("convert sentinel")

    def fail_convert(_content: str) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(yarax_command, "convert_yara_to_yarax", fail_convert)

    result = CliRunner().invoke(yarax, ["convert", yarax_path], standalone_mode=False)

    assert result.exit_code != 0
    assert "Error converting file: convert sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)
