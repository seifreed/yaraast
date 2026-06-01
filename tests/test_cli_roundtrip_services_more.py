"""Additional tests for roundtrip service helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.cli.roundtrip_services import pretty_print_file


def _write_rule(path: Path) -> None:
    path.write_text(
        """
rule sample {
    strings:
        $a = "abc"
    condition:
        $a
}
""".strip(),
        encoding="utf-8",
    )


def test_pretty_print_file_uses_dense_style(tmp_path: Path) -> None:
    yara_path = tmp_path / "dense.yar"
    _write_rule(yara_path)

    ast, formatted = pretty_print_file(
        yara_path,
        "dense",
        2,
        80,
        True,
        True,
        False,
        False,
    )

    assert ast.rules[0].name == "sample"
    assert "rule sample" in formatted


def test_pretty_print_file_uses_readable_style(tmp_path: Path) -> None:
    yara_path = tmp_path / "readable.yar"
    _write_rule(yara_path)

    ast, formatted = pretty_print_file(
        yara_path,
        "readable",
        4,
        120,
        False,
        False,
        True,
        True,
    )

    assert ast.rules[0].name == "sample"
    assert "condition:" in formatted


@pytest.mark.parametrize("style", [None, 123])
def test_pretty_print_file_rejects_non_string_styles(tmp_path: Path, style: object) -> None:
    yara_path = tmp_path / "style.yar"
    _write_rule(yara_path)

    with pytest.raises(TypeError, match="pretty style must be a string"):
        pretty_print_file(yara_path, style, 4, 120, True, True, True, True)


@pytest.mark.parametrize("style", ["", "unknown-style"])
def test_pretty_print_file_rejects_unknown_styles(tmp_path: Path, style: str) -> None:
    yara_path = tmp_path / "style.yar"
    _write_rule(yara_path)

    with pytest.raises(
        ValueError,
        match="pretty style must be one of: compact, dense, readable, verbose",
    ):
        pretty_print_file(yara_path, style, 4, 120, True, True, True, True)


def test_pretty_print_file_rejects_invalid_numeric_options(tmp_path: Path) -> None:
    yara_path = tmp_path / "invalid_options.yar"
    _write_rule(yara_path)

    with pytest.raises(TypeError, match="indent_size must be an integer"):
        pretty_print_file(yara_path, "readable", cast(Any, True), 120, True, True, True, True)

    with pytest.raises(TypeError, match="max_line_length must be an integer"):
        pretty_print_file(yara_path, "readable", 4, cast(Any, True), True, True, True, True)

    with pytest.raises(ValueError, match="indent_size must be at least 1"):
        pretty_print_file(yara_path, "readable", 0, 120, True, True, True, True)

    with pytest.raises(ValueError, match="max_line_length must be at least 1"):
        pretty_print_file(yara_path, "readable", 4, 0, True, True, True, True)
