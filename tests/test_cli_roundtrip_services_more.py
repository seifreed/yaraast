"""Additional tests for roundtrip service helpers."""

from __future__ import annotations

from pathlib import Path

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


def test_pretty_print_file_falls_back_to_readable_style(tmp_path: Path) -> None:
    yara_path = tmp_path / "readable.yar"
    _write_rule(yara_path)

    ast, formatted = pretty_print_file(
        yara_path,
        "unknown-style",
        4,
        120,
        False,
        False,
        True,
        True,
    )

    assert ast.rules[0].name == "sample"
    assert "condition:" in formatted
