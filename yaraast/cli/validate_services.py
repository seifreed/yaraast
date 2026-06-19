"""Validation services for CLI (logic without IO)."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.cli.utils import parse_yara_file
from yaraast.errors import ValidationError
from yaraast.libyara.equivalence import EquivalenceTester


def validate_rule_file(rule_file: str) -> tuple[YaraFile, int, int, int]:
    ast = parse_yara_file(rule_file)
    return ast, len(ast.rules), len(ast.imports), sum(len(rule.strings) for rule in ast.rules)


def roundtrip_test(rule_file: str, data: bytes | None) -> Any:
    tester = EquivalenceTester()
    return tester.test_file_round_trip(rule_file, data)


def read_test_data(test_data_path: str | PathLike[str] | None) -> bytes | None:
    """Read test data if provided."""
    if test_data_path is None:
        return None
    if not isinstance(test_data_path, str | PathLike):
        msg = "test data path must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(test_data_path)
    if not isinstance(raw_path, str):
        msg = "test data path must be a string or path-like object"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = "test data path cannot be empty"
        raise ValueError(msg)

    try:
        with Path(raw_path).open("rb") as f:
            return f.read()
    except Exception as exc:
        msg = f"Error reading test data: {exc}"
        raise ValidationError(msg) from exc
