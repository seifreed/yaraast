"""Validation services for CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path
import re

from yaraast.cli.utils import parse_yara_file
from yaraast.errors import ValidationError
from yaraast.libyara.cross_validator import CrossValidator
from yaraast.libyara.equivalence import EquivalenceTester
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures

EXTERNAL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def validate_rule_file(rule_file: str):
    ast = parse_yara_file(rule_file)
    return ast, len(ast.rules), len(ast.imports), sum(len(rule.strings) for rule in ast.rules)


def cross_validate_rules(rule_file: str, test_data: bytes, externals: dict[str, str]):
    ast = parse_yara_file(rule_file)
    validator = CrossValidator()
    return validator.validate(ast, test_data, externals)


def roundtrip_test(rule_file: str, data: bytes | None):
    tester = EquivalenceTester()
    return tester.test_file_round_trip(rule_file, data)


def yarax_check(ast, strict: bool):
    if not isinstance(strict, bool):
        msg = "strict must be a boolean"
        raise TypeError(msg)
    features = YaraXFeatures.yarax_strict() if strict else YaraXFeatures.yarax_compatible()
    checker = YaraXCompatibilityChecker(features)
    return checker.check(ast)


def parse_externals(external: object) -> dict[str, str]:
    if isinstance(external, str) or not isinstance(external, tuple | list):
        msg = "external variables must be a tuple or list of strings"
        raise TypeError(msg)

    externals: dict[str, str] = {}
    for ext in external:
        if not isinstance(ext, str):
            msg = "external variables must be a tuple or list of strings"
            raise TypeError(msg)
        if "=" not in ext:
            msg = f"Invalid external format: {ext}"
            raise ValidationError(msg)
        key, value = ext.split("=", 1)
        if not key.strip():
            msg = "External variable name cannot be empty"
            raise ValidationError(msg)
        if EXTERNAL_NAME_RE.fullmatch(key) is None:
            msg = f"Invalid external variable name: {key}"
            raise ValidationError(msg)
        externals[key] = value
    return externals


def read_test_data(test_data_path: str | None) -> bytes | None:
    """Read test data if provided."""
    if not test_data_path:
        return None

    try:
        with Path(test_data_path).open("rb") as f:
            return f.read()
    except Exception as exc:
        msg = f"Error reading test data: {exc}"
        raise ValidationError(msg) from exc
