"""Dated Google YARA-L documentation conformance corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.validator import YaraLValidator

CORPUS_DIR = Path(__file__).parent / "corpus" / "conformance" / "yaral-2026-08"
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.yaral"))
INVALID_CORPUS_DIR = Path(__file__).parent / "corpus" / "conformance" / "yaral-2026-08-invalid"
INVALID_CORPUS_FILES = sorted(INVALID_CORPUS_DIR.glob("*.yaral"))


def test_yaral_snapshot_corpus_is_non_empty() -> None:
    assert CORPUS_FILES
    assert INVALID_CORPUS_FILES
    assert len(CORPUS_FILES) >= 9
    assert len(INVALID_CORPUS_FILES) >= 3


@pytest.mark.parametrize("rule_file", CORPUS_FILES, ids=lambda path: path.stem)
def test_yaral_snapshot_parses_validates_and_round_trips(rule_file: Path) -> None:
    parser = EnhancedYaraLParser(rule_file.read_text(encoding="utf-8"))
    ast = parser.parse()

    assert parser.errors == []
    errors, _warnings = YaraLValidator().validate(ast)
    assert errors == []

    generated = YaraLGenerator().generate(ast)
    regenerated_parser = EnhancedYaraLParser(generated)
    regenerated_ast = regenerated_parser.parse()

    assert regenerated_parser.errors == []
    assert [rule.name for rule in regenerated_ast.rules] == [rule.name for rule in ast.rules]
    assert YaraLGenerator().generate(regenerated_ast) == generated


@pytest.mark.parametrize("rule_file", INVALID_CORPUS_FILES, ids=lambda path: path.stem)
def test_yaral_invalid_snapshot_produces_diagnostics(rule_file: Path) -> None:
    parser = EnhancedYaraLParser(rule_file.read_text(encoding="utf-8"))
    ast = parser.parse()
    validation_errors, _warnings = YaraLValidator().validate(ast)
    diagnostics = [str(error) for error in parser.errors] + [
        str(error) for error in validation_errors
    ]

    assert diagnostics
