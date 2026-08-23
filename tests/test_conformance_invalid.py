"""Invalid-corpus rejection parity for YARA and YARA-X."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.conformance import LibyaraEngine, YaraXEngine
from yaraast.errors import YaraASTError
from yaraast.parser import Parser
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.parser import YaraXParser

CORPUS_DIR = Path(__file__).parent / "corpus" / "conformance" / "invalid"
CLASSIC_FILES = sorted((CORPUS_DIR / "classic").glob("*.yar"))
YARAX_FILES = sorted((CORPUS_DIR / "yarax").glob("*.yar"))


def _yarax_frontend_diagnostics(source: str) -> list[str]:
    try:
        ast = YaraXParser(source).parse()
    except (YaraASTError, TypeError, ValueError) as exc:
        return [str(exc)]
    return [
        issue.message
        for issue in YaraXCompatibilityChecker().check(ast)
        if issue.severity == "error"
    ]


def test_invalid_conformance_corpora_are_non_empty() -> None:
    assert CLASSIC_FILES
    assert YARAX_FILES


@pytest.mark.skipif(
    not LibyaraEngine().available,
    reason="yara-python not installed; https://github.com/seifreed/yaraast/issues/24",
)
@pytest.mark.parametrize("rule_file", CLASSIC_FILES, ids=lambda path: path.stem)
def test_classic_invalid_corpus_is_rejected_with_diagnostics(rule_file: Path) -> None:
    source = rule_file.read_text(encoding="utf-8")
    reference = LibyaraEngine().evaluate(source)

    assert reference.accepted is False
    assert reference.error
    with pytest.raises((YaraASTError, TypeError, ValueError), match=r"\S"):
        Parser(source).parse()


@pytest.mark.skipif(
    not YaraXEngine().available,
    reason="yara-x not installed; https://github.com/seifreed/yaraast/issues/24",
)
@pytest.mark.parametrize("rule_file", YARAX_FILES, ids=lambda path: path.stem)
def test_yarax_invalid_corpus_is_rejected_with_diagnostics(rule_file: Path) -> None:
    source = rule_file.read_text(encoding="utf-8")
    reference = YaraXEngine().evaluate(source)

    assert reference.accepted is False
    assert reference.error
    assert _yarax_frontend_diagnostics(source)
