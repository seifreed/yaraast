"""YARA-X 1.19 differential conformance corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.conformance import DifferentialChecker, YaraXEngine
from yaraast.dialects import YaraDialect

CORPUS_DIR = Path(__file__).parent / "corpus" / "conformance" / "yarax"
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.yar"))


def _data_for(rule_file: Path) -> bytes | None:
    data_path = rule_file.with_suffix(".bin")
    return data_path.read_bytes() if data_path.exists() else None


def test_yarax_conformance_corpus_is_non_empty() -> None:
    assert CORPUS_FILES


@pytest.mark.skipif(
    not YaraXEngine().available,
    reason="yara-x not installed; https://github.com/seifreed/yaraast/issues/24",
)
@pytest.mark.parametrize("rule_file", CORPUS_FILES, ids=lambda path: path.stem)
def test_yarax_corpus_round_trip_matches_reference(rule_file: Path) -> None:
    engine = YaraXEngine()
    source = rule_file.read_text(encoding="utf-8")
    report = DifferentialChecker([engine], dialect=YaraDialect.YARA_X).check(
        source,
        _data_for(rule_file),
        name=rule_file.name,
    )

    assert report.engine_results[engine.name].accepted
    assert report.parse_ok, report.parse_error
    assert not report.divergences, "\n".join(
        f"{divergence.kind}: {divergence.detail}" for divergence in report.divergences
    )
