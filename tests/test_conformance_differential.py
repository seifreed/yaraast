"""Differential conformance gate: yaraast round-trip must not drift.

For every rule in the vendored corpus, yaraast parses then regenerates the
source; each installed reference engine (libyara, YARA-X) must still accept it
and match the same rules. The unit tests below drive the divergence branches
with deterministic fake engines so the gate logic itself is fully exercised
even on a machine where no engine is installed.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from yaraast.conformance import (
    DifferentialChecker,
    EngineResult,
    LibyaraEngine,
    ReferenceEngine,
    YaraXEngine,
    available_engines,
)

CORPUS_DIR = Path(__file__).parent / "corpus" / "conformance"
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.yar"))


def _data_for(rule_file: Path) -> bytes | None:
    data_path = rule_file.with_suffix(".bin")
    return data_path.read_bytes() if data_path.exists() else None


@pytest.mark.skipif(not available_engines(), reason="no reference YARA engine installed")
@pytest.mark.parametrize("rule_file", CORPUS_FILES, ids=lambda p: p.stem)
def test_corpus_round_trip_is_conformant(rule_file: Path) -> None:
    checker = DifferentialChecker()
    report = checker.check(
        rule_file.read_text(encoding="utf-8"), _data_for(rule_file), name=rule_file.name
    )

    # Every corpus file is authored to be accepted by the installed engines, so
    # the round-trip must preserve both acceptance and matches.
    assert report.parse_ok, f"yaraast failed to parse {rule_file.name}: {report.parse_error}"
    assert report.conformant, "\n".join(
        f"{d.engine}/{d.kind}: {d.detail}" for d in report.divergences
    )


def test_corpus_is_non_empty_and_accepted_by_every_engine() -> None:
    assert CORPUS_FILES, "conformance corpus must not be empty"

    engines = available_engines()
    if not engines:
        pytest.skip("no reference YARA engine installed")

    checker = DifferentialChecker(engines)
    for rule_file in CORPUS_FILES:
        report = checker.check(rule_file.read_text(encoding="utf-8"), name=rule_file.name)
        for engine in engines:
            assert report.engine_results[engine.name].accepted, (
                f"{engine.name} rejected corpus file {rule_file.name}: "
                f"{report.engine_results[engine.name].error}"
            )


class _FakeEngine(ReferenceEngine):
    """Engine whose verdicts are driven by an injected callable, for testing."""

    def __init__(self, name: str, verdict: Callable[[str, bytes | None], EngineResult]) -> None:
        self.name = name
        self._verdict = verdict

    @property
    def available(self) -> bool:
        return True

    def evaluate(self, source: str, data: bytes | None = None) -> EngineResult:
        return self._verdict(source, data)


_OK_RULE = 'rule ok { strings: $a = "hi" condition: $a }'


def test_checker_reports_no_divergence_when_engine_is_stable() -> None:
    engine = _FakeEngine(
        "stable", lambda source, data: EngineResult(accepted=True, matches=frozenset({"ok"}))
    )
    report = DifferentialChecker([engine]).check(_OK_RULE, data=b"hi", name="stable")

    assert report.conformant
    assert report.parse_ok
    assert report.engine_results["stable"].accepted


def test_checker_skips_rules_the_engine_rejects() -> None:
    engine = _FakeEngine("rejects", lambda source, data: EngineResult(accepted=False, error="nope"))
    report = DifferentialChecker([engine]).check(_OK_RULE, name="rejected")

    # Original rejected -> no codegen invariant to check, no divergence.
    assert report.conformant


def test_checker_flags_codegen_acceptance_drift() -> None:
    # Accept the verbatim original, reject anything else (the regenerated form).
    def verdict(source: str, data: bytes | None) -> EngineResult:
        return EngineResult(
            accepted=source == _OK_RULE, error=None if source == _OK_RULE else "regen rejected"
        )

    report = DifferentialChecker([_FakeEngine("drift", verdict)]).check(_OK_RULE, name="acc-drift")

    assert not report.conformant
    assert report.divergences[0].kind == "codegen_acceptance"


def test_checker_flags_match_drift() -> None:
    def verdict(source: str, data: bytes | None) -> EngineResult:
        matched = frozenset({"ok"}) if source == _OK_RULE else frozenset()
        return EngineResult(accepted=True, matches=matched)

    report = DifferentialChecker([_FakeEngine("match", verdict)]).check(
        _OK_RULE, data=b"hi", name="match-drift"
    )

    assert not report.conformant
    assert report.divergences[0].kind == "match_drift"


def test_checker_flags_parse_parity_gap_for_libyara() -> None:
    # libyara accepts the (unparseable-by-yaraast) source -> parse parity gap.
    engine = _FakeEngine("libyara", lambda source, data: EngineResult(accepted=True))
    report = DifferentialChecker([engine]).check("this is not valid yara @#$", name="parse-gap")

    assert not report.parse_ok
    assert not report.conformant
    assert report.divergences[0].kind == "parse_parity"


def test_parse_parity_gap_not_reported_for_non_libyara_engines() -> None:
    engine = _FakeEngine("yara-x", lambda source, data: EngineResult(accepted=True))
    report = DifferentialChecker([engine]).check("not valid yara @#$", name="no-gap")

    # Non-libyara strictness must not gate yaraast's classic parser.
    assert not report.parse_ok
    assert report.conformant


def test_available_engines_returns_reference_engine_instances() -> None:
    for engine in available_engines():
        assert isinstance(engine, ReferenceEngine)
        assert engine.available


@pytest.mark.skipif(not LibyaraEngine().available, reason="yara-python not installed")
def test_libyara_engine_accept_reject_and_match() -> None:
    engine = LibyaraEngine()
    assert engine.evaluate(_OK_RULE).accepted
    assert not engine.evaluate("rule bad { condition: undefined_identifier }").accepted
    assert engine.evaluate(_OK_RULE, data=b"xx hi xx").matches == frozenset({"ok"})


@pytest.mark.skipif(not YaraXEngine().available, reason="yara-x not installed")
def test_yarax_engine_accept_reject_and_match() -> None:
    engine = YaraXEngine()
    assert engine.evaluate(_OK_RULE).accepted
    assert not engine.evaluate("rule bad { condition: undefined_identifier }").accepted
    assert engine.evaluate(_OK_RULE, data=b"xx hi xx").matches == frozenset({"ok"})
