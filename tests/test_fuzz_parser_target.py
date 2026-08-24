"""Regression checks for the parser fuzz target."""

from __future__ import annotations

from pathlib import Path

import pytest

from fuzz.parser_target import test_one_input as run_fuzz_input

CORPUS_DIR = Path(__file__).resolve().parents[1] / "fuzz" / "corpus" / "parser"
ROUNDTRIP_CORPUS_DIR = Path(__file__).resolve().parents[1] / "fuzz" / "corpus" / "roundtrip"


def test_parser_fuzz_target_accepts_valid_and_invalid_bytes() -> None:
    run_fuzz_input(b'rule valid { strings: $a = "x" condition: $a }')
    run_fuzz_input(b"\xff\x00rule invalid {")


def test_parser_fuzz_target_ignores_invalid_generated_string_references() -> None:
    run_fuzz_input(b'rule basic { strings: $text = "example" ascii wide condition: $tex8 }')


def test_parser_fuzz_seed_corpus_exercises_the_target() -> None:
    seeds = sorted(CORPUS_DIR.glob("*.yar"))
    assert len(seeds) == 3
    for seed in seeds:
        run_fuzz_input(seed.read_bytes())


def test_roundtrip_target_reports_generator_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    from fuzz import roundtrip_target

    class BrokenGenerator:
        def generate(self, _ast: object) -> str:
            raise RuntimeError("generator regression")

    monkeypatch.setattr(roundtrip_target, "CodeGenerator", BrokenGenerator)
    source = b'rule valid { strings: $a = "x" condition: $a }'

    with pytest.raises(RuntimeError, match="generator regression"):
        roundtrip_target.test_one_input(source)


def test_roundtrip_target_skips_semantically_invalid_ast() -> None:
    from fuzz.roundtrip_target import test_one_input

    test_one_input(b'rule basic { strings: $text = "example" condition: $tex8 }')


def test_roundtrip_fuzz_seed_corpus_is_parseable() -> None:
    from fuzz.roundtrip_target import test_one_input

    seeds = sorted(ROUNDTRIP_CORPUS_DIR.glob("*.yar"))
    assert len(seeds) == 2
    for seed in seeds:
        test_one_input(seed.read_bytes())
