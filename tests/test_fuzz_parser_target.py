"""Regression checks for the parser fuzz target."""

from __future__ import annotations

from pathlib import Path

from fuzz.parser_target import test_one_input as run_fuzz_input

CORPUS_DIR = Path(__file__).resolve().parents[1] / "fuzz" / "corpus" / "parser"


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
