"""Regression checks for the parser fuzz target."""

from __future__ import annotations

from fuzz.parser_target import test_one_input as run_fuzz_input


def test_parser_fuzz_target_accepts_valid_and_invalid_bytes() -> None:
    run_fuzz_input(b'rule valid { strings: $a = "x" condition: $a }')
    run_fuzz_input(b"\xff\x00rule invalid {")
