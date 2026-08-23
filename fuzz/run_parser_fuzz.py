"""Atheris runner for the parser fuzz target."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from fuzz.parser_target import test_one_input


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
