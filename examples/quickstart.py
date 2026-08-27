"""Minimal parse, inspect, and generate example."""

from __future__ import annotations

import yaraast


def main() -> None:
    source = "rule example { condition: true }"
    document = yaraast.parse(source, dialect="yara")
    assert document.ast.rules[0].name == "example"
    print(yaraast.generate(document))


if __name__ == "__main__":
    main()
