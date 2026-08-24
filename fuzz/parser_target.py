"""Pure entry point for parser coverage-guided fuzzing."""

from __future__ import annotations

from yaraast.codegen import CodeGenerator
from yaraast.errors import YaraASTError
from yaraast.parser import Parser


def test_one_input(data: bytes) -> None:
    source = data.decode("utf-8", errors="replace")
    try:
        ast = Parser(source).parse()
    except (YaraASTError, TypeError, ValueError):
        return

    try:
        generated = CodeGenerator().generate(ast)
        Parser(generated).parse()
    except (YaraASTError, TypeError, ValueError):
        return
