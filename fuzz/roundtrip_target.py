"""Coverage-guided fuzz target for accepted-input code generation round trips."""

from __future__ import annotations

from yaraast.codegen import CodeGenerator
from yaraast.errors import YaraASTError
from yaraast.parser import Parser
from yaraast.types.semantic_validator import validate_yara_file


def test_one_input(data: bytes) -> None:
    source = data.decode("utf-8", errors="replace")
    try:
        ast = Parser(source).parse()
    except (YaraASTError, TypeError, ValueError):
        return

    try:
        ast.validate_structure()
    except (TypeError, ValueError):
        return

    if validate_yara_file(ast).errors:
        return

    generated = CodeGenerator().generate(ast)
    Parser(generated).parse()
