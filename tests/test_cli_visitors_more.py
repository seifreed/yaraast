"""Real tests for CLI visitors (no mocks)."""

from __future__ import annotations

from yaraast.cli.visitors import ASTDumper
from yaraast.parser import Parser


def test_ast_dumper_outputs_structure() -> None:
    code = """
    import "pe"
    include "base.yar"

    rule demo : tag1 {
        meta:
            author = "unit"
        strings:
            $a = "abc" ascii
        condition:
            $a and pe.is_pe
    }
    """

    ast = Parser().parse(code)
    dump = ASTDumper().visit(ast)

    assert dump["type"] == "YaraFile"
    assert dump["imports"][0]["module"] == "pe"
    assert dump["includes"][0]["path"] == "base.yar"
    assert dump["rules"][0]["name"] == "demo"
    assert dump["rules"][0]["tags"]
    assert dump["rules"][0]["meta"]["author"] == "unit"
