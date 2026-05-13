"""Additional branch coverage for unified parser paths (no mocks)."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import ArrayAccess, BinaryExpression
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.parser.source import parse_yara_source
from yaraast.unified_parser import UnifiedParser
from yaraast.yarax.ast_nodes import DictExpression, ListExpression, SliceExpression


def test_unified_parser_parse_yarax_branch_and_get_dialect() -> None:
    parser = UnifiedParser("rule x { condition: true }", dialect=YaraDialect.YARA_X)
    ast = parser.parse()
    assert isinstance(ast, YaraFile)
    assert ast.rules[0].name == "x"
    assert parser.get_dialect() == YaraDialect.YARA_X


def test_auto_detects_yarax_collection_only_syntax() -> None:
    list_source = "rule x { condition: [true][0] }"
    dict_source = 'rule x { condition: {"a": true}["a"] }'
    slice_source = 'rule x { condition: "abc"[0:1] == "a" }'

    assert detect_dialect(list_source) == YaraDialect.YARA_X
    assert detect_dialect(dict_source) == YaraDialect.YARA_X
    assert detect_dialect(slice_source) == YaraDialect.YARA_X

    list_ast = parse_yara_source(list_source)
    dict_ast = parse_yara_source(dict_source)
    slice_ast = parse_yara_source(slice_source)

    list_condition = list_ast.rules[0].condition
    dict_condition = dict_ast.rules[0].condition
    slice_condition = slice_ast.rules[0].condition

    assert isinstance(list_condition, ArrayAccess)
    assert isinstance(dict_condition, ArrayAccess)
    assert isinstance(slice_condition, BinaryExpression)
    assert isinstance(list_condition.array, ListExpression)
    assert isinstance(dict_condition.array, DictExpression)
    assert isinstance(slice_condition.left, SliceExpression)


def test_yarax_collection_detection_does_not_match_classic_hex_jumps() -> None:
    source = """
rule classic_hex_jump {
    strings:
        $a = { 01 [1-2] 02 }
    condition:
        $a
}
"""

    assert detect_dialect(source) == YaraDialect.YARA


def test_extract_preamble_fast_handles_comments_and_aliases() -> None:
    with TemporaryDirectory() as tmp:
        p = Path(tmp) / "r.yar"
        p.write_text(
            """
/* top block
still in comment */
import "pe" as pe_mod
include "base.yar"
// line comment
rule r { condition: true }
""".lstrip(),
            encoding="utf-8",
        )

        imports, includes = UnifiedParser._extract_preamble_fast(p)
        assert len(imports) == 1
        assert imports[0].module == "pe"
        assert imports[0].alias == "pe_mod"
        assert len(includes) == 1
        assert includes[0].path == "base.yar"


def test_extract_preamble_fast_error_and_parse_file_not_found() -> None:
    missing = Path("/definitely/not/here/file.yar")
    imports, includes = UnifiedParser._extract_preamble_fast(missing)
    assert imports == []
    assert includes == []

    with pytest.raises(FileNotFoundError, match="YARA file not found"):
        UnifiedParser.parse_file(missing)
