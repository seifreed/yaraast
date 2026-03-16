"""Additional branch coverage for unified parser paths (no mocks)."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from yaraast.ast.base import YaraFile
from yaraast.dialects import YaraDialect
from yaraast.unified_parser import UnifiedParser


def test_unified_parser_parse_yarax_branch_and_get_dialect() -> None:
    parser = UnifiedParser("rule x { condition: true }", dialect=YaraDialect.YARA_X)
    ast = parser.parse()
    assert isinstance(ast, YaraFile)
    assert ast.rules[0].name == "x"
    assert parser.get_dialect() == YaraDialect.YARA_X


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
