"""Real tests for libyara equivalence tester (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.equivalence import EquivalenceTester
from yaraast.parser import Parser


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_equivalence_round_trip() -> None:
    code = """
    rule eq_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = Parser().parse(code)
    tester = EquivalenceTester()
    result = tester.test_round_trip(ast, test_data=b"xxabcxx")

    assert result.equivalent is True
    assert result.code_equivalent is True
    assert result.ast_equivalent is True
    assert result.original_compiles is True
    assert result.regenerated_compiles is True
