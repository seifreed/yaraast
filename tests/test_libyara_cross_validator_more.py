"""Real tests for libyara cross-validator (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.cross_validator import CrossValidator
from yaraast.parser import Parser


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_cross_validator_single_and_batch() -> None:
    code = """
    rule cv_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = Parser().parse(code)
    validator = CrossValidator()

    result = validator.validate(ast, b"xxabcxx")
    assert result.valid is True
    assert result.rules_tested == 1
    assert result.rules_matched == 1
    assert result.match_rate == 100.0

    batch = validator.validate_batch(ast, [b"xxabcxx", b"zzz"])
    assert len(batch) == 2
    assert batch[0].valid is True
    assert batch[1].valid is True
