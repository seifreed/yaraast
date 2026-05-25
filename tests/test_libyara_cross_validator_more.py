"""Real tests for libyara cross-validator (no mocks)."""

from __future__ import annotations

from typing import Any, cast

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


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_cross_validator_applies_externals_to_yaraast_and_batch_compile() -> None:
    ast = Parser().parse("rule ext_rule { condition: ext_flag }")

    validator = CrossValidator()
    result = validator.validate(ast, b"payload", externals={"ext_flag": True})

    assert result.valid is True
    assert result.yaraast_results == {"ext_rule": True}
    assert result.libyara_results == {"ext_rule": True}

    fresh_validator = CrossValidator()
    batch = fresh_validator.validate_batch(ast, [b"payload"], externals={"ext_flag": True})

    assert len(batch) == 1
    assert batch[0].valid is True
    assert batch[0].yaraast_results == {"ext_rule": True}
    assert batch[0].libyara_results == {"ext_rule": True}


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_cross_validator_rejects_non_mapping_externals() -> None:
    ast = Parser().parse("rule ext_rule { condition: true }")
    validator = CrossValidator()

    with pytest.raises(TypeError, match="libyara externals must be a dictionary"):
        validator.validate(ast, b"payload", externals=cast(Any, []))

    with pytest.raises(TypeError, match="libyara externals must be a dictionary"):
        validator.validate_batch(ast, [b"payload"], externals=cast(Any, []))


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_cross_validator_resets_compiler_externals_between_calls() -> None:
    validator = CrossValidator()
    ast = Parser().parse("rule plain_rule { condition: true }")

    validator.validate(ast, b"payload", externals={"ext_flag": True})
    result = validator.validate(ast, b"payload")

    assert result.valid is True
    assert validator.compiler.externals == {}
