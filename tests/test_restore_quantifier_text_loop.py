# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for ``_restore_quantifier_text``.

The digit-restore and float-restore branches were removed because
``_validate_quantifier_value`` (via ``_validate_quantifier_text``) only ever
returns ``str`` or ``int``: pure-digit strings parse to ``int`` first, and any
float-shaped string is rejected upstream. So once the ``int`` early-return is
taken, every remaining value is returned verbatim. These tests pin that
contract across keyword, integer, percentage, and identifier quantifiers.
"""

from __future__ import annotations

import pytest

from yaraast.errors import SerializationError
from yaraast.serialization.protobuf_conversion import _restore_quantifier_text


@pytest.mark.parametrize("keyword", ["all", "any", "none"])
def test_keyword_quantifiers_pass_through(keyword: str) -> None:
    assert _restore_quantifier_text(keyword, "quantifier", allow_percentage=True) == keyword


@pytest.mark.parametrize(("text", "expected"), [("5", 5), ("+5", 5), ("0", 0)])
def test_integer_quantifiers_become_int(text: str, expected: int) -> None:
    result = _restore_quantifier_text(text, "quantifier", allow_percentage=True)
    assert result == expected
    assert isinstance(result, int)


@pytest.mark.parametrize("identifier", ["myvar", "test", "where", "x"])
def test_identifier_quantifiers_pass_through(identifier: str) -> None:
    result = _restore_quantifier_text(identifier, "quantifier", allow_percentage=True)
    assert result == identifier
    assert isinstance(result, str)


def test_percentage_passes_through_when_allowed() -> None:
    assert _restore_quantifier_text("50%", "quantifier", allow_percentage=True) == "50%"


def test_percentage_rejected_when_not_allowed() -> None:
    with pytest.raises(SerializationError, match="Invalid quantifier"):
        _restore_quantifier_text("50%", "quantifier", allow_percentage=False)


def test_dotted_text_rejected_as_invalid_identifier() -> None:
    with pytest.raises(SerializationError, match="Invalid quantifier identifier"):
        _restore_quantifier_text("abc.def", "quantifier", allow_percentage=True)
