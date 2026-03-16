from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import BinaryCondition, ReferenceList
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_enhanced_reference_check_success_and_missing_list_error() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IN, "in"),
            _tok(T.IDENTIFIER, "%blocked%", YaraLTokenType.REFERENCE_LIST),
        ],
    )

    cond = p._parse_reference_check()
    assert isinstance(cond, BinaryCondition)
    assert cond.operator == "in"
    assert isinstance(cond.right, ReferenceList)
    assert cond.right.name == "blocked"

    p2 = EnhancedYaraLParser("")
    _set_tokens(
        p2,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IN, "in"),
            _tok(T.STRING, "oops"),
        ],
    )
    with pytest.raises(ValueError, match="Expected reference list"):
        p2._parse_reference_check()


def test_enhanced_primary_condition_reference_list_branch_is_shadowed() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "%blocked%", YaraLTokenType.REFERENCE_LIST)])

    with pytest.raises(ValueError, match="Expected comparison operator"):
        p._parse_primary_condition()


def test_enhanced_primary_condition_rejects_invalid_token() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.STRING, "oops")])

    with pytest.raises(ValueError, match="Expected condition expression"):
        p._parse_primary_condition()
