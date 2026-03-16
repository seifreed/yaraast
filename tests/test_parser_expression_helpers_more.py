"""Additional tests for parser expression helper mixins and hex parser."""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexNibble, HexWildcard
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.hex_parser import HexParseError, HexStringParser
from yaraast.parser.parser import Parser


def _t(tt: TokenType, value) -> Token:
    return Token(type=tt, value=value, line=1, column=1)


def _parser_with_tokens(tokens: list[Token]) -> Parser:
    p = Parser("rule seed { condition: true }")
    p.tokens = [*tokens, _t(TokenType.EOF, None)]
    p.current = 0
    return p


def test_parse_postfix_helpers_cover_success_and_error_paths() -> None:
    p = _parser_with_tokens(
        [_t(TokenType.IDENTIFIER, "obj"), _t(TokenType.DOT, "."), _t(TokenType.IDENTIFIER, "field")]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, MemberAccess)
    assert expr.member == "field"

    p = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "arr"),
            _t(TokenType.LBRACKET, "["),
            _t(TokenType.INTEGER, 2),
            _t(TokenType.RBRACKET, "]"),
        ]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, ArrayAccess)
    assert isinstance(expr.index, IntegerLiteral)

    p = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "dict"),
            _t(TokenType.LBRACKET, "["),
            _t(TokenType.STRING, "key"),
            _t(TokenType.RBRACKET, "]"),
        ]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, DictionaryAccess)
    assert expr.key == "key"

    p = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "f"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 1),
            _t(TokenType.COMMA, ","),
            _t(TokenType.STRING, "x"),
            _t(TokenType.RPAREN, ")"),
        ]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, FunctionCall)
    assert expr.function == "f"
    assert len(expr.arguments) == 2

    p = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "pe"),
            _t(TokenType.DOT, "."),
            _t(TokenType.IDENTIFIER, "section"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 1),
            _t(TokenType.RPAREN, ")"),
        ]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, FunctionCall)
    assert expr.function == "pe.section"

    p = _parser_with_tokens(
        [_t(TokenType.STRING_IDENTIFIER, "$a"), _t(TokenType.AT, "at"), _t(TokenType.INTEGER, 10)]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, AtExpression)
    assert expr.string_id == "$a"

    p = _parser_with_tokens(
        [_t(TokenType.STRING_IDENTIFIER, "$a"), _t(TokenType.IN, "in"), _t(TokenType.INTEGER, 4)]
    )
    expr = p._parse_postfix_expression()
    assert isinstance(expr, InExpression)
    assert expr.subject == "$a"

    of_expr = OfExpression(quantifier=StringLiteral("any"), string_set=Identifier("them"))
    p = Parser("rule seed { condition: true }")
    p.tokens = [_t(TokenType.INTEGER, 7), _t(TokenType.EOF, None)]
    p.current = 0
    expr = p._parse_in_postfix(of_expr)
    assert isinstance(expr, InExpression)
    assert expr.subject is of_expr

    p = _parser_with_tokens([_t(TokenType.IDENTIFIER, "obj"), _t(TokenType.DOT, ".")])
    with pytest.raises(ParserError, match="Expected member name after '.'"):
        p._parse_postfix_expression()

    p = _parser_with_tokens(
        [_t(TokenType.IDENTIFIER, "arr"), _t(TokenType.LBRACKET, "["), _t(TokenType.INTEGER, 2)]
    )
    with pytest.raises(ParserError, match="Expected ']'"):
        p._parse_postfix_expression()

    p = _parser_with_tokens(
        [_t(TokenType.IDENTIFIER, "f"), _t(TokenType.LPAREN, "("), _t(TokenType.INTEGER, 1)]
    )
    with pytest.raises(ParserError, match="Expected '\\)' after arguments"):
        p._parse_postfix_expression()

    p = Parser("rule seed { condition: true }")
    p.tokens = [_t(TokenType.RPAREN, ")"), _t(TokenType.EOF, None)]
    p.current = 0
    with pytest.raises(ParserError, match="Invalid function call"):
        p._parse_function_call_postfix(StringLiteral("x"))

    p = Parser("rule seed { condition: true }")
    p.tokens = [_t(TokenType.INTEGER, 1), _t(TokenType.EOF, None)]
    p.current = 0
    with pytest.raises(ParserError, match="AT keyword can only be used with string identifiers"):
        p._parse_at_postfix(Identifier("x"))

    p = Parser("rule seed { condition: true }")
    p.tokens = [_t(TokenType.INTEGER, 1), _t(TokenType.EOF, None)]
    p.current = 0
    with pytest.raises(
        ParserError, match="IN keyword can only be used with string identifiers or 'of' expressions"
    ):
        p._parse_in_postfix(Identifier("x"))

    p = Parser("rule seed { condition: true }")
    assert (
        p._build_function_name_from_member_access(
            MemberAccess(object=Identifier("pe"), member="sec"),
        )
        == "pe.sec"
    )
    assert (
        p._build_function_name_from_member_access(
            MemberAccess(object=ModuleReference(module="pe"), member="sec"),
        )
        == "pe.sec"
    )
    nested = MemberAccess(object=MemberAccess(object=Identifier("a"), member="b"), member="c")
    assert p._build_function_name_from_member_access(nested) == "a.b.c"
    assert (
        p._build_function_name_from_member_access(
            MemberAccess(object=StringLiteral("x"), member="c")
        )
        == "unknown.c"
    )


def test_parse_primary_helpers_cover_literals_strings_keywords_and_sets() -> None:
    p = _parser_with_tokens([_t(TokenType.INTEGER, 7)])
    assert isinstance(p._parse_primary_expression(), IntegerLiteral)

    p = _parser_with_tokens([_t(TokenType.DOUBLE, 1.5)])
    assert isinstance(p._parse_primary_expression(), DoubleLiteral)

    p = _parser_with_tokens([_t(TokenType.STRING, "abc")])
    assert isinstance(p._parse_primary_expression(), StringLiteral)

    p = _parser_with_tokens([_t(TokenType.BOOLEAN_TRUE, "true")])
    lit = p._parse_primary_expression()
    assert isinstance(lit, BooleanLiteral) and lit.value is True

    p = _parser_with_tokens([_t(TokenType.BOOLEAN_FALSE, "false")])
    lit = p._parse_primary_expression()
    assert isinstance(lit, BooleanLiteral) and lit.value is False

    p = _parser_with_tokens([_t(TokenType.REGEX, "ab+\x00is")])
    lit = p._parse_primary_expression()
    assert isinstance(lit, RegexLiteral)
    assert lit.pattern == "ab+"
    assert lit.modifiers == "is"

    p = _parser_with_tokens([_t(TokenType.STRING_IDENTIFIER, "$a")])
    assert isinstance(p._parse_primary_expression(), StringIdentifier)

    p = _parser_with_tokens([_t(TokenType.STRING_IDENTIFIER, "$a*")])
    assert isinstance(p._parse_primary_expression(), StringWildcard)

    p = _parser_with_tokens([_t(TokenType.STRING_COUNT, "#a")])
    node = p._parse_primary_expression()
    assert isinstance(node, StringCount)
    assert node.string_id == "a"

    p = _parser_with_tokens(
        [
            _t(TokenType.STRING_OFFSET, "@a"),
            _t(TokenType.LBRACKET, "["),
            _t(TokenType.INTEGER, 1),
            _t(TokenType.RBRACKET, "]"),
        ]
    )
    node = p._parse_primary_expression()
    assert isinstance(node, StringOffset)
    assert isinstance(node.index, IntegerLiteral)

    p = _parser_with_tokens(
        [
            _t(TokenType.STRING_LENGTH, "!a"),
            _t(TokenType.LBRACKET, "["),
            _t(TokenType.INTEGER, 1),
            _t(TokenType.RBRACKET, "]"),
        ]
    )
    node = p._parse_primary_expression()
    assert isinstance(node, StringLength)
    assert isinstance(node.index, IntegerLiteral)

    p = _parser_with_tokens([_t(TokenType.FILESIZE, "filesize")])
    assert p._parse_primary_expression().name == "filesize"
    p = _parser_with_tokens([_t(TokenType.ENTRYPOINT, "entrypoint")])
    assert p._parse_primary_expression().name == "entrypoint"
    p = _parser_with_tokens([_t(TokenType.THEM, "them")])
    assert p._parse_primary_expression().name == "them"

    p = _parser_with_tokens([_t(TokenType.IDENTIFIER, "pe")])
    ident = p._parse_primary_expression()
    assert isinstance(ident, ModuleReference)

    p = _parser_with_tokens(
        [
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 1),
            _t(TokenType.COMMA, ","),
            _t(TokenType.INTEGER, 2),
            _t(TokenType.RPAREN, ")"),
        ]
    )
    expr = p._parse_primary_expression()
    assert isinstance(expr, SetExpression)
    assert len(expr.elements) == 2

    p = _parser_with_tokens(
        [_t(TokenType.LPAREN, "("), _t(TokenType.INTEGER, 1), _t(TokenType.RPAREN, ")")]
    )
    expr = p._parse_primary_expression()
    assert isinstance(expr, ParenthesesExpression)

    p = _parser_with_tokens(
        [
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 2),
            _t(TokenType.RPAREN, ")"),
            _t(TokenType.OF, "of"),
            _t(TokenType.THEM, "them"),
        ]
    )
    expr = p._parse_primary_expression()
    assert isinstance(expr, OfExpression)

    p = _parser_with_tokens(
        [_t(TokenType.INTEGER, 2), _t(TokenType.OF, "of"), _t(TokenType.THEM, "them")]
    )
    expr = p._parse_primary_expression()
    assert isinstance(expr, OfExpression)

    p = _parser_with_tokens(
        [_t(TokenType.ANY, "any"), _t(TokenType.OF, "of"), _t(TokenType.THEM, "them")]
    )
    assert isinstance(p._parse_primary_expression(), OfExpression)

    p = _parser_with_tokens(
        [_t(TokenType.STRING_IDENTIFIER, "$a"), _t(TokenType.AT, "at"), _t(TokenType.INTEGER, 5)]
    )
    expr = p._try_parse_string_operation()
    assert isinstance(expr, AtExpression)

    p = _parser_with_tokens(
        [_t(TokenType.STRING_IDENTIFIER, "$a"), _t(TokenType.IN, "in"), _t(TokenType.INTEGER, 5)]
    )
    expr = p._try_parse_string_operation()
    assert isinstance(expr, InExpression)

    p = _parser_with_tokens([_t(TokenType.STRING_IDENTIFIER, "$a*")])
    assert isinstance(p._try_parse_string_operation(), StringWildcard)

    p = _parser_with_tokens([_t(TokenType.STRING_IDENTIFIER, "$a")])
    assert isinstance(p._try_parse_string_operation(), StringIdentifier)

    p = _parser_with_tokens(
        [
            _t(TokenType.FOR, "for"),
            _t(TokenType.ANY, "any"),
            _t(TokenType.OF, "of"),
            _t(TokenType.THEM, "them"),
            _t(TokenType.COLON, ":"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.BOOLEAN_TRUE, "true"),
            _t(TokenType.RPAREN, ")"),
        ]
    )
    expr = p._try_parse_for_expression()
    assert expr is not None

    p = _parser_with_tokens(
        [_t(TokenType.STRING_OFFSET, "@a"), _t(TokenType.LBRACKET, "["), _t(TokenType.INTEGER, 1)]
    )
    with pytest.raises(ParserError, match="Expected ']'"):
        p._parse_primary_expression()

    p = _parser_with_tokens(
        [_t(TokenType.STRING_LENGTH, "!a"), _t(TokenType.LBRACKET, "["), _t(TokenType.INTEGER, 1)]
    )
    with pytest.raises(ParserError, match="Expected ']'"):
        p._parse_primary_expression()

    p = _parser_with_tokens(
        [
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 1),
            _t(TokenType.COMMA, ","),
            _t(TokenType.INTEGER, 2),
        ]
    )
    with pytest.raises(ParserError, match="Expected '\\)' after set elements"):
        p._parse_primary_expression()

    p = _parser_with_tokens([_t(TokenType.LPAREN, "("), _t(TokenType.INTEGER, 1)])
    with pytest.raises(ParserError, match="Expected '\\)' after expression"):
        p._parse_primary_expression()

    p = _parser_with_tokens([_t(TokenType.RPAREN, ")")])
    with pytest.raises(ParserError, match="Unexpected token"):
        p._parse_primary_expression()


def test_hex_string_parser_covers_remaining_branches_and_errors() -> None:
    parser = HexStringParser()

    assert str(HexParseError("boom")) == "Hex parse error: boom"

    cleaned = parser._remove_comments("AA // one\n BB /* two */ CC /* unterminated")
    assert "one" not in cleaned
    assert "two" not in cleaned
    assert "AA" in cleaned and "BB" in cleaned and "CC" in cleaned

    parser.content = " \t\nAA"
    parser.pos = 0
    parser._skip_whitespace()
    assert parser.pos == 3

    assert len(parser.parse("AA   ")) == 1

    parser.content = "A?"
    parser.pos = 0
    tok = parser._parse_hex_byte()
    assert isinstance(tok, HexNibble) and tok.high is True and tok.value == 10

    parser.content = "AB"
    parser.pos = 0
    tok = parser._parse_hex_byte()
    assert isinstance(tok, HexByte) and tok.value == 0xAB

    parser.content = "?B"
    parser.pos = 0
    tok = parser._parse_wildcard()
    assert isinstance(tok, HexNibble) and tok.high is False and tok.value == 0xB

    parser.content = "??"
    parser.pos = 0
    tok = parser._parse_wildcard()
    assert isinstance(tok, HexWildcard)

    assert parser._parse_jump_range("-5") == HexJump(min_jump=None, max_jump=5)
    assert parser._parse_jump_range("3-") == HexJump(min_jump=3, max_jump=None)
    assert parser._parse_jump_range("4") == HexJump(min_jump=4, max_jump=4)

    parser.content = "( AA | ( BB | CC ) )"
    parser.pos = 0
    alt = parser._parse_alternative()
    assert isinstance(alt, HexAlternative)
    assert alt.alternatives

    parser.content = "( [1-2] X"
    parser.pos = 0
    alt = parser._parse_alternative()
    assert isinstance(alt, HexAlternative)
    assert alt.alternatives
    assert any(isinstance(tok, HexJump) for tok in alt.alternatives[0])

    parser.content = "[1-3]"
    parser.pos = 0
    jump = parser._parse_jump()
    assert isinstance(jump, HexJump)
    assert jump.min_jump == 1 and jump.max_jump == 3

    parser.content = "("
    parser.pos = 0
    alt = parser._parse_alternative()
    assert isinstance(alt, HexAlternative)
    assert alt.alternatives == []

    with pytest.raises(HexParseError, match="Invalid hex byte"):
        parser.parse("A ")

    with pytest.raises(HexParseError, match="Invalid wildcard"):
        parser.parse("? ")

    with pytest.raises(HexParseError, match="Invalid jump range"):
        parser._parse_jump_range("1-2-3")

    parser.content = "[1-"
    parser.pos = 0
    with pytest.raises(HexParseError, match="Unterminated jump"):
        parser._parse_jump()

    parser.content = "A"
    parser.pos = 0
    with pytest.raises(HexParseError, match="Incomplete hex byte"):
        parser._parse_hex_byte()

    parser.content = "()"
    parser.pos = 1
    with pytest.raises(HexParseError, match="Expected '\\(' at start of alternative"):
        parser._parse_alternative()
