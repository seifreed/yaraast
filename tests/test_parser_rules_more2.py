from __future__ import annotations

import pytest

from yaraast.lexer import Lexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.parser import Parser


def _t(tt: TokenType, value) -> Token:
    return Token(type=tt, value=value, line=1, column=1)


def _parser_with_tokens(tokens: list[Token]) -> Parser:
    parser = Parser("rule seed { condition: true }")
    parser.tokens = [*tokens, _t(TokenType.EOF, None)]
    parser.current = 0
    return parser


def test_parse_import_and_include_success_and_errors() -> None:
    parser = _parser_with_tokens(
        [_t(TokenType.STRING, "pe"), _t(TokenType.AS, "as"), _t(TokenType.IDENTIFIER, "pe_mod")]
    )
    imp = parser._parse_import()
    assert imp.module == "pe"
    assert imp.alias == "pe_mod"

    parser2 = _parser_with_tokens([_t(TokenType.STRING, "pe"), _t(TokenType.AS, "as")])
    with pytest.raises(ParserError, match="Expected alias after 'as'"):
        parser2._parse_import()

    parser3 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "pe")])
    with pytest.raises(ParserError, match="Expected module name after 'import'"):
        parser3._parse_import()

    parser4 = _parser_with_tokens([_t(TokenType.STRING, "common.yar")])
    inc = parser4._parse_include()
    assert inc.path == "common.yar"

    parser5 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "common.yar")])
    with pytest.raises(ParserError, match="Expected file path after 'include'"):
        parser5._parse_include()


def test_parse_rule_helpers_and_meta_section_variants() -> None:
    parser = Parser(
        'private global rule demo : tag1 tag2 { meta: a = -1 b = "x" c = true d = false strings: $a = "x" condition: true }'
    )
    rule = parser._parse_rule()
    assert rule.name == "demo"
    assert rule.modifiers == ["private", "global"]
    assert [tag.name for tag in rule.tags] == ["tag1", "tag2"]
    assert rule.meta == {"a": -1, "b": "x", "c": True, "d": False}
    assert len(rule.strings) == 1
    assert rule.condition is not None

    parser2 = _parser_with_tokens(
        [_t(TokenType.PRIVATE, "PRIVATE"), _t(TokenType.GLOBAL, "GLOBAL")]
    )
    assert parser2._parse_rule_modifiers() == ["private", "global"]

    parser3 = _parser_with_tokens([_t(TokenType.RULE, "rule"), _t(TokenType.IDENTIFIER, "named")])
    assert parser3._parse_rule_name() == "named"

    parser4 = _parser_with_tokens(
        [
            _t(TokenType.COLON, ":"),
            _t(TokenType.IDENTIFIER, "tag1"),
            _t(TokenType.IDENTIFIER, "tag2"),
        ]
    )
    assert [t.name for t in parser4._parse_rule_tags()] == ["tag1", "tag2"]

    parser5 = _parser_with_tokens([_t(TokenType.STRINGS, "strings")])
    with pytest.raises(ParserError, match="Expected ':' after 'meta'"):
        parser5._expect_colon("meta")

    parser6 = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "neg"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.INTEGER, 7),
            _t(TokenType.IDENTIFIER, "txt"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.STRING, "v"),
            _t(TokenType.IDENTIFIER, "yes"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.BOOLEAN_TRUE, "true"),
            _t(TokenType.IDENTIFIER, "no"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.BOOLEAN_FALSE, "false"),
            _t(TokenType.RBRACE, "}"),
        ]
    )
    assert parser6._parse_meta_section() == {
        "neg": -7,
        "txt": "v",
        "yes": True,
        "no": False,
    }

    parser7 = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "bad"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.STRING, "x"),
        ]
    )
    with pytest.raises(ParserError, match="Expected number after '-' in meta value"):
        parser7._parse_meta_section()

    parser8 = _parser_with_tokens(
        [_t(TokenType.IDENTIFIER, "bad"), _t(TokenType.ASSIGN, "="), _t(TokenType.LBRACE, "{")]
    )
    with pytest.raises(ParserError, match="Invalid meta value"):
        parser8._parse_meta_section()

    parser9 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "bad")])
    with pytest.raises(ParserError, match="Expected '=' after meta key"):
        parser9._parse_meta_section()

    parser10 = _parser_with_tokens([_t(TokenType.STRING, "not-a-key")])
    assert parser10._parse_meta_section() == {}


def test_parse_rule_and_sections_error_paths() -> None:
    with pytest.raises(ParserError, match="Expected 'rule' keyword"):
        _parser_with_tokens([_t(TokenType.IDENTIFIER, "x")])._parse_rule_name()

    with pytest.raises(ParserError, match="Expected rule name"):
        _parser_with_tokens([_t(TokenType.RULE, "rule")])._parse_rule_name()

    with pytest.raises(ParserError, match="Expected '\\{' after rule name"):
        Parser("rule r")._parse_rule()

    with pytest.raises(ParserError, match="Expected '\\}' at end of rule"):
        Parser("rule r { condition: true ")._parse_rule()

    parser = Parser("rule r { junk: true }")
    parser.current = 3  # position on junk
    with pytest.raises(ParserError, match="Unexpected section: junk"):
        parser._parse_rule_sections()

    parser2 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "x")])
    assert parser2._parse_rule_tags() == []

    parser3 = _parser_with_tokens([_t(TokenType.RBRACE, "}")])
    meta, strings, condition = parser3._parse_rule_sections()
    assert meta == {}
    assert strings == []
    assert condition is None


def test_parse_import_include_and_rule_via_full_parse() -> None:
    ast = Parser(
        'import "pe" as pe_mod include "common.yar" private rule sample : t1 { meta: score = 1 strings: $a = "x" condition: true }'
    ).parse()
    assert ast.imports[0].module == "pe"
    assert ast.imports[0].alias == "pe_mod"
    assert ast.includes[0].path == "common.yar"
    assert ast.rules[0].name == "sample"
    assert ast.rules[0].modifiers == ["private"]

    tokens = Lexer("rule only_condition { condition: true }").tokenize()
    parser = Parser("rule seed { condition: true }")
    parser.tokens = tokens
    parser.current = 0
    rule = parser._parse_rule()
    assert rule.name == "only_condition"
