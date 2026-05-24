"""Additional branch coverage for parser string helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.strings import HexNegatedByte, HexString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.parser.parser import Parser
from yaraast.types.semantic_validator import SemanticValidator


def _t(tt: TokenType, value: str | int | float | None) -> Token:
    return Token(type=tt, value=value, line=1, column=1)


def _parser_with_tokens(tokens: list[Token]) -> Parser:
    p = Parser("rule seed { condition: true }")
    p.tokens = [*tokens, _t(TokenType.EOF, None)]
    p.current = 0
    return p


def test_parse_strings_section_success_and_main_errors() -> None:
    p = _parser_with_tokens(
        [
            _t(TokenType.STRING_IDENTIFIER, "$"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.STRING, "abc"),
            _t(TokenType.NOCASE, "nocase"),
            _t(TokenType.STRING_IDENTIFIER, "$h"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.HEX_STRING, "AA BB"),
            _t(TokenType.STRING_IDENTIFIER, "$r"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.REGEX, "x+"),
            _t(TokenType.CONDITION, "condition"),
        ],
    )
    out = p._parse_strings_section()
    assert len(out) == 3
    assert out[0].identifier == "$anon_1"
    assert out[0].modifiers and out[0].modifiers[0].name == "nocase"

    p = _parser_with_tokens([_t(TokenType.STRING_IDENTIFIER, "$a")])
    with pytest.raises(ParserError, match="Expected '=' after string identifier"):
        p._parse_strings_section()

    p = _parser_with_tokens(
        [
            _t(TokenType.STRING_IDENTIFIER, "$a"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.IDENTIFIER, "bad"),
        ],
    )
    with pytest.raises(ParserError, match="Invalid string value"):
        p._parse_strings_section()


@pytest.mark.parametrize(
    "source",
    [
        'rule r { strings: $anon_1 = "a" $ = "b" condition: any of them }',
        'rule r { strings: $ = "b" $anon_1 = "a" condition: any of them }',
    ],
)
def test_anonymous_string_internal_names_do_not_collide_with_explicit_names(
    source: str,
) -> None:
    ast = Parser(source).parse()
    strings = ast.rules[0].strings
    anonymous = [string for string in strings if string.is_anonymous]

    assert len(anonymous) == 1
    assert anonymous[0].identifier == "$anon_2"
    assert [string.identifier for string in strings].count("$anon_1") == 1
    assert SemanticValidator().validate(ast).is_valid
    assert "$anon_2" not in CodeGenerator().generate(ast)


def test_parse_rejects_empty_hex_strings() -> None:
    source = "rule r { strings: $a = { } condition: $a }"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="Empty hex string"):
            parser_factory().parse(source)


@pytest.mark.parametrize("hex_pattern", ["{ ~ 00 }", "{ ~/* comment */00 }", "{ A/* comment */B }"])
def test_parse_rejects_comment_or_space_joined_hex_tokens(hex_pattern: str) -> None:
    source = f"rule r {{ strings: $a = {hex_pattern} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="Hex parse error"):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    "source",
    [
        "rule r { strings: $a = /(/ condition: $a }",
        'rule r { condition: "abc" matches /(/ }',
    ],
)
def test_parse_rejects_invalid_regex_patterns(source: str) -> None:
    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="regex"):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    ("hex_pattern", "expected_value", "expected_output"),
    [
        ("{ ~?0 }", "?0", "~?0"),
        ("{ ~a? }", "a?", "~A?"),
    ],
)
def test_parse_negated_hex_nibbles(
    hex_pattern: str, expected_value: str, expected_output: str
) -> None:
    source = f"rule r {{ strings: $a = {hex_pattern} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        string_def = ast.rules[0].strings[0]

        assert isinstance(string_def, HexString)
        token = string_def.tokens[0]
        assert isinstance(token, HexNegatedByte)
        assert token.value == expected_value
        assert SemanticValidator().validate(ast).is_valid
        assert expected_output in CodeGenerator().generate(ast)


def test_parse_regex_string_inline_modifiers_do_not_roundtrip_nul() -> None:
    ast = Parser("rule r { strings: $r = /ab+c/ims condition: $r }").parse()
    regex = ast.rules[0].strings[0]

    assert isinstance(regex, RegexString)
    assert regex.regex == "ab+c"
    assert [modifier.name for modifier in regex.modifiers] == ["nocase", "multiline", "dotall"]

    generated = CodeGenerator().generate(ast)
    assert "\x00" not in generated
    assert "$r = /ab+c/ms nocase" in generated
    reparsed = Parser(generated).parse()
    reparsed_regex = reparsed.rules[0].strings[0]
    assert isinstance(reparsed_regex, RegexString)
    assert [modifier.name for modifier in reparsed_regex.modifiers] == [
        "multiline",
        "dotall",
        "nocase",
    ]


def test_parse_string_modifiers_xor_variants_and_errors() -> None:
    p = _parser_with_tokens(
        [
            _t(TokenType.NOCASE, "nocase"),
            _t(TokenType.WIDE, "wide"),
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 3),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.INTEGER, 9),
            _t(TokenType.RPAREN, ")"),
        ],
    )
    mods = p._parse_string_modifiers()
    assert [m.name for m in mods[:2]] == ["nocase", "wide"]
    assert mods[2].name == "xor"
    assert mods[2].value == (3, 9)

    p = _parser_with_tokens(
        [
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 5),
            _t(TokenType.RPAREN, ")"),
        ],
    )
    mods = p._parse_string_modifiers()
    assert mods[0].value == 5

    p = _parser_with_tokens(
        [_t(TokenType.XOR_MOD, "xor"), _t(TokenType.LPAREN, "("), _t(TokenType.RPAREN, ")")]
    )
    with pytest.raises(ParserError, match="Expected integer or range in xor"):
        p._parse_string_modifiers()

    p = _parser_with_tokens(
        [
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 2),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.RPAREN, ")"),
        ],
    )
    with pytest.raises(ParserError, match="Expected integer after '-'"):
        p._parse_string_modifiers()

    p = _parser_with_tokens(
        [
            _t(TokenType.XOR_MOD, "xor"),
            _t(TokenType.LPAREN, "("),
            _t(TokenType.INTEGER, 2),
        ],
    )
    with pytest.raises(ParserError, match="Expected '\\)' after xor parameter"):
        p._parse_string_modifiers()

    for modifier in (TokenType.BASE64, TokenType.BASE64WIDE):
        p = _parser_with_tokens(
            [
                _t(modifier, modifier.name.lower()),
                _t(TokenType.LPAREN, "("),
                _t(TokenType.RPAREN, ")"),
            ],
        )
        with pytest.raises(ParserError, match="Expected string in"):
            p._parse_string_modifiers()


def test_parse_hex_string_error_conversion() -> None:
    p = _parser_with_tokens([_t(TokenType.EOF, None)])
    with pytest.raises(ParserError):
        p._parse_hex_string("AA [1-")
