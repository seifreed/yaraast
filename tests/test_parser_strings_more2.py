"""Additional branch coverage for parser string helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.strings import HexNegatedByte, HexString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.tokens import Token, TokenType
from yaraast.limits import LIBYARA_HEX_JUMP_MAX
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


@pytest.mark.parametrize("parser", [Parser(), CommentAwareParser()])
def test_parse_rejects_wildcard_string_definition_identifier(
    parser: Parser | CommentAwareParser,
) -> None:
    source = 'rule r { strings: $* = "x" condition: all of them }'

    with pytest.raises(ParserError, match="Invalid string definition identifier"):
        parser.parse(source)


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
    "source",
    [
        "rule r { strings: $a = /a\n/ condition: $a }",
        'rule r { condition: "abc" matches /a\n/ }',
    ],
)
def test_parse_rejects_raw_newline_inside_regex(source: str) -> None:
    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(LexerError, match="Unterminated regex"):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    "source",
    [
        "rule r { strings: $a = /a\r/ condition: $a }",
        'rule r { condition: "abc" matches /a\\\r/ }',
    ],
)
def test_parse_accepts_carriage_return_inside_regex(source: str) -> None:
    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        assert len(ast.rules) == 1


@pytest.mark.parametrize(
    "pattern",
    [
        "+",
        "?",
        "a**",
        "a++",
        "a*+",
        "a{2,1}",
        "[]",
        "[z-a]",
        r"[\x]",
        r"[\x0]",
        "(?:a)",
        "(?=a)",
        "(?!a)",
        "(?P<x>a)",
        "|a",
        "(|a)",
        "()",
        r"\x",
        r"\x0",
        r"\1",
        "^*",
        r"\b*",
    ],
)
def test_parse_rejects_libyara_invalid_regex_patterns(pattern: str) -> None:
    string_source = f"rule r {{ strings: $a = /{pattern}/ condition: $a }}"
    condition_source = f'rule r {{ condition: "abc" matches /{pattern}/ }}'

    for source in (string_source, condition_source):
        for parser_factory in (Parser, CommentAwareParser):
            with pytest.raises(ParserError, match="regex"):
                parser_factory().parse(source)


@pytest.mark.parametrize("pattern", ["a{32768}", "a{0,32768}", "a{32768,}"])
def test_parse_rejects_regex_repeat_intervals_above_libyara_limit(pattern: str) -> None:
    string_source = f"rule r {{ strings: $a = /{pattern}/ condition: $a }}"
    condition_source = f'rule r {{ condition: "abc" matches /{pattern}/ }}'

    for source in (string_source, condition_source):
        for parser_factory in (Parser, CommentAwareParser):
            with pytest.raises(ParserError, match="repeat interval"):
                parser_factory().parse(source)


@pytest.mark.parametrize(
    "modifiers",
    [
        "ascii ascii",
        "nocase xor",
        "fullword base64",
        "xor base64wide",
        "xor(256)",
        "xor(2-1)",
        "xor(0-256)",
        'base64("short")',
    ],
)
def test_parse_rejects_libyara_invalid_string_modifiers(modifiers: str) -> None:
    source = f'rule r {{ strings: $a = "abc" {modifiers} condition: $a }}'

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    "modifiers",
    [
        "xor(0)",
        "xor(255)",
        "xor(0x0-0xff)",
        "base64 base64wide",
        "base64 ascii wide private",
    ],
)
def test_parse_accepts_libyara_valid_string_modifier_edges(modifiers: str) -> None:
    source = f'rule r {{ strings: $a = "abc" {modifiers} condition: $a }}'

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        assert ast.rules[0].strings[0].modifiers


_DEFAULT_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_ALT_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


@pytest.mark.parametrize(
    "modifiers",
    [
        f'base64("{_ALT_BASE64_ALPHABET}") base64wide',
        f'base64 base64wide("{_ALT_BASE64_ALPHABET}")',
        f'base64("{_DEFAULT_BASE64_ALPHABET}") base64wide("{_ALT_BASE64_ALPHABET}")',
        f'base64wide("{_ALT_BASE64_ALPHABET}") base64("{_DEFAULT_BASE64_ALPHABET}")',
    ],
)
def test_parse_rejects_base64_modifiers_with_differing_alphabets(modifiers: str) -> None:
    source = f'rule r {{ strings: $a = "abc" {modifiers} condition: $a }}'

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="can not specify multiple alphabets"):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    "modifiers",
    [
        f'base64("{_DEFAULT_BASE64_ALPHABET}") base64wide',
        f'base64 base64wide("{_DEFAULT_BASE64_ALPHABET}")',
        f'base64("{_ALT_BASE64_ALPHABET}") base64wide("{_ALT_BASE64_ALPHABET}")',
    ],
)
def test_parse_accepts_base64_modifiers_with_matching_alphabets(modifiers: str) -> None:
    source = f'rule r {{ strings: $a = "abc" {modifiers} condition: $a }}'

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        assert ast.rules[0].strings[0].modifiers


def test_parse_rejects_empty_plain_string_definitions() -> None:
    invalid_sources = [
        'rule r { strings: $a = "" condition: $a }',
        'rule r { strings: $a = "" private condition: $a }',
        'rule r { strings: $a = "" wide condition: $a }',
    ]

    for source in invalid_sources:
        for parser_factory in (Parser, CommentAwareParser):
            with pytest.raises(ParserError, match="empty string"):
                parser_factory().parse(source)


def test_parse_rejects_duplicate_named_string_identifiers() -> None:
    invalid_sources = [
        'rule r { strings: $a = "x" $a = "y" condition: $a }',
        'rule r { strings: $a = "x" $b = { 01 } $a = /x/ condition: any of them }',
    ]

    for source in invalid_sources:
        for parser_factory in (Parser, CommentAwareParser):
            with pytest.raises(ParserError, match="duplicated string identifier"):
                parser_factory().parse(source)


def test_parse_allows_multiple_anonymous_strings() -> None:
    source = 'rule r { strings: $ = "x" $ = "y" condition: all of them }'

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        identifiers = [string.identifier for string in ast.rules[0].strings]
        assert identifiers == ["$anon_1", "$anon_2"]


@pytest.mark.parametrize(
    "modifier",
    [
        "ascii",
        "wide",
        "nocase",
        "fullword",
        "xor",
        "xor(1)",
        "base64",
        "base64wide",
    ],
)
def test_parse_rejects_libyara_invalid_hex_string_modifiers(modifier: str) -> None:
    source = f"rule r {{ strings: $a = {{ 01 }} {modifier} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="not valid on hex strings"):
            parser_factory().parse(source)


def test_parse_accepts_private_hex_string_modifier() -> None:
    source = "rule r { strings: $a = { 01 } private condition: $a }"

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        assert ast.rules[0].strings[0].modifiers[0].name == "private"


@pytest.mark.parametrize("modifier", ["xor", "xor(1)", "base64", "base64wide"])
def test_parse_rejects_libyara_invalid_regex_string_modifiers(modifier: str) -> None:
    source = f"rule r {{ strings: $a = /abc/ {modifier} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="not valid on regex strings"):
            parser_factory().parse(source)


@pytest.mark.parametrize("modifier", ["ascii", "wide", "nocase", "fullword", "private"])
def test_parse_accepts_libyara_valid_regex_string_modifiers(modifier: str) -> None:
    source = f"rule r {{ strings: $a = /abc/ {modifier} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        assert ast.rules[0].strings[0].modifiers


@pytest.mark.parametrize(
    "pattern",
    [
        "a*?",
        "a+?",
        "a??",
        "a{,2}",
        "a{2,}",
        "a{32767}",
        "a{0,32767}",
        "a{32767,}",
        "a{x}",
        "a{1,2,3}",
        "a|",
        "a||b",
        "(a|)",
        "(a||b)",
        r"\q",
        r"[\1]",
        "[]a]",
        "[^]a]",
    ],
)
def test_parse_accepts_libyara_valid_regex_edge_cases(pattern: str) -> None:
    source = f"rule r {{ strings: $a = /{pattern}/ condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, RegexString)
        assert string_def.regex == pattern


@pytest.mark.parametrize(
    "hex_pattern",
    [
        "[1-2]",
        "00 [1-2]",
        "[1-2] 00",
        "00 ( [1-2] | 11 ) 22",
        "00 ( 11 [1-2] | 22 ) 33",
        "00 ( 11 | [1-2] 22 ) 33",
        "00 ( 11 [-] 22 | 33 ) 44",
        "00 ( 11 [1-] 22 | 33 ) 44",
    ],
)
def test_parse_rejects_invalid_hex_jump_placement(hex_pattern: str) -> None:
    source = f"rule r {{ strings: $a = {{ {hex_pattern} }} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="Hex parse error"):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    "hex_pattern",
    [
        "00 [1-2] 11",
        "00 [1] 11",
        "00 [-] 11",
        "00 [1-] 11",
        "00 ( 11 [1-2] 22 | 33 ) 44",
        "00 ( 11 [0-2] 22 | 33 ) 44",
    ],
)
def test_parse_accepts_valid_hex_jump_placement(hex_pattern: str) -> None:
    source = f"rule r {{ strings: $a = {{ {hex_pattern} }} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        ast = parser_factory().parse(source)
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)


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


@pytest.mark.parametrize("pattern", ["AA [{too_large}] BB", "AA [1-{too_large}] BB"])
def test_parse_rejects_hex_jumps_above_libyara_limit(pattern: str) -> None:
    too_large = LIBYARA_HEX_JUMP_MAX + 1
    source = f"rule r {{ strings: $a = {{ {pattern.format(too_large=too_large)} }} condition: $a }}"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match="Invalid jump length"):
            parser_factory().parse(source)


def test_parse_regex_string_inline_modifiers_do_not_roundtrip_nul() -> None:
    ast = Parser("rule r { strings: $r = /ab+c/is condition: $r }").parse()
    regex = ast.rules[0].strings[0]

    assert isinstance(regex, RegexString)
    assert regex.regex == "ab+c"
    assert regex.modifiers == ["i", "s"]

    generated = CodeGenerator().generate(ast)
    assert "\x00" not in generated
    assert "$r = /ab+c/is" in generated
    reparsed = Parser(generated).parse()
    reparsed_regex = reparsed.rules[0].strings[0]
    assert isinstance(reparsed_regex, RegexString)
    assert reparsed_regex.modifiers == ["i", "s"]


@pytest.mark.parametrize("parser_factory", [Parser, CommentAwareParser])
def test_parse_regex_inline_and_spaced_nocase_roundtrips(
    parser_factory: type[Parser] | type[CommentAwareParser],
) -> None:
    source = "rule r { strings: $r = /ab+c/i nocase condition: $r }"
    ast = parser_factory().parse(source)

    assert SemanticValidator().validate(ast).is_valid
    generated = CodeGenerator().generate(ast)
    assert "$r = /ab+c/i nocase" in generated


@pytest.mark.parametrize(
    "source",
    [
        "rule r { strings: $r = /ab+c/m condition: $r }",
        "rule r { strings: $r = /ab+c/ii condition: $r }",
        "rule r { strings: $r = /ab+c/si condition: $r }",
        'rule r { condition: "abc" matches /ab+c/m }',
        'rule r { condition: "abc" matches /ab+c/ii }',
        'rule r { condition: "abc" matches /ab+c/si }',
    ],
)
def test_parse_rejects_invalid_regex_literal_modifiers(source: str) -> None:
    with pytest.raises(ParserError):
        Parser(source).parse()


def test_parse_string_modifiers_xor_variants_and_errors() -> None:
    p = _parser_with_tokens(
        [
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
    assert mods[0].name == "wide"
    assert mods[1].name == "xor"
    assert mods[1].value == (3, 9)

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
