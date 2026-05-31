"""Additional branch coverage for comment-aware parser internals."""

from __future__ import annotations

import pytest

from yaraast.ast.comments import CommentGroup
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.strings import RegexString
from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.types.semantic_validator import SemanticValidator


def _t(tt: TokenType, value: str | int | float | None, line: int, col: int = 1) -> Token:
    return Token(type=tt, value=value, line=line, column=col)


def test_parse_top_level_import_include_and_unexpected_token_paths() -> None:
    parser = CommentAwareParser()

    code = 'import "pe"\ninclude "x.yar"\nrule r { condition: true }\n// trailing\n'
    ast = parser.parse(code)
    assert len(ast.imports) == 1
    assert len(ast.includes) == 1
    assert len(ast.rules) == 1
    assert ast.trailing_comment is not None

    with pytest.raises(ParserError):
        parser.parse("42")


def test_rule_name_and_section_errors_and_recovery() -> None:
    p = CommentAwareParser()

    p.tokens = [_t(TokenType.IDENTIFIER, "x", 1), _t(TokenType.EOF, "", 1)]
    p.current = 0
    with pytest.raises(Exception, match="Expected 'rule'"):
        p._parse_rule_name_with_comments()

    p.tokens = [_t(TokenType.RULE, "rule", 1), _t(TokenType.EOF, "", 1)]
    p.current = 0
    with pytest.raises(Exception, match="Expected rule name"):
        p._parse_rule_name_with_comments()

    p.tokens = [_t(TokenType.IDENTIFIER, "x", 1), _t(TokenType.EOF, "", 1)]
    p.current = 0
    with pytest.raises(Exception, match="Expected '\\{'"):
        p._expect_lbrace()

    p.tokens = [_t(TokenType.IDENTIFIER, "x", 1), _t(TokenType.EOF, "", 1)]
    p.current = 0
    with pytest.raises(Exception, match="Expected ':' after 'meta'"):
        p._expect_section_colon("meta")

    p.tokens = [
        _t(TokenType.IDENTIFIER, "a", 1),
        _t(TokenType.IDENTIFIER, "b", 1),
        _t(TokenType.RBRACE, "}", 1),
        _t(TokenType.EOF, "", 1),
    ]
    p.current = 0
    p._expect_rbrace_with_recovery()
    assert p.current == 3


def test_parse_rule_sections_skip_and_ensure_condition() -> None:
    p = CommentAwareParser()

    p.tokens = [
        _t(TokenType.IDENTIFIER, "junk", 1),
        _t(TokenType.RBRACE, "}", 1),
        _t(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(ParserError, match="Unexpected section: junk"):
        p._parse_rule_sections_with_comments()

    p.current = 0
    assert p._skip_unrecognized_token() is True
    assert p.current == 1

    # _skip_unrecognized_token false branch when RBRACE
    assert p._skip_unrecognized_token() is False

    ensured = p._ensure_condition(None)
    assert isinstance(ensured, BooleanLiteral)


def test_comment_aware_parser_rejects_unknown_rule_sections() -> None:
    with pytest.raises(ParserError, match="Unexpected section: garbage"):
        CommentAwareParser().parse("rule r { garbage condition: false }")


def test_comment_aware_parser_rejects_missing_rule_closing_brace() -> None:
    with pytest.raises(ParserError, match="Expected '\\}' at end of rule"):
        CommentAwareParser().parse("rule r { condition: true // trailing\n")


def test_parse_strings_section_branches_and_modifier_parsing() -> None:
    p = CommentAwareParser()

    p.comment_tokens = [_t(TokenType.COMMENT, "// lead", 1), _t(TokenType.COMMENT, "// tail", 2)]
    p.tokens = [
        _t(TokenType.STRING_IDENTIFIER, "$", 2),
        _t(TokenType.ASSIGN, "=", 2),
        _t(TokenType.STRING, "abc", 2),
        _t(TokenType.NOCASE, "nocase", 2),
        _t(TokenType.STRING_IDENTIFIER, "$h", 3),
        _t(TokenType.ASSIGN, "=", 3),
        _t(TokenType.HEX_STRING, "AA ?? BB", 3),
        _t(TokenType.STRING_IDENTIFIER, "$r", 4),
        _t(TokenType.ASSIGN, "=", 4),
        _t(TokenType.REGEX, "abc\\x00is", 4),
        _t(TokenType.WIDE, "wide", 4),
        _t(TokenType.EOF, "", 5),
    ]
    p.current = 0

    strings = p._parse_strings_section()
    assert len(strings) == 3
    assert strings[0].identifier == "$anon_1"
    assert strings[0].leading_comments
    assert strings[0].trailing_comment is not None

    # Missing assign error path
    p.tokens = [_t(TokenType.STRING_IDENTIFIER, "$a", 1), _t(TokenType.EOF, "", 1)]
    p.current = 0
    with pytest.raises(Exception, match="Expected '='"):
        p._parse_strings_section()

    # Missing string value error path
    p.tokens = [
        _t(TokenType.STRING_IDENTIFIER, "$a", 1),
        _t(TokenType.ASSIGN, "=", 1),
        _t(TokenType.IDENTIFIER, "x", 1),
        _t(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(Exception, match="Expected string value"):
        p._parse_strings_section()


@pytest.mark.parametrize(
    "source",
    [
        'rule r { strings: $anon_1 = "a" $ = "b" condition: any of them }',
        'rule r { strings: $ = "b" $anon_1 = "a" condition: any of them }',
    ],
)
def test_comment_aware_anonymous_internal_names_avoid_explicit_collisions(
    source: str,
) -> None:
    ast = CommentAwareParser().parse(source)
    strings = ast.rules[0].strings
    anonymous = [string for string in strings if string.is_anonymous]

    assert len(anonymous) == 1
    assert anonymous[0].identifier == "$anon_2"
    assert [string.identifier for string in strings].count("$anon_1") == 1
    assert SemanticValidator().validate(ast).is_valid


def test_comment_aware_parser_preserves_parameterized_string_modifiers() -> None:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    ast = CommentAwareParser().parse(f"""
        rule modifiers {{
            strings:
                $xor = "abc" xor(1-2) private
                $b64 = "abc" base64("{alphabet}")
                $b64w = "abc" base64wide("{alphabet}")
            condition:
                any of them
        }}
        """)

    string_modifiers = {
        string_def.identifier: [
            (modifier.name, modifier.value) for modifier in string_def.modifiers
        ]
        for string_def in ast.rules[0].strings
    }

    assert string_modifiers["$xor"] == [("xor", (1, 2)), ("private", None)]
    assert string_modifiers["$b64"] == [("base64", alphabet)]
    assert string_modifiers["$b64w"] == [("base64wide", alphabet)]

    generated = CommentAwareCodeGenerator().generate(ast)

    assert "xor(1-2) private" in generated
    assert f'base64("{alphabet}")' in generated
    assert f'base64wide("{alphabet}")' in generated


def test_comment_aware_parser_preserves_escaped_line_comment_marker_in_regex() -> None:
    ast = CommentAwareParser().parse(r"rule r { strings: $a = /\/\// condition: $a }")
    string_def = ast.rules[0].strings[0]

    assert isinstance(string_def, RegexString)
    assert string_def.regex == r"\/\/"


def test_comment_aware_parser_rejects_empty_base64_parameters() -> None:
    for modifier in ("base64", "base64wide"):
        with pytest.raises(ParserError, match=f"Expected string in {modifier} parameter"):
            CommentAwareParser().parse(
                f'rule modifiers {{ strings: $a = "abc" {modifier}() condition: $a }}'
            )


def test_comment_aware_parser_rejects_invalid_xor_parameters() -> None:
    invalid_rules = [
        'rule modifiers { strings: $a = "abc" xor() condition: $a }',
        'rule modifiers { strings: $a = "abc" xor(foo) condition: $a }',
        'rule modifiers { strings: $a = "abc" xor(1-) condition: $a }',
    ]

    for rule in invalid_rules:
        with pytest.raises(ParserError):
            CommentAwareParser().parse(rule)


def test_parse_meta_section_boolean_and_error_paths_and_trailing_comments() -> None:
    p = CommentAwareParser()

    p.comment_tokens = [_t(TokenType.COMMENT, "// m1", 1), _t(TokenType.COMMENT, "// m2", 2)]
    p.tokens = [
        _t(TokenType.IDENTIFIER, "enabled", 2),
        _t(TokenType.ASSIGN, "=", 2),
        _t(TokenType.BOOLEAN_TRUE, True, 2),
        _t(TokenType.IDENTIFIER, "disabled", 3),
        _t(TokenType.ASSIGN, "=", 3),
        _t(TokenType.BOOLEAN_FALSE, False, 3),
        _t(TokenType.EOF, "", 4),
    ]
    p.current = 0
    meta = p._parse_meta_section()
    assert len(meta) == 2
    assert meta[0].leading_comments

    p.tokens = [_t(TokenType.IDENTIFIER, "k", 1), _t(TokenType.EOF, "", 1)]
    p.current = 0
    with pytest.raises(Exception, match="Expected '=' in meta"):
        p._parse_meta_section()

    p.tokens = [
        _t(TokenType.IDENTIFIER, "k", 1),
        _t(TokenType.ASSIGN, "=", 1),
        _t(TokenType.RBRACE, "}", 1),
        _t(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(Exception, match="Expected meta value"):
        p._parse_meta_section()


def test_comment_aware_parser_accepts_negative_meta_values() -> None:
    ast = CommentAwareParser().parse("rule r { meta: score = -1 condition: true }")

    assert ast.rules[0].meta[0].key == "score"
    assert ast.rules[0].meta[0].value == -1


def test_attach_trailing_comments_group_and_single() -> None:
    p = CommentAwareParser()

    ast = p.parse("rule r { condition: true }\n")

    p.comment_tokens = [_t(TokenType.COMMENT, "// one", 10)]
    p._attach_trailing_comments(ast)
    assert ast.trailing_comment is not None

    p.comment_tokens = [_t(TokenType.COMMENT, "// a", 11), _t(TokenType.COMMENT, "// b", 12)]
    p._attach_trailing_comments(ast)
    assert isinstance(ast.trailing_comment, CommentGroup)


def test_comment_aware_parser_populates_core_node_locations() -> None:
    parser = CommentAwareParser()
    ast = parser.parse("""
rule sample {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip())

    rule = ast.rules[0]
    assert rule.location is not None
    assert rule.location.end_line is not None
    assert rule.location.end_line >= rule.location.line

    meta = rule.meta[0]
    assert meta.location is not None
    assert meta.location.end_column is not None

    string_def = rule.strings[0]
    assert string_def.location is not None
    assert string_def.location.end_column is not None
