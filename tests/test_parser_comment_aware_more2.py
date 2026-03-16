"""Additional branch coverage for comment-aware parser internals."""

from __future__ import annotations

import pytest

from yaraast.ast.comments import CommentGroup
from yaraast.ast.expressions import BooleanLiteral
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.comment_aware_parser import CommentAwareParser


def _t(tt: TokenType, value, line: int, col: int = 1) -> Token:
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
    meta, strings, cond = p._parse_rule_sections_with_comments()
    assert meta == [] and strings == [] and cond is None

    # _skip_unrecognized_token false branch when RBRACE
    assert p._skip_unrecognized_token() is False

    ensured = p._ensure_condition(None)
    assert isinstance(ensured, BooleanLiteral)


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
        _t(TokenType.XOR_MOD, "xor", 4),
        _t(TokenType.LPAREN, "(", 4),
        _t(TokenType.INTEGER, 1, 4),
        _t(TokenType.COMMA, ",", 4),
        _t(TokenType.INTEGER, 2, 4),
        _t(TokenType.RPAREN, ")", 4),
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
    ast = parser.parse(
        """
rule sample {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    )

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
