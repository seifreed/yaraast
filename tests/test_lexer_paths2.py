from __future__ import annotations

import pytest

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.tokens import Token, TokenType


def test_lexer_properties_reset_and_basic_helpers() -> None:
    lex = Lexer("rule a { condition: true }")
    _ = lex.tokenize()

    lex.text = "rule b { condition: true }"
    lex.position = 0
    lex.line = 1
    lex.column = 1
    assert lex.text.startswith("rule b")
    assert lex._peek_char(10) is not None

    tokens = lex.tokenize("rule c { condition: true }")
    assert any(t.value == "c" for t in tokens if t.type == TokenType.IDENTIFIER)

    lex2 = Lexer("")
    assert lex2._next_token() is None
    assert lex2._peek_char() is None


def test_lexer_tokenize_reuse_resets_previous_tokens() -> None:
    lex = Lexer("rule a { condition: true }")

    first = lex.tokenize()
    second = lex.tokenize()

    assert [token.type for token in second] == [token.type for token in first]
    assert len([token for token in second if token.type == TokenType.EOF]) == 1


def test_lexer_number_suffix_and_regex_context_and_hex_context_helpers() -> None:
    lex = Lexer("10KB")
    toks = lex.tokenize()
    nums = [t for t in toks if t.type == TokenType.INTEGER]
    assert nums[0].value == 10 * 1024

    lex2 = Lexer("\\ \n")
    assert lex2._is_line_continuation() is True

    lex3 = Lexer("/")
    lex3.tokens = [Token(TokenType.RPAREN, ")", 1, 1)]
    assert lex3._is_regex_context() is False

    lex4 = Lexer("/")
    lex4.tokens = [Token(TokenType.CONDITION, "condition", 1, 1)]
    assert lex4._is_regex_context() is True

    lex5 = Lexer("{")
    lex5.tokens = [
        Token(TokenType.COMMENT, "//", 1, 1),
        Token(TokenType.STRING_IDENTIFIER, "$a", 1, 1),
        Token(TokenType.ASSIGN, "=", 1, 1),
    ]
    assert lex5._is_hex_string_context() is True

    lex6 = Lexer("/")
    assert lex6._is_regex_context() is True

    lex7 = Lexer("/")
    lex7.tokens = [Token(TokenType.MATCHES, "matches", 1, 1)]
    assert lex7._is_regex_context() is True

    lex8 = Lexer("{")
    lex8.tokens = [Token(TokenType.IDENTIFIER, "x", 1, 1), Token(TokenType.ASSIGN, "=", 1, 2)]
    assert lex8._is_hex_string_context() is False

    lex9 = Lexer("\\  x")
    assert lex9._is_line_continuation() is False


def test_lexer_rejects_integer_literals_above_int64_maximum() -> None:
    valid_values = [
        "9223372036854775807",
        "0x7fffffffffffffff",
        "0o777777777777777777777",
    ]
    for value in valid_values:
        tokens = Lexer(value).tokenize()
        assert tokens[0].type == TokenType.INTEGER

    invalid_values = [
        "9223372036854775808",
        "0x8000000000000000",
        "9100000000000000KB",
    ]
    for value in invalid_values:
        with pytest.raises(LexerError, match="Integer literal exceeds int64 maximum"):
            Lexer(value).tokenize()


def test_lexer_reports_malformed_prefixed_integer_literals_as_lexer_errors() -> None:
    malformed_hex_values = ["0x", "0x_", "0x1_", "0x1__2", "0xg", "0x1g"]
    for value in malformed_hex_values:
        with pytest.raises(LexerError, match="Invalid hexadecimal integer literal"):
            Lexer(value).tokenize()

    malformed_octal_values = ["0o", "0o_", "0o7_", "0o7__1", "0o8", "0o78"]
    for value in malformed_octal_values:
        with pytest.raises(LexerError, match="Invalid octal integer literal"):
            Lexer(value).tokenize()


def test_lexer_reports_malformed_decimal_separators_as_lexer_errors() -> None:
    valid_values = ["1_000", "1_000.5"]
    for value in valid_values:
        tokens = Lexer(value).tokenize()
        assert tokens[0].type in {TokenType.INTEGER, TokenType.DOUBLE}

    malformed_decimal_values = ["1_", "1__2", "1_.5", "1.5_", "1.5__2"]
    for value in malformed_decimal_values:
        with pytest.raises(LexerError, match="Invalid decimal"):
            Lexer(value).tokenize()


def test_lexer_reports_invalid_size_suffixes_as_lexer_errors() -> None:
    valid_values = {"10KB": 10 * 1024, "10MB": 10 * 1024 * 1024}
    for value, expected in valid_values.items():
        tokens = Lexer(value).tokenize()
        assert tokens[0].type == TokenType.INTEGER
        assert tokens[0].value == expected

    invalid_values = ["10K", "10M", "10kb", "10Kb", "10kB", "10mb", "10MBps"]
    for value in invalid_values:
        with pytest.raises(LexerError, match="Invalid size suffix"):
            Lexer(value).tokenize()


def test_lexer_string_and_hex_error_paths() -> None:
    with pytest.raises(LexerError, match="Unterminated string"):
        Lexer('"unterminated').tokenize()

    code = """
rule r {
 strings:
   $a = { 4D // comment with }
"""
    with pytest.raises(LexerError, match="Unterminated hex string"):
        Lexer(code).tokenize()


def test_lexer_regex_and_backslash_division_paths() -> None:
    tokens = Lexer(r"rule r { condition: /a\/b/i }").tokenize()
    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert regex_tokens
    regex_value = regex_tokens[0].value
    assert isinstance(regex_value, str)
    assert "\x00i" in regex_value

    # Backslash followed by a non-newline expression is YARA integer division.
    tokens2 = Lexer("10 \\ 2").tokenize()
    assert any(t.type == TokenType.DIVIDE and t.value == "\\" for t in tokens2)

    tokens3 = Lexer("rule r { condition: true \\ \n and false }").tokenize()
    assert not any(t.type == TokenType.DIVIDE for t in tokens3)


def test_lexer_slash_after_expression_operand_is_division() -> None:
    tokens = Lexer("rule r { condition: 4 / 2 == 2 and filesize / 2 >= 1 }").tokenize()

    assert [token.type for token in tokens].count(TokenType.DIVIDE) == 2
    assert not any(token.type == TokenType.REGEX for token in tokens)


def test_lexer_skips_comments_inside_hex_string_and_reads_regex_modifiers() -> None:
    code = """
rule r {
 strings:
   $a = { 4D // inline comment with }
          5A /* block comment with } */ 90 }
 condition:
   $a
}
"""
    tokens = Lexer(code).tokenize()
    hex_tokens = [t for t in tokens if t.type == TokenType.HEX_STRING]
    assert len(hex_tokens) == 1
    hex_value = hex_tokens[0].value
    assert isinstance(hex_value, str)
    assert "inline comment" not in hex_value
    assert "block comment" not in hex_value
    assert "4D" in hex_value
    assert "5A" in hex_value
    assert "90" in hex_value

    regex_tokens = Lexer(r"rule r { condition: /ab+c/ims }").tokenize()
    assert any(
        t.type == TokenType.REGEX and isinstance(t.value, str) and t.value.endswith("\x00ims")
        for t in regex_tokens
    )


def test_lexer_reports_unterminated_regex_and_handles_hex_numbers_and_line_continuation_edge() -> (
    None
):
    with pytest.raises(LexerError, match="Unterminated regex"):
        Lexer("rule r { condition: /abc }").tokenize()

    tokens = Lexer("0x10").tokenize()
    integer_tokens = [t for t in tokens if t.type == TokenType.INTEGER]
    assert integer_tokens[0].value == 16

    lex = Lexer("\\\r")
    assert lex._is_line_continuation() is True


def test_lexer_covers_escape_sequences_and_malformed_string_endings() -> None:
    string_tokens = [t for t in Lexer(r"""
rule r {
 strings:
   $a = "line\n\t\r\""
   $b = "\x41"
   $c = "C:\TEMP\" wide
 condition:
   all of them
}
""").tokenize() if t.type == TokenType.STRING]

    assert string_tokens[0].value == 'line\n\t\r"'
    assert string_tokens[1].value == "A"
    assert string_tokens[2].value == "C:\\TEMP\\"


def test_lexer_reads_two_char_operators_numbers_and_string_markers() -> None:
    tokens = Lexer("""
rule r {
 condition:
   $* and $name* and #hits > 1 and @off >= 10KB and !len <= 2MB and 1.5 != 2
}
""").tokenize()

    by_type: dict[TokenType, list[Token]] = {}
    for token in tokens:
        by_type.setdefault(token.type, []).append(token)

    assert any(t.value == "!=" for t in by_type[TokenType.NEQ])
    assert any(t.value == "$*" for t in by_type[TokenType.STRING_IDENTIFIER])
    assert any(t.value == "$name*" for t in by_type[TokenType.STRING_IDENTIFIER])
    assert any(t.value == "#hits" for t in by_type[TokenType.STRING_COUNT])
    assert any(t.value == "@off" for t in by_type[TokenType.STRING_OFFSET])
    assert any(t.value == "!len" for t in by_type[TokenType.STRING_LENGTH])
    assert any(t.type == TokenType.DOUBLE and t.value == 1.5 for t in tokens)
    assert any(t.type == TokenType.INTEGER and t.value == 10 * 1024 for t in tokens)
    assert any(t.type == TokenType.INTEGER and t.value == 2 * 1024 * 1024 for t in tokens)


def test_lexer_reports_unexpected_character_and_edge_regex_comment_paths() -> None:
    with pytest.raises(LexerError, match="Unexpected character: `"):
        Lexer("`").tokenize()

    with pytest.raises(LexerError, match="Unterminated regex"):
        Lexer("rule r { condition: /abc\\").tokenize()

    with pytest.raises(LexerError, match="Unterminated hex string"):
        Lexer("""
rule r {
 strings:
   $a = { 4D // eof comment""").tokenize()

    with pytest.raises(LexerError, match="Unterminated hex string"):
        Lexer("""
rule r {
 strings:
   $a = { 4D /* eof block""").tokenize()


def test_lexer_context_helpers_cover_default_regex_and_comment_only_hex_cases() -> None:
    lex = Lexer("x")
    lex.position = len(lex.text)
    lex._advance()
    assert lex.position == len(lex.text)

    lex2 = Lexer("x")
    assert lex2._is_line_continuation() is False

    lex3 = Lexer("/")
    lex3.tokens = [Token(TokenType.IDENTIFIER, "x", 1, 1)]
    assert lex3._is_regex_context() is False

    lex3b = Lexer("/")
    lex3b.tokens = [
        Token(TokenType.COMMENT, "// one", 1, 1),
        Token(TokenType.NEWLINE, "\n", 1, 2),
    ]
    assert lex3b._is_regex_context() is True

    lex4 = Lexer("{")
    lex4.tokens = [
        Token(TokenType.COMMENT, "// one", 1, 1),
        Token(TokenType.COMMENT, "// two", 1, 2),
    ]
    assert lex4._is_hex_string_context() is False
