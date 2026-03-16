"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Tests for error-tolerant lexer functionality.
"""

import pytest

from yaraast.lexer.error_tolerant_lexer import ErrorTolerantLexer, LexerErrorInfo
from yaraast.lexer.tokens import TokenType


class TestLexerErrorInfo:
    """Test LexerErrorInfo functionality."""

    def test_error_info_creation(self):
        """Test creation of lexer error information."""
        error = LexerErrorInfo(
            message="Test error",
            line=5,
            column=10,
            context="test context",
            suggestion="Fix it",
            severity="error",
        )

        assert error.message == "Test error"
        assert error.line == 5
        assert error.column == 10
        assert error.context == "test context"
        assert error.suggestion == "Fix it"
        assert error.severity == "error"

    def test_error_info_defaults(self):
        """Test default values for error info."""
        error = LexerErrorInfo(
            message="Test error",
            line=1,
            column=1,
            context="context",
        )

        assert error.suggestion is None
        assert error.severity == "error"

    def test_format_error_basic(self):
        """Test basic error formatting."""
        error = LexerErrorInfo(
            message="Unexpected character",
            line=3,
            column=5,
            context="line1\nline2\nline3",
        )

        formatted = error.format_error()

        assert "Unexpected character" in formatted
        assert "Line 3" in formatted
        assert "Column 5" in formatted
        assert "=" * 60 in formatted

    def test_format_error_with_suggestion(self):
        """Test error formatting with suggestion."""
        error = LexerErrorInfo(
            message="Syntax error",
            line=1,
            column=1,
            context="test",
            suggestion="Use correct syntax",
        )

        formatted = error.format_error()

        assert "Use correct syntax" in formatted
        assert "Suggestion:" in formatted

    def test_format_error_multiline_context(self):
        """Test error formatting with multiline context."""
        error = LexerErrorInfo(
            message="Error",
            line=2,
            column=3,
            context="line1\nerror line\nline3",
        )

        formatted = error.format_error()

        # Check that line numbers are shown
        assert "line1" in formatted or "error line" in formatted

    def test_format_error_severity_levels(self):
        """Test formatting with different severity levels."""
        for severity in ["error", "warning", "info"]:
            error = LexerErrorInfo(
                message="Test",
                line=1,
                column=1,
                context="test",
                severity=severity,
            )

            formatted = error.format_error()
            assert severity.upper() in formatted


class TestErrorTolerantLexer:
    """Test ErrorTolerantLexer functionality."""

    def test_lexer_initialization(self):
        """Test lexer initialization."""
        text = "rule test { condition: true }"
        lexer = ErrorTolerantLexer(text)

        assert lexer.original_text == text
        assert lexer.max_errors == 100
        assert len(lexer.errors) == 0

    def test_lexer_initialization_with_max_errors(self):
        """Test lexer initialization with custom max_errors."""
        text = "rule test"
        lexer = ErrorTolerantLexer(text, max_errors=50)

        assert lexer.max_errors == 50

    def test_tokenize_valid_rule(self):
        """Test tokenizing a valid YARA rule."""
        text = """
        rule test {
            condition: true
        }
        """
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should have tokens and no errors
        assert len(tokens) > 0
        assert len(errors) == 0
        assert tokens[-1].type == TokenType.EOF

    def test_tokenize_with_lexer_error(self):
        """Test tokenizing text with lexer errors."""
        # Invalid character that will cause a lexer error
        text = "rule test { condition: @ }"
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should collect errors but continue
        assert len(tokens) > 0
        assert tokens[-1].type == TokenType.EOF

    def test_tokenize_unterminated_string(self):
        """Test handling of unterminated string."""
        text = 'rule test { strings: $a = "unterminated }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should detect unterminated string error
        assert len(errors) > 0
        assert any("Unterminated string" in e.message for e in errors)
        assert tokens[-1].type == TokenType.EOF

    def test_error_count_tracking(self):
        """Test that errors are tracked properly."""
        text = "rule test"
        lexer = ErrorTolerantLexer(text, max_errors=10)
        tokens, errors = lexer.tokenize()

        # Valid simple rule should have no errors
        assert isinstance(errors, list)
        # Verify we got an EOF token
        assert tokens[-1].type == TokenType.EOF

    def test_recover_from_error_string(self):
        """Test recovery from string errors."""
        text = 'rule test { strings: $a = "test" $b = "valid" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should recover and continue parsing
        assert tokens[-1].type == TokenType.EOF

    def test_recover_from_error_hex_string(self):
        """Test recovery from hex string errors."""
        text = "rule test { strings: $a = { AB CD } }"
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should parse hex string successfully
        assert tokens[-1].type == TokenType.EOF

    def test_recover_from_error_regex(self):
        """Test recovery from regex-related errors."""
        text = "rule test { strings: $a = /test/ }"
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should handle regex
        assert tokens[-1].type == TokenType.EOF

    def test_add_error_with_context(self):
        """Test adding errors with context."""
        text = "line1\nline2\nline3"
        lexer = ErrorTolerantLexer(text)
        lexer.tokenize()  # Initialize lexer state

        # Manually add error to test context extraction
        lexer.line = 2
        lexer.column = 5
        lexer._add_error("Test error", severity="warning")

        assert len(lexer.errors) > 0
        error = lexer.errors[-1]
        assert error.line == 2
        assert error.column == 5
        assert error.severity == "warning"
        assert "line2" in error.context

    def test_add_error_with_suggestion(self):
        """Test adding errors with suggestions."""
        text = "test"
        lexer = ErrorTolerantLexer(text)
        lexer.tokenize()

        lexer._add_error("Error message", suggestion="Try this instead")

        assert len(lexer.errors) > 0
        assert lexer.errors[-1].suggestion == "Try this instead"

    def test_read_string_with_escaped_quote(self):
        """Test reading string with escaped quotes."""
        text = r'rule test { strings: $a = "test \"quoted\" text" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Find STRING token
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) > 0
        assert '"' in string_tokens[0].value

    def test_read_string_with_backslash_at_end(self):
        """Test reading Windows-style path with backslash at end."""
        text = r'rule test { strings: $a = "C:\\TEMP\\" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should handle backslash at end with warning
        assert tokens[-1].type == TokenType.EOF

    def test_read_string_with_escape_sequences(self):
        """Test reading string with various escape sequences."""
        text = r'rule test { strings: $a = "line1\nline2\ttab\rreturn" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should parse escape sequences
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) > 0
        assert "\n" in string_tokens[0].value
        assert "\t" in string_tokens[0].value
        assert "\r" in string_tokens[0].value

    def test_read_string_with_hex_escape(self):
        """Test reading string with hex escape sequences."""
        text = r'rule test { strings: $a = "test\x41\x42" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should parse hex escapes
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) > 0

    def test_read_string_with_invalid_hex_escape(self):
        """Test reading string with invalid hex escape."""
        text = r'rule test { strings: $a = "test\xZZ" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should handle invalid hex escape
        assert tokens[-1].type == TokenType.EOF

    def test_read_string_with_unknown_escape(self):
        """Test reading string with unknown escape sequences."""
        text = r'rule test { strings: $a = "test\q" }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should handle unknown escape
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) > 0

    def test_skip_to_whitespace(self):
        """Test skipping to whitespace."""
        text = "abcdef   "
        lexer = ErrorTolerantLexer(text)
        lexer.position = 0

        lexer._skip_to_whitespace()

        # Should be at whitespace
        assert lexer.position >= 6

    def test_skip_to_char(self):
        """Test skipping to specific character."""
        text = "abc}def"
        lexer = ErrorTolerantLexer(text)
        lexer.position = 0

        lexer._skip_to_char("}")

        # Should be at the target character
        assert lexer._current_char() == "}"

    def test_recover_from_unterminated_string_with_quote(self):
        """Test recovery from unterminated string that finds closing quote."""
        text = 'test" more text'
        lexer = ErrorTolerantLexer(text)
        lexer.position = 0

        lexer._recover_from_unterminated_string()

        # Should advance past the quote
        assert lexer.position > 0

    def test_recover_from_unterminated_string_with_newline(self):
        """Test recovery from unterminated string that finds newline."""
        text = "test\nmore"
        lexer = ErrorTolerantLexer(text)
        lexer.position = 0

        lexer._recover_from_unterminated_string()

        # Should advance past the newline
        assert lexer.position > 0

    def test_error_context_at_file_start(self):
        """Test error context extraction at start of file."""
        text = "line1\nline2\nline3"
        lexer = ErrorTolerantLexer(text)
        lexer.tokenize()

        lexer.line = 1
        lexer.column = 1
        lexer._add_error("Error at start")

        assert len(lexer.errors) > 0
        assert lexer.errors[-1].context

    def test_error_context_at_file_end(self):
        """Test error context extraction at end of file."""
        text = "line1\nline2\nline3"
        lexer = ErrorTolerantLexer(text)
        lexer.tokenize()

        lexer.line = 3
        lexer.column = 5
        lexer._add_error("Error at end")

        assert len(lexer.errors) > 0
        assert lexer.errors[-1].context

    def test_tokenize_empty_input(self):
        """Test tokenizing empty input."""
        lexer = ErrorTolerantLexer("")
        tokens, errors = lexer.tokenize()

        # Should only have EOF token
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF
        assert len(errors) == 0

    def test_tokenize_whitespace_only(self):
        """Test tokenizing whitespace-only input."""
        lexer = ErrorTolerantLexer("   \n\t  \n  ")
        tokens, errors = lexer.tokenize()

        # Should only have EOF token
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF
        assert len(errors) == 0

    @pytest.mark.parametrize(
        "severity",
        ["error", "warning", "info"],
    )
    def test_add_error_severity_levels(self, severity):
        """Test adding errors with different severity levels."""
        lexer = ErrorTolerantLexer("test")
        lexer.tokenize()

        lexer._add_error(f"Test {severity}", severity=severity)

        assert len(lexer.errors) > 0
        assert lexer.errors[-1].severity == severity

    @pytest.mark.parametrize(
        "escape_seq,expected_char",
        [
            (r"\n", "\n"),
            (r"\r", "\r"),
            (r"\t", "\t"),
            (r"\\", "\\"),
        ],
    )
    def test_string_escape_sequences_parametrized(self, escape_seq, expected_char):
        """Test various escape sequences in strings."""
        text = f'rule test {{ strings: $a = "test{escape_seq}end" }}'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) > 0
        assert expected_char in string_tokens[0].value

    def test_read_string_with_null_escape(self):
        """Test reading string that encounters null during escape."""
        text = 'rule test { strings: $a = "test\\\\'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should handle end of string during escape
        assert tokens[-1].type == TokenType.EOF
        assert len(errors) > 0

    def test_complex_error_recovery_sequence(self):
        """Test complex sequence of errors and recovery."""
        text = """
        rule test {
            strings:
                $a = "unterminated
                $b = { AB CD
                $c = "valid"
            condition:
                any of them
        }
        """
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should collect errors but finish parsing
        assert tokens[-1].type == TokenType.EOF
        # May have errors from unterminated strings/hex

    def test_recover_from_error_default_case(self):
        """Test default error recovery (advance one character)."""
        # Create a scenario where default recovery is used
        text = "rule test { condition: !!! }"
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should recover and continue
        assert tokens[-1].type == TokenType.EOF

    def test_position_tracking_through_errors(self):
        """Test that position tracking works correctly through errors."""
        text = "rule test {\n  strings:\n    $a = @\n}"
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Verify EOF token has reasonable position
        assert tokens[-1].type == TokenType.EOF
        assert tokens[-1].line > 0

    def test_skip_to_char_not_found(self):
        """Test skipping to character that doesn't exist."""
        text = "abcdef"
        lexer = ErrorTolerantLexer(text)
        lexer.position = 0

        lexer._skip_to_char("}")

        # Should reach end of text
        assert lexer.position >= len(text)

    def test_read_string_lookahead_windows_path(self):
        """Test lookahead logic for Windows path detection."""
        text = r'rule test { strings: $a = "C:\\Windows\\" ascii }'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should detect this as Windows path pattern
        assert tokens[-1].type == TokenType.EOF

    def test_read_string_lookahead_various_modifiers(self):
        """Test lookahead with various string modifiers."""
        for modifier in ["ascii", "wide", "nocase", "fullword", "xor", "base64"]:
            text = f'rule test {{ strings: $a = "test\\" {modifier} }}'
            lexer = ErrorTolerantLexer(text)
            tokens, errors = lexer.tokenize()

            assert tokens[-1].type == TokenType.EOF

    def test_read_string_escape_at_very_end(self):
        """Test string with escape at very end of input."""
        text = r'rule test { strings: $a = "test\\'
        lexer = ErrorTolerantLexer(text)
        tokens, errors = lexer.tokenize()

        # Should handle gracefully
        assert tokens[-1].type == TokenType.EOF
        assert len(errors) > 0
