"""YARA-L lexer implementation."""

import attrs

from yaraast.lexer.string_escape import StringEscapeHandler
from yaraast.lexer.tokens import Token, TokenType as BaseTokenType

from .lexer_tables import (
    EVENT_VAR_PATTERN,
    KEYWORDS as LEXER_KEYWORDS,
    REFERENCE_LIST_PATTERN,
    SINGLE_CHAR_TOKENS,
    TIME_PATTERN,
    TWO_CHAR_TOKENS,
    UDM_FIELD_PATTERN,
)
from .tokens import YaraLTokenType


@attrs.define
class YaraLToken(Token):
    """YARA-L specific token."""

    yaral_type: YaraLTokenType | None = None


class YaraLLexer:
    """Lexer for YARA-L 2.0 syntax."""

    KEYWORDS = LEXER_KEYWORDS

    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: list[YaraLToken] = []

    def tokenize(self) -> list[YaraLToken]:
        """Tokenize YARA-L input."""
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens = []

        while self.position < len(self.text):
            self._skip_whitespace_and_comments()

            if self.position >= len(self.text):
                break

            previous_position = self.position
            token = self._next_token()
            if token:
                self.tokens.append(token)
            if self.position == previous_position or not token:
                self._advance_one_character()

        # Create basic EOF token
        eof_token = YaraLToken(
            type=BaseTokenType.EOF,
            value=None,
            line=self.line,
            column=self.column,
            length=1,
            yaral_type=YaraLTokenType.EOF,
        )
        self.tokens.append(eof_token)
        return list(self.tokens)

    def _advance_one_character(self) -> None:
        """Advance over one unrecognized character while preserving position state."""
        if self.text[self.position] == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        self.position += 1

    def _skip_whitespace_and_comments(self) -> None:
        """Skip whitespace and comments."""
        while self.position < len(self.text):
            if (
                not self._skip_whitespace()
                and not self._skip_single_line_comment()
                and not self._skip_multi_line_comment()
            ):
                break

    def _skip_whitespace(self) -> bool:
        """Skip whitespace characters. Returns True if whitespace was skipped."""
        if self.text[self.position].isspace():
            if self.text[self.position] == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.position += 1
            return True
        return False

    def _skip_single_line_comment(self) -> bool:
        """Skip single-line comment. Returns True if comment was skipped."""
        if (
            self.position + 1 < len(self.text)
            and self.text[self.position : self.position + 2] == "//"
        ):
            while self.position < len(self.text) and self.text[self.position] != "\n":
                self._advance_one_character()
            return True
        return False

    def _skip_multi_line_comment(self) -> bool:
        """Skip multi-line comment. Returns True if comment was skipped."""
        if (
            self.position + 1 < len(self.text)
            and self.text[self.position : self.position + 2] == "/*"
        ):
            self._advance_one_character()
            self._advance_one_character()
            while self.position < len(self.text):
                if self.text[self.position : self.position + 2] == "*/":
                    self._advance_one_character()
                    self._advance_one_character()
                    break
                self._advance_one_character()
            return True
        return False

    def _next_token(self) -> YaraLToken | None:
        """Get next token."""
        start_column = self.column

        # Try pattern-based tokens
        token = self._try_time_literal(start_column)
        if token:
            return token

        token = self._try_reference_list(start_column)
        if token:
            return token

        token = self._try_event_variable(start_column)
        if token:
            return token

        # Check for strings
        if self.text[self.position] == '"':
            return self._read_string()

        # Check for backtick regex patterns
        if self.text[self.position] == "`":
            return self._read_backtick_regex()

        # Check for regex patterns
        if self.text[self.position] == "/":
            return self._try_regex_or_div(start_column)

        # Check for operators and symbols
        token = self._try_two_char_token(start_column)
        if token:
            return token

        # Single character tokens
        token = self._try_single_char_token(start_column)
        if token:
            return token

        # Numbers
        if self.text[self.position].isdigit():
            return self._read_number()

        # Identifiers and keywords
        if self.text[self.position].isalpha() or self.text[self.position] == "_":
            return self._read_identifier()

        # Unknown character
        return None

    def _try_time_literal(self, start_column: int) -> YaraLToken | None:
        """Try to match a time literal (5m, 1h, 7d)."""
        time_match = TIME_PATTERN.match(self.text[self.position :])
        if time_match:
            value = time_match.group(0)
            self.position += len(value)
            self.column += len(value)
            return YaraLToken(
                type=BaseTokenType.IDENTIFIER,
                value=value,
                line=self.line,
                column=start_column,
                yaral_type=YaraLTokenType.TIME_LITERAL,
            )
        return None

    def _try_reference_list(self, start_column: int) -> YaraLToken | None:
        """Try to match a reference list (%list_name%)."""
        ref_match = REFERENCE_LIST_PATTERN.match(self.text[self.position :])
        if ref_match:
            value = ref_match.group(0)
            self.position += len(value)
            self.column += len(value)
            return YaraLToken(
                type=BaseTokenType.IDENTIFIER,
                value=value,
                line=self.line,
                column=start_column,
                yaral_type=YaraLTokenType.REFERENCE_LIST,
            )
        return None

    def _try_event_variable(self, start_column: int) -> YaraLToken | None:
        """Try to match an event variable ($e, $e1, etc.)."""
        event_match = EVENT_VAR_PATTERN.match(self.text[self.position :])
        if event_match:
            value = event_match.group(0)
            self.position += len(value)
            self.column += len(value)
            return YaraLToken(
                type=BaseTokenType.STRING_IDENTIFIER,
                value=value,
                line=self.line,
                column=start_column,
                yaral_type=YaraLTokenType.EVENT_VAR,
            )
        return None

    def _try_regex_or_div(self, start_column: int) -> YaraLToken:
        """Try to parse regex or division operator."""
        if self._is_regex_context():
            return self._read_regex()
        self.position += 1
        self.column += 1
        return YaraLToken(
            type=BaseTokenType.DIVIDE,
            value="/",
            line=self.line,
            column=start_column,
        )

    def _try_two_char_token(self, start_column: int) -> YaraLToken | None:
        """Try to match two-character operators."""
        if self.position + 1 >= len(self.text):
            return None

        two_char = self.text[self.position : self.position + 2]
        if two_char in TWO_CHAR_TOKENS:
            base_type, yaral_type = TWO_CHAR_TOKENS[two_char]
            self.position += 2
            self.column += 2
            return YaraLToken(
                type=base_type,
                value=two_char,
                line=self.line,
                column=start_column,
                yaral_type=yaral_type,
            )
        return None

    def _try_single_char_token(self, start_column: int) -> YaraLToken | None:
        """Try to match single-character tokens."""
        char = self.text[self.position]
        if char in SINGLE_CHAR_TOKENS:
            self.position += 1
            self.column += 1
            return YaraLToken(
                type=SINGLE_CHAR_TOKENS[char],
                value=char,
                line=self.line,
                column=start_column,
            )
        return None

    def _read_string(self) -> YaraLToken:
        """Read a quoted string."""
        start_column = self.column
        self.position += 1  # Skip opening quote
        self.column += 1

        value = ""
        while self.position < len(self.text) and self.text[self.position] != '"':
            if self.text[self.position] == "\\":
                next_char = (
                    self.text[self.position + 1] if self.position + 1 < len(self.text) else None
                )
                handler = StringEscapeHandler(self.text, self.position + 1)
                advance = 2 if next_char is not None else 1
                try:
                    result = handler.handle_backslash(next_char)
                except ValueError:
                    value += "\\" if next_char is None else f"\\{next_char}"
                else:
                    value += "".join(result.chars)
                    advance += result.advance_count
                    if result.ends_string:
                        break
                self.position += advance
                self.column += advance
            else:
                value += self.text[self.position]
                self.position += 1
                self.column += 1

        if self.position < len(self.text):
            self.position += 1  # Skip closing quote
            self.column += 1

        return YaraLToken(
            type=BaseTokenType.STRING,
            value=value,
            line=self.line,
            column=start_column,
        )

    def _read_backtick_regex(self) -> YaraLToken:
        """Read a backtick-delimited regex pattern `...`."""
        start_column = self.column
        self.position += 1  # Skip opening backtick
        self.column += 1

        pattern = ""
        while self.position < len(self.text) and self.text[self.position] != "`":
            if self.text[self.position] == "\\" and self.position + 1 < len(self.text):
                # Handle escape sequences
                pattern += self.text[self.position : self.position + 2]
                self.position += 2
                self.column += 2
            else:
                pattern += self.text[self.position]
                if self.text[self.position] == "\n":
                    self.line += 1
                    self.column = 1
                else:
                    self.column += 1
                self.position += 1

        if self.position < len(self.text):
            self.position += 1  # Skip closing backtick
            self.column += 1

        return YaraLToken(
            type=BaseTokenType.REGEX,
            value=pattern,
            line=self.line,
            column=start_column,
            yaral_type=YaraLTokenType.REGEX,
        )

    def _read_regex(self) -> YaraLToken:
        """Read a regex pattern /.../ with optional flags."""
        start_column = self.column
        self.position += 1  # Skip opening /
        self.column += 1

        pattern = ""
        while self.position < len(self.text) and self.text[self.position] != "/":
            if self.text[self.position] == "\\" and self.position + 1 < len(self.text):
                # Handle escape sequences
                pattern += self.text[self.position : self.position + 2]
                self.position += 2
                self.column += 2
            else:
                pattern += self.text[self.position]
                self.position += 1
                self.column += 1

        if self.position < len(self.text):
            self.position += 1  # Skip closing /
            self.column += 1

        # Check for regex flags (like nocase)
        flags = ""
        while self.position < len(self.text) and self.text[self.position].isalpha():
            flags += self.text[self.position]
            self.position += 1
            self.column += 1

        value = f"/{pattern}/"
        if flags:
            value += flags

        return YaraLToken(
            type=BaseTokenType.REGEX,
            value=value,
            line=self.line,
            column=start_column,
            yaral_type=YaraLTokenType.REGEX,
        )

    def _read_number(self) -> YaraLToken:
        """Read a number."""
        start_column = self.column
        value = ""
        has_decimal_point = False

        while self.position < len(self.text) and (
            self.text[self.position].isdigit() or self.text[self.position] == "."
        ):
            if self.text[self.position] == ".":
                next_position = self.position + 1
                if (
                    has_decimal_point
                    or next_position >= len(self.text)
                    or not self.text[next_position].isdigit()
                ):
                    break
                has_decimal_point = True
            value += self.text[self.position]
            self.position += 1
            self.column += 1

        if has_decimal_point:
            return YaraLToken(
                type=BaseTokenType.DOUBLE,
                value=float(value),
                line=self.line,
                column=start_column,
            )

        return YaraLToken(
            type=BaseTokenType.INTEGER,
            value=value,
            line=self.line,
            column=start_column,
        )

    def _read_identifier(self) -> YaraLToken:
        """Read an identifier or keyword."""
        start_column = self.column
        value = ""

        # Read identifier
        while self.position < len(self.text) and (
            self.text[self.position].isalnum() or self.text[self.position] in "_.-"
        ):
            value += self.text[self.position]
            self.position += 1
            self.column += 1

        # Check if it's a keyword
        lower_value = value.lower()
        if lower_value in self.KEYWORDS:
            token_type = self.KEYWORDS[lower_value]
            if isinstance(token_type, YaraLTokenType):
                return YaraLToken(
                    type=BaseTokenType.IDENTIFIER,
                    value=value,
                    line=self.line,
                    column=start_column,
                    yaral_type=token_type,
                )
            return YaraLToken(
                type=token_type,
                value=value,
                line=self.line,
                column=start_column,
            )

        # Check if it's a UDM field path
        if "." in value and UDM_FIELD_PATTERN.match(value):
            return YaraLToken(
                type=BaseTokenType.IDENTIFIER,
                value=value,
                line=self.line,
                column=start_column,
                yaral_type=YaraLTokenType.UDM,
            )

        # Regular identifier
        return YaraLToken(
            type=BaseTokenType.IDENTIFIER,
            value=value,
            line=self.line,
            column=start_column,
        )

    def _is_regex_context(self) -> bool:
        """Check if we're in a regex context (heuristic)."""
        # Look back for operators or delimiters that can introduce regex values.
        lookback = max(0, self.position - 20)
        recent = self.text[lookback : self.position].strip()
        return recent.endswith(("=", "regex", "~", ",", "("))
