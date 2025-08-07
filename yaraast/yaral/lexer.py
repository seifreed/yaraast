"""YARA-L lexer implementation."""

import re

import attrs

from yaraast.lexer.tokens import Token
from yaraast.lexer.tokens import TokenType as BaseTokenType

from .tokens import YaraLTokenType


@attrs.define
class YaraLToken(Token):
    """YARA-L specific token."""

    yaral_type: YaraLTokenType | None = None


class YaraLLexer:
    """Lexer for YARA-L 2.0 syntax."""

    KEYWORDS = {
        # Sections
        "rule": YaraLTokenType.EVENTS,  # Reuse for rule start
        "meta": BaseTokenType.META,
        "events": YaraLTokenType.EVENTS,
        "match": YaraLTokenType.MATCH,
        "outcome": YaraLTokenType.OUTCOME,
        "condition": BaseTokenType.CONDITION,
        "options": YaraLTokenType.OPTIONS,
        # Time-related
        "over": YaraLTokenType.OVER,
        "before": YaraLTokenType.BEFORE,
        "after": YaraLTokenType.AFTER,
        "within": YaraLTokenType.WITHIN,
        "by": YaraLTokenType.BY,
        "every": YaraLTokenType.EVERY,
        # Aggregation functions
        "count": YaraLTokenType.COUNT,
        "count_distinct": YaraLTokenType.COUNT_DISTINCT,
        "sum": YaraLTokenType.SUM,
        "min": YaraLTokenType.MIN,
        "max": YaraLTokenType.MAX,
        "avg": YaraLTokenType.AVG,
        "array": YaraLTokenType.ARRAY,
        "array_distinct": YaraLTokenType.ARRAY_DISTINCT,
        "earliest": YaraLTokenType.EARLIEST,
        "latest": YaraLTokenType.LATEST,
        # UDM prefixes
        "metadata": YaraLTokenType.METADATA,
        "principal": YaraLTokenType.PRINCIPAL,
        "target": YaraLTokenType.TARGET,
        "network": YaraLTokenType.NETWORK,
        "security_result": YaraLTokenType.SECURITY_RESULT,
        "udm": YaraLTokenType.UDM,
        "additional": YaraLTokenType.ADDITIONAL,
        # Operators
        "and": BaseTokenType.AND,
        "or": BaseTokenType.OR,
        "not": BaseTokenType.NOT,
        "in": BaseTokenType.IN,
        "nocase": YaraLTokenType.NOCASE,
        "is": YaraLTokenType.IS,
        "null": YaraLTokenType.NULL,
        "if": YaraLTokenType.IF,
        "else": YaraLTokenType.ELSE,
        "cidr": YaraLTokenType.CIDR,
        "regex": YaraLTokenType.REGEX,
        "re.regex": YaraLTokenType.REGEX,
        # Boolean
        "true": BaseTokenType.BOOLEAN_TRUE,
        "false": BaseTokenType.BOOLEAN_FALSE,
        # Special
        "all": BaseTokenType.ALL,
        "any": BaseTokenType.ANY,
    }

    # Time unit patterns
    TIME_PATTERN = re.compile(r"(\d+)([smhd])")

    # Event variable pattern ($e, $e1, $event_name)
    EVENT_VAR_PATTERN = re.compile(r"\$[a-zA-Z_][a-zA-Z0-9_]*")

    # Reference list pattern (%list_name%)
    REFERENCE_LIST_PATTERN = re.compile(r"%[a-zA-Z_][a-zA-Z0-9_]*%")

    # UDM field path pattern
    UDM_FIELD_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+")

    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: list[YaraLToken] = []

    def tokenize(self) -> list[YaraLToken]:
        """Tokenize YARA-L input."""
        max_iterations = 10000  # Safety limit to prevent infinite loops
        iteration = 0

        while self.position < len(self.text) and iteration < max_iterations:
            old_position = self.position
            self._skip_whitespace_and_comments()

            if self.position >= len(self.text):
                break

            token = self._next_token()
            if token:
                self.tokens.append(token)
            else:
                # Skip unrecognized character
                self.position += 1

            # Check if position advanced to avoid infinite loops
            if self.position == old_position:
                self.position += 1  # Force advance if stuck

            iteration += 1

        if iteration >= max_iterations:
            # Add error token instead of crashing
            error_token = YaraLToken(
                type=BaseTokenType.ERROR,
                value="Lexer exceeded maximum iterations",
                line=self.line,
                column=self.column,
                length=1,
                yaral_type=None,
            )
            self.tokens.append(error_token)

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
        return self.tokens

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
                self.position += 1
            return True
        return False

    def _skip_multi_line_comment(self) -> bool:
        """Skip multi-line comment. Returns True if comment was skipped."""
        if (
            self.position + 1 < len(self.text)
            and self.text[self.position : self.position + 2] == "/*"
        ):
            self.position += 2
            while self.position + 1 < len(self.text):
                if self.text[self.position : self.position + 2] == "*/":
                    self.position += 2
                    break
                if self.text[self.position] == "\n":
                    self.line += 1
                    self.column = 1
                else:
                    self.column += 1
                self.position += 1
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

        # Check for regex patterns
        if self.text[self.position] == "/":
            return self._try_regex_or_div(start_column)
        return None

    def _try_time_literal(self, start_column: int) -> YaraLToken | None:
        """Try to match a time literal (5m, 1h, 7d)."""
        time_match = self.TIME_PATTERN.match(self.text[self.position :])
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
        ref_match = self.REFERENCE_LIST_PATTERN.match(self.text[self.position :])
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
        event_match = self.EVENT_VAR_PATTERN.match(self.text[self.position :])
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
            type=BaseTokenType.DIV,
            value="/",
            line=self.line,
            column=start_column,
        )

        # Check for operators and symbols
        token = self._try_two_char_token(start_column)
        if token:
            return token
        return None

    def _try_two_char_token(self, start_column: int) -> YaraLToken | None:
        """Try to match two-character operators."""
        if self.position + 1 >= len(self.text):
            return None

        two_char = self.text[self.position : self.position + 2]
        two_char_tokens = {
            "->": (BaseTokenType.IDENTIFIER, YaraLTokenType.ARROW),
            "::": (BaseTokenType.IDENTIFIER, YaraLTokenType.DOUBLE_COLON),
            ">=": (BaseTokenType.GTE, None),
            "<=": (BaseTokenType.LTE, None),
            "==": (BaseTokenType.EQ, None),
            "!=": (BaseTokenType.NEQ, None),
        }

        if two_char in two_char_tokens:
            base_type, yaral_type = two_char_tokens[two_char]
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
        self.position += 1
        self.column += 1
        return None

    def _try_single_char_token(self, start_column: int) -> YaraLToken | None:
        """Try to match single-character tokens."""
        char = self.text[self.position]
        single_tokens = {
            "(": BaseTokenType.LPAREN,
            ")": BaseTokenType.RPAREN,
            "{": BaseTokenType.LBRACE,
            "}": BaseTokenType.RBRACE,
            "[": BaseTokenType.LBRACKET,
            "]": BaseTokenType.RBRACKET,
            ":": BaseTokenType.COLON,
            ";": BaseTokenType.SEMICOLON,
            ",": BaseTokenType.COMMA,
            ".": BaseTokenType.DOT,
            "=": BaseTokenType.EQ,
            ">": BaseTokenType.GT,
            "<": BaseTokenType.LT,
            "+": BaseTokenType.PLUS,
            "-": BaseTokenType.MINUS,
            "*": BaseTokenType.MUL,
            "#": BaseTokenType.HASH,
        }

        if char in single_tokens:
            self.position += 1
            self.column += 1
            return YaraLToken(
                type=single_tokens[char],
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
            if self.text[self.position] == "\\" and self.position + 1 < len(self.text):
                # Handle escape sequences
                self.position += 2
                self.column += 2
                value += self.text[self.position - 1]
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

        while self.position < len(self.text) and (
            self.text[self.position].isdigit() or self.text[self.position] == "."
        ):
            value += self.text[self.position]
            self.position += 1
            self.column += 1

        return YaraLToken(
            type=BaseTokenType.NUMBER,
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
        if "." in value and self.UDM_FIELD_PATTERN.match(value):
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
        # Look back for = or regex keyword
        lookback = max(0, self.position - 20)
        recent = self.text[lookback : self.position].strip()
        return recent.endswith(("=", "regex", "~"))
