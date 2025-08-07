"""Error-tolerant YARA lexer that continues parsing despite errors."""

from dataclasses import dataclass

from yaraast.lexer.lexer import Lexer, LexerError
from yaraast.lexer.tokens import Token, TokenType


@dataclass
class LexerErrorInfo:
    """Detailed information about a lexer error."""

    message: str
    line: int
    column: int
    context: str
    suggestion: str | None = None
    severity: str = "error"  # error, warning, info

    def format_error(self) -> str:
        """Format error for display."""
        lines = []
        lines.append(f"\n{'=' * 60}")
        lines.append(f"❌ {self.severity.upper()}: {self.message}")
        lines.append(f"📍 Location: Line {self.line}, Column {self.column}")

        if self.context:
            lines.append("\n📄 Context:")
            # Show the problematic line with markers
            context_lines = self.context.split("\n")
            for i, line in enumerate(context_lines):
                if i == 1:  # Middle line is the error line
                    lines.append(f"    {self.line:4d} | {line}")
                    # Add pointer to the error position
                    pointer = " " * (10 + self.column - 1) + "^" + "~" * 5
                    lines.append(f"         | {pointer}")
                else:
                    line_num = self.line - 1 + i
                    lines.append(f"    {line_num:4d} | {line}")

        if self.suggestion:
            lines.append(f"\n💡 Suggestion: {self.suggestion}")

        lines.append("=" * 60)
        return "\n".join(lines)


class ErrorTolerantLexer(Lexer):
    """Lexer that collects errors and continues parsing."""

    def __init__(self, text: str, max_errors: int = 100) -> None:
        super().__init__(text)
        self.errors: list[LexerErrorInfo] = []
        self.max_errors = max_errors
        self.original_text = text

    def tokenize(self) -> tuple[list[Token], list[LexerErrorInfo]]:
        """Tokenize text and return both tokens and errors."""
        self.tokens = []  # Use self.tokens so _is_hex_string_context() works
        self.position = 0
        self.line = 1
        self.column = 1
        self.errors = []

        while self.position < len(self.text):
            if len(self.errors) >= self.max_errors:
                self._add_error(
                    f"Too many errors (>{self.max_errors}), stopping",
                    severity="error",
                )
                break

            # Skip whitespace and comments first
            self._skip_whitespace_and_comments()

            if self.position >= len(self.text):
                break

            try:
                token = self._next_token()
                if token:
                    self.tokens.append(token)
            except LexerError as e:
                # Record the error with context
                self._add_error(str(e).split(": ", 1)[1] if ": " in str(e) else str(e))
                # Try to recover
                self._recover_from_error()

        # Add EOF token
        self.tokens.append(Token(TokenType.EOF, None, self.line, self.column))
        return self.tokens, self.errors

    def _add_error(
        self,
        message: str,
        severity: str = "error",
        suggestion: str | None = None,
    ) -> None:
        """Add an error with context."""
        # Get context lines
        lines = self.original_text.split("\n")
        context_lines = []

        # Get line before, current line, and line after
        for i in range(max(0, self.line - 2), min(len(lines), self.line + 1)):
            if i < len(lines):
                context_lines.append(lines[i])

        context = "\n".join(context_lines)

        error = LexerErrorInfo(
            message=message,
            line=self.line,
            column=self.column,
            context=context,
            suggestion=suggestion,
            severity=severity,
        )
        self.errors.append(error)

    def _recover_from_error(self) -> None:
        """Try to recover from an error and continue parsing."""
        char = self._current_char()

        # Special recovery for common cases
        if char == '"':
            # Unterminated string - skip to next line or next quote
            self._recover_from_unterminated_string()
        elif char == "/":
            # Possible regex error - skip to next space
            self._skip_to_whitespace()
        elif char == "{":
            # Hex string error - skip to closing brace
            self._skip_to_char("}")
            self._advance()
        else:
            # Default: skip current character and continue
            self._advance()

    def _recover_from_unterminated_string(self) -> None:
        """Recover from unterminated string error."""
        # Skip to end of line or next string delimiter
        while self._current_char() and self._current_char() not in '\n"':
            self._advance()

        if self._current_char() in ('"', "\n"):
            self._advance()  # Skip the quote or newline

    def _skip_to_whitespace(self) -> None:
        """Skip to next whitespace character."""
        while self._current_char() and not self._current_char().isspace():
            self._advance()

    def _skip_to_char(self, target: str) -> None:
        """Skip to target character."""
        while self._current_char() and self._current_char() != target:
            self._advance()

    def _read_string(self) -> Token:
        """Override to handle problematic strings better."""
        start_line = self.line
        start_column = self.column
        value = ""

        self._advance()  # skip opening quote

        while self._current_char() and self._current_char() != '"':
            if self._current_char() == "\\":
                # Look ahead to see what follows the backslash
                self._advance()
                next_char = self._current_char()

                if next_char == "\\":
                    value += "\\"
                elif next_char == '"':
                    # Check for special case: \" at end of string like "\TEMP\"
                    look_ahead_pos = self.position + 1
                    if look_ahead_pos < len(self.text):
                        chars_after = self.text[look_ahead_pos : look_ahead_pos + 20]
                        # Skip whitespace
                        i = 0
                        while i < len(chars_after) and chars_after[i] in " \t":
                            i += 1
                        chars_after = chars_after[i:]

                        # Check if this looks like end of string
                        if not chars_after or chars_after.startswith(
                            (
                                "ascii",
                                "wide",
                                "nocase",
                                "fullword",
                                "xor",
                                "base64",
                                "\n",
                                "\r",
                            ),
                        ):
                            # Treat as Windows path with backslash at end
                            value += "\\"
                            self._advance()  # consume quote

                            # Add warning about non-standard syntax
                            self._add_error(
                                'String ends with \\" which is non-standard YARA syntax',
                                severity="warning",
                                suggestion='Consider using "\\\\" for literal backslash or escaping properly',
                            )
                            break
                        # Normal escaped quote
                        value += '"'
                    else:
                        value += "\\"
                        self._advance()
                        break
                elif next_char == "n":
                    value += "\n"
                elif next_char == "r":
                    value += "\r"
                elif next_char == "t":
                    value += "\t"
                elif next_char == "x" and self.position + 2 < len(self.text):
                    # Hex escape
                    hex_digits = self.text[self.position + 1 : self.position + 3]
                    if all(c in "0123456789abcdefABCDEF" for c in hex_digits):
                        value += chr(int(hex_digits, 16))
                        self._advance()  # skip first hex digit
                        self._advance()  # skip second hex digit
                    else:
                        value += "\\" + next_char
                elif next_char is None:
                    value += "\\"
                    break
                else:
                    # Unknown escape - keep literal
                    value += "\\" + next_char
            else:
                value += self._current_char()

            self._advance()

        if not self._current_char():
            # Unterminated string
            self._add_error(
                "Unterminated string",
                suggestion='Add closing quote " to terminate the string',
            )
            # Return what we have
            return Token(TokenType.STRING, value, start_line, start_column)

        self._advance()  # skip closing quote
        return Token(TokenType.STRING, value, start_line, start_column)
