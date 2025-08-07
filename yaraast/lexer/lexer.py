"""YARA lexer implementation."""

from yaraast.lexer.tokens import Token, TokenType


class LexerError(Exception):
    """Lexer error exception."""

    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"Lexer error at {line}:{column}: {message}")
        self.line = line
        self.column = column


class Lexer:
    """YARA lexer for tokenizing YARA rules."""

    KEYWORDS = {
        "rule": TokenType.RULE,
        "private": TokenType.PRIVATE,
        "global": TokenType.GLOBAL,
        "import": TokenType.IMPORT,
        "include": TokenType.INCLUDE,
        "meta": TokenType.META,
        "strings": TokenType.STRINGS,
        "condition": TokenType.CONDITION,
        "and": TokenType.AND,
        "or": TokenType.OR,
        "not": TokenType.NOT,
        "for": TokenType.FOR,
        "of": TokenType.OF,
        "in": TokenType.IN,
        "as": TokenType.AS,
        "at": TokenType.AT,
        "them": TokenType.THEM,
        "any": TokenType.ANY,
        "all": TokenType.ALL,
        "entrypoint": TokenType.ENTRYPOINT,
        "filesize": TokenType.FILESIZE,
        "matches": TokenType.MATCHES,
        "contains": TokenType.CONTAINS,
        "startswith": TokenType.STARTSWITH,
        "endswith": TokenType.ENDSWITH,
        "icontains": TokenType.ICONTAINS,
        "istartswith": TokenType.ISTARTSWITH,
        "iendswith": TokenType.IENDSWITH,
        "iequals": TokenType.IEQUALS,
        "defined": TokenType.DEFINED,
        "true": TokenType.BOOLEAN_TRUE,
        "false": TokenType.BOOLEAN_FALSE,
        "nocase": TokenType.NOCASE,
        "wide": TokenType.WIDE,
        "ascii": TokenType.ASCII,
        "xor": TokenType.XOR_MOD,
        "base64": TokenType.BASE64,
        "base64wide": TokenType.BASE64WIDE,
        "fullword": TokenType.FULLWORD,
    }

    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: list[Token] = []

    def tokenize(self) -> list[Token]:
        """Tokenize the input text and return list of tokens."""
        while self.position < len(self.text):
            self._skip_whitespace_and_comments()

            if self.position >= len(self.text):
                break

            token = self._next_token()
            if token:
                self.tokens.append(token)

        self.tokens.append(Token(TokenType.EOF, None, self.line, self.column))
        return self.tokens

    def _current_char(self) -> str | None:
        """Get current character."""
        if self.position < len(self.text):
            return self.text[self.position]
        return None

    def _peek_char(self, offset: int = 1) -> str | None:
        """Peek at character at offset."""
        pos = self.position + offset
        if pos < len(self.text):
            return self.text[pos]
        return None

    def _advance(self) -> None:
        """Advance position and update line/column."""
        if self.position < len(self.text):
            if self.text[self.position] == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.position += 1

    def _skip_whitespace_and_comments(self) -> None:
        """Skip whitespace and comments."""
        while self.position < len(self.text):
            char = self._current_char()

            if char in " \t\r\n":
                self._advance()
            elif char == "/" and self._peek_char() == "/":
                # Single-line comment
                while self._current_char() and self._current_char() != "\n":
                    self._advance()
            elif char == "/" and self._peek_char() == "*":
                # Multi-line comment
                self._advance()  # skip /
                self._advance()  # skip *
                while self.position < len(self.text) - 1:
                    if self._current_char() == "*" and self._peek_char() == "/":
                        self._advance()  # skip *
                        self._advance()  # skip /
                        break
                    self._advance()
            else:
                break

    def _next_token(self) -> Token | None:
        """Get next token."""
        start_line = self.line
        start_column = self.column
        char = self._current_char()

        if not char:
            return None

        # String literals
        if char == '"':
            return self._read_string()

        # Hex strings (only in strings section)
        if char == "{" and self._is_hex_string_context():
            return self._read_hex_string()

        # Regular expressions
        if char == "/" and self._is_regex_context():
            return self._read_regex()

        # Numbers
        if char.isdigit() or (char == "0" and self._peek_char() in "xX"):
            return self._read_number()

        # Identifiers and keywords
        if char.isalpha() or char == "_":
            return self._read_identifier()

        # String identifiers
        if char == "$":
            return self._read_string_identifier()

        # String count
        if char == "#":
            return self._read_string_count()

        # String offset
        if char == "@":
            return self._read_string_offset()

        # Two-character operators (check before single-char operators like !)
        if self.position < len(self.text) - 1:
            two_char = self.text[self.position : self.position + 2]
            token_type = self._get_two_char_operator(two_char)
            if token_type:
                self._advance()
                self._advance()
                return Token(token_type, two_char, start_line, start_column, 2)

        # String length (check after two-char operators to handle != correctly)
        if char == "!":
            return self._read_string_length()

        # Single-character operators and delimiters
        token_type = self._get_single_char_token(char)
        if token_type:
            self._advance()
            return Token(token_type, char, start_line, start_column, 1)

        msg = f"Unexpected character: {char}"
        raise LexerError(msg, self.line, self.column)

    def _read_string(self) -> Token:
        """Read string literal."""
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
                    # \\ -> single backslash in YARA output
                    # But we need to check if this is really an escape or Windows path
                    # In YARA strings, \\ is used for literal backslash
                    value += "\\"
                elif next_char == '"':
                    # This is the tricky case: \"
                    # Some YARA files use \" at the end like "\TEMP\"
                    # which technically should be invalid but appears in real files
                    #
                    # Heuristic: if \" is followed by whitespace and valid string modifiers
                    # or end of line, treat the backslash as literal and end the string
                    look_ahead_pos = self.position + 1
                    if look_ahead_pos < len(self.text):
                        chars_after = self.text[look_ahead_pos : look_ahead_pos + 20]
                        # Skip any whitespace
                        i = 0
                        while i < len(chars_after) and chars_after[i] in " \t":
                            i += 1
                        chars_after = chars_after[i:]

                        # Check if what follows looks like string modifiers or end of string
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
                                "//",
                            ),
                        ):  # Comment after string
                            # Looks like end of string, treat \ as literal and break
                            value += "\\"
                            # Advance to consume the quote and exit loop
                            self._advance()
                            break
                        # Treat as escaped quote
                        value += '"'
                    else:
                        # At end of file, treat as literal backslash
                        value += "\\"
                        self._advance()  # consume the quote
                        break
                elif next_char == "n":
                    # \n -> newline
                    value += "\n"
                elif next_char == "r":
                    # \r -> carriage return
                    value += "\r"
                elif next_char == "t":
                    # \t -> tab
                    value += "\t"
                elif next_char == "x" and self.position + 2 < len(self.text):
                    # \xHH -> hex character
                    hex_digits = self.text[self.position + 1 : self.position + 3]
                    if all(c in "0123456789abcdefABCDEF" for c in hex_digits):
                        value += chr(int(hex_digits, 16))
                        self._advance()  # skip first hex digit
                        self._advance()  # skip second hex digit
                    else:
                        # Not valid hex escape, keep as literal
                        value += "\\" + next_char
                elif next_char is None:
                    # Backslash at end of input
                    value += "\\"
                    break
                else:
                    # Any other character after \ is kept literally
                    # e.g., \T becomes \T (common in Windows paths)
                    value += "\\" + next_char
            else:
                # Regular character
                value += self._current_char()

            self._advance()

        if not self._current_char():
            msg = "Unterminated string"
            raise LexerError(msg, start_line, start_column)

        self._advance()  # skip closing quote
        return Token(TokenType.STRING, value, start_line, start_column)

    def _read_hex_string(self) -> Token:
        """Read hex string."""
        start_line = self.line
        start_column = self.column
        value = ""

        self._advance()  # skip {

        while self._current_char() and self._current_char() != "}":
            value += self._current_char()
            self._advance()

        if not self._current_char():
            msg = "Unterminated hex string"
            raise LexerError(msg, start_line, start_column)

        self._advance()  # skip }
        return Token(TokenType.HEX_STRING, value, start_line, start_column)

    def _read_regex(self) -> Token:
        """Read regular expression."""
        start_line = self.line
        start_column = self.column
        value = ""

        self._advance()  # skip opening /

        while self._current_char() and self._current_char() != "/":
            if self._current_char() == "\\":
                value += self._current_char()
                self._advance()
                if self._current_char():
                    value += self._current_char()
            else:
                value += self._current_char()
            self._advance()

        if not self._current_char():
            msg = "Unterminated regex"
            raise LexerError(msg, start_line, start_column)

        self._advance()  # skip closing /

        # Read regex modifiers
        modifiers = ""
        while self._current_char() and self._current_char() in "ims":
            modifiers += self._current_char()
            self._advance()

        # Store the pattern and modifiers together but in a way we can parse
        # Use a special marker that won't appear in regex patterns
        if modifiers:
            # Use null byte as separator since it's not valid in regex patterns
            return Token(
                TokenType.REGEX,
                value + "\x00" + modifiers,
                start_line,
                start_column,
            )
        return Token(TokenType.REGEX, value, start_line, start_column)

    def _read_number(self) -> Token:
        """Read number (integer or double)."""
        start_line = self.line
        start_column = self.column
        value = ""

        # Handle hex numbers
        if self._current_char() == "0" and self._peek_char() in "xX":
            value += self._current_char()
            self._advance()
            value += self._current_char()
            self._advance()

            while self._current_char() and self._current_char() in "0123456789abcdefABCDEF":
                value += self._current_char()
                self._advance()

            return Token(TokenType.INTEGER, int(value, 16), start_line, start_column)

        # Read integer part
        while self._current_char() and self._current_char().isdigit():
            value += self._current_char()
            self._advance()

        # Check for decimal point
        if self._current_char() == "." and self._peek_char() and self._peek_char().isdigit():
            value += self._current_char()
            self._advance()

            while self._current_char() and self._current_char().isdigit():
                value += self._current_char()
                self._advance()

            return Token(TokenType.DOUBLE, float(value), start_line, start_column)

        # Handle size suffixes (KB, MB)
        if self._current_char() and self._current_char().upper() in "KM":
            suffix = self._current_char().upper()
            self._advance()
            if self._current_char() and self._current_char().upper() == "B":
                self._advance()
                multiplier = 1024 if suffix == "K" else 1024 * 1024
                return Token(
                    TokenType.INTEGER,
                    int(value) * multiplier,
                    start_line,
                    start_column,
                )

        return Token(TokenType.INTEGER, int(value), start_line, start_column)

    def _read_identifier(self) -> Token:
        """Read identifier or keyword."""
        start_line = self.line
        start_column = self.column
        value = ""

        while self._current_char() and (
            self._current_char().isalnum() or self._current_char() == "_"
        ):
            value += self._current_char()
            self._advance()

        token_type = self.KEYWORDS.get(value.lower(), TokenType.IDENTIFIER)
        return Token(token_type, value, start_line, start_column)

    def _read_string_identifier(self) -> Token:
        """Read string identifier ($name)."""
        start_line = self.line
        start_column = self.column

        self._advance()  # skip $

        if self._current_char() == "*":
            self._advance()
            return Token(TokenType.STRING_IDENTIFIER, "$*", start_line, start_column)

        value = "$"
        while self._current_char() and (
            self._current_char().isalnum() or self._current_char() == "_"
        ):
            value += self._current_char()
            self._advance()

        return Token(TokenType.STRING_IDENTIFIER, value, start_line, start_column)

    def _read_string_count(self) -> Token:
        """Read string count (#name)."""
        start_line = self.line
        start_column = self.column

        self._advance()  # skip #
        value = "#"

        while self._current_char() and (
            self._current_char().isalnum() or self._current_char() == "_"
        ):
            value += self._current_char()
            self._advance()

        return Token(TokenType.STRING_COUNT, value, start_line, start_column)

    def _read_string_offset(self) -> Token:
        """Read string offset (@name)."""
        start_line = self.line
        start_column = self.column

        self._advance()  # skip @
        value = "@"

        while self._current_char() and (
            self._current_char().isalnum() or self._current_char() == "_"
        ):
            value += self._current_char()
            self._advance()

        return Token(TokenType.STRING_OFFSET, value, start_line, start_column)

    def _read_string_length(self) -> Token:
        """Read string length (!name)."""
        start_line = self.line
        start_column = self.column

        self._advance()  # skip !
        value = "!"

        while self._current_char() and (
            self._current_char().isalnum() or self._current_char() == "_"
        ):
            value += self._current_char()
            self._advance()

        return Token(TokenType.STRING_LENGTH, value, start_line, start_column)

    def _get_two_char_operator(self, chars: str) -> TokenType | None:
        """Get token type for two-character operators."""
        operators = {
            "==": TokenType.EQ,
            "!=": TokenType.NEQ,
            "<=": TokenType.LE,
            ">=": TokenType.GE,
            "<<": TokenType.SHIFT_LEFT,
            ">>": TokenType.SHIFT_RIGHT,
            "..": TokenType.DOUBLE_DOT,
        }
        return operators.get(chars)

    def _get_single_char_token(self, char: str) -> TokenType | None:
        """Get token type for single-character tokens."""
        tokens = {
            "=": TokenType.ASSIGN,
            "+": TokenType.PLUS,
            "-": TokenType.MINUS,
            "*": TokenType.MULTIPLY,
            "/": TokenType.DIVIDE,
            "%": TokenType.MODULO,
            "^": TokenType.XOR,
            "&": TokenType.BITWISE_AND,
            "|": TokenType.BITWISE_OR,
            "~": TokenType.BITWISE_NOT,
            "<": TokenType.LT,
            ">": TokenType.GT,
            ".": TokenType.DOT,
            "(": TokenType.LPAREN,
            ")": TokenType.RPAREN,
            "{": TokenType.LBRACE,
            "}": TokenType.RBRACE,
            "[": TokenType.LBRACKET,
            "]": TokenType.RBRACKET,
            ",": TokenType.COMMA,
            ":": TokenType.COLON,
            ";": TokenType.SEMICOLON,
        }
        return tokens.get(char)

    def _is_regex_context(self) -> bool:
        """Check if we're in a regex context."""
        # Simple heuristic: check if previous non-whitespace token suggests regex
        # This is a simplified version - a full implementation would track parser state

        # Check if we're at the start of a condition or after certain tokens
        if not self.tokens:
            return True  # Could be regex at start

        # Look at previous significant tokens
        i = len(self.tokens) - 1
        while i >= 0:
            token = self.tokens[i]

            # These tokens often precede regex
            if token.type in (
                TokenType.MATCHES,
                TokenType.CONTAINS,
                TokenType.ASSIGN,
                TokenType.COLON,
                TokenType.LPAREN,
                TokenType.COMMA,
                TokenType.AND,
                TokenType.OR,
                TokenType.NOT,
            ):
                return True

            # If we see CONDITION, we're likely in a condition context where regex is common
            if token.type == TokenType.CONDITION:
                return True

            if token.type not in (TokenType.NEWLINE, TokenType.COMMENT):
                # Check if previous token could end an expression that would be followed by regex
                if token.type in (TokenType.RPAREN, TokenType.RBRACKET):
                    return False  # Probably division after closing paren/bracket
                break

            i -= 1

        # Default to true for regex since it's more common in YARA than division
        return True

    def _is_hex_string_context(self) -> bool:
        """Check if we're in a hex string context (inside strings section)."""
        # Look for pattern: string_id = <here>
        # Check if we have: IDENTIFIER ASSIGN pattern
        if len(self.tokens) >= 2:
            # Check last two non-comment tokens
            non_comment_tokens = []
            for token in reversed(self.tokens):
                if token.type != TokenType.COMMENT:
                    non_comment_tokens.append(token)
                    if len(non_comment_tokens) >= 2:
                        break

            if (
                len(non_comment_tokens) >= 2
                and non_comment_tokens[0].type == TokenType.ASSIGN
                and non_comment_tokens[1].type == TokenType.STRING_IDENTIFIER
            ):
                return True

        return False
