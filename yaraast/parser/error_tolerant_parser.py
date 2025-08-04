"""Error-tolerant YARA parser that continues parsing despite errors."""

from dataclasses import dataclass

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.lexer.error_tolerant_lexer import ErrorTolerantLexer, LexerErrorInfo
from yaraast.parser.better_parser import Parser


@dataclass
class ParserErrorInfo:
    """Information about a parser error."""

    message: str
    line: int
    column: int
    context: str = ""
    suggestion: str | None = None
    severity: str = "error"

    def format_error(self) -> str:
        """Format error for display."""
        lines = []
        lines.append(f"\n{'=' * 60}")
        lines.append(f"❌ PARSER {self.severity.upper()}: {self.message}")
        lines.append(f"📍 Location: Line {self.line}, Column {self.column}")

        if self.context:
            lines.append("\n📄 Context:")
            lines.append(f"    {self.context}")

        if self.suggestion:
            lines.append(f"\n💡 Suggestion: {self.suggestion}")

        lines.append("=" * 60)
        return "\n".join(lines)


class ErrorTolerantParser(Parser):
    """Parser that collects errors and continues parsing."""

    def __init__(self):
        super().__init__()
        self.parser_errors: list[ParserErrorInfo] = []
        self.lexer_errors: list[LexerErrorInfo] = []

    def parse_with_errors(
        self, text: str
    ) -> tuple[YaraFile | None, list[LexerErrorInfo], list[ParserErrorInfo]]:
        """Parse text and return AST along with all errors found."""
        # First, tokenize with error-tolerant lexer
        error_lexer = ErrorTolerantLexer(text)
        tokens, self.lexer_errors = error_lexer.tokenize()

        # Set tokens for parser
        self.tokens = tokens
        self.position = 0
        self.text = text
        self.parser_errors = []

        # Try to parse
        ast = None
        try:
            ast = self._parse_yara_file()
        except Exception as e:
            # Record parser error
            if self._current_token():
                error = ParserErrorInfo(
                    message=str(e),
                    line=self._current_token().line if self._current_token() else 0,
                    column=self._current_token().column if self._current_token() else 0,
                    context=self._get_context_at_position(),
                    severity="error",
                )
            else:
                error = ParserErrorInfo(message=str(e), line=0, column=0, severity="error")
            self.parser_errors.append(error)

        return ast, self.lexer_errors, self.parser_errors

    def _get_context_at_position(self) -> str:
        """Get context around current position."""
        if not self._current_token():
            return ""

        # Get surrounding tokens
        start = max(0, self.position - 5)
        end = min(len(self.tokens), self.position + 5)

        context_tokens = []
        for i in range(start, end):
            if i < len(self.tokens):
                token = self.tokens[i]
                if i == self.position:
                    context_tokens.append(f">>>{token.value}<<<")
                else:
                    context_tokens.append(str(token.value) if token.value else token.type.name)

        return " ".join(context_tokens)

    def _parse_rule(self) -> Rule:
        """Parse a rule with error recovery."""

        start_pos = self.position

        try:
            # Try to get basic rule structure even if parts fail
            modifiers = []

            # Parse modifiers (private, global)
            while self._current_token() and self._current_token().type.name in (
                "PRIVATE",
                "GLOBAL",
            ):
                modifiers.append(self._current_token().value)
                self._advance()

            # Expect 'rule'
            if not self._current_token() or self._current_token().type.name != "RULE":
                return super()._parse_rule()  # Fall back to parent

            self._advance()  # skip 'rule'

            # Get rule name
            if not self._current_token() or self._current_token().type.name != "IDENTIFIER":
                raise Exception("Expected rule name")
            name = self._current_token().value
            self._advance()

            # Parse tags if present
            tags = []
            if self._current_token() and self._current_token().type.name == "COLON":
                self._advance()
                # Parse tags until we hit '{'
                while self._current_token() and self._current_token().type.name != "LBRACE":
                    if self._current_token().type.name == "IDENTIFIER":
                        tags.append(self._current_token().value)
                        self._advance()
                    else:
                        # Skip unexpected tokens in tag position
                        self._advance()

            # Expect '{'
            if not self._current_token() or self._current_token().type.name != "LBRACE":
                raise Exception("Expected '{'")
            self._advance()

            # Try to parse sections
            meta = {}
            strings = []
            condition = None

            while self._current_token() and self._current_token().type.name != "RBRACE":
                try:
                    if self._current_token().type.name == "META":
                        self._advance()
                        if self._current_token() and self._current_token().type.name == "COLON":
                            self._advance()
                        meta = self._parse_meta_section()
                    elif self._current_token().type.name == "STRINGS":
                        self._advance()
                        if self._current_token() and self._current_token().type.name == "COLON":
                            self._advance()
                        strings = self._parse_strings_section()
                    elif self._current_token().type.name == "CONDITION":
                        self._advance()
                        if self._current_token() and self._current_token().type.name == "COLON":
                            self._advance()
                        # Handle empty condition
                        if self._current_token() and self._current_token().type.name != "RBRACE":
                            condition = self._parse_expression()
                        else:
                            # Empty condition - create a dummy true condition
                            condition = BooleanLiteral(value=True)
                            self.parser_errors.append(
                                ParserErrorInfo(
                                    message="Empty condition section, using 'true' as default",
                                    line=self._current_token().line if self._current_token() else 0,
                                    column=(
                                        self._current_token().column if self._current_token() else 0
                                    ),
                                    context="condition: <empty>",
                                    suggestion="Add a condition like 'any of them' or 'true'",
                                    severity="warning",
                                )
                            )
                    else:
                        # Unknown section, skip it
                        self._advance()
                except Exception as e:
                    # Record error and try to continue to next section
                    self.parser_errors.append(
                        ParserErrorInfo(
                            message=f"Error parsing rule section: {e}",
                            line=self._current_token().line if self._current_token() else 0,
                            column=self._current_token().column if self._current_token() else 0,
                            context=self._get_context_at_position(),
                            severity="error",
                        )
                    )
                    # Skip to next section keyword or closing brace
                    self._skip_to_next_section()

            # Consume closing '}'
            if self._current_token() and self._current_token().type.name == "RBRACE":
                self._advance()

            # Create rule even if incomplete
            return Rule(
                name=name,
                modifiers=modifiers,
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition if condition else BooleanLiteral(value=True),
            )

        except Exception as e:
            # Record error and try to recover
            error = ParserErrorInfo(
                message=f"Failed to parse rule: {e}",
                line=self._current_token().line if self._current_token() else 0,
                column=self._current_token().column if self._current_token() else 0,
                context=self._get_context_at_position(),
                suggestion="Check rule syntax and structure",
                severity="error",
            )
            self.parser_errors.append(error)

            # Reset to start and skip to next rule
            if self.position == start_pos:
                self._skip_to_next_rule()
            return None

    def _skip_to_next_section(self):
        """Skip tokens until we find the next section keyword or closing brace."""
        while self._current_token():
            if self._current_token().type.name in (
                "META",
                "STRINGS",
                "CONDITION",
                "RBRACE",
                "RULE",
            ):
                break
            self._advance()

    def _skip_to_next_rule(self):
        """Skip tokens until we find the next rule or EOF."""
        while self._current_token() and self._current_token().type.name != "RULE":
            self._advance()

    def _parse_yara_file(self) -> YaraFile:
        """Parse complete YARA file with error recovery."""
        imports = []
        includes = []
        rules = []

        while not self._is_at_end():
            token = self._current_token()
            if not token:
                break

            try:
                if token.type.name == "IMPORT":
                    self._advance()
                    imports.append(self._parse_import())
                elif token.type.name == "INCLUDE":
                    self._advance()
                    includes.append(self._parse_include())
                elif token.type.name in ("RULE", "PRIVATE", "GLOBAL"):
                    rule = self._parse_rule()
                    if rule:  # Only add if successfully parsed
                        rules.append(rule)
                else:
                    self._advance()  # Skip unknown tokens
            except Exception as e:
                # Record error and continue
                error = ParserErrorInfo(
                    message=str(e),
                    line=token.line if token else 0,
                    column=token.column if token else 0,
                    context=self._get_context_at_position(),
                    severity="error",
                )
                self.parser_errors.append(error)
                self._advance()  # Skip problematic token

        return YaraFile(imports=imports, includes=includes, rules=rules)
