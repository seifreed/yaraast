"""Better parser implementation that merges old logic."""

from __future__ import annotations

from yaraast.ast.base import *
from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.ast.meta import *
from yaraast.ast.modules import *
from yaraast.ast.operators import *
from yaraast.ast.rules import *
from yaraast.ast.strings import *
from yaraast.lexer import Lexer, Token, TokenType


class Parser:
    """Better YARA parser implementation."""

    def __init__(self) -> None:
        self.tokens: list[Token] = []
        self.position = 0
        self.text = ""

    def parse(self, text: str) -> YaraFile:
        """Parse YARA text and return AST."""
        lexer = Lexer(text)
        self.tokens = lexer.tokenize()
        self.position = 0
        self.text = text

        return self._parse_yara_file()

    def _parse_yara_file(self) -> YaraFile:
        """Parse complete YARA file."""
        imports = []
        includes = []
        rules = []

        while not self._is_at_end():
            token = self._current_token()
            if not token:
                break

            if token.type == TokenType.IMPORT:
                self._advance()
                imports.append(self._parse_import())
            elif token.type == TokenType.INCLUDE:
                self._advance()
                includes.append(self._parse_include())
            elif token.type in (TokenType.RULE, TokenType.PRIVATE, TokenType.GLOBAL):
                rules.append(self._parse_rule())
            else:
                self._advance()  # Skip unknown tokens

        return YaraFile(imports=imports, includes=includes, rules=rules)

    def _parse_rule(self) -> Rule:
        """Parse a rule."""
        modifiers = []

        # Parse modifiers
        while self._current_token() and self._current_token().type in (
            TokenType.PRIVATE,
            TokenType.GLOBAL,
        ):
            modifiers.append(self._current_token().value)
            self._advance()

        # Expect 'rule'
        if not self._match(TokenType.RULE):
            msg = "Expected 'rule'"
            raise Exception(msg)

        # Parse rule name
        if not self._current_token() or self._current_token().type != TokenType.IDENTIFIER:
            msg = "Expected rule name"
            raise Exception(msg)

        name = self._current_token().value
        self._advance()

        # Parse tags
        tags = []
        if self._match(TokenType.COLON):
            while self._current_token() and self._current_token().type == TokenType.IDENTIFIER:
                from yaraast.ast.rules import Tag

                tags.append(Tag(name=self._current_token().value))
                self._advance()

        # Expect '{'
        if not self._match(TokenType.LBRACE):
            msg = "Expected '{'"
            raise Exception(msg)

        # Parse sections
        meta = {}
        strings = []
        condition = None

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'meta'"
                    raise Exception(msg)
                meta_list = self._parse_meta_section()
                # Convert list of Meta objects to dict
                for m in meta_list:
                    meta[m.key] = m.value
            elif self._match(TokenType.STRINGS):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'strings'"
                    raise Exception(msg)
                strings = self._parse_strings_section()
            elif self._match(TokenType.CONDITION):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'condition'"
                    raise Exception(msg)
                condition = self._parse_condition()
            else:
                # Try to skip unrecognized tokens until we find something we know or '}'
                if self._current_token() and self._current_token().type != TokenType.RBRACE:
                    self._advance()
                    continue
                break  # Stop if we find '}' or reach end

        # Expect '}'
        if not self._match(TokenType.RBRACE):
            # Try to recover by finding the closing brace
            current = self._current_token()
            attempts = 0
            while not self._is_at_end() and attempts < 1000:
                if self._match(TokenType.RBRACE):
                    break
                self._advance()
                attempts += 1
            else:
                msg = f"Expected '}}' but found {current.type if current else 'EOF'} at position {self.position}"
                raise Exception(
                    msg,
                )

        # Condition is required
        if condition is None:
            condition = BooleanLiteral(value=True)  # Default to true

        return Rule(
            name=name,
            modifiers=modifiers,
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
        )

    def _parse_condition(self) -> Expression:
        """Parse condition expression."""
        return self._parse_or_expression()

    def _parse_or_expression(self) -> Expression:
        """Parse OR expression."""
        expr = self._parse_and_expression()

        while self._match(TokenType.OR):
            right = self._parse_and_expression()
            expr = BinaryExpression(left=expr, operator="or", right=right)

        # Check for range operator (..)
        if self._match(TokenType.DOUBLE_DOT):
            high = self._parse_and_expression()
            from yaraast.ast.expressions import RangeExpression

            return RangeExpression(low=expr, high=high)

        return expr

    def _parse_and_expression(self) -> Expression:
        """Parse AND expression."""
        expr = self._parse_bitwise_expression()

        while self._match(TokenType.AND):
            right = self._parse_bitwise_expression()
            expr = BinaryExpression(left=expr, operator="and", right=right)

        return expr

    def _parse_bitwise_expression(self) -> Expression:
        """Parse bitwise expressions (&, |, ^, <<, >>)."""
        expr = self._parse_not_expression()

        while self._match(
            TokenType.BITWISE_AND,
            TokenType.BITWISE_OR,
            TokenType.XOR,
            TokenType.SHIFT_LEFT,
            TokenType.SHIFT_RIGHT,
        ):
            operator = self._previous().value
            right = self._parse_not_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_not_expression(self) -> Expression:
        """Parse NOT expression."""
        if self._match(TokenType.NOT):
            operand = self._parse_not_expression()
            return UnaryExpression(operator="not", operand=operand)

        return self._parse_relational_expression()

    def _parse_additive_expression(self) -> Expression:
        """Parse additive expressions (+ and -)."""
        expr = self._parse_multiplicative_expression()

        while self._match(TokenType.PLUS, TokenType.MINUS):
            operator = self._previous().value
            right = self._parse_multiplicative_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_multiplicative_expression(self) -> Expression:
        """Parse multiplicative expressions (*, /, %)."""
        expr = self._parse_primary_expression()

        while self._match(TokenType.MULTIPLY, TokenType.DIVIDE, TokenType.MODULO):
            operator = self._previous().value
            right = self._parse_primary_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_relational_expression(self) -> Expression:
        """Parse relational expressions."""
        expr = self._parse_additive_expression()

        while True:
            if self._match(
                TokenType.LT,
                TokenType.LE,
                TokenType.GT,
                TokenType.GE,
                TokenType.EQ,
                TokenType.NEQ,
                TokenType.CONTAINS,
                TokenType.MATCHES,
                TokenType.STARTSWITH,
                TokenType.ENDSWITH,
                TokenType.ICONTAINS,
                TokenType.ISTARTSWITH,
                TokenType.IENDSWITH,
                TokenType.IEQUALS,
            ):
                operator = self._previous().value.lower()
                right = self._parse_additive_expression()
                expr = BinaryExpression(left=expr, operator=operator, right=right)
            elif self._match(TokenType.AT):
                # Handle 'at' operator (e.g., $string at offset)
                if isinstance(expr, StringIdentifier):
                    # Parse the offset expression (could be complex like filesize - 42)
                    offset = self._parse_additive_expression()
                    from yaraast.ast.conditions import AtExpression

                    expr = AtExpression(string_id=expr.name, offset=offset)
                else:
                    msg = "'at' operator requires string identifier on left side"
                    raise ValueError(
                        msg,
                    )
            elif self._match(TokenType.IN):
                # Handle 'in' operator (e.g., $string in (0..100))
                if isinstance(expr, StringIdentifier):
                    range_expr = self._parse_additive_expression()
                    from yaraast.ast.conditions import InExpression

                    expr = InExpression(string_id=expr.name, range=range_expr)
                else:
                    # Could be other 'in' usage, treat as binary operator
                    right = self._parse_additive_expression()
                    expr = BinaryExpression(left=expr, operator="in", right=right)
            else:
                break

        return expr

    def _parse_primary_expression(self) -> Expression:
        """Parse primary expression."""
        # Handle 'defined' operator
        if self._match(TokenType.DEFINED):
            # Parse the full expression that follows 'defined' (could be complex like pe.sections[0].name)
            expr = self._parse_postfix_expression()
            return DefinedExpression(expression=expr)

        # String identifiers
        if self._match(TokenType.STRING_IDENTIFIER):
            return StringIdentifier(name=self._previous().value)

        # String count (#string)
        if self._match(TokenType.STRING_COUNT):
            string_id = self._previous().value  # e.g., "#a"
            # Remove the # prefix to get just the identifier
            string_id = string_id.removeprefix("#")
            return StringCount(string_id=string_id)

        # String offset (@string or @string[index])
        if self._match(TokenType.STRING_OFFSET):
            string_id = self._previous().value  # e.g., "@a"
            # Remove the @ prefix to get just the identifier
            string_id = string_id.removeprefix("@")
            index = None
            if self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']' after string offset index"
                    raise Exception(msg)
            return StringOffset(string_id=string_id, index=index)

        # String length (!string or !string[index])
        if self._match(TokenType.STRING_LENGTH):
            string_id = self._previous().value  # e.g., "!a"
            # Remove the ! prefix to get just the identifier
            string_id = string_id.removeprefix("!")
            index = None
            if self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']' after string length index"
                    raise Exception(msg)
            return StringLength(string_id=string_id, index=index)

        # Skip - integers are handled later to check for "N of" pattern

        if self._match(TokenType.DOUBLE):
            return DoubleLiteral(value=self._previous().value)

        if self._match(TokenType.STRING):
            return StringLiteral(value=self._previous().value)

        if self._match(TokenType.BOOLEAN_TRUE):
            return BooleanLiteral(value=True)

        if self._match(TokenType.BOOLEAN_FALSE):
            return BooleanLiteral(value=False)

        # Regex literals
        if self._match(TokenType.REGEX):
            # Parse regex: pattern with optional modifiers
            regex_val = self._previous().value
            pattern = regex_val
            modifiers = ""

            # The lexer returns pattern or pattern\x00modifiers
            if "\x00" in regex_val:
                parts = regex_val.split("\x00", 1)
                pattern = parts[0]
                modifiers = parts[1] if len(parts) > 1 else ""

            return RegexLiteral(pattern=pattern, modifiers=modifiers)

        # Identifiers and keywords that can be used as identifiers
        if self._match(TokenType.IDENTIFIER, TokenType.FILESIZE, TokenType.ENTRYPOINT):
            return self._parse_postfix_from_identifier(self._previous().value)

        # Handle 'them' as special identifier
        if self._match(TokenType.THEM):
            return Identifier(name="them")

        # Parentheses
        if self._match(TokenType.LPAREN):
            expr = self._parse_or_expression()

            # Handle range with dash syntax (0-100) as alternative to (0..100)
            if self._current_token() and self._current_token().type == TokenType.MINUS:
                self._advance()
                high = self._parse_or_expression()
                from yaraast.ast.expressions import RangeExpression

                expr = RangeExpression(low=expr, high=high)

            if not self._match(TokenType.RPAREN):
                current = self._current_token()
                # Try to recover by skipping unexpected tokens
                while not self._is_at_end() and not self._check(TokenType.RPAREN):
                    self._advance()
                    if self._match(TokenType.RPAREN):
                        break
                else:
                    msg = f"Expected ')' in parentheses at position {self.position}, got {current.type if current else 'EOF'}"
                    raise Exception(
                        msg,
                    )
            return ParenthesesExpression(expression=expr)

        # Unary minus for negative numbers
        if self._match(TokenType.MINUS):
            if self._match(TokenType.INTEGER):
                return IntegerLiteral(value=-self._previous().value)
            if self._match(TokenType.DOUBLE):
                return DoubleLiteral(value=-self._previous().value)
            msg = "Expected number after '-'"
            raise Exception(msg)

        # Special expressions: for
        if self._match(TokenType.FOR):
            return self._parse_for_expression()

        # Special expressions: quantifier of (any of, all of, 2 of, etc.)
        if self._match(TokenType.ANY, TokenType.ALL):
            quantifier = self._previous().value
            if self._match(TokenType.OF):
                return self._parse_of_expression(quantifier)
            # Put the token back, it's just an identifier
            self.position -= 1
            return Identifier(name=quantifier)

        # Check for integer - might be part of "N of" expression
        if self._match(TokenType.INTEGER):
            value = self._previous().value
            # Look ahead to see if "of" follows
            if self._match(TokenType.OF):
                return self._parse_of_expression(value)
            # Just a regular integer literal
            return IntegerLiteral(value=value)

        msg = f"Unexpected token in expression: {self._current_token()}"
        raise Exception(msg)

    def _parse_postfix_expression(self) -> Expression:
        """Parse postfix expression starting from primary."""
        # Get base identifier (could be regular identifier or string identifier)
        if self._match(TokenType.IDENTIFIER):
            return self._parse_postfix_from_identifier(self._previous().value)
        if self._match(TokenType.STRING_IDENTIFIER):
            # For string identifiers like $string1, return a StringIdentifier directly
            return StringIdentifier(name=self._previous().value)
        msg = "Expected identifier in postfix expression"
        raise ValueError(msg)

    def _parse_postfix_from_identifier(self, name: str) -> Expression:
        """Parse postfix operations from an identifier."""
        expr = Identifier(name=name)

        while True:
            if self._match(TokenType.DOT):
                if not self._match(TokenType.IDENTIFIER):
                    msg = "Expected member name after '.'"
                    raise Exception(msg)
                member = self._previous().value
                expr = MemberAccess(object=expr, member=member)
            elif self._match(TokenType.LBRACKET):
                index = self._parse_primary_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise Exception(msg)
                if isinstance(index, StringLiteral):
                    expr = DictionaryAccess(object=expr, key=index.value)
                else:
                    expr = ArrayAccess(array=expr, index=index)
            elif self._match(TokenType.LPAREN):
                # Function call
                args = []
                while not self._check(TokenType.RPAREN) and not self._is_at_end():
                    # Try to parse argument, but be tolerant of errors
                    try:
                        args.append(self._parse_or_expression())
                    except (ValueError, TypeError, AttributeError):
                        # If parsing fails, try to recover by finding comma or closing paren
                        while not self._is_at_end():
                            if self._check(TokenType.COMMA) or self._check(
                                TokenType.RPAREN,
                            ):
                                break
                            self._advance()

                    if not self._match(TokenType.COMMA):
                        break

                if not self._match(TokenType.RPAREN):
                    # Try to recover by finding the closing parenthesis
                    current = self._current_token()
                    attempts = 0
                    while not self._is_at_end() and attempts < 100:
                        if self._match(TokenType.RPAREN):
                            break
                        self._advance()
                        attempts += 1
                    else:
                        msg = f"Expected ')' in function call at position {self.position}, got {current.type if current else 'EOF'}"
                        raise Exception(
                            msg,
                        )
                # Get function name from expression
                if isinstance(expr, Identifier):
                    expr = FunctionCall(function=expr.name, arguments=args)
                elif isinstance(expr, MemberAccess):
                    # Method call like math.entropy(...)
                    expr = FunctionCall(
                        function=f"{self._get_full_name(expr)}",
                        arguments=args,
                    )
                else:
                    msg = "Invalid function call"
                    raise Exception(msg)
            else:
                break

        return expr

    def _get_full_name(self, expr: Expression) -> str:
        """Get full name from member access chain."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, MemberAccess):
            obj_name = (
                self._get_full_name(expr.object)
                if isinstance(expr.object, Identifier | MemberAccess)
                else str(expr.object)
            )
            return f"{obj_name}.{expr.member}"
        return str(expr)

    def _parse_meta_section(self) -> list[Meta]:
        """Parse meta section."""
        meta_list = []

        while self._current_token() and self._current_token().type == TokenType.IDENTIFIER:
            key = self._current_token().value
            self._advance()

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' in meta"
                raise Exception(msg)

            # Parse value
            if self._match(TokenType.STRING) or self._match(TokenType.INTEGER):
                value = self._previous().value
            elif self._match(TokenType.BOOLEAN_TRUE):
                value = True
            elif self._match(TokenType.BOOLEAN_FALSE):
                value = False
            else:
                msg = "Expected meta value"
                raise Exception(msg)

            meta_list.append(Meta(key=key, value=value))

        return meta_list

    def _parse_strings_section(self) -> list[StringDefinition]:
        """Parse strings section."""
        strings = []
        anonymous_counter = 0  # Counter for anonymous strings

        while self._current_token() and self._current_token().type == TokenType.STRING_IDENTIFIER:
            identifier = self._current_token().value
            self._advance()

            # Generate unique identifier for anonymous strings
            if identifier == "$":
                anonymous_counter += 1
                identifier = f"$anon_{anonymous_counter}"

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '='"
                raise Exception(msg)

            # Parse string value
            if self._match(TokenType.STRING):
                value = self._previous().value
                # Parse modifiers
                modifiers = []
                while self._current_token() and self._current_token().type in (
                    TokenType.NOCASE,
                    TokenType.WIDE,
                    TokenType.ASCII,
                    TokenType.FULLWORD,
                    TokenType.BASE64,
                    TokenType.BASE64WIDE,
                    TokenType.XOR_MOD,
                ):
                    mod_name = self._current_token().value
                    self._advance()

                    # Handle XOR with optional parameters
                    if (
                        mod_name.lower() == "xor"
                        and self._current_token()
                        and self._current_token().type == TokenType.LPAREN
                    ):
                        self._advance()  # consume '('
                        # Parse XOR parameter (can be single value or range)
                        # For now, just skip to closing paren
                        depth = 1
                        while depth > 0 and self._current_token():
                            if self._current_token().type == TokenType.LPAREN:
                                depth += 1
                            elif self._current_token().type == TokenType.RPAREN:
                                depth -= 1
                            self._advance()
                        modifiers.append(StringModifier(name="xor"))
                    else:
                        modifiers.append(StringModifier(name=mod_name))
                strings.append(
                    PlainString(identifier=identifier, value=value, modifiers=modifiers),
                )
            elif self._match(TokenType.HEX_STRING):
                # Parse hex string content
                hex_content = self._previous().value.strip()
                hex_tokens = []

                # Parse hex string content including wildcards
                from yaraast.ast.strings import HexByte, HexWildcard

                # Remove any whitespace and parse pairs of hex digits
                hex_clean = hex_content.replace(" ", "").replace("\t", "").replace("\n", "")

                i = 0
                while i < len(hex_clean):
                    if i + 1 < len(hex_clean):
                        two_chars = hex_clean[i : i + 2]
                        if two_chars == "??":
                            # Wildcard
                            hex_tokens.append(HexWildcard())
                            i += 2
                        elif all(c in "0123456789ABCDEFabcdef" for c in two_chars):
                            # Hex byte - convert to integer
                            hex_tokens.append(HexByte(value=int(two_chars, 16)))
                            i += 2
                        else:
                            # Skip invalid character
                            i += 1
                    else:
                        # Skip single character at end
                        i += 1

                strings.append(HexString(identifier=identifier, tokens=hex_tokens))
            elif self._match(TokenType.REGEX):
                # Regex string
                regex_val = self._previous().value
                # Extract modifiers if present
                modifiers = []
                pattern = regex_val

                # The lexer returns pattern or pattern\x00modifiers
                if "\x00" in regex_val:
                    parts = regex_val.split("\x00", 1)
                    pattern = parts[0]
                    mod_str = parts[1] if len(parts) > 1 else ""
                    for m in mod_str:
                        if m == "i":
                            modifiers.append(StringModifier(name="nocase"))
                        elif m == "s":
                            modifiers.append(StringModifier(name="dotall"))

                # Parse YARA modifiers (nocase, wide, etc.) after the regex
                while self._current_token() and self._current_token().type in (
                    TokenType.NOCASE,
                    TokenType.WIDE,
                    TokenType.ASCII,
                    TokenType.FULLWORD,
                    TokenType.BASE64,
                    TokenType.BASE64WIDE,
                    TokenType.XOR_MOD,
                ):
                    mod_name = self._current_token().value
                    self._advance()

                    # Handle XOR with optional parameters
                    if (
                        mod_name.lower() == "xor"
                        and self._current_token()
                        and self._current_token().type == TokenType.LPAREN
                    ):
                        self._advance()  # consume '('
                        # Parse XOR parameter (can be single value or range)
                        # For now, just skip to closing paren
                        depth = 1
                        while depth > 0 and self._current_token():
                            if self._current_token().type == TokenType.LPAREN:
                                depth += 1
                            elif self._current_token().type == TokenType.RPAREN:
                                depth -= 1
                            self._advance()
                        modifiers.append(StringModifier(name="xor"))
                    else:
                        modifiers.append(StringModifier(name=mod_name))

                strings.append(
                    RegexString(
                        identifier=identifier,
                        regex=pattern,
                        modifiers=modifiers,
                    ),
                )
            else:
                msg = "Expected string value"
                raise Exception(msg)

        return strings

    def _parse_import(self) -> Import:
        """Parse import statement."""
        if not self._match(TokenType.STRING):
            msg = "Expected module name"
            raise Exception(msg)

        module = self._previous().value
        alias = None

        # Check for 'as alias'
        if self._match(TokenType.AS):
            if not self._match(TokenType.IDENTIFIER):
                msg = "Expected alias after 'as'"
                raise Exception(msg)
            alias = self._previous().value

        return Import(module=module, alias=alias)

    def _parse_include(self) -> Include:
        """Parse include statement."""
        if not self._match(TokenType.STRING):
            msg = "Expected file path"
            raise Exception(msg)

        return Include(path=self._previous().value)

    # Helper methods
    def _current_token(self) -> Token | None:
        """Get current token."""
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return None

    def _previous(self) -> Token:
        """Get previous token."""
        return self.tokens[self.position - 1]

    def _advance(self) -> None:
        """Advance to next token."""
        if self.position < len(self.tokens):
            self.position += 1

    def _parse_for_expression(self) -> Expression:
        """Parse for expression."""
        # Parse quantifier (any, all, or number)
        if self._match(TokenType.ANY):
            quantifier = "any"
        elif self._match(TokenType.ALL):
            quantifier = "all"
        elif self._match(TokenType.INTEGER):
            quantifier = self._previous().value
        else:
            msg = "Expected quantifier after 'for'"
            raise Exception(msg)

        # Check for 'of' (for...of expression)
        if self._match(TokenType.OF):
            # for...of expression
            # Parse string set which could be:
            # - them
            # - ($a, $b, $c)
            # - ($a*)
            # - $a
            if self._match(TokenType.THEM):
                string_set = Identifier(name="them")
            elif self._match(TokenType.LPAREN):
                # Parse string set like ($a, $b, $c) or ($a*)
                string_ids = []
                while not self._check(TokenType.RPAREN) and not self._is_at_end():
                    if self._match(TokenType.STRING_IDENTIFIER):
                        string_name = self._previous().value
                        # Check for wildcard pattern (e.g., $a*)
                        if self._match(TokenType.MULTIPLY):
                            string_name += "*"
                        from yaraast.ast.expressions import StringIdentifier

                        string_ids.append(StringIdentifier(name=string_name))
                    elif self._match(TokenType.MULTIPLY):
                        # Handle standalone wildcards (*)
                        from yaraast.ast.expressions import StringIdentifier

                        string_ids.append(StringIdentifier(name="*"))
                    else:
                        # Skip unexpected tokens and try to continue
                        if self._current_token():
                            self._advance()
                        continue

                    if not self._match(TokenType.COMMA):
                        break

                if not self._match(TokenType.RPAREN):
                    # Try to recover by finding the closing parenthesis
                    while not self._is_at_end() and not self._check(TokenType.RPAREN):
                        self._advance()
                    if not self._match(TokenType.RPAREN):
                        msg = "Expected ')' after string set"
                        raise Exception(msg)

                from yaraast.ast.expressions import SetExpression

                string_set = SetExpression(elements=string_ids)
            else:
                # Single string or identifier
                string_set = self._parse_primary_expression()

            # Optional condition
            body = None
            if self._match(TokenType.COLON) and self._match(TokenType.LPAREN):
                # Save position in case we need to retry
                saved_pos = self.position
                try:
                    body = self._parse_expression()
                except (ValueError, TypeError, AttributeError):
                    # Reset and try to parse with special handling for $
                    self.position = saved_pos

                    # Check if it starts with $ (anonymous string reference in for context)
                    if (
                        self._current_token()
                        and self._current_token().type == TokenType.STRING_IDENTIFIER
                    ):
                        token_val = self._current_token().value
                        if token_val == "$":
                            # This is a reference to the current string in the for loop
                            self._advance()
                            from yaraast.ast.expressions import StringIdentifier

                            current_string = StringIdentifier(name="$")

                            # Now parse the rest (like "in (0..65536)")
                            if self._match(TokenType.IN):
                                range_expr = self._parse_additive_expression()
                                from yaraast.ast.conditions import InExpression

                                body = InExpression(string_id="$", range=range_expr)
                            else:
                                body = current_string
                        else:
                            # Normal string identifier, retry parsing
                            body = self._parse_expression()
                    else:
                        # If all else fails, use default
                        body = BooleanLiteral(value=True)
                        while not self._is_at_end() and not self._check(
                            TokenType.RPAREN,
                        ):
                            self._advance()

                if not self._match(TokenType.RPAREN):
                    # Try to recover by finding the closing parenthesis
                    current = self._current_token()
                    attempts = 0
                    while not self._is_at_end() and attempts < 100:
                        if self._match(TokenType.RPAREN):
                            break
                        self._advance()
                        attempts += 1
                    else:
                        msg = f"Expected ')' after for...of condition at position {self.position}, got {current.type if current else 'EOF'}"
                        raise Exception(
                            msg,
                        )

            # Create ForOfExpression
            from yaraast.ast.conditions import ForOfExpression
            from yaraast.ast.expressions import IntegerLiteral, StringLiteral

            # Convert quantifier to appropriate Expression type
            if isinstance(quantifier, int):
                quantifier_expr = IntegerLiteral(value=str(quantifier))
            elif isinstance(quantifier, str):
                if quantifier in ["any", "all"]:
                    quantifier_expr = Identifier(name=quantifier)
                else:
                    quantifier_expr = StringLiteral(value=quantifier)
            else:
                quantifier_expr = quantifier

            return ForOfExpression(
                quantifier=quantifier_expr,
                string_set=string_set,
                condition=body,
            )

        # Otherwise it's a regular for expression (for all i in (0..10) : (...))
        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected variable name after quantifier"
            raise Exception(msg)

        variable = self._previous().value

        if not self._match(TokenType.IN):
            msg = "Expected 'in' after variable"
            raise Exception(msg)

        iterable = self._parse_primary_expression()

        if not self._match(TokenType.COLON):
            msg = "Expected ':' after iterable"
            raise Exception(msg)

        if not self._match(TokenType.LPAREN):
            msg = "Expected '(' after ':'"
            raise Exception(msg)

        try:
            body = self._parse_expression()
        except (ValueError, TypeError, AttributeError):
            # If expression parsing fails, try to recover
            body = BooleanLiteral(value=True)
            while not self._is_at_end() and not self._check(TokenType.RPAREN):
                self._advance()

        if not self._match(TokenType.RPAREN):
            # Try to recover by finding the closing parenthesis
            current = self._current_token()
            attempts = 0
            while not self._is_at_end() and attempts < 100:
                if self._match(TokenType.RPAREN):
                    break
                self._advance()
                attempts += 1
            else:
                msg = f"Expected ')' after for body at position {self.position}, got {current.type if current else 'EOF'}"
                raise Exception(
                    msg,
                )

        from yaraast.ast.conditions import ForExpression

        return ForExpression(
            quantifier=quantifier,
            variable=variable,
            iterable=iterable,
            body=body,
        )

    def _parse_of_expression(self, quantifier) -> Expression:
        """Parse of expression (e.g., '2 of them')."""
        # Convert quantifier to appropriate Expression type
        from yaraast.ast.expressions import IntegerLiteral, StringLiteral

        if isinstance(quantifier, int):
            quantifier_expr = IntegerLiteral(value=str(quantifier))
        elif isinstance(quantifier, str):
            if quantifier in ["any", "all"]:
                quantifier_expr = Identifier(name=quantifier)
            else:
                quantifier_expr = StringLiteral(value=quantifier)
        else:
            quantifier_expr = quantifier

        # Parse the string set expression
        if self._match(TokenType.THEM):
            string_set = Identifier(name="them")
        elif self._match(TokenType.LPAREN):
            # Parse string set like ($a, $b, $c)
            string_ids = []
            while not self._check(TokenType.RPAREN) and not self._is_at_end():
                if self._match(TokenType.STRING_IDENTIFIER):
                    string_name = self._previous().value
                    # Check for wildcard pattern (e.g., $a*)
                    if self._match(TokenType.MULTIPLY):
                        string_name += "*"
                    string_ids.append(StringIdentifier(name=string_name))
                elif self._match(TokenType.MULTIPLY):
                    # Handle standalone wildcards (*)
                    string_ids.append(StringIdentifier(name="*"))
                elif self._match(TokenType.INTEGER):
                    # Handle integer literals in set expressions
                    value = self._previous().value
                    string_ids.append(IntegerLiteral(value=value))
                else:
                    # Skip unexpected tokens and try to continue
                    # This helps with parsing files with unsupported syntax
                    if self._current_token():
                        self._advance()
                    continue

                if not self._match(TokenType.COMMA):
                    break

            if not self._match(TokenType.RPAREN):
                # Try to recover by finding the closing parenthesis
                while not self._is_at_end() and not self._check(TokenType.RPAREN):
                    self._advance()
                if not self._match(TokenType.RPAREN):
                    msg = "Expected ')' after string set"
                    raise Exception(msg)

            from yaraast.ast.expressions import SetExpression

            string_set = SetExpression(elements=string_ids)
        else:
            # Try to parse a primary expression
            string_set = self._parse_primary_expression()

        from yaraast.ast.conditions import OfExpression

        return OfExpression(quantifier=quantifier_expr, string_set=string_set)

    def _parse_expression(self) -> Expression:
        """Parse a general expression."""
        return self._parse_or_expression()

    def _match(self, *types: TokenType) -> bool:
        """Check if current token matches any of the given types."""
        for token_type in types:
            if self._check(token_type):
                self._advance()
                return True
        return False

    def _check(self, token_type: TokenType) -> bool:
        """Check if current token is of given type."""
        if self._is_at_end():
            return False
        token = self._current_token()
        return token and token.type == token_type

    def _is_at_end(self) -> bool:
        """Check if at end of tokens."""
        return self.position >= len(self.tokens) or (
            self._current_token() and self._current_token().type == TokenType.EOF
        )
