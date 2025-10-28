"""YARA parser implementation.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import *
from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.ast.meta import *
from yaraast.ast.modules import *
from yaraast.ast.operators import *
from yaraast.ast.rules import *
from yaraast.ast.strings import *
from yaraast.lexer import Lexer, Token, TokenType


class ParserError(Exception):
    """Parser error exception."""

    def __init__(self, message: str, token: Token) -> None:
        super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
        self.token = token
        self.line = token.line
        self.column = token.column


class Parser:
    """YARA parser for building AST from tokens.

    Supports two API styles:
    1. Original: Parser(text).parse()
    2. Reusable: Parser().parse(text)
    """

    def __init__(self, text: str | None = None) -> None:
        """Initialize parser.

        Args:
            text: Optional YARA code to parse. If provided, parser is ready
                  to call parse(). If None, text must be passed to parse().
        """
        if text is not None:
            self.lexer = Lexer(text)
            self.tokens = self.lexer.tokenize()
            self.current = 0
        else:
            self.lexer = None
            self.tokens = []
            self.current = 0

    def parse(self, text: str | None = None) -> YaraFile:
        """Parse YARA file and return AST.

        Args:
            text: Optional YARA code to parse. If provided, will tokenize
                  this text. If None, uses text from constructor.

        Returns:
            YaraFile AST
        """
        # Support better_parser.py API: Parser().parse(text)
        if text is not None:
            self.lexer = Lexer(text)
            self.tokens = self.lexer.tokenize()
            self.current = 0

        # Ensure we have tokens to parse
        if not self.tokens:
            msg = "No text provided to parse"
            raise ValueError(msg)

        imports = []
        includes = []
        rules = []

        while not self._is_at_end():
            if self._match(TokenType.IMPORT):
                imports.append(self._parse_import())
            elif self._match(TokenType.INCLUDE):
                includes.append(self._parse_include())
            elif (
                self._check(TokenType.RULE)
                or self._check(TokenType.PRIVATE)
                or self._check(TokenType.GLOBAL)
            ):
                rules.append(self._parse_rule())
            else:
                msg = f"Unexpected token: {self._peek().value}"
                raise ParserError(
                    msg,
                    self._peek(),
                )

        return YaraFile(imports=imports, includes=includes, rules=rules)

    def _parse_import(self) -> Import:
        """Parse import statement."""
        if not self._match(TokenType.STRING):
            msg = "Expected module name after 'import'"
            raise ParserError(msg, self._peek())

        module = self._previous().value
        alias = None

        # Check for 'as alias'
        if self._match(TokenType.AS):
            if not self._match(TokenType.IDENTIFIER):
                msg = "Expected alias after 'as'"
                raise ParserError(msg, self._peek())
            alias = self._previous().value

        return Import(module=module, alias=alias)

    def _parse_include(self) -> Include:
        """Parse include statement."""
        if not self._match(TokenType.STRING):
            msg = "Expected file path after 'include'"
            raise ParserError(msg, self._peek())

        path = self._previous().value
        return Include(path=path)

    def _parse_rule(self) -> Rule:
        """Parse rule definition."""
        modifiers = []

        # Parse modifiers
        while self._match(TokenType.PRIVATE, TokenType.GLOBAL):
            modifiers.append(self._previous().value.lower())

        if not self._match(TokenType.RULE):
            msg = "Expected 'rule' keyword"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected rule name"
            raise ParserError(msg, self._peek())

        name = self._previous().value

        # Parse tags
        tags = []
        if self._match(TokenType.COLON):
            while self._check(TokenType.IDENTIFIER):
                tag_name = self._advance().value
                tags.append(Tag(name=tag_name))

        if not self._match(TokenType.LBRACE):
            msg = "Expected '{' after rule name"
            raise ParserError(msg, self._peek())

        # Parse rule sections
        meta = {}
        strings = []
        condition = None

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'meta'"
                    raise ParserError(msg, self._peek())
                meta = self._parse_meta_section()
            elif self._match(TokenType.STRINGS):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'strings'"
                    raise ParserError(msg, self._peek())
                strings = self._parse_strings_section()
            elif self._match(TokenType.CONDITION):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'condition'"
                    raise ParserError(msg, self._peek())
                condition = self._parse_condition()
            else:
                msg = f"Unexpected section: {self._peek().value}"
                raise ParserError(
                    msg,
                    self._peek(),
                )

        if not self._match(TokenType.RBRACE):
            msg = "Expected '}' at end of rule"
            raise ParserError(msg, self._peek())

        return Rule(
            name=name,
            modifiers=modifiers,
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
        )

    def _parse_meta_section(self) -> dict[str, Any]:
        """Parse meta section."""
        meta = {}

        while not self._check_any(
            TokenType.STRINGS,
            TokenType.CONDITION,
            TokenType.RBRACE,
        ):
            if not self._check(TokenType.IDENTIFIER):
                break

            key = self._advance().value

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' after meta key"
                raise ParserError(msg, self._peek())

            # Parse meta value
            # Handle negative numbers: -159
            if self._match(TokenType.MINUS):
                if self._match(TokenType.INTEGER):
                    value = -self._previous().value
                else:
                    msg = "Expected number after '-' in meta value"
                    raise ParserError(msg, self._peek())
            elif self._match(TokenType.STRING) or self._match(TokenType.INTEGER):
                value = self._previous().value
            elif self._match(TokenType.BOOLEAN_TRUE):
                value = True
            elif self._match(TokenType.BOOLEAN_FALSE):
                value = False
            else:
                msg = "Invalid meta value"
                raise ParserError(msg, self._peek())

            meta[key] = value

        return meta

    def _parse_strings_section(self) -> list[StringDefinition]:
        """Parse strings section."""
        strings = []
        anonymous_counter = 0

        while not self._check_any(TokenType.CONDITION, TokenType.RBRACE):
            if not self._check(TokenType.STRING_IDENTIFIER):
                break

            identifier = self._advance().value

            # Handle anonymous strings (just "$")
            if identifier == "$":
                anonymous_counter += 1
                identifier = f"$anon_{anonymous_counter}"

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' after string identifier"
                raise ParserError(msg, self._peek())

            # Parse string value
            if self._match(TokenType.STRING):
                value = self._previous().value
                modifiers = self._parse_string_modifiers()
                strings.append(
                    PlainString(identifier=identifier, value=value, modifiers=modifiers),
                )
            elif self._match(TokenType.HEX_STRING):
                hex_value = self._previous().value
                tokens = self._parse_hex_string(hex_value)
                modifiers = self._parse_string_modifiers()
                strings.append(
                    HexString(identifier=identifier, tokens=tokens, modifiers=modifiers),
                )
            elif self._match(TokenType.REGEX):
                regex = self._previous().value
                modifiers = self._parse_string_modifiers()
                strings.append(
                    RegexString(identifier=identifier, regex=regex, modifiers=modifiers),
                )
            else:
                msg = "Invalid string value"
                raise ParserError(msg, self._peek())

        return strings

    def _parse_string_modifiers(self) -> list[StringModifier]:
        """Parse string modifiers."""
        modifiers = []

        while self._check_any(
            TokenType.NOCASE,
            TokenType.WIDE,
            TokenType.ASCII,
            TokenType.XOR_MOD,
            TokenType.BASE64,
            TokenType.BASE64WIDE,
            TokenType.FULLWORD,
        ):
            mod_token = self._advance()
            mod_name = mod_token.value.lower()

            # Some modifiers can have parameters
            if mod_name == "xor" and self._match(TokenType.LPAREN):
                # Parse xor range
                if self._match(TokenType.INTEGER):
                    min_val = self._previous().value
                    if self._match(TokenType.MINUS):
                        if self._match(TokenType.INTEGER):
                            max_val = self._previous().value
                            value = (min_val, max_val)
                        else:
                            msg = "Expected integer after '-'"
                            raise ParserError(
                                msg,
                                self._peek(),
                            )
                    else:
                        value = min_val
                else:
                    msg = "Expected integer or range in xor"
                    raise ParserError(msg, self._peek())

                if not self._match(TokenType.RPAREN):
                    msg = "Expected ')' after xor parameter"
                    raise ParserError(msg, self._peek())

                modifiers.append(StringModifier(name=mod_name, value=value))
            else:
                modifiers.append(StringModifier(name=mod_name))

        return modifiers

    def _parse_hex_string(self, hex_content: str) -> list[HexToken]:
        """Parse hex string content into tokens.

        Performance optimization: Uses list builder pattern O(m) instead of
        string concatenation O(m²) where m is the length of hex_content.
        For large hex strings (e.g., 100KB), this reduces processing time
        from ~10s to ~0.1s (100x improvement).
        """
        # Remove comments from hex content
        # Handle both single-line (//) and multi-line (/* */) comments
        # OPTIMIZATION: Use list builder instead of string concatenation
        # This changes complexity from O(m²) to O(m) for m characters
        cleaned_chars = []
        i = 0
        while i < len(hex_content):
            if i < len(hex_content) - 1 and hex_content[i : i + 2] == "//":
                # Skip until newline
                while i < len(hex_content) and hex_content[i] != "\n":
                    i += 1
            elif i < len(hex_content) - 1 and hex_content[i : i + 2] == "/*":
                # Skip until */
                i += 2
                while i < len(hex_content) - 1:
                    if hex_content[i : i + 2] == "*/":
                        i += 2
                        break
                    i += 1
            else:
                cleaned_chars.append(hex_content[i])
                i += 1

        # Join once at the end - O(m) operation
        hex_content = "".join(cleaned_chars)
        tokens = []
        i = 0

        while i < len(hex_content):
            # Skip whitespace
            while i < len(hex_content) and hex_content[i] in " \t\n\r":
                i += 1

            if i >= len(hex_content):
                break

            char = hex_content[i]

            # Jump
            if char == "[":
                i += 1
                # OPTIMIZATION: Use list builder for jump string extraction
                jump_chars = []
                while i < len(hex_content) and hex_content[i] != "]":
                    jump_chars.append(hex_content[i])
                    i += 1

                if i >= len(hex_content):
                    msg = "Unterminated jump in hex string"
                    raise ParserError(msg, self._peek())

                i += 1  # skip ]

                # Parse jump range
                jump_str = "".join(jump_chars).strip()
                if "-" in jump_str:
                    parts = jump_str.split("-")
                    if len(parts) == 2:
                        min_jump = int(parts[0]) if parts[0].strip() else None
                        max_jump = int(parts[1]) if parts[1].strip() else None
                        tokens.append(HexJump(min_jump=min_jump, max_jump=max_jump))
                    else:
                        msg = "Invalid jump range"
                        raise ParserError(msg, self._peek())
                else:
                    val = int(jump_str)
                    tokens.append(HexJump(min_jump=val, max_jump=val))

            # Alternative (with nested support)
            elif char == "(":
                alt_tokens = self._parse_hex_alternative(hex_content[i:])
                tokens.append(alt_tokens[0])  # Add the alternative token
                # Skip past the parsed alternative
                paren_count = 1
                i += 1
                while i < len(hex_content) and paren_count > 0:
                    if hex_content[i] == "(":
                        paren_count += 1
                    elif hex_content[i] == ")":
                        paren_count -= 1
                    i += 1

            # Wildcard or nibble
            elif char == "?":
                if i + 1 < len(hex_content) and hex_content[i + 1] == "?":
                    # Full wildcard
                    tokens.append(HexWildcard())
                    i += 2
                elif i + 1 < len(hex_content) and hex_content[i + 1] in "0123456789ABCDEFabcdef":
                    # ?X pattern - low nibble
                    nibble_val = int(hex_content[i + 1], 16)
                    tokens.append(HexNibble(high=False, value=nibble_val))
                    i += 2
                else:
                    msg = f"Invalid wildcard at position {i}"
                    raise ParserError(msg, self._peek())

            # Hex byte or nibble
            elif char in "0123456789ABCDEFabcdef":
                if i + 1 < len(hex_content):
                    next_char = hex_content[i + 1]
                    if next_char == "?":
                        # X? pattern - high nibble
                        nibble_val = int(char, 16)
                        tokens.append(HexNibble(high=True, value=nibble_val))
                        i += 2
                    elif next_char in "0123456789ABCDEFabcdef":
                        # Regular hex byte
                        byte_val = int(hex_content[i : i + 2], 16)
                        tokens.append(HexByte(value=byte_val))
                        i += 2
                    else:
                        msg = f"Invalid hex byte at position {i}"
                        raise ParserError(
                            msg,
                            self._peek(),
                        )
                else:
                    msg = f"Incomplete hex byte at position {i}"
                    raise ParserError(
                        msg,
                        self._peek(),
                    )

            else:
                msg = f"Invalid character in hex string: {char}"
                raise ParserError(
                    msg,
                    self._peek(),
                )

        return tokens

    def _parse_hex_alternative(self, hex_content: str) -> list[HexToken]:
        """Parse hex alternative with nested support."""
        if not hex_content.startswith("("):
            msg = "Expected '(' at start of alternative"
            raise ParserError(msg, self._peek())

        i = 1  # Skip opening (
        alternatives = []
        current_alt = []
        paren_depth = 0

        while i < len(hex_content):
            # Skip whitespace
            while i < len(hex_content) and hex_content[i] in " \t\n\r":
                i += 1

            if i >= len(hex_content):
                break

            char = hex_content[i]

            # Handle nested parentheses
            if char == "(":
                # Nested alternative
                nested_alt = self._parse_hex_alternative(hex_content[i:])
                current_alt.extend(nested_alt)
                # Skip past nested alternative
                nested_depth = 1
                i += 1
                while i < len(hex_content) and nested_depth > 0:
                    if hex_content[i] == "(":
                        nested_depth += 1
                    elif hex_content[i] == ")":
                        nested_depth -= 1
                    i += 1

            elif char == ")" and paren_depth == 0:
                # End of this alternative group
                if current_alt:
                    alternatives.append(current_alt)
                i += 1
                break

            elif char == "|" and paren_depth == 0:
                # Alternative separator
                if current_alt:
                    alternatives.append(current_alt)
                current_alt = []
                i += 1

            elif char == "[":
                # Jump in alternative
                jump_i = i + 1
                # OPTIMIZATION: Use list builder for jump string extraction in alternatives
                jump_chars = []
                while jump_i < len(hex_content) and hex_content[jump_i] != "]":
                    jump_chars.append(hex_content[jump_i])
                    jump_i += 1

                if jump_i >= len(hex_content):
                    msg = "Unterminated jump in alternative"
                    raise ParserError(msg, self._peek())

                # Parse jump
                jump_str = "".join(jump_chars).strip()
                if "-" in jump_str:
                    parts = jump_str.split("-")
                    min_jump = int(parts[0]) if parts[0].strip() else None
                    max_jump = int(parts[1]) if parts[1].strip() else None
                    current_alt.append(HexJump(min_jump=min_jump, max_jump=max_jump))
                else:
                    val = int(jump_str)
                    current_alt.append(HexJump(min_jump=val, max_jump=val))

                i = jump_i + 1

            elif char == "?":
                if i + 1 < len(hex_content) and hex_content[i + 1] == "?":
                    current_alt.append(HexWildcard())
                    i += 2
                elif i + 1 < len(hex_content) and hex_content[i + 1] in "0123456789ABCDEFabcdef":
                    nibble_val = int(hex_content[i + 1], 16)
                    current_alt.append(HexNibble(high=False, value=nibble_val))
                    i += 2
                else:
                    msg = "Invalid wildcard in alternative"
                    raise ParserError(msg, self._peek())

            elif char in "0123456789ABCDEFabcdef":
                if i + 1 < len(hex_content):
                    next_char = hex_content[i + 1]
                    if next_char == "?":
                        nibble_val = int(char, 16)
                        current_alt.append(HexNibble(high=True, value=nibble_val))
                        i += 2
                    elif next_char in "0123456789ABCDEFabcdef":
                        byte_val = int(hex_content[i : i + 2], 16)
                        current_alt.append(HexByte(value=byte_val))
                        i += 2
                    else:
                        msg = "Invalid hex in alternative"
                        raise ParserError(msg, self._peek())
                else:
                    msg = "Incomplete hex in alternative"
                    raise ParserError(msg, self._peek())

            else:
                i += 1

        if not alternatives and current_alt:
            alternatives.append(current_alt)

        return [HexAlternative(alternatives=alternatives)]

    def _parse_condition(self) -> Condition:
        """Parse condition expression."""
        return self._parse_or_expression()

    def _parse_or_expression(self) -> Expression:
        """Parse OR expression."""
        expr = self._parse_and_expression()

        while self._match(TokenType.OR):
            operator = "or"
            right = self._parse_and_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_and_expression(self) -> Expression:
        """Parse AND expression."""
        expr = self._parse_not_expression()

        while self._match(TokenType.AND):
            operator = "and"
            right = self._parse_not_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_not_expression(self) -> Expression:
        """Parse NOT expression."""
        if self._match(TokenType.NOT):
            operand = self._parse_not_expression()
            return UnaryExpression(operator="not", operand=operand)

        return self._parse_relational_expression()

    def _parse_relational_expression(self) -> Expression:
        """Parse relational expression."""
        expr = self._parse_range_expression()

        while self._match(
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
            right = self._parse_range_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_range_expression(self) -> Expression:
        """Parse range expression (a..b)."""
        expr = self._parse_bitwise_expression()

        if self._match(TokenType.DOUBLE_DOT):
            high = self._parse_bitwise_expression()
            expr = RangeExpression(low=expr, high=high)

        return expr

    def _parse_bitwise_expression(self) -> Expression:
        """Parse bitwise expression."""
        expr = self._parse_shift_expression()

        while self._match(TokenType.BITWISE_AND, TokenType.BITWISE_OR, TokenType.XOR):
            operator = self._previous().value
            right = self._parse_shift_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_shift_expression(self) -> Expression:
        """Parse shift expression."""
        expr = self._parse_additive_expression()

        while self._match(TokenType.SHIFT_LEFT, TokenType.SHIFT_RIGHT):
            operator = self._previous().value
            right = self._parse_additive_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_additive_expression(self) -> Expression:
        """Parse additive expression."""
        expr = self._parse_multiplicative_expression()

        while self._match(TokenType.PLUS, TokenType.MINUS):
            operator = self._previous().value
            right = self._parse_multiplicative_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_multiplicative_expression(self) -> Expression:
        """Parse multiplicative expression."""
        expr = self._parse_unary_expression()

        while self._match(TokenType.MULTIPLY, TokenType.DIVIDE, TokenType.MODULO):
            operator = self._previous().value
            right = self._parse_unary_expression()
            expr = BinaryExpression(left=expr, operator=operator, right=right)

        return expr

    def _parse_unary_expression(self) -> Expression:
        """Parse unary expression."""
        if self._match(TokenType.MINUS, TokenType.BITWISE_NOT):
            operator = self._previous().value
            operand = self._parse_unary_expression()
            return UnaryExpression(operator=operator, operand=operand)

        if self._match(TokenType.DEFINED):
            operand = self._parse_postfix_expression()
            return DefinedExpression(expression=operand)

        return self._parse_postfix_expression()

    def _parse_postfix_expression(self) -> Expression:
        """Parse postfix expression."""
        expr = self._parse_primary_expression()

        while True:
            if self._match(TokenType.DOT):
                if not self._match(TokenType.IDENTIFIER):
                    msg = "Expected member name after '.'"
                    raise ParserError(msg, self._peek())
                member = self._previous().value
                expr = MemberAccess(object=expr, member=member)
            elif self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise ParserError(msg, self._peek())
                # Check if this is dictionary access (string key) or array access (numeric)
                if isinstance(index, StringLiteral):
                    expr = DictionaryAccess(object=expr, key=index.value)
                else:
                    expr = ArrayAccess(array=expr, index=index)
            elif self._match(TokenType.LPAREN):
                # Function call
                args = []
                while not self._check(TokenType.RPAREN) and not self._is_at_end():
                    args.append(self._parse_expression())
                    if not self._match(TokenType.COMMA):
                        break

                if not self._match(TokenType.RPAREN):
                    msg = "Expected ')' after arguments"
                    raise ParserError(msg, self._peek())

                # Handle different types of function calls
                if isinstance(expr, Identifier):
                    expr = FunctionCall(function=expr.name, arguments=args)
                elif isinstance(expr, MemberAccess):
                    # Module function call like pe.imphash()
                    if isinstance(expr.object, Identifier):
                        function_name = f"{expr.object.name}.{expr.member}"
                    elif isinstance(expr.object, ModuleReference):
                        function_name = f"{expr.object.module}.{expr.member}"
                    elif isinstance(expr.object, MemberAccess):
                        # Nested member access like obj.subobj.func()
                        function_name = (
                            f"{self._member_access_to_string(expr.object)}.{expr.member}"
                        )
                    else:
                        function_name = f"unknown.{expr.member}"
                    expr = FunctionCall(function=function_name, arguments=args)
                else:
                    msg = "Invalid function call"
                    raise ParserError(msg, self._peek())
            elif self._match(TokenType.AT):
                # At expression: $string at offset
                if isinstance(expr, StringIdentifier):
                    offset = self._parse_additive_expression()
                    expr = AtExpression(string_id=expr.name, offset=offset)
                else:
                    msg = "AT keyword can only be used with string identifiers"
                    raise ParserError(msg, self._peek())
            elif self._match(TokenType.IN):
                # In expression: $string in range OR all of ($a*) in range
                if isinstance(expr, StringIdentifier):
                    range_expr = self._parse_additive_expression()
                    expr = InExpression(subject=expr.name, range=range_expr)
                elif isinstance(expr, OfExpression):
                    # Support: all of ($a*) in (0..100)
                    range_expr = self._parse_additive_expression()
                    expr = InExpression(subject=expr, range=range_expr)
                else:
                    msg = "IN keyword can only be used with string identifiers or 'of' expressions"
                    raise ParserError(msg, self._peek())
            else:
                break

        return expr

    def _parse_primary_expression(self) -> Expression:
        """Parse primary expression."""
        # Check for numeric quantifiers BEFORE parsing simple integers
        # This handles patterns like "7 of them" or "3 of ($a*)"
        if self._check(TokenType.INTEGER):
            # Peek ahead to see if this is a quantifier
            saved_pos = self.current
            self._advance()
            quantifier_value = self._previous().value

            if self._match(TokenType.OF):
                # It's a numeric quantifier expression
                # Parse the string set without consuming IN/AT operators
                string_set = self._parse_of_string_set()
                return OfExpression(
                    quantifier=IntegerLiteral(value=quantifier_value),
                    string_set=string_set,
                )
            # Not a quantifier, backtrack and parse as normal integer
            self.current = saved_pos

        # Literals
        if self._match(TokenType.INTEGER):
            return IntegerLiteral(value=self._previous().value)

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
            regex_val = self._previous().value
            pattern = regex_val
            modifiers = ""

            # The lexer returns pattern or pattern\x00modifiers
            if "\x00" in regex_val:
                parts = regex_val.split("\x00", 1)
                pattern = parts[0]
                modifiers = parts[1] if len(parts) > 1 else ""

            return RegexLiteral(pattern=pattern, modifiers=modifiers)

        # String references
        if self._match(TokenType.STRING_IDENTIFIER):
            name = self._previous().value
            if name.endswith("*"):
                return StringWildcard(pattern=name)
            return StringIdentifier(name=name)

        if self._match(TokenType.STRING_COUNT):
            return StringCount(string_id=self._previous().value[1:])  # Remove #

        if self._match(TokenType.STRING_OFFSET):
            string_id = self._previous().value[1:]  # Remove @
            index = None
            if self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise ParserError(msg, self._peek())
            return StringOffset(string_id=string_id, index=index)

        if self._match(TokenType.STRING_LENGTH):
            string_id = self._previous().value[1:]  # Remove !
            index = None
            if self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise ParserError(msg, self._peek())
            return StringLength(string_id=string_id, index=index)

        # Keywords
        if self._match(TokenType.FILESIZE):
            return Identifier(name="filesize")

        if self._match(TokenType.ENTRYPOINT):
            return Identifier(name="entrypoint")

        if self._match(TokenType.THEM):
            return Identifier(name="them")

        # Identifiers
        if self._match(TokenType.IDENTIFIER):
            name = self._previous().value
            # Check if it's a known module
            if name in [
                "pe",
                "elf",
                "math",
                "dotnet",
                "cuckoo",
                "magic",
                "hash",
                "console",
                "string",
                "time",
                "vt",
            ]:
                return ModuleReference(module=name)
            return Identifier(name=name)

        # Parentheses
        if self._match(TokenType.LPAREN):
            # Check for set expression
            exprs = [self._parse_expression()]

            if self._match(TokenType.COMMA):
                # It's a set
                while not self._check(TokenType.RPAREN) and not self._is_at_end():
                    exprs.append(self._parse_expression())
                    if not self._match(TokenType.COMMA):
                        break

                if not self._match(TokenType.RPAREN):
                    msg = "Expected ')' after set elements"
                    raise ParserError(msg, self._peek())

                return SetExpression(elements=exprs)
            # It's a parenthesized expression
            if not self._match(TokenType.RPAREN):
                msg = "Expected ')' after expression"
                raise ParserError(msg, self._peek())

            # Check if this is a quantifier expression like "(2+3) of them"
            if self._match(TokenType.OF):
                # Parse the string set without consuming IN/AT operators
                string_set = self._parse_of_string_set()
                return OfExpression(
                    quantifier=exprs[0],
                    string_set=string_set,
                )

            return ParenthesesExpression(expression=exprs[0])

        # Range
        if self._check(TokenType.INTEGER) or self._check(TokenType.IDENTIFIER):
            expr = self._parse_expression()
            if self._match(TokenType.DOUBLE_DOT):
                high = self._parse_expression()
                return RangeExpression(low=expr, high=high)
            return expr

        # Special expressions
        if self._match(TokenType.FOR):
            return self._parse_for_expression()

        if self._match(TokenType.ANY, TokenType.ALL):
            quantifier = self._previous().value
            if self._match(TokenType.OF):
                return self._parse_of_expression(quantifier)

        # String operations
        if self._check(TokenType.STRING_IDENTIFIER):
            string_id = self._advance().value

            if self._match(TokenType.AT):
                offset = self._parse_expression()
                return AtExpression(string_id=string_id, offset=offset)

            if self._match(TokenType.IN):
                range_expr = self._parse_expression()
                return InExpression(subject=string_id, range=range_expr)

            # Otherwise it's just a string identifier or wildcard
            if string_id.endswith("*"):
                return StringWildcard(pattern=string_id)
            return StringIdentifier(name=string_id)

        msg = f"Unexpected token: {self._peek().value}"
        raise ParserError(msg, self._peek())

    def _parse_for_expression(self) -> ForExpression:
        """Parse for expression."""
        # Parse quantifier
        if self._match(TokenType.ANY):
            quantifier = "any"
        elif self._match(TokenType.ALL):
            quantifier = "all"
        elif self._match(TokenType.INTEGER):
            quantifier = str(self._previous().value)
        else:
            msg = "Expected quantifier after 'for'"
            raise ParserError(msg, self._peek())

        # Check for 'of' (for...of expression)
        if self._match(TokenType.OF):
            return self._parse_for_of_expression(quantifier)

        # Otherwise it's a regular for expression
        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected variable name"
            raise ParserError(msg, self._peek())

        variable = self._previous().value

        if not self._match(TokenType.IN):
            msg = "Expected 'in' after variable"
            raise ParserError(msg, self._peek())

        iterable = self._parse_expression()

        if not self._match(TokenType.COLON):
            msg = "Expected ':' after iterable"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.LPAREN):
            msg = "Expected '(' after ':'"
            raise ParserError(msg, self._peek())

        body = self._parse_expression()

        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after for body"
            raise ParserError(msg, self._peek())

        return ForExpression(
            quantifier=quantifier,
            variable=variable,
            iterable=iterable,
            body=body,
        )

    def _parse_for_of_expression(self, quantifier: str) -> ForOfExpression:
        """Parse for...of expression."""
        string_set = self._parse_expression()

        condition = None
        if self._match(TokenType.COLON) and self._match(TokenType.LPAREN):
            condition = self._parse_expression()
            if not self._match(TokenType.RPAREN):
                msg = "Expected ')' after condition"
                raise ParserError(msg, self._peek())

        return ForOfExpression(
            quantifier=quantifier,
            string_set=string_set,
            condition=condition,
        )

    def _parse_of_expression(self, quantifier: str) -> OfExpression:
        """Parse of expression."""
        # Parse the string set but don't consume IN/AT operators that should apply to the whole OfExpression
        string_set = self._parse_of_string_set()
        return OfExpression(
            quantifier=StringLiteral(value=quantifier),
            string_set=string_set,
        )

    def _parse_of_string_set(self) -> Expression:
        """Parse string set for 'of' expression without consuming IN/AT postfix operators."""
        expr = self._parse_primary_expression()

        # Only allow member access, array access, and function calls
        # Do NOT allow IN or AT here - those should apply to the whole OfExpression
        while True:
            if self._match(TokenType.DOT):
                if not self._match(TokenType.IDENTIFIER):
                    msg = "Expected member name after '.'"
                    raise ParserError(msg, self._peek())
                member = self._previous().value
                expr = MemberAccess(object=expr, member=member)
            elif self._match(TokenType.LBRACKET):
                index = self._parse_expression()
                if not self._match(TokenType.RBRACKET):
                    msg = "Expected ']'"
                    raise ParserError(msg, self._peek())
                # Check if this is dictionary access (string key) or array access (numeric)
                if isinstance(index, StringLiteral):
                    expr = DictionaryAccess(object=expr, key=index.value)
                else:
                    expr = ArrayAccess(array=expr, index=index)
            elif self._match(TokenType.LPAREN):
                # Function call
                args = []
                while not self._check(TokenType.RPAREN) and not self._is_at_end():
                    args.append(self._parse_expression())
                    if not self._match(TokenType.COMMA):
                        break

                if not self._match(TokenType.RPAREN):
                    msg = "Expected ')' after arguments"
                    raise ParserError(msg, self._peek())

                # Handle different types of function calls
                if isinstance(expr, Identifier):
                    expr = FunctionCall(function=expr.name, arguments=args)
                elif isinstance(expr, MemberAccess):
                    # Module function call like pe.imphash()
                    if isinstance(expr.object, Identifier):
                        function_name = f"{expr.object.name}.{expr.member}"
                    elif isinstance(expr.object, ModuleReference):
                        function_name = f"{expr.object.module}.{expr.member}"
                    elif isinstance(expr.object, MemberAccess):
                        # Nested member access like obj.subobj.func()
                        function_name = (
                            f"{self._member_access_to_string(expr.object)}.{expr.member}"
                        )
                    else:
                        function_name = f"unknown.{expr.member}"
                    expr = FunctionCall(function=function_name, arguments=args)
                else:
                    msg = "Invalid function call"
                    raise ParserError(msg, self._peek())
            else:
                # Don't consume IN or AT - let them be handled by the caller
                break

        return expr

    def _parse_expression(self) -> Expression:
        """Parse general expression."""
        return self._parse_or_expression()

    # Helper methods
    def _member_access_to_string(self, expr: MemberAccess) -> str:
        """Convert MemberAccess to string representation."""
        if isinstance(expr.object, Identifier):
            return f"{expr.object.name}.{expr.member}"
        if isinstance(expr.object, ModuleReference):
            return f"{expr.object.module}.{expr.member}"
        if isinstance(expr.object, MemberAccess):
            return f"{self._member_access_to_string(expr.object)}.{expr.member}"
        return f"unknown.{expr.member}"

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
        return self._peek().type == token_type

    def _check_any(self, *types: TokenType) -> bool:
        """Check if current token matches any of the given types."""
        return any(self._check(t) for t in types)

    def _advance(self) -> Token:
        """Consume current token and return it."""
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _is_at_end(self) -> bool:
        """Check if we're at end of tokens."""
        return self._peek().type == TokenType.EOF

    def _peek(self) -> Token:
        """Return current token without advancing."""
        return self.tokens[self.current]

    def _previous(self) -> Token:
        """Return previous token."""
        return self.tokens[self.current - 1]
