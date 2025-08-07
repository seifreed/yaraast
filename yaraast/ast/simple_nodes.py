"""Simple AST nodes without dataclass complexity."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ASTNode(ABC):
    """Base class for all AST nodes."""

    def __init__(self, **kwargs) -> None:
        self.location = kwargs.get("location")

    @abstractmethod
    def accept(self, visitor: Any) -> Any:
        """Accept a visitor for the visitor pattern."""


class Expression(ASTNode):
    """Base class for expressions."""

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_expression(self)


class StringIdentifier(Expression):
    """String identifier like $a."""

    def __init__(self, name: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.name = name

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_identifier(self)


class BooleanLiteral(Expression):
    """Boolean literal."""

    def __init__(self, value: bool, **kwargs) -> None:
        super().__init__(**kwargs)
        self.value = value

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_boolean_literal(self)


class IntegerLiteral(Expression):
    """Integer literal."""

    def __init__(self, value: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.value = value

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_integer_literal(self)


class Identifier(Expression):
    """Generic identifier."""

    def __init__(self, name: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.name = name

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_identifier(self)


class BinaryExpression(Expression):
    """Binary expression."""

    def __init__(self, left: Expression, operator: str, right: Expression, **kwargs) -> None:
        super().__init__(**kwargs)
        self.left = left
        self.operator = operator
        self.right = right

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_binary_expression(self)


class Tag(ASTNode):
    """Rule tag."""

    def __init__(self, name: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.name = name

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_tag(self)


class StringModifier(ASTNode):
    """String modifier."""

    def __init__(self, name: str, value: Any = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.name = name
        self.value = value

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_modifier(self)


class StringDefinition(ASTNode):
    """Base string definition."""

    def __init__(
        self,
        identifier: str,
        modifiers: list[StringModifier] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.identifier = identifier
        self.modifiers = modifiers or []

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_definition(self)


class PlainString(StringDefinition):
    """Plain string."""

    def __init__(
        self,
        identifier: str,
        value: str,
        modifiers: list[StringModifier] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(identifier, modifiers, **kwargs)
        self.value = value

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_plain_string(self)


class HexToken(ASTNode):
    """Base hex token."""

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_hex_token(self)


class HexByte(HexToken):
    """Hex byte."""

    def __init__(self, value: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.value = value

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_hex_byte(self)


class HexWildcard(HexToken):
    """Hex wildcard."""

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_hex_wildcard(self)


class HexString(StringDefinition):
    """Hex string."""

    def __init__(
        self,
        identifier: str,
        tokens: list[HexToken],
        modifiers: list[StringModifier] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(identifier, modifiers, **kwargs)
        self.tokens = tokens

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_hex_string(self)


class RegexString(StringDefinition):
    """Regex string."""

    def __init__(
        self,
        identifier: str,
        regex: str,
        modifiers: list[StringModifier] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(identifier, modifiers, **kwargs)
        self.regex = regex

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_regex_string(self)


class Rule(ASTNode):
    """YARA rule."""

    def __init__(
        self,
        name: str,
        modifiers: list[str] | None = None,
        tags: list[Tag] | None = None,
        meta: dict[str, Any] | None = None,
        strings: list[StringDefinition] | None = None,
        condition: Expression | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.name = name
        self.modifiers = modifiers or []
        self.tags = tags or []
        self.meta = meta or {}
        self.strings = strings or []
        self.condition = condition

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_rule(self)
