"""Pragma and directive support for YARA AST."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from yaraast.ast.base import ASTNode


class PragmaType(Enum):
    """Types of pragma directives."""

    # Compiler directives
    INCLUDE_ONCE = "include_once"
    PRAGMA = "pragma"
    DEFINE = "define"
    UNDEF = "undef"

    # Conditional compilation
    IFDEF = "ifdef"
    IFNDEF = "ifndef"
    ENDIF = "endif"

    # Custom pragmas
    CUSTOM = "custom"

    @classmethod
    def from_string(cls, pragma_str: str) -> PragmaType:
        """Convert string to pragma type."""
        try:
            return cls(pragma_str.lower())
        except ValueError:
            return cls.CUSTOM


class PragmaScope(Enum):
    """Scope where pragma applies."""

    FILE = "file"  # File-level pragma
    RULE = "rule"  # Rule-level pragma
    BLOCK = "block"  # Block-level pragma
    LOCAL = "local"  # Local scope pragma


@dataclass
class Pragma(ASTNode):
    """Base pragma/directive node."""

    pragma_type: PragmaType
    name: str
    arguments: list[str] = field(default_factory=list)
    scope: PragmaScope = PragmaScope.FILE

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_pragma(self)

    @property
    def is_include_once(self) -> bool:
        """Check if this is an include_once pragma."""
        return self.pragma_type == PragmaType.INCLUDE_ONCE

    @property
    def is_define(self) -> bool:
        """Check if this is a define pragma."""
        return self.pragma_type == PragmaType.DEFINE

    def __str__(self) -> str:
        """String representation of pragma."""
        args_str = " " + " ".join(self.arguments) if self.arguments else ""

        if self.pragma_type == PragmaType.PRAGMA:
            return f"#pragma {self.name}{args_str}"
        return f"#{self.name}{args_str}"


@dataclass
class IncludeOncePragma(Pragma):
    """Include-once pragma to prevent multiple inclusions."""

    def __init__(self) -> None:
        super().__init__(
            pragma_type=PragmaType.INCLUDE_ONCE,
            name="include_once",
            scope=PragmaScope.FILE,
        )

    def __str__(self) -> str:
        return "#include_once"


@dataclass
class DefineDirective(Pragma):
    """Define directive for macro definitions."""

    macro_name: str = ""
    macro_value: str | None = None

    def __init__(self, macro_name: str, macro_value: str | None = None) -> None:
        super().__init__(
            pragma_type=PragmaType.DEFINE,
            name="define",
            arguments=[macro_name] + ([macro_value] if macro_value else []),
        )
        self.macro_name = macro_name
        self.macro_value = macro_value

    def __str__(self) -> str:
        if self.macro_value:
            return f"#define {self.macro_name} {self.macro_value}"
        return f"#define {self.macro_name}"


@dataclass
class UndefDirective(Pragma):
    """Undefine directive for removing macro definitions."""

    macro_name: str = ""

    def __init__(self, macro_name: str) -> None:
        super().__init__(
            pragma_type=PragmaType.UNDEF,
            name="undef",
            arguments=[macro_name],
        )
        self.macro_name = macro_name

    def __str__(self) -> str:
        return f"#undef {self.macro_name}"


@dataclass
class ConditionalDirective(Pragma):
    """Conditional compilation directives (ifdef, ifndef, endif)."""

    condition: str | None = None

    def __init__(self, pragma_type: PragmaType, condition: str | None = None) -> None:
        name = pragma_type.value
        args = [condition] if condition else []
        super().__init__(pragma_type=pragma_type, name=name, arguments=args)
        self.condition = condition

    @classmethod
    def ifdef(cls, condition: str) -> ConditionalDirective:
        """Create an ifdef directive."""
        return cls(PragmaType.IFDEF, condition)

    @classmethod
    def ifndef(cls, condition: str) -> ConditionalDirective:
        """Create an ifndef directive."""
        return cls(PragmaType.IFNDEF, condition)

    @classmethod
    def endif(cls) -> ConditionalDirective:
        """Create an endif directive."""
        return cls(PragmaType.ENDIF)

    def __str__(self) -> str:
        if self.condition:
            return f"#{self.pragma_type.value} {self.condition}"
        return f"#{self.pragma_type.value}"


@dataclass
class CustomPragma(Pragma):
    """Custom pragma for vendor-specific or extended functionality."""

    parameters: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        name: str,
        arguments: list[str] | None = None,
        parameters: dict[str, Any] | None = None,
        scope: PragmaScope = PragmaScope.FILE,
    ) -> None:
        super().__init__(
            pragma_type=PragmaType.CUSTOM,
            name=name,
            arguments=arguments or [],
            scope=scope,
        )
        self.parameters = parameters or {}

    def get_parameter(self, key: str, default: Any = None) -> Any:
        """Get a parameter value by key."""
        return self.parameters.get(key, default)

    def set_parameter(self, key: str, value: Any) -> None:
        """Set a parameter value."""
        self.parameters[key] = value

    def __str__(self) -> str:
        args_str = " " + " ".join(self.arguments) if self.arguments else ""
        return f"#pragma {self.name}{args_str}"


@dataclass
class InRulePragma(ASTNode):
    """Pragma that appears within a rule definition."""

    pragma: Pragma
    position: str = "before_strings"  # "before_strings", "after_strings", "before_condition"

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_in_rule_pragma(self)

    @property
    def is_before_strings(self) -> bool:
        """Check if pragma appears before strings section."""
        return self.position == "before_strings"

    @property
    def is_after_strings(self) -> bool:
        """Check if pragma appears after strings section."""
        return self.position == "after_strings"

    @property
    def is_before_condition(self) -> bool:
        """Check if pragma appears before condition section."""
        return self.position == "before_condition"

    def __str__(self) -> str:
        return str(self.pragma)


@dataclass
class PragmaBlock(ASTNode):
    """Block of pragmas that should be processed together."""

    pragmas: list[Pragma] = field(default_factory=list)
    scope: PragmaScope = PragmaScope.FILE

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_pragma_block(self)

    def add_pragma(self, pragma: Pragma) -> None:
        """Add a pragma to this block."""
        pragma.scope = self.scope
        self.pragmas.append(pragma)

    def get_pragmas_by_type(self, pragma_type: PragmaType) -> list[Pragma]:
        """Get all pragmas of a specific type."""
        return [p for p in self.pragmas if p.pragma_type == pragma_type]

    def has_pragma(self, pragma_type: PragmaType) -> bool:
        """Check if block contains a pragma of specific type."""
        return any(p.pragma_type == pragma_type for p in self.pragmas)

    def __str__(self) -> str:
        return "\n".join(str(pragma) for pragma in self.pragmas)


# Convenience functions for creating pragmas


def create_pragma(
    name: str,
    arguments: list[str] | None = None,
    scope: PragmaScope = PragmaScope.FILE,
) -> Pragma:
    """Create a generic pragma."""
    pragma_type = PragmaType.from_string(name)
    if pragma_type == PragmaType.CUSTOM:
        return CustomPragma(name, arguments, scope=scope)
    return Pragma(pragma_type, name, arguments or [], scope)


def create_include_once() -> IncludeOncePragma:
    """Create an include_once pragma."""
    return IncludeOncePragma()


def create_define(macro_name: str, macro_value: str | None = None) -> DefineDirective:
    """Create a define directive."""
    return DefineDirective(macro_name, macro_value)


def create_undef(macro_name: str) -> UndefDirective:
    """Create an undef directive."""
    return UndefDirective(macro_name)


def create_ifdef(condition: str) -> ConditionalDirective:
    """Create an ifdef directive."""
    return ConditionalDirective.ifdef(condition)


def create_ifndef(condition: str) -> ConditionalDirective:
    """Create an ifndef directive."""
    return ConditionalDirective.ifndef(condition)


def create_endif() -> ConditionalDirective:
    """Create an endif directive."""
    return ConditionalDirective.endif()


def create_in_rule_pragma(
    pragma: Pragma,
    position: str = "before_strings",
) -> InRulePragma:
    """Create an in-rule pragma."""
    return InRulePragma(pragma, position)
