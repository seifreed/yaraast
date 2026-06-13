"""Pragma and directive support for YARA AST."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
import re
from typing import Any

from yaraast.ast.base import ASTNode, _require_nonempty_string, _VisitorType, require_string
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)


def _normalize_arguments(arguments: list[str] | None) -> list[str]:
    if arguments is None:
        return []
    if not isinstance(arguments, list) or not all(
        isinstance(argument, str) for argument in arguments
    ):
        msg = "Pragma arguments must be a list of strings"
        raise TypeError(msg)
    return arguments


def _require_scope(scope: PragmaScope) -> PragmaScope:
    if not isinstance(scope, PragmaScope):
        msg = "Pragma scope must be a PragmaScope"
        raise TypeError(msg)
    return scope


def _validate_pragma_parameter_value(value: Any) -> None:
    if isinstance(value, str | bool | int):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    msg = "Pragma parameter value must be a string, integer, boolean, or finite float"
    raise TypeError(msg)


def _validate_pragma_parameters(parameters: Any) -> None:
    if not isinstance(parameters, dict):
        msg = "Pragma parameters must be a dictionary"
        raise TypeError(msg)
    for key, value in parameters.items():
        if not isinstance(key, str):
            msg = "Pragma parameters keys must be strings"
            raise TypeError(msg)
        _validate_pragma_parameter_value(value)


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
        pragma_text = require_string(pragma_str, "Pragma type input")
        if not pragma_text.strip():
            msg = "Pragma type input cannot be empty"
            raise ValueError(msg)
        try:
            return cls(pragma_text.lower())
        except ValueError:
            return cls.CUSTOM


class PragmaScope(Enum):
    """Scope where pragma applies."""

    FILE = "file"  # File-level pragma
    RULE = "rule"  # Rule-level pragma
    BLOCK = "block"  # Block-level pragma
    LOCAL = "local"  # Local scope pragma


def _require_pragma_type(pragma_type: PragmaType) -> PragmaType:
    if not isinstance(pragma_type, PragmaType):
        msg = "Pragma type must be a PragmaType"
        raise TypeError(msg)
    return pragma_type


def _validate_yara_identifier(name: object, kind: str) -> str:
    if not isinstance(name, str):
        msg = f"{kind.capitalize()} identifier must be a string for libyara output"
        raise TypeError(msg)
    if (
        len(name) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(name) is not None
        and name not in _YARA_KEYWORDS
    ):
        return name
    msg = f"Invalid {kind} identifier '{name}' for libyara output"
    raise ValueError(msg)


@dataclass
class Pragma(ASTNode):
    """Base pragma/directive node."""

    pragma_type: PragmaType
    name: str
    arguments: list[str] = field(default_factory=list)
    scope: PragmaScope = PragmaScope.FILE

    def validate_structure(self) -> None:
        """Validate pragma scalar fields before direct analysis."""
        _require_pragma_type(self.pragma_type)
        _require_nonempty_string(self.name, "Pragma name")
        _validate_yara_identifier(self.name, "pragma")
        _normalize_arguments(self.arguments)
        _require_scope(self.scope)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_pragma(self)

    @property
    def is_include_once(self) -> bool:
        """Check if this is an include_once pragma."""
        return _require_pragma_type(self.pragma_type) == PragmaType.INCLUDE_ONCE

    @property
    def is_define(self) -> bool:
        """Check if this is a define pragma."""
        return _require_pragma_type(self.pragma_type) == PragmaType.DEFINE

    def __str__(self) -> str:
        """String representation of pragma."""
        name = _require_nonempty_string(self.name, "Pragma name")
        arguments = _normalize_arguments(self.arguments)
        args_str = " " + " ".join(arguments) if arguments else ""

        if self.pragma_type == PragmaType.PRAGMA:
            return f"#pragma {name}{args_str}"
        return f"#{name}{args_str}"


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
            arguments=[macro_name] + ([macro_value] if macro_value is not None else []),
        )
        self.macro_name = macro_name
        self.macro_value = macro_value

    def validate_structure(self) -> None:
        """Validate define directive fields before direct analysis."""
        super().validate_structure()
        _require_nonempty_string(self.macro_name, "Pragma macro_name")
        _validate_yara_identifier(self.macro_name, "pragma macro")
        if self.macro_value is not None:
            require_string(self.macro_value, "Pragma macro_value")

    def __str__(self) -> str:
        macro_name = _require_nonempty_string(self.macro_name, "Pragma macro_name")
        if self.macro_value is not None:
            macro_value = require_string(self.macro_value, "Pragma macro_value")
            if macro_value:
                return f"#define {macro_name} {macro_value}"
        return f"#define {macro_name}"


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

    def validate_structure(self) -> None:
        """Validate undef directive fields before direct analysis."""
        super().validate_structure()
        _require_nonempty_string(self.macro_name, "Pragma macro_name")
        _validate_yara_identifier(self.macro_name, "pragma macro")

    def __str__(self) -> str:
        macro_name = _require_nonempty_string(self.macro_name, "Pragma macro_name")
        return f"#undef {macro_name}"


@dataclass
class ConditionalDirective(Pragma):
    """Conditional compilation directives (ifdef, ifndef, endif)."""

    condition: str | None = None

    def __init__(self, pragma_type: PragmaType, condition: str | None = None) -> None:
        name = pragma_type.value
        args = [condition] if condition else []
        super().__init__(pragma_type=pragma_type, name=name, arguments=args)
        self.condition = condition

    def validate_structure(self) -> None:
        """Validate conditional directive fields before direct analysis."""
        super().validate_structure()
        if self.pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}:
            if self.condition is None:
                msg = "Pragma condition must be a string"
                raise TypeError(msg)
            _require_nonempty_string(self.condition, "Pragma condition")
            _validate_yara_identifier(self.condition, "pragma condition")
        elif self.condition is not None:
            require_string(self.condition, "Pragma condition")

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
        if self.pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}:
            condition = _require_nonempty_string(self.condition, "Pragma condition")
            return f"#{self.pragma_type.value} {condition}"
        if self.condition is not None:
            condition = require_string(self.condition, "Pragma condition")
            if condition:
                return f"#{self.pragma_type.value} {condition}"
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
            arguments=arguments if arguments is not None else [],
            scope=scope,
        )
        self.parameters = parameters if parameters is not None else {}

    def validate_structure(self) -> None:
        """Validate custom pragma fields before direct analysis."""
        super().validate_structure()
        _validate_pragma_parameters(self.parameters)

    def get_parameter(self, key: str, default: Any = None) -> Any:
        """Get a parameter value by key."""
        _validate_pragma_parameters(self.parameters)
        return self.parameters.get(require_string(key, "Pragma parameter key"), default)

    def set_parameter(self, key: str, value: Any) -> None:
        """Set a parameter value."""
        _validate_pragma_parameters(self.parameters)
        parameter_key = require_string(key, "Pragma parameter key")
        _validate_pragma_parameter_value(value)
        self.parameters[parameter_key] = value

    def __str__(self) -> str:
        name = _require_nonempty_string(self.name, "Pragma name")
        arguments = _normalize_arguments(self.arguments)
        args_str = " " + " ".join(arguments) if arguments else ""
        return f"#pragma {name}{args_str}"


@dataclass
class InRulePragma(ASTNode):
    """Pragma that appears within a rule definition."""

    pragma: Pragma
    position: str = "before_strings"  # "before_strings", "after_strings", "before_condition"

    def validate_structure(self) -> None:
        """Validate nested pragma and position before direct analysis."""
        self._validated_pragma()
        self._validated_position()

    def _validated_pragma(self) -> Pragma:
        if not isinstance(self.pragma, Pragma):
            msg = "InRulePragma pragma must be a Pragma"
            raise TypeError(msg)
        self.pragma.validate_structure()
        return self.pragma

    def _validated_position(self) -> str:
        return _require_nonempty_string(self.position, "InRulePragma position")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_in_rule_pragma(self)

    @property
    def is_before_strings(self) -> bool:
        """Check if pragma appears before strings section."""
        self._validated_pragma()
        return self._validated_position() == "before_strings"

    @property
    def is_after_strings(self) -> bool:
        """Check if pragma appears after strings section."""
        self._validated_pragma()
        return self._validated_position() == "after_strings"

    @property
    def is_before_condition(self) -> bool:
        """Check if pragma appears before condition section."""
        self._validated_pragma()
        return self._validated_position() == "before_condition"

    def __str__(self) -> str:
        self._validated_position()
        return str(self._validated_pragma())


@dataclass
class PragmaBlock(ASTNode):
    """Block of pragmas that should be processed together."""

    pragmas: list[Pragma] = field(default_factory=list)
    scope: PragmaScope = PragmaScope.FILE

    def validate_structure(self) -> None:
        """Validate block pragma container before direct analysis."""
        self._validated_pragmas()

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_pragma_block(self)

    def add_pragma(self, pragma: Pragma) -> None:
        """Add a pragma to this block."""
        scope = _require_scope(self.scope)
        if not isinstance(pragma, Pragma):
            msg = "Pragma input must be a Pragma"
            raise TypeError(msg)
        pragma.validate_structure()
        pragma.scope = scope
        self.pragmas.append(pragma)

    def get_pragmas_by_type(self, pragma_type: PragmaType) -> list[Pragma]:
        """Get all pragmas of a specific type."""
        pragma_type = _require_pragma_type(pragma_type)
        return [p for p in self._validated_pragmas() if p.pragma_type == pragma_type]

    def has_pragma(self, pragma_type: PragmaType) -> bool:
        """Check if block contains a pragma of specific type."""
        pragma_type = _require_pragma_type(pragma_type)
        return any(p.pragma_type == pragma_type for p in self._validated_pragmas())

    def __str__(self) -> str:
        return "\n".join(str(pragma) for pragma in self._validated_pragmas())

    def _validated_pragmas(self) -> list[Pragma]:
        if not isinstance(self.pragmas, list | tuple):
            msg = "PragmaBlock pragmas must be a list or tuple"
            raise TypeError(msg)
        _require_scope(self.scope)
        pragmas = []
        for pragma in self.pragmas:
            if not isinstance(pragma, Pragma):
                msg = "PragmaBlock pragmas must contain Pragma nodes"
                raise TypeError(msg)
            pragma.validate_structure()
            pragmas.append(pragma)
        return pragmas


# Convenience functions for creating pragmas


def create_pragma(
    name: str,
    arguments: list[str] | None = None,
    scope: PragmaScope = PragmaScope.FILE,
) -> Pragma:
    """Create a generic pragma."""
    pragma_name = require_string(name, "Pragma name")
    pragma_arguments = _normalize_arguments(arguments)
    pragma_scope = _require_scope(scope)
    pragma_type = PragmaType.from_string(pragma_name)
    if pragma_type == PragmaType.CUSTOM:
        return CustomPragma(pragma_name, pragma_arguments, scope=pragma_scope)
    return Pragma(pragma_type, pragma_name, pragma_arguments, pragma_scope)


def create_include_once() -> IncludeOncePragma:
    """Create an include_once pragma."""
    return IncludeOncePragma()


def create_define(macro_name: str, macro_value: str | None = None) -> DefineDirective:
    """Create a define directive."""
    validated_macro_name = _require_nonempty_string(macro_name, "Pragma macro_name")
    if macro_value is not None:
        macro_value = require_string(macro_value, "Pragma macro_value")
    return DefineDirective(validated_macro_name, macro_value)


def create_undef(macro_name: str) -> UndefDirective:
    """Create an undef directive."""
    return UndefDirective(_require_nonempty_string(macro_name, "Pragma macro_name"))


def create_ifdef(condition: str) -> ConditionalDirective:
    """Create an ifdef directive."""
    return ConditionalDirective.ifdef(_require_nonempty_string(condition, "Pragma condition"))


def create_ifndef(condition: str) -> ConditionalDirective:
    """Create an ifndef directive."""
    return ConditionalDirective.ifndef(_require_nonempty_string(condition, "Pragma condition"))


def create_endif() -> ConditionalDirective:
    """Create an endif directive."""
    return ConditionalDirective.endif()


def create_in_rule_pragma(
    pragma: Pragma,
    position: str = "before_strings",
) -> InRulePragma:
    """Create an in-rule pragma."""
    if not isinstance(pragma, Pragma):
        msg = "InRulePragma pragma must be a Pragma"
        raise TypeError(msg)
    return InRulePragma(
        pragma,
        _require_nonempty_string(position, "InRulePragma position"),
    )
