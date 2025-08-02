"""Fluent builder for YARA files."""

from typing import Any, Dict, List, Optional, Self, Set, Tuple, Union

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)
from yaraast.builder.rule_builder import RuleBuilder


class YaraFileBuilder:
    """Fluent builder for constructing YARA files."""

    def __init__(self):
        self._imports: List[str] = []
        self._includes: List[str] = []
        self._rules: List[Rule] = []

    def with_import(self, module: str) -> Self:
        """Add an import."""
        self._imports.append(module)
        return self

    def with_imports(self, *modules: str) -> Self:
        """Add multiple imports."""
        self._imports.extend(modules)
        return self

    def with_include(self, path: str) -> Self:
        """Add an include."""
        self._includes.append(path)
        return self

    def with_includes(self, *paths: str) -> Self:
        """Add multiple includes."""
        self._includes.extend(paths)
        return self

    def with_rule(self, rule: Union[Rule, RuleBuilder]) -> Self:
        """Add a rule."""
        if isinstance(rule, RuleBuilder):
            rule = rule.build()
        self._rules.append(rule)
        return self

    def with_rule_builder(self, builder_func) -> Self:
        """Add a rule using a builder function."""
        builder = RuleBuilder()
        builder_func(builder)
        self._rules.append(builder.build())
        return self

    def with_rules(self, *rules: Union[Rule, RuleBuilder]) -> Self:
        """Add multiple rules."""
        for rule in rules:
            self.with_rule(rule)
        return self

    def build(self) -> YaraFile:
        """Build the YaraFile AST node."""
        return YaraFile(
            imports=[Import(module=module) for module in self._imports],
            includes=[Include(path=path) for path in self._includes],
            rules=self._rules
        )

    # Convenience static methods
    @staticmethod
    def create() -> 'YaraFileBuilder':
        """Create a new file builder."""
        return YaraFileBuilder()

    @staticmethod
    def from_rules(*rules: Union[Rule, RuleBuilder]) -> YaraFile:
        """Create a YARA file from rules."""
        builder = YaraFileBuilder()
        builder.with_rules(*rules)
        return builder.build()
