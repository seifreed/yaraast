"""Fluent builder for YARA rules."""

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
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder


class RuleBuilder:
    """Fluent builder for constructing YARA rules."""

    def __init__(self):
        self._name: Optional[str] = None
        self._modifiers: List[str] = []
        self._tags: List[str] = []
        self._meta: Dict[str, Any] = {}
        self._strings: List[StringDefinition] = []
        self._condition: Optional[Expression] = None

    def with_name(self, name: str) -> Self:
        """Set the rule name."""
        self._name = name
        return self

    def private(self) -> Self:
        """Mark rule as private."""
        if "private" not in self._modifiers:
            self._modifiers.append("private")
        return self

    def global_(self) -> Self:
        """Mark rule as global."""
        if "global" not in self._modifiers:
            self._modifiers.append("global")
        return self

    def with_tag(self, tag: str) -> Self:
        """Add a tag to the rule."""
        self._tags.append(tag)
        return self

    def with_regex_string(self, identifier: str, pattern: str, **modifiers) -> Self:
        """Add a regex string with modifiers."""
        mod_list = [StringModifier(name=k) for k, v in modifiers.items() if v]
        self._strings.append(RegexString(
            identifier=identifier,
            regex=pattern,
            modifiers=mod_list
        ))
        return self

    def with_tags(self, *tags: str) -> Self:
        """Add multiple tags to the rule."""
        self._tags.extend(tags)
        return self

    def with_meta(self, key: str, value: Union[str, int, bool]) -> Self:
        """Add a meta field."""
        self._meta[key] = value
        return self

    def with_author(self, author: str) -> Self:
        """Add author meta field."""
        return self.with_meta("author", author)

    def with_description(self, description: str) -> Self:
        """Add description meta field."""
        return self.with_meta("description", description)

    def with_version(self, version: int) -> Self:
        """Add version meta field."""
        return self.with_meta("version", version)

    def with_plain_string(self, identifier: str, value: str,
                         nocase: bool = False, wide: bool = False,
                         ascii: bool = False, fullword: bool = False) -> Self:
        """Add a plain string."""
        modifiers = []
        if nocase:
            modifiers.append(StringModifier(name="nocase"))
        if wide:
            modifiers.append(StringModifier(name="wide"))
        if ascii:
            modifiers.append(StringModifier(name="ascii"))
        if fullword:
            modifiers.append(StringModifier(name="fullword"))

        self._strings.append(PlainString(
            identifier=identifier,
            value=value,
            modifiers=modifiers
        ))
        return self

    def with_hex_string(self, identifier: str, builder: HexStringBuilder) -> Self:
        """Add a hex string using a builder."""
        self._strings.append(HexString(
            identifier=identifier,
            tokens=builder.build(),
            modifiers=[]
        ))
        return self

    def with_hex_string_raw(self, identifier: str, hex_pattern: str) -> Self:
        """Add a hex string from raw pattern."""
        # Parse hex pattern - simplified version
        tokens = []
        i = 0
        hex_chars = hex_pattern.replace(" ", "").upper()

        while i < len(hex_chars):
            if i + 1 < len(hex_chars) and hex_chars[i:i+2] == "??":
                tokens.append(HexWildcard())
                i += 2
            elif i + 1 < len(hex_chars):
                try:
                    byte_val = int(hex_chars[i:i+2], 16)
                    tokens.append(HexByte(value=byte_val))
                    i += 2
                except ValueError:
                    i += 1
            else:
                i += 1

        self._strings.append(HexString(
            identifier=identifier,
            tokens=tokens,
            modifiers=[]
        ))
        return self

    def with_regex(self, identifier: str, pattern: str,
                   case_insensitive: bool = False,
                   dotall: bool = False,
                   multiline: bool = False) -> Self:
        """Add a regex string."""
        # Add modifiers to pattern
        if case_insensitive or dotall or multiline:
            modifiers = ""
            if case_insensitive:
                modifiers += "i"
            if dotall:
                modifiers += "s"
            if multiline:
                modifiers += "m"
            pattern = pattern + modifiers

        self._strings.append(RegexString(
            identifier=identifier,
            regex=pattern,
            modifiers=[]
        ))
        return self

    def with_condition(self, condition: Union[Expression, ConditionBuilder, str]) -> Self:
        """Set the rule condition."""
        if isinstance(condition, str):
            # Simple conditions
            if condition == "true":
                self._condition = BooleanLiteral(value=True)
            elif condition == "false":
                self._condition = BooleanLiteral(value=False)
            elif condition == "any of them":
                self._condition = OfExpression(
                    quantifier=StringLiteral(value="any"),
                    string_set=Identifier(name="them")
                )
            elif condition == "all of them":
                self._condition = OfExpression(
                    quantifier=StringLiteral(value="all"),
                    string_set=Identifier(name="them")
                )
            elif condition.startswith("$"):
                self._condition = StringIdentifier(name=condition)
            else:
                # For complex conditions, would need a parser
                self._condition = Identifier(name=condition)
        elif isinstance(condition, ConditionBuilder):
            self._condition = condition.build()
        else:
            self._condition = condition

        return self

    def with_condition_lambda(self, builder_func) -> Self:
        """Set condition using a lambda that receives a ConditionBuilder."""
        cb = ConditionBuilder()
        self._condition = builder_func(cb).build()
        return self

    def build(self) -> Rule:
        """Build the Rule AST node."""
        if not self._name:
            raise ValueError("Rule name is required")

        if not self._condition:
            # Default to true if no condition
            self._condition = BooleanLiteral(value=True)

        return Rule(
            name=self._name,
            modifiers=self._modifiers,
            tags=[Tag(name=tag) for tag in self._tags],
            meta=self._meta,
            strings=self._strings,
            condition=self._condition
        )
