"""Fluent builder for YARA rules."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
import re
from typing import TYPE_CHECKING, Any, Self

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Expression,
    Identifier,
    StringIdentifier,
    StringLiteral,
)
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import (
    HexString,
    HexToken,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.file_builder_validation import validate_version_value
from yaraast.builder.hex_validation import validate_hex_tokens_for_builder
from yaraast.builder.string_identifier_validation import validate_new_string_definitions
from yaraast.errors import ValidationError, YaraASTError
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH
from yaraast.parser.hex_parser import HexParseError, HexStringParser

if TYPE_CHECKING:
    from yaraast.builder.hex_string_builder import HexStringBuilder


_SIMPLE_STRING_IDENTIFIER_RE = re.compile(r"^\$[A-Za-z0-9_]+$")
_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)
_YARA_CONTEXTUAL_IDENTIFIER_KEYWORDS = frozenset({"as", "include"})
_YARA_CONTEXTUAL_IDENTIFIER_KINDS = frozenset({"meta", "rule", "tag"})


def _parse_condition_text(condition: str) -> Expression:
    from yaraast.parser.parser import Parser

    try:
        ast = Parser(f"rule __condition_probe {{ condition: {condition} }}").parse()
    except YaraASTError as exc:
        msg = f"Invalid condition expression: {condition}"
        raise ValidationError(msg) from exc

    parsed_condition = ast.rules[0].condition if ast.rules else None
    if parsed_condition is None:
        msg = f"Invalid condition expression: {condition}"
        raise ValidationError(msg)
    return parsed_condition


def _validated_condition(condition: Expression) -> Expression:
    validate_structure = getattr(condition, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()
    return condition


def _validate_yara_identifier(name: str, kind: str) -> None:
    if not isinstance(name, str):
        msg = f"Invalid {kind} identifier: {name}"
        raise TypeError(msg)
    keyword_allowed = (
        kind in _YARA_CONTEXTUAL_IDENTIFIER_KINDS and name in _YARA_CONTEXTUAL_IDENTIFIER_KEYWORDS
    )
    if (
        len(name) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(name) is not None
        and (name not in _YARA_KEYWORDS or keyword_allowed)
    ):
        return
    msg = f"Invalid {kind} identifier: {name}"
    raise ValidationError(msg)


def _validate_rule_identifier(name: str) -> None:
    _validate_yara_identifier(name, "rule")


def _validate_tag_identifier(tag: str) -> None:
    _validate_yara_identifier(tag, "tag")


def _validate_new_tags(existing: list[str], tags: tuple[str, ...]) -> None:
    seen = set(existing)
    for tag in tags:
        _validate_tag_identifier(tag)
        if tag in seen:
            msg = f"Duplicate tag identifier: {tag}"
            raise ValidationError(msg)
        seen.add(tag)


def _validate_meta_identifier(key: str) -> None:
    _validate_yara_identifier(key, "meta")


def _validate_meta_value(value: object) -> None:
    if isinstance(value, str | bool | int):
        return
    msg = f"Invalid meta value: {value}"
    raise TypeError(msg)


def _validate_text_value(value: object, field: str) -> str:
    if isinstance(value, str):
        return value
    msg = f"{field} must be a string"
    raise TypeError(msg)


def _coerce_plain_string_value(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if isinstance(value, str):
        return value
    msg = "Plain string value must be a string or bytes"
    raise TypeError(msg)


def _validate_regex_pattern(pattern: object) -> str:
    if isinstance(pattern, str):
        return pattern
    msg = "Regex pattern must be a string"
    raise TypeError(msg)


def _validate_hex_pattern(pattern: object) -> str:
    if isinstance(pattern, str):
        return pattern
    msg = "Hex pattern must be a string"
    raise TypeError(msg)


def _require_bool_flag(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        msg = f"RuleBuilder {name} flag must be a boolean"
        raise TypeError(msg)
    return value


class RuleBuilder:
    """Fluent builder for constructing YARA rules programmatically.

    Examples:
        >>> from yaraast.builder.rule_builder import RuleBuilder
        >>> rule = (RuleBuilder()
        ...     .with_name("detect_malware")
        ...     .with_tag("apt")
        ...     .with_meta("author", "analyst")
        ...     .with_plain_string("$s1", "malicious")
        ...     .with_condition("any of them")
        ...     .build())
        >>> rule.name
        'detect_malware'
    """

    def __init__(self, name: str | None = None) -> None:
        self._name: str | None = None
        self._modifiers: list[RuleModifier] = []
        self._tags: list[str] = []
        self._meta: dict[str, Any] = {}
        self._strings: list[StringDefinition] = []
        self._condition: Expression | None = None
        self._require_condition: bool = False
        if name is not None:
            self.with_name(name)

    def with_name(self, name: str) -> Self:
        """Set the rule name."""
        _validate_rule_identifier(name)
        self._name = name
        return self

    def private(self) -> Self:
        """Mark rule as private."""
        if not any(mod.name == "private" for mod in self._modifiers):
            self._modifiers.append(RuleModifier.from_string("private"))
        return self

    def global_(self) -> Self:
        """Mark rule as global."""
        if not any(mod.name == "global" for mod in self._modifiers):
            self._modifiers.append(RuleModifier.from_string("global"))
        return self

    def public(self) -> Self:
        """Mark rule as public.

        Public is the default visibility, so remove any private modifier.
        """
        self._modifiers = [modifier for modifier in self._modifiers if modifier.name != "private"]
        return self

    def with_tag(self, tag: str) -> Self:
        """Add a tag to the rule."""
        _validate_new_tags(self._tags, (tag,))
        self._tags.append(tag)
        return self

    def with_regex_string(self, identifier: str, pattern: str, **modifiers: bool) -> Self:
        """Add a regex string with modifiers."""
        pattern = _validate_regex_pattern(pattern)
        mod_list = [
            StringModifier.from_name_value(name)
            for name, value in modifiers.items()
            if _require_bool_flag(value, name)
        ]
        self._append_string_definition(
            RegexString(identifier=identifier, regex=pattern, modifiers=mod_list),
        )
        return self

    def with_tags(self, *tags: str) -> Self:
        """Add multiple tags to the rule."""
        _validate_new_tags(self._tags, tags)
        self._tags.extend(tags)
        return self

    def with_meta(self, key: str, value: str | int | bool) -> Self:
        """Add a meta field."""
        _validate_meta_identifier(key)
        _validate_meta_value(value)
        self._meta[key] = value
        return self

    def with_author(self, author: str) -> Self:
        """Add author meta field."""
        author = _validate_text_value(author, "Author")
        return self.with_meta("author", author)

    def with_description(self, description: str) -> Self:
        """Add description meta field."""
        description = _validate_text_value(description, "Description")
        return self.with_meta("description", description)

    def with_version(self, version: int) -> Self:
        """Add version meta field."""
        return self.with_meta("version", validate_version_value(version))

    def with_plain_string(
        self,
        identifier: str,
        value: str | bytes,
        nocase: bool = False,
        wide: bool = False,
        ascii: bool = False,
        fullword: bool = False,
    ) -> Self:
        """Add a plain string."""
        value = _coerce_plain_string_value(value)
        nocase = _require_bool_flag(nocase, "nocase")
        wide = _require_bool_flag(wide, "wide")
        ascii = _require_bool_flag(ascii, "ascii")
        fullword = _require_bool_flag(fullword, "fullword")
        modifiers = []
        if nocase:
            modifiers.append(StringModifier.from_name_value("nocase"))
        if wide:
            modifiers.append(StringModifier.from_name_value("wide"))
        if ascii:
            modifiers.append(StringModifier.from_name_value("ascii"))
        if fullword:
            modifiers.append(StringModifier.from_name_value("fullword"))

        self._append_string_definition(
            PlainString(identifier=identifier, value=value, modifiers=modifiers),
        )
        return self

    def with_string(
        self,
        identifier: str,
        value: str,
        nocase: bool = False,
        wide: bool = False,
        ascii: bool = False,
        fullword: bool = False,
    ) -> Self:
        """Add a plain string (alias for with_plain_string)."""
        return self.with_plain_string(
            identifier,
            value,
            nocase=nocase,
            wide=wide,
            ascii=ascii,
            fullword=fullword,
        )

    def with_hex_string(self, identifier: str, builder: HexStringBuilder | list[HexToken]) -> Self:
        """Add a hex string using a builder or token list."""
        from yaraast.builder.hex_string_builder import HexStringBuilder

        if isinstance(builder, list):
            tokens = list(builder)
        elif isinstance(builder, HexStringBuilder):
            tokens = builder.build()
        else:
            msg = "Hex string builder must be a HexStringBuilder or token list"
            raise TypeError(msg)
        validate_hex_tokens_for_builder(tokens, identifier)
        self._append_string_definition(
            HexString(identifier=identifier, tokens=tokens, modifiers=[])
        )
        return self

    def with_hex_string_builder(
        self,
        identifier: str,
        builder_func: Callable[[HexStringBuilder], object],
    ) -> Self:
        """Add a hex string using a builder callback."""
        from yaraast.builder.hex_string_builder import HexStringBuilder

        if not callable(builder_func):
            msg = "Hex string builder callback must be callable"
            raise TypeError(msg)
        builder = HexStringBuilder(identifier=identifier)
        builder_func(builder)
        return self.with_hex_string(identifier, builder)

    def with_hex_string_raw(self, identifier: str, hex_pattern: str) -> Self:
        """Add a hex string from raw pattern."""
        hex_pattern = _validate_hex_pattern(hex_pattern)
        try:
            tokens = HexStringParser().parse(hex_pattern)
        except HexParseError as exc:
            if exc.position is None and str(exc) == "Hex parse error: Empty hex string":
                tokens = []
            else:
                raise ValidationError(str(exc)) from exc

        validate_hex_tokens_for_builder(tokens, identifier)
        self._append_string_definition(
            HexString(identifier=identifier, tokens=tokens, modifiers=[])
        )
        return self

    def with_regex(
        self,
        identifier: str,
        pattern: str,
        case_insensitive: bool = False,
        dotall: bool = False,
        multiline: bool = False,
    ) -> Self:
        """Add a regex string."""
        from yaraast.ast.modifiers import StringModifier, StringModifierType

        pattern = _validate_regex_pattern(pattern)
        case_insensitive = _require_bool_flag(case_insensitive, "case_insensitive")
        dotall = _require_bool_flag(dotall, "dotall")
        multiline = _require_bool_flag(multiline, "multiline")
        mods: list[StringModifier] = []
        if case_insensitive:
            mods.append(StringModifier(modifier_type=StringModifierType.NOCASE))
        if dotall:
            mods.append(StringModifier(modifier_type=StringModifierType.DOTALL))
        if multiline:
            mods.append(StringModifier(modifier_type=StringModifierType.MULTILINE))

        self._append_string_definition(
            RegexString(identifier=identifier, regex=pattern, modifiers=mods),
        )
        return self

    def with_condition(self, condition: Expression | ConditionBuilder | str) -> Self:
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
                    string_set=Identifier(name="them"),
                )
            elif condition == "all of them":
                self._condition = OfExpression(
                    quantifier=StringLiteral(value="all"),
                    string_set=Identifier(name="them"),
                )
            elif _SIMPLE_STRING_IDENTIFIER_RE.fullmatch(condition):
                self._condition = StringIdentifier(name=condition)
            else:
                self._condition = _parse_condition_text(condition)
        elif isinstance(condition, ConditionBuilder):
            self._condition = _validated_condition(condition.build())
        elif isinstance(condition, Expression):
            self._condition = _validated_condition(deepcopy(condition))
        else:
            msg = f"Rule condition must be an Expression, got {type(condition).__name__}"
            raise TypeError(msg)

        return self

    def set_condition(self, condition: Expression | ConditionBuilder | str) -> Self:
        """Set the rule condition (alias for with_condition)."""
        return self.with_condition(condition)

    def get_condition(self) -> Expression | None:
        """Return the currently configured condition."""
        return self._condition

    def with_simple_condition(self, condition: str) -> Self:
        """Set a simple condition string."""
        return self.with_condition(condition)

    def with_any_string(self) -> Self:
        """Set condition to any of them."""
        return self.with_condition("any of them")

    def with_all_strings(self) -> Self:
        """Set condition to all of them."""
        return self.with_condition("all of them")

    def with_condition_lambda(self, builder_func: Callable[[ConditionBuilder], object]) -> Self:
        """Set condition using a lambda that receives a ConditionBuilder."""
        if not callable(builder_func):
            msg = "Condition lambda must be callable"
            raise TypeError(msg)
        cb = ConditionBuilder()
        result = builder_func(cb)
        if not isinstance(result, ConditionBuilder):
            msg = "Condition lambda must return a ConditionBuilder"
            raise ValidationError(msg)
        self._condition = result.build()
        return self

    def require_condition(self, require: bool = True) -> Self:
        """Require an explicit condition before build."""
        require = _require_bool_flag(require, "require")
        self._require_condition = require
        return self

    def _append_string_definition(self, string_def: StringDefinition) -> None:
        validate_new_string_definitions(self._strings, [string_def])
        self._strings.append(deepcopy(string_def))

    def _extend_string_definitions(self, string_defs: list[StringDefinition]) -> None:
        validate_new_string_definitions(self._strings, string_defs)
        self._strings.extend(deepcopy(string_defs))

    def build(self) -> Rule:
        """Build the Rule AST node."""
        if not self._name:
            msg = "Rule name is required"
            raise ValidationError(msg)

        validate_new_string_definitions([], self._strings)

        condition = self._condition
        if condition is None:
            if self._require_condition:
                msg = "Rule condition is required"
                raise ValidationError(msg)
            condition = BooleanLiteral(value=True)

        return Rule(
            name=self._name,
            modifiers=deepcopy(self._modifiers),
            tags=[Tag(name=tag) for tag in self._tags],
            meta=dict(self._meta),  # Use dict for consistency with parser output
            strings=deepcopy(self._strings),
            condition=deepcopy(condition),
        )
