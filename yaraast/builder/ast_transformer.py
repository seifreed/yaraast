"""AST cloning and transformation utilities."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, cast

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Expression,
    Identifier,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.builder.file_builder_validation import (
    validate_identifier,
    validate_meta_value,
    validate_nonempty_text,
    validate_unique_rule_names,
    validate_version_value,
)
from yaraast.builder.string_identifier_validation import validate_new_string_definitions
from yaraast.errors import ValidationError

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.strings import StringDefinition


class CloneTransformer:
    """Utility for cloning and transforming AST nodes."""

    @staticmethod
    def clone(node: ASTNode) -> ASTNode:
        """Deep clone an AST node."""
        if not isinstance(node, ASTNode):
            msg = "AST node input must be an ASTNode"
            raise TypeError(msg)
        return deepcopy(node)

    @staticmethod
    def clone_rule(rule: Rule) -> Rule:
        """Clone a rule with all its components."""
        if not isinstance(rule, Rule):
            msg = "Rule input must be a Rule"
            raise TypeError(msg)
        return deepcopy(rule)

    @staticmethod
    def clone_yara_file(yara_file: YaraFile) -> YaraFile:
        """Clone a YARA file with all its components."""
        if not isinstance(yara_file, YaraFile):
            msg = "YaraFile input must be a YaraFile"
            raise TypeError(msg)
        return deepcopy(yara_file)


class RuleTransformer:
    """Specialized transformer for rule modifications."""

    def __init__(self, rule: Rule) -> None:
        cloned_rule = CloneTransformer.clone_rule(rule)
        cloned_rule.validate_structure()
        self.rule = cloned_rule

    @staticmethod
    def _require_expression(value: object, context: str) -> Expression:
        if isinstance(value, Expression):
            validate_structure = getattr(value, "validate_structure", None)
            if callable(validate_structure):
                validate_structure()
            return value
        msg = f"{context}, got {type(value).__name__}"
        raise TypeError(msg)

    @staticmethod
    def _require_callable(value: object, context: str) -> None:
        if callable(value):
            return
        msg = f"{context} must be callable"
        raise TypeError(msg)

    @staticmethod
    def _require_text(value: object, context: str) -> str:
        if isinstance(value, str):
            return value
        msg = f"{context} must be a string"
        raise TypeError(msg)

    def rename(self, new_name: str) -> RuleTransformer:
        """Rename the rule."""
        validate_identifier(new_name, "rule")
        self.rule.name = new_name
        return self

    def add_prefix(self, prefix: str) -> RuleTransformer:
        """Add prefix to rule name."""
        prefix = self._require_text(prefix, "Rule prefix")
        new_name = f"{prefix}{self.rule.name}"
        validate_identifier(new_name, "rule")
        self.rule.name = new_name
        return self

    def add_suffix(self, suffix: str) -> RuleTransformer:
        """Add suffix to rule name."""
        suffix = self._require_text(suffix, "Rule suffix")
        new_name = f"{self.rule.name}{suffix}"
        validate_identifier(new_name, "rule")
        self.rule.name = new_name
        return self

    def add_tag(self, tag: str) -> RuleTransformer:
        """Add a tag to the rule."""
        validate_identifier(tag, "tag")
        if not any(t.name == tag for t in self.rule.tags):
            self.rule.tags.append(Tag(name=tag))
        return self

    def remove_tag(self, tag: str) -> RuleTransformer:
        """Remove a tag from the rule."""
        tag = self._require_text(tag, "Tag")
        self.rule.tags = [t for t in self.rule.tags if t.name != tag]
        return self

    def replace_tag(self, old_tag: str, new_tag: str) -> RuleTransformer:
        """Replace a tag."""
        old_tag = self._require_text(old_tag, "Old tag")
        validate_identifier(new_tag, "tag")
        if old_tag != new_tag and any(t.name == new_tag for t in self.rule.tags):
            msg = f"Duplicate tag identifier: {new_tag}"
            raise ValidationError(msg)
        for tag in self.rule.tags:
            if tag.name == old_tag:
                tag.name = new_tag
        return self

    def add_modifier(self, modifier: str) -> RuleTransformer:
        """Add a modifier to the rule."""
        modifier = self._require_text(modifier, "Rule modifier")
        validate_nonempty_text(modifier, "Rule modifier")
        if not any(str(m) == modifier for m in self.rule.modifiers):
            try:
                from yaraast.ast.modifiers import RuleModifier

                self.rule.modifiers.append(RuleModifier.from_string(modifier))
            except (ValueError, ValidationError):
                validate_identifier(modifier, "rule modifier")
                self.rule.modifiers.append(modifier)
        return self

    def remove_modifier(self, modifier: str) -> RuleTransformer:
        """Remove a modifier from the rule."""
        modifier = self._require_text(modifier, "Rule modifier")
        self.rule.modifiers = [m for m in self.rule.modifiers if str(m) != modifier]
        return self

    def make_private(self) -> RuleTransformer:
        """Make the rule private."""
        return self.add_modifier("private")

    def make_global(self) -> RuleTransformer:
        """Make the rule global."""
        return self.add_modifier("global")

    def make_public(self) -> RuleTransformer:
        """Make the rule public (remove private)."""
        return self.remove_modifier("private")

    def add_meta(self, key: str, value: str | int | bool) -> RuleTransformer:
        """Add metadata."""
        from yaraast.ast.modifiers import MetaEntry

        validate_identifier(key, "meta")
        validate_meta_value(value)

        # Update existing entry or append new one
        for entry in self.rule.meta:
            if hasattr(entry, "key") and entry.key == key:
                entry.value = value
                return self
        self.rule.meta.append(MetaEntry.from_key_value(key, value))
        return self

    def remove_meta(self, key: str) -> RuleTransformer:
        """Remove metadata."""
        self.rule.meta = [
            entry for entry in self.rule.meta if not (hasattr(entry, "key") and entry.key == key)
        ]
        return self

    def set_author(self, author: str) -> RuleTransformer:
        """Set author metadata."""
        author = self._require_text(author, "Rule author")
        return self.add_meta("author", author)

    def set_description(self, description: str) -> RuleTransformer:
        """Set description metadata."""
        description = self._require_text(description, "Rule description")
        return self.add_meta("description", description)

    def set_version(self, version: int) -> RuleTransformer:
        """Set version metadata."""
        return self.add_meta("version", validate_version_value(version))

    def _validate_string_rename_mapping(self, mapping: object) -> dict[str, str]:
        if not isinstance(mapping, dict):
            msg = "String rename mapping must be a dict"
            raise TypeError(msg)
        for source, target in mapping.items():
            self._require_text(source, "String rename source")
            self._require_text(target, "String rename target")
        return cast(dict[str, str], mapping)

    def rename_strings(self, mapping: dict[str, str]) -> RuleTransformer:
        """Rename string identifiers based on mapping."""
        mapping = self._validate_string_rename_mapping(mapping)
        renamed_strings = deepcopy(self.rule.strings)
        for string_def in renamed_strings:
            string_def.identifier = self._rename_string_reference(string_def.identifier, mapping)
        validate_new_string_definitions([], renamed_strings)

        # Update string definitions
        for string_def in self.rule.strings:
            string_def.identifier = self._rename_string_reference(string_def.identifier, mapping)

        # Update string references in condition
        if self.rule.condition is not None:
            self.rule.condition = self._rename_strings_in_expression(
                self.rule.condition,
                mapping,
            )

        return self

    def prefix_strings(self, prefix: str) -> RuleTransformer:
        """Add prefix to all string identifiers."""
        prefix = self._require_text(prefix, "String prefix")
        mapping = {}
        for string_def in self.rule.strings:
            old_id = string_def.identifier
            # Handle $ prefix
            new_id = f"${prefix}{old_id[1:]}" if old_id.startswith("$") else f"{prefix}{old_id}"
            mapping[old_id] = new_id

        return self.rename_strings(mapping)

    def suffix_strings(self, suffix: str) -> RuleTransformer:
        """Add suffix to all string identifiers."""
        suffix = self._require_text(suffix, "String suffix")
        mapping = {}
        for string_def in self.rule.strings:
            old_id = string_def.identifier
            # Handle $ prefix
            new_id = f"${old_id[1:]}{suffix}" if old_id.startswith("$") else f"{old_id}{suffix}"
            mapping[old_id] = new_id

        return self.rename_strings(mapping)

    def add_string(self, string_def: StringDefinition) -> RuleTransformer:
        """Add a string definition."""
        validate_new_string_definitions(self.rule.strings, [string_def])
        self.rule.strings.append(deepcopy(string_def))
        return self

    def remove_string(self, identifier: str) -> RuleTransformer:
        """Remove a string definition by identifier."""
        identifier = self._require_text(identifier, "String identifier")
        self.rule.strings = [s for s in self.rule.strings if s.identifier != identifier]
        return self

    def replace_condition(self, new_condition: Expression) -> RuleTransformer:
        """Replace the rule condition."""
        self.rule.condition = self._require_expression(
            new_condition,
            "Rule condition must be an Expression",
        )
        return self

    def transform_condition(
        self,
        transformer_func: Callable[[Expression], Expression],
    ) -> RuleTransformer:
        """Transform the condition using a function."""
        self._require_callable(transformer_func, "Condition transformer")
        if self.rule.condition is not None:
            self.rule.condition = self._require_expression(
                transformer_func(deepcopy(self.rule.condition)),
                "Condition transformer must return an Expression",
            )
        return self

    def build(self) -> Rule:
        """Build the transformed rule."""
        return CloneTransformer.clone_rule(self.rule)

    # Helper methods
    def _rename_strings_in_expression(
        self,
        expr: Expression,
        mapping: dict[str, str],
    ) -> Expression:
        """Recursively rename string identifiers in expression."""
        if isinstance(expr, StringIdentifier):
            expr.name = self._rename_string_reference(expr.name, mapping)
            return expr

        if isinstance(expr, StringCount):
            expr.string_id = self._rename_string_reference(expr.string_id, mapping)
            return expr

        if isinstance(expr, StringOffset | StringLength):
            expr.string_id = self._rename_string_reference(expr.string_id, mapping)
            expr.index = cast(Expression | None, self._rename_expression_value(expr.index, mapping))
            return expr

        if isinstance(expr, StringWildcard):
            expr.pattern = self._rename_string_pattern(expr.pattern, mapping)
            return expr

        if isinstance(expr, AtExpression):
            if isinstance(expr.string_id, str):
                expr.string_id = self._rename_string_reference(expr.string_id, mapping)
            else:
                expr.string_id = cast(
                    str | Expression,
                    self._rename_expression_value(expr.string_id, mapping),
                )
            expr.offset = cast(Expression, self._rename_expression_value(expr.offset, mapping))
            return expr

        if isinstance(expr, InExpression):
            if isinstance(expr.subject, str):
                expr.subject = self._rename_string_reference(expr.subject, mapping)
            else:
                expr.subject = cast(
                    str | Expression,
                    self._rename_expression_value(expr.subject, mapping),
                )
            expr.range = cast(Expression, self._rename_expression_value(expr.range, mapping))
            return expr

        if isinstance(expr, OfExpression | ForOfExpression):
            expr.quantifier = cast(
                Expression | str | int | float,
                self._rename_expression_value(expr.quantifier, mapping),
            )
            expr.string_set = cast(
                Expression
                | str
                | list[str | Expression]
                | tuple[str | Expression, ...]
                | set[str | Expression]
                | frozenset[str | Expression],
                self._rename_string_set_value(expr.string_set, mapping),
            )
            if isinstance(expr, ForOfExpression) and expr.condition is not None:
                expr.condition = cast(
                    Expression | None,
                    self._rename_expression_value(expr.condition, mapping),
                )
            return expr

        if isinstance(expr, BinaryExpression):
            # Children are renamed in place; this visitor always returns the
            # same node it was given, so no reconstruction is needed.
            self._rename_strings_in_expression(expr.left, mapping)
            self._rename_strings_in_expression(expr.right, mapping)
            return expr

        if isinstance(expr, UnaryExpression):
            self._rename_strings_in_expression(expr.operand, mapping)
            return expr

        if isinstance(expr, ParenthesesExpression):
            self._rename_strings_in_expression(expr.expression, mapping)
            return expr

        for attr_name, attr_value in vars(expr).items():
            if attr_name in {"location", "leading_comments", "trailing_comment"}:
                continue
            setattr(expr, attr_name, self._rename_expression_value(attr_value, mapping))

        return expr

    def _rename_expression_value(
        self,
        value: object,
        mapping: dict[str, str],
    ) -> object:
        if isinstance(value, Expression):
            return self._rename_strings_in_expression(value, mapping)
        if isinstance(value, list):
            return [self._rename_expression_value(item, mapping) for item in value]
        if isinstance(value, tuple):
            return tuple(self._rename_expression_value(item, mapping) for item in value)
        if isinstance(value, set):
            return {self._rename_expression_value(item, mapping) for item in value}
        if isinstance(value, frozenset):
            return frozenset(self._rename_expression_value(item, mapping) for item in value)
        return value

    def _rename_string_set_value(
        self,
        value: object,
        mapping: dict[str, str],
    ) -> object:
        if isinstance(value, str):
            return self._rename_string_pattern(value, mapping)
        if isinstance(value, Identifier):
            if isinstance(value.name, str) and value.name.startswith("$"):
                value.name = self._rename_string_reference(value.name, mapping)
            return value
        if isinstance(value, StringLiteral):
            value.value = self._rename_string_pattern(value.value, mapping)
            return value
        if isinstance(value, ParenthesesExpression):
            renamed = self._rename_string_set_value(value.expression, mapping)
            if isinstance(renamed, Expression):
                value.expression = renamed
            return value
        if isinstance(value, SetExpression):
            renamed_elements = []
            for element in value.elements:
                renamed = self._rename_string_set_value(element, mapping)
                renamed_elements.append(renamed if isinstance(renamed, Expression) else element)
            value.elements = renamed_elements
            return value
        if isinstance(value, Expression):
            return self._rename_strings_in_expression(value, mapping)
        if isinstance(value, list):
            return [self._rename_string_set_value(item, mapping) for item in value]
        if isinstance(value, tuple):
            return tuple(self._rename_string_set_value(item, mapping) for item in value)
        if isinstance(value, set):
            return {self._rename_string_set_value(item, mapping) for item in value}
        if isinstance(value, frozenset):
            return frozenset(self._rename_string_set_value(item, mapping) for item in value)
        return value

    @staticmethod
    def _rename_string_reference(value: str, mapping: dict[str, str]) -> str:
        if value in mapping:
            return RuleTransformer._format_string_reference(value, mapping[value])
        if value.startswith("$"):
            bare_name = value[1:]
            if bare_name in mapping:
                return RuleTransformer._format_string_reference(value, mapping[bare_name])
        else:
            prefixed_name = f"${value}"
            if prefixed_name in mapping:
                return mapping[prefixed_name].lstrip("$")
        return value

    @staticmethod
    def _format_string_reference(original: str, replacement: str) -> str:
        if original.startswith("$"):
            return replacement if replacement.startswith("$") else f"${replacement}"
        return replacement.lstrip("$")

    def _rename_string_pattern(self, value: str, mapping: dict[str, str]) -> str:
        renamed = self._rename_string_reference(value, mapping)
        if renamed != value:
            return renamed
        if value.endswith("*"):
            prefix = value[:-1]
            renamed_prefix = self._rename_string_reference(prefix, mapping)
            if renamed_prefix != prefix:
                return f"{renamed_prefix}*"
        return value


class YaraFileTransformer:
    """Specialized transformer for YARA file modifications."""

    def __init__(self, yara_file: YaraFile) -> None:
        cloned_file = CloneTransformer.clone_yara_file(yara_file)
        cloned_file.validate_structure()
        self._validate_rule_list(cloned_file.rules)
        self.yara_file = cloned_file

    @staticmethod
    def _require_rule(value: object) -> Rule:
        if isinstance(value, Rule):
            return value
        msg = f"Rule transformer must return a Rule, got {type(value).__name__}"
        raise TypeError(msg)

    @staticmethod
    def _validate_rule_list(rules: list[Rule]) -> None:
        for rule in rules:
            validate_identifier(rule.name, "rule")
            rule.validate_structure()
        validate_unique_rule_names([], rules)

    def add_import(self, module: str, alias: str | None = None) -> YaraFileTransformer:
        """Add an import statement."""
        validate_nonempty_text(module, "Import module")
        if alias is not None:
            msg = "Import aliases are not supported"
            raise ValidationError(msg)
        # Check if already imported
        if not any(imp.module == module for imp in self.yara_file.imports):
            self.yara_file.imports.append(Import(module=module))
        return self

    def remove_import(self, module: str) -> YaraFileTransformer:
        """Remove an import statement."""
        module = RuleTransformer._require_text(module, "Import module")
        self.yara_file.imports = [imp for imp in self.yara_file.imports if imp.module != module]
        return self

    def add_include(self, path: str) -> YaraFileTransformer:
        """Add an include statement."""
        validate_nonempty_text(path, "Include path")
        # Check if already included
        if not any(inc.path == path for inc in self.yara_file.includes):
            self.yara_file.includes.append(Include(path=path))
        return self

    def remove_include(self, path: str) -> YaraFileTransformer:
        """Remove an include statement."""
        path = RuleTransformer._require_text(path, "Include path")
        self.yara_file.includes = [inc for inc in self.yara_file.includes if inc.path != path]
        return self

    def add_rule(self, rule: Rule) -> YaraFileTransformer:
        """Add a rule to the file."""
        if not isinstance(rule, Rule):
            msg = "Rule input must be a Rule"
            raise TypeError(msg)
        self._validate_rule_list([*self.yara_file.rules, rule])
        self.yara_file.rules.append(CloneTransformer.clone_rule(rule))
        return self

    def remove_rule(self, rule_name: str) -> YaraFileTransformer:
        """Remove a rule by name."""
        rule_name = RuleTransformer._require_text(rule_name, "Rule name")
        self.yara_file.rules = [rule for rule in self.yara_file.rules if rule.name != rule_name]
        return self

    def transform_rule(
        self,
        rule_name: str,
        transformer_func: Callable[[Rule], Rule],
    ) -> YaraFileTransformer:
        """Transform a specific rule."""
        rule_name = RuleTransformer._require_text(rule_name, "Rule name")
        RuleTransformer._require_callable(transformer_func, "Rule transformer")
        for i, rule in enumerate(self.yara_file.rules):
            if rule.name == rule_name:
                transformed_rule = self._require_rule(
                    transformer_func(CloneTransformer.clone_rule(rule))
                )
                transformed_rules = self.yara_file.rules.copy()
                transformed_rules[i] = transformed_rule
                self._validate_rule_list(transformed_rules)
                self.yara_file.rules = transformed_rules
                break
        return self

    def transform_all_rules(
        self,
        transformer_func: Callable[[Rule], Rule],
    ) -> YaraFileTransformer:
        """Transform all rules."""
        RuleTransformer._require_callable(transformer_func, "Rule transformer")
        transformed_rules = [
            self._require_rule(transformer_func(CloneTransformer.clone_rule(rule)))
            for rule in self.yara_file.rules
        ]
        self._validate_rule_list(transformed_rules)
        self.yara_file.rules = transformed_rules
        return self

    def prefix_all_rules(self, prefix: str) -> YaraFileTransformer:
        """Add prefix to all rule names."""
        return self.transform_all_rules(
            lambda rule: RuleTransformer(rule).add_prefix(prefix).build(),
        )

    def suffix_all_rules(self, suffix: str) -> YaraFileTransformer:
        """Add suffix to all rule names."""
        return self.transform_all_rules(
            lambda rule: RuleTransformer(rule).add_suffix(suffix).build(),
        )

    def add_tag_to_all_rules(self, tag: str) -> YaraFileTransformer:
        """Add tag to all rules."""
        return self.transform_all_rules(
            lambda rule: RuleTransformer(rule).add_tag(tag).build(),
        )

    def make_all_rules_private(self) -> YaraFileTransformer:
        """Make all rules private."""
        return self.transform_all_rules(
            lambda rule: RuleTransformer(rule).make_private().build(),
        )

    def filter_rules(self, predicate: Callable[[Rule], bool]) -> YaraFileTransformer:
        """Filter rules based on predicate."""
        RuleTransformer._require_callable(predicate, "Rule filter predicate")
        filtered_rules = []
        for rule in self.yara_file.rules:
            should_keep = predicate(CloneTransformer.clone_rule(rule))
            if not isinstance(should_keep, bool):
                msg = f"Rule filter predicate must return bool, got {type(should_keep).__name__}"
                raise TypeError(msg)
            if should_keep:
                filtered_rules.append(rule)
        self.yara_file.rules = filtered_rules
        return self

    def filter_by_tag(self, tag: str) -> YaraFileTransformer:
        """Filter rules that have a specific tag."""
        tag = RuleTransformer._require_text(tag, "Tag")
        return self.filter_rules(lambda rule: any(t.name == tag for t in rule.tags))

    def filter_by_modifier(self, modifier: str) -> YaraFileTransformer:
        """Filter rules that have a specific modifier."""
        modifier = RuleTransformer._require_text(modifier, "Rule modifier")
        return self.filter_rules(lambda rule: any(str(m) == modifier for m in rule.modifiers))

    def build(self) -> YaraFile:
        """Build the transformed YARA file."""
        return CloneTransformer.clone_yara_file(self.yara_file)


# Convenience functions
def clone_rule(rule: Rule) -> Rule:
    """Clone a rule."""
    return CloneTransformer.clone_rule(rule)


def clone_yara_file(yara_file: YaraFile) -> YaraFile:
    """Clone a YARA file."""
    return CloneTransformer.clone_yara_file(yara_file)


def transform_rule(rule: Rule) -> RuleTransformer:
    """Create a rule transformer."""
    return RuleTransformer(rule)


def transform_yara_file(yara_file: YaraFile) -> YaraFileTransformer:
    """Create a YARA file transformer."""
    return YaraFileTransformer(yara_file)
