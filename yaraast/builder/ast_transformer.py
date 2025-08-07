"""AST cloning and transformation utilities."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.expressions import Expression, StringIdentifier
from yaraast.ast.rules import Import, Include, Rule, Tag

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.strings import StringDefinition


class CloneTransformer:
    """Utility for cloning and transforming AST nodes."""

    @staticmethod
    def clone(node: ASTNode) -> ASTNode:
        """Deep clone an AST node."""
        return deepcopy(node)

    @staticmethod
    def clone_rule(rule: Rule) -> Rule:
        """Clone a rule with all its components."""
        return Rule(
            name=rule.name,
            modifiers=rule.modifiers.copy(),
            tags=[Tag(name=tag.name) for tag in rule.tags],
            meta=rule.meta.copy(),
            strings=[CloneTransformer.clone(s) for s in rule.strings],
            condition=(CloneTransformer.clone(rule.condition) if rule.condition else None),
        )

    @staticmethod
    def clone_yara_file(yara_file: YaraFile) -> YaraFile:
        """Clone a YARA file with all its components."""
        return YaraFile(
            imports=[Import(module=imp.module, alias=imp.alias) for imp in yara_file.imports],
            includes=[Include(path=inc.path) for inc in yara_file.includes],
            rules=[CloneTransformer.clone_rule(rule) for rule in yara_file.rules],
            extern_rules=[CloneTransformer.clone(rule) for rule in yara_file.extern_rules],
            extern_imports=[CloneTransformer.clone(imp) for imp in yara_file.extern_imports],
            pragmas=[CloneTransformer.clone(pragma) for pragma in yara_file.pragmas],
            namespaces=[CloneTransformer.clone(ns) for ns in yara_file.namespaces],
        )


class RuleTransformer:
    """Specialized transformer for rule modifications."""

    def __init__(self, rule: Rule) -> None:
        self.rule = CloneTransformer.clone_rule(rule)

    def rename(self, new_name: str) -> RuleTransformer:
        """Rename the rule."""
        self.rule.name = new_name
        return self

    def add_prefix(self, prefix: str) -> RuleTransformer:
        """Add prefix to rule name."""
        self.rule.name = f"{prefix}{self.rule.name}"
        return self

    def add_suffix(self, suffix: str) -> RuleTransformer:
        """Add suffix to rule name."""
        self.rule.name = f"{self.rule.name}{suffix}"
        return self

    def add_tag(self, tag: str) -> RuleTransformer:
        """Add a tag to the rule."""
        if not any(t.name == tag for t in self.rule.tags):
            self.rule.tags.append(Tag(name=tag))
        return self

    def remove_tag(self, tag: str) -> RuleTransformer:
        """Remove a tag from the rule."""
        self.rule.tags = [t for t in self.rule.tags if t.name != tag]
        return self

    def replace_tag(self, old_tag: str, new_tag: str) -> RuleTransformer:
        """Replace a tag."""
        for tag in self.rule.tags:
            if tag.name == old_tag:
                tag.name = new_tag
        return self

    def add_modifier(self, modifier: str) -> RuleTransformer:
        """Add a modifier to the rule."""
        if modifier not in self.rule.modifiers:
            self.rule.modifiers.append(modifier)
        return self

    def remove_modifier(self, modifier: str) -> RuleTransformer:
        """Remove a modifier from the rule."""
        self.rule.modifiers = [m for m in self.rule.modifiers if m != modifier]
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
        if isinstance(self.rule.meta, dict):
            self.rule.meta[key] = value
        return self

    def remove_meta(self, key: str) -> RuleTransformer:
        """Remove metadata."""
        if isinstance(self.rule.meta, dict) and key in self.rule.meta:
            del self.rule.meta[key]
        return self

    def set_author(self, author: str) -> RuleTransformer:
        """Set author metadata."""
        return self.add_meta("author", author)

    def set_description(self, description: str) -> RuleTransformer:
        """Set description metadata."""
        return self.add_meta("description", description)

    def set_version(self, version: int) -> RuleTransformer:
        """Set version metadata."""
        return self.add_meta("version", version)

    def rename_strings(self, mapping: dict[str, str]) -> RuleTransformer:
        """Rename string identifiers based on mapping."""
        # Update string definitions
        for string_def in self.rule.strings:
            if string_def.identifier in mapping:
                string_def.identifier = mapping[string_def.identifier]

        # Update string references in condition
        if self.rule.condition:
            self.rule.condition = self._rename_strings_in_expression(
                self.rule.condition,
                mapping,
            )

        return self

    def prefix_strings(self, prefix: str) -> RuleTransformer:
        """Add prefix to all string identifiers."""
        mapping = {}
        for string_def in self.rule.strings:
            old_id = string_def.identifier
            # Handle $ prefix
            new_id = f"${prefix}{old_id[1:]}" if old_id.startswith("$") else f"{prefix}{old_id}"
            mapping[old_id] = new_id

        return self.rename_strings(mapping)

    def suffix_strings(self, suffix: str) -> RuleTransformer:
        """Add suffix to all string identifiers."""
        mapping = {}
        for string_def in self.rule.strings:
            old_id = string_def.identifier
            # Handle $ prefix
            new_id = f"${old_id[1:]}{suffix}" if old_id.startswith("$") else f"{old_id}{suffix}"
            mapping[old_id] = new_id

        return self.rename_strings(mapping)

    def add_string(self, string_def: StringDefinition) -> RuleTransformer:
        """Add a string definition."""
        self.rule.strings.append(string_def)
        return self

    def remove_string(self, identifier: str) -> RuleTransformer:
        """Remove a string definition by identifier."""
        self.rule.strings = [s for s in self.rule.strings if s.identifier != identifier]
        return self

    def replace_condition(self, new_condition: Expression) -> RuleTransformer:
        """Replace the rule condition."""
        self.rule.condition = new_condition
        return self

    def transform_condition(
        self,
        transformer_func: Callable[[Expression], Expression],
    ) -> RuleTransformer:
        """Transform the condition using a function."""
        if self.rule.condition:
            self.rule.condition = transformer_func(self.rule.condition)
        return self

    def build(self) -> Rule:
        """Build the transformed rule."""
        return self.rule

    # Helper methods
    def _rename_strings_in_expression(
        self,
        expr: Expression,
        mapping: dict[str, str],
    ) -> Expression:
        """Recursively rename string identifiers in expression."""
        if isinstance(expr, StringIdentifier):
            if expr.name in mapping:
                return StringIdentifier(name=mapping[expr.name], location=expr.location)
            return expr

        # For other expression types, would need to traverse recursively
        # This is a simplified implementation
        return expr


class YaraFileTransformer:
    """Specialized transformer for YARA file modifications."""

    def __init__(self, yara_file: YaraFile) -> None:
        self.yara_file = CloneTransformer.clone_yara_file(yara_file)

    def add_import(self, module: str, alias: str | None = None) -> YaraFileTransformer:
        """Add an import statement."""
        # Check if already imported
        if not any(imp.module == module for imp in self.yara_file.imports):
            self.yara_file.imports.append(Import(module=module, alias=alias))
        return self

    def remove_import(self, module: str) -> YaraFileTransformer:
        """Remove an import statement."""
        self.yara_file.imports = [imp for imp in self.yara_file.imports if imp.module != module]
        return self

    def add_include(self, path: str) -> YaraFileTransformer:
        """Add an include statement."""
        # Check if already included
        if not any(inc.path == path for inc in self.yara_file.includes):
            self.yara_file.includes.append(Include(path=path))
        return self

    def remove_include(self, path: str) -> YaraFileTransformer:
        """Remove an include statement."""
        self.yara_file.includes = [inc for inc in self.yara_file.includes if inc.path != path]
        return self

    def add_rule(self, rule: Rule) -> YaraFileTransformer:
        """Add a rule to the file."""
        self.yara_file.rules.append(CloneTransformer.clone_rule(rule))
        return self

    def remove_rule(self, rule_name: str) -> YaraFileTransformer:
        """Remove a rule by name."""
        self.yara_file.rules = [rule for rule in self.yara_file.rules if rule.name != rule_name]
        return self

    def transform_rule(
        self,
        rule_name: str,
        transformer_func: Callable[[Rule], Rule],
    ) -> YaraFileTransformer:
        """Transform a specific rule."""
        for i, rule in enumerate(self.yara_file.rules):
            if rule.name == rule_name:
                self.yara_file.rules[i] = transformer_func(rule)
                break
        return self

    def transform_all_rules(
        self,
        transformer_func: Callable[[Rule], Rule],
    ) -> YaraFileTransformer:
        """Transform all rules."""
        self.yara_file.rules = [transformer_func(rule) for rule in self.yara_file.rules]
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

    def set_author_for_all_rules(self, author: str) -> YaraFileTransformer:
        """Set author for all rules."""
        return self.transform_all_rules(
            lambda rule: RuleTransformer(rule).set_author(author).build(),
        )

    def filter_rules(self, predicate: Callable[[Rule], bool]) -> YaraFileTransformer:
        """Filter rules based on predicate."""
        self.yara_file.rules = [rule for rule in self.yara_file.rules if predicate(rule)]
        return self

    def filter_by_tag(self, tag: str) -> YaraFileTransformer:
        """Filter rules that have a specific tag."""
        return self.filter_rules(lambda rule: any(t.name == tag for t in rule.tags))

    def filter_by_modifier(self, modifier: str) -> YaraFileTransformer:
        """Filter rules that have a specific modifier."""
        return self.filter_rules(lambda rule: modifier in rule.modifiers)

    def build(self) -> YaraFile:
        """Build the transformed YARA file."""
        return self.yara_file


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


# Factory functions for common transformations
def create_variant_rule(rule: Rule, variant_name: str, **changes) -> Rule:
    """Create a variant of a rule with changes."""
    transformer = RuleTransformer(rule).rename(variant_name)

    if "prefix" in changes:
        transformer = transformer.add_prefix(changes["prefix"])
    if "suffix" in changes:
        transformer = transformer.add_suffix(changes["suffix"])
    if "tags" in changes:
        for tag in changes["tags"]:
            transformer = transformer.add_tag(tag)
    if "author" in changes:
        transformer = transformer.set_author(changes["author"])
    if "description" in changes:
        transformer = transformer.set_description(changes["description"])
    if changes.get("private"):
        transformer = transformer.make_private()

    return transformer.build()


def create_rule_collection(rules: list[Rule], collection_name: str) -> YaraFile:
    """Create a YARA file from a collection of rules."""
    yara_file = YaraFile()
    transformer = YaraFileTransformer(yara_file)

    # Add all rules with collection prefix
    for rule in rules:
        new_rule = RuleTransformer(rule).add_prefix(f"{collection_name}_").build()
        transformer = transformer.add_rule(new_rule)

    return transformer.build()


def merge_yara_files(*yara_files: YaraFile) -> YaraFile:
    """Merge multiple YARA files into one."""
    if not yara_files:
        return YaraFile()

    result = CloneTransformer.clone_yara_file(yara_files[0])
    transformer = YaraFileTransformer(result)

    for yara_file in yara_files[1:]:
        # Add imports (avoiding duplicates)
        for imp in yara_file.imports:
            transformer = transformer.add_import(imp.module, imp.alias)

        # Add includes (avoiding duplicates)
        for inc in yara_file.includes:
            transformer = transformer.add_include(inc.path)

        # Add rules (all rules, may have name conflicts)
        for rule in yara_file.rules:
            transformer = transformer.add_rule(rule)

    return transformer.build()
