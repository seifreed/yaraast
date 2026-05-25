"""Fluent builder for YARA files."""

from copy import deepcopy
from typing import Self

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include, Rule
from yaraast.builder.file_builder_validation import (
    validate_nonempty_text,
    validate_nonempty_texts,
    validate_rule_names,
    validate_unique_rule_names,
)
from yaraast.builder.rule_builder import RuleBuilder


class YaraFileBuilder:
    """Fluent builder for constructing YARA files."""

    def __init__(self) -> None:
        self._imports: list[str] = []
        self._includes: list[str] = []
        self._rules: list[Rule] = []

    def with_import(self, module: str) -> Self:
        """Add an import."""
        validate_nonempty_text(module, "Import module")
        self._imports.append(module)
        return self

    def with_imports(self, *modules: str) -> Self:
        """Add multiple imports."""
        validate_nonempty_texts(modules, "Import module")
        self._imports.extend(modules)
        return self

    def with_include(self, path: str) -> Self:
        """Add an include."""
        validate_nonempty_text(path, "Include path")
        self._includes.append(path)
        return self

    def with_includes(self, *paths: str) -> Self:
        """Add multiple includes."""
        validate_nonempty_texts(paths, "Include path")
        self._includes.extend(paths)
        return self

    def with_rule(self, rule: Rule | RuleBuilder) -> Self:
        """Add a rule."""
        built_rule = self._build_rule(rule)
        validate_rule_names([built_rule])
        validate_unique_rule_names(self._rules, [built_rule])
        self._rules.append(built_rule)
        return self

    def with_rule_builder(self, builder_func) -> Self:
        """Add a rule using a builder function."""
        builder = RuleBuilder()
        builder_func(builder)
        built_rule = builder.build()
        validate_rule_names([built_rule])
        validate_unique_rule_names(self._rules, [built_rule])
        self._rules.append(built_rule)
        return self

    def with_rules(self, *rules: Rule | RuleBuilder) -> Self:
        """Add multiple rules."""
        built_rules = [self._build_rule(rule) for rule in rules]
        validate_rule_names(built_rules)
        validate_unique_rule_names(self._rules, built_rules)
        self._rules.extend(built_rules)
        return self

    def _build_rule(self, rule: Rule | RuleBuilder) -> Rule:
        if isinstance(rule, RuleBuilder):
            return rule.build()
        return deepcopy(rule)

    def build(self) -> YaraFile:
        """Build the YaraFile AST node."""
        return YaraFile(
            imports=[Import(module=module) for module in self._imports],
            includes=[Include(path=path) for path in self._includes],
            rules=deepcopy(self._rules),
        )

    # Convenience static methods
    @staticmethod
    def create() -> "YaraFileBuilder":
        """Create a new file builder."""
        return YaraFileBuilder()

    @staticmethod
    def from_rules(*rules: Rule | RuleBuilder) -> YaraFile:
        """Create a YARA file from rules."""
        builder = YaraFileBuilder()
        builder.with_rules(*rules)
        return builder.build()
