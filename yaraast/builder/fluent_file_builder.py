"""Fluent builders for complete YARA files."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include, Rule

if TYPE_CHECKING:
    from yaraast.builder.fluent_rule_builder import FluentRuleBuilder


class FluentYaraFileBuilder:
    """Fluent builder for complete YARA files."""

    def __init__(self) -> None:
        self.imports: list[Import] = []
        self.includes: list[Include] = []
        self.rules: list[Rule] = []

    def import_module(self, module: str, alias: str | None = None) -> Self:
        """Add import statement."""
        if not any(imp.module == module for imp in self.imports):
            self.imports.append(Import(module=module, alias=alias))
        return self

    def include_file(self, path: str) -> Self:
        """Add include statement."""
        if not any(inc.path == path for inc in self.includes):
            self.includes.append(Include(path=path))
        return self

    def with_rule(self, rule: Rule) -> Self:
        """Add a rule."""
        self.rules.append(rule)
        return self

    def rule(self, name: str) -> FluentRuleBuilder:
        """Start building a rule."""
        from yaraast.builder.fluent_rule_builder import FluentRuleBuilderWithFile

        return FluentRuleBuilderWithFile(self, name)

    def build(self) -> YaraFile:
        """Build the YARA file."""
        return YaraFile(imports=self.imports, includes=self.includes, rules=self.rules)


def yara_file() -> FluentYaraFileBuilder:
    """Create a new fluent YARA file builder."""
    return FluentYaraFileBuilder()
