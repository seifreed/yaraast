"""Ruleset-level inference for YARA (environment population)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Rule
from yaraast.visitor import BaseVisitor

from ._registry import TypeEnvironment


class RulesetTypeInference(BaseVisitor[TypeEnvironment]):
    """Populate a type environment from a YARA ruleset."""

    def __init__(self, env: TypeEnvironment) -> None:
        self.env = env

    def infer(self, node: YaraFile) -> TypeEnvironment:
        self.visit(node)
        return self.env

    def visit_yara_file(self, node: YaraFile) -> TypeEnvironment:
        for imp in node.imports:
            self.visit(imp)

        for rule in node.rules:
            self.env.add_rule(rule.name)

        for rule in node.rules:
            self.visit(rule)

        return self.env

    def visit_import(self, node: Import) -> TypeEnvironment:
        name = node.alias if node.alias else node.module
        self.env.add_module(name, node.module)
        return self.env

    def visit_rule(self, node: Rule) -> TypeEnvironment:
        for string in node.strings:
            self.env.add_string(string.identifier)
        return self.env
