"""Type environment for semantic validation and inference."""

from __future__ import annotations

from ._registry_base import YaraType


class TypeEnvironment:
    """Type environment for tracking variable types."""

    def __init__(self) -> None:
        self.scopes: list[dict[str, YaraType]] = [{}]
        self.modules: set[str] = set()
        self.module_aliases: dict[str, str] = {}
        self.strings: set[str] = set()
        self.rules: set[str] = set()

    def push_scope(self) -> None:
        self.scopes.append({})

    def pop_scope(self) -> None:
        if len(self.scopes) > 1:
            self.scopes.pop()

    def define(self, name: str, type: YaraType) -> None:
        self.scopes[-1][name] = type

    def lookup(self, name: str) -> YaraType | None:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def add_module(self, alias: str, module: str | None = None) -> None:
        if module is None:
            self.modules.add(alias)
        else:
            self.modules.add(module)
            self.module_aliases[alias] = module

    def add_string(self, string_id: str) -> None:
        self.strings.add(string_id)

    def has_module(self, name: str) -> bool:
        return name in self.modules or name in self.module_aliases

    def get_module_name(self, name: str) -> str | None:
        if name in self.module_aliases:
            return self.module_aliases[name]
        if name in self.modules:
            return name
        return None

    def has_string(self, string_id: str) -> bool:
        return string_id in self.strings

    def has_string_pattern(self, pattern: str) -> bool:
        if not pattern.endswith("*"):
            return self.has_string(pattern)
        prefix = pattern[:-1]
        return any(string_id.startswith(prefix) for string_id in self.strings)

    def add_rule(self, rule_name: str) -> None:
        self.rules.add(rule_name)

    def has_rule(self, rule_name: str) -> bool:
        return rule_name in self.rules
