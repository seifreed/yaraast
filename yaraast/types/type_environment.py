"""Type environment for semantic validation and inference."""

from __future__ import annotations

from typing import Any

from ._registry_base import YaraType


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def _require_nonempty_string(value: Any, field_name: str) -> str:
    text = _require_string(value, field_name)
    if not text.strip():
        msg = f"{field_name} cannot be empty"
        raise ValueError(msg)
    return text


def _normalize_string_id(string_id: str, field_name: str = "TypeEnvironment string id") -> str:
    string_id = _require_string(string_id, field_name)
    return string_id if string_id.startswith("$") else f"${string_id}"


class TypeEnvironment:
    """Type environment for tracking variable types."""

    def __init__(self) -> None:
        self.scopes: list[dict[str, YaraType]] = [{}]
        self.modules: set[str] = set()
        self.module_aliases: dict[str, str] = {}
        self.strings: set[str] = set()
        self.anonymous_strings: set[str] = set()
        self.rules: set[str] = set()

    def push_scope(self) -> None:
        self.scopes.append({})

    def pop_scope(self) -> None:
        if len(self.scopes) > 1:
            self.scopes.pop()

    def define(self, name: str, type: YaraType) -> None:
        variable_name = _require_nonempty_string(name, "TypeEnvironment variable name")
        if not isinstance(type, YaraType):
            msg = "TypeEnvironment type must be a YaraType"
            raise TypeError(msg)
        self.scopes[-1][variable_name] = type

    def lookup(self, name: str) -> YaraType | None:
        variable_name = _require_string(name, "TypeEnvironment variable name")
        for scope in reversed(self.scopes):
            if variable_name in scope:
                return scope[variable_name]
        return None

    def add_module(self, alias: str, module: str | None = None) -> None:
        alias = _require_nonempty_string(alias, "TypeEnvironment module alias")
        if module is None:
            self.modules.add(alias)
        else:
            module = _require_nonempty_string(module, "TypeEnvironment module name")
            self.modules.add(alias)
            self.modules.add(module)
            self.module_aliases[alias] = module

    def add_string(self, string_id: str, *, is_anonymous: bool = False) -> None:
        if not isinstance(is_anonymous, bool):
            msg = "TypeEnvironment is_anonymous must be a boolean"
            raise TypeError(msg)
        _require_nonempty_string(string_id, "TypeEnvironment string id")
        string_id = _normalize_string_id(string_id)
        self.strings.add(string_id)
        if is_anonymous:
            self.anonymous_strings.add(string_id)

    def has_module(self, name: str) -> bool:
        name = _require_string(name, "TypeEnvironment module name")
        return name in self.modules or name in self.module_aliases

    def get_module_name(self, name: str) -> str | None:
        name = _require_string(name, "TypeEnvironment module name")
        if name in self.module_aliases:
            return self.module_aliases[name]
        if name in self.modules:
            return name
        return None

    def has_string(self, string_id: str) -> bool:
        string_id = _normalize_string_id(string_id)
        return string_id in self.strings

    def has_string_pattern(self, pattern: str) -> bool:
        pattern = _normalize_string_id(pattern, "TypeEnvironment string pattern")
        if not pattern.endswith("*"):
            return self.has_string(pattern)
        if pattern == "$*":
            return bool(self.strings)
        prefix = pattern[:-1]
        return any(
            string_id.startswith(prefix) for string_id in self.strings - self.anonymous_strings
        )

    def add_rule(self, rule_name: str) -> None:
        rule_name = _require_nonempty_string(rule_name, "TypeEnvironment rule name")
        self.rules.add(rule_name)

    def has_rule(self, rule_name: str) -> bool:
        rule_name = _require_string(rule_name, "TypeEnvironment rule name")
        return rule_name in self.rules
