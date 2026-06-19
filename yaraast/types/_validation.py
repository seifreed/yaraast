"""Type validation logic for YARA AST."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Expression
from yaraast.ast.rules import Import, Rule
from yaraast.types._expr_inference import ExpressionTypeInference as TypeInference
from yaraast.types.module_loader import ModuleLoader
from yaraast.visitor import BaseVisitor

from ._registry import (
    BooleanType,
    DoubleType,
    FloatType,
    IntegerType,
    RegexType,
    StringIdentifierType,
    StringType,
    TypeEnvironment,
    UnknownType,
    YaraType,
)
from .type_environment import _normalize_string_id


def _copy_type_environment(env: TypeEnvironment) -> TypeEnvironment:
    copied = TypeEnvironment()
    copied.scopes = [dict(scope) for scope in env.scopes]
    copied.modules = set(env.modules)
    copied.module_aliases = dict(env.module_aliases)
    copied.strings = set(env.strings)
    copied.anonymous_strings = set(env.anonymous_strings)
    copied.rules = set(env.rules)
    return copied


class TypeChecker(BaseVisitor[None]):
    """Type checker for YARA rules."""

    def __init__(self, env: TypeEnvironment | None = None) -> None:
        self._base_env = _copy_type_environment(env) if env is not None else None
        self.env = self._fresh_environment()
        self.inference = TypeInference(self.env)
        self.errors: list[str] = []

    def _fresh_environment(self) -> TypeEnvironment:
        env = (
            _copy_type_environment(self._base_env)
            if self._base_env is not None
            else TypeEnvironment()
        )
        self._define_vt_livehunt_globals(env)
        return env

    def _define_vt_livehunt_globals(self, env: TypeEnvironment) -> None:
        vt_module = ModuleLoader().get_module("vt")
        if vt_module is None:
            return
        for constant_name, constant_type in vt_module.constants.items():
            if env.lookup(constant_name) is None:
                env.define(constant_name, constant_type)

    def _base_env_has_variable(self, name: str) -> bool:
        return self._base_env is not None and self._base_env.lookup(name) is not None

    def check_compatibility(self, type1: object, type2: object) -> bool:
        """Check if two types are compatible."""
        if isinstance(type1, YaraType) and isinstance(type2, YaraType):
            return type1.is_compatible_with(type2)
        return type1 == type2

    def infer_type(self, node: Expression) -> YaraType:
        """Infer type from AST node."""
        return self.inference.infer(node)

    def check(self, ast: YaraFile) -> list[str]:
        """Type check a YARA file and return errors."""
        self.errors = []
        self.env = self._fresh_environment()
        self.inference = TypeInference(self.env)
        self.visit(ast)
        self.errors.extend(self.inference.errors)
        return list(self.errors)

    def visit_yara_file(self, node: YaraFile) -> None:
        # Process imports first
        for imp in node.imports:
            self.visit(imp)

        # Process rules in source order. YARA rule references can point at the
        # current rule or previously declared rules, but not forward.
        seen_rules: set[str] = set()
        for rule in node.rules:
            if rule.name in seen_rules:
                self.errors.append(f"Duplicate rule identifier: {rule.name}")
                continue
            seen_rules.add(rule.name)
            try:
                self.env.add_rule(rule.name)
            except ValueError as exc:
                self.errors.append(str(exc))
                continue
            if self._base_env_has_variable(rule.name):
                self.errors.append(f"Duplicate rule identifier: {rule.name}")
                continue
            self.visit(rule)

    def visit_import(self, node: Import) -> None:
        try:
            module = ModuleLoader().get_module(node.module)
        except (TypeError, ValueError) as exc:
            self.errors.append(str(exc))
            return

        if module is None:
            self.errors.append(f"Unknown module: {node.module}")
            return

        # Use alias if provided, otherwise use module name
        name = node.alias if node.alias else node.module
        try:
            self.env.add_module(name, node.module)
        except ValueError as exc:
            self.errors.append(str(exc))

    def visit_rule(self, node: Rule) -> None:
        seen_tags: set[str] = set()
        for tag in node.tags:
            if tag.name in seen_tags:
                self.errors.append(f"Duplicate tag identifier '{tag.name}' in rule '{node.name}'")
            else:
                seen_tags.add(tag.name)

        previous_strings = set(self.env.strings)
        previous_anonymous_strings = set(self.env.anonymous_strings)

        rule_strings: set[str] = set()
        rule_anonymous_strings: set[str] = set()
        for string in node.strings:
            try:
                string_id = _normalize_string_id(string.identifier)
            except (TypeError, ValueError) as exc:
                self.errors.append(str(exc))
                continue
            rule_strings.add(string_id)
            if getattr(string, "is_anonymous", False):
                rule_anonymous_strings.add(string_id)

        self.env.strings = set(rule_strings)
        self.env.anonymous_strings = set(rule_anonymous_strings)

        try:
            # Type check condition
            if node.condition is not None:
                try:
                    cond_type = self.inference.infer(node.condition)
                except (TypeError, ValueError) as exc:
                    self.errors.append(str(exc))
                    return
                # In YARA, integer conditions are valid (0 = false, non-zero = true)
                # Also string counts and offsets return integers that can be used as conditions
                # String identifiers ($a, $b) are also valid as boolean conditions
                if not isinstance(
                    cond_type,
                    BooleanType
                    | IntegerType
                    | DoubleType
                    | FloatType
                    | RegexType
                    | StringType
                    | StringIdentifierType,
                ):
                    self.errors.append(
                        "Rule condition must be boolean, integer, double, regex, string, "
                        f"or string identifier, got {cond_type}",
                    )
        finally:
            self.env.strings = previous_strings | rule_strings
            self.env.anonymous_strings = previous_anonymous_strings | rule_anonymous_strings

    # Explicit no-ops for coverage and compatibility with tests that call visit_* directly.
    def visit_include(self, _node: Any) -> None:
        return None

    def visit_tag(self, _node: Any) -> None:
        return None

    def visit_string_definition(self, _node: Any) -> None:
        return None

    def visit_plain_string(self, _node: Any) -> None:
        return None

    def visit_hex_string(self, _node: Any) -> None:
        return None

    def visit_regex_string(self, _node: Any) -> None:
        return None

    def visit_string_modifier(self, _node: Any) -> None:
        return None

    def visit_hex_token(self, _node: Any) -> None:
        return None

    def visit_hex_byte(self, _node: Any) -> None:
        return None

    def visit_hex_negated_byte(self, _node: Any) -> None:
        return None

    def visit_hex_wildcard(self, _node: Any) -> None:
        return None

    def visit_hex_jump(self, _node: Any) -> None:
        return None

    def visit_hex_alternative(self, _node: Any) -> None:
        return None

    def visit_hex_nibble(self, _node: Any) -> None:
        return None

    def visit_expression(self, _node: Any) -> None:
        return None

    def visit_identifier(self, _node: Any) -> None:
        return None

    def visit_string_identifier(self, _node: Any) -> None:
        return None

    def visit_string_wildcard(self, _node: Any) -> None:
        return None

    def visit_string_count(self, _node: Any) -> None:
        return None

    def visit_string_offset(self, _node: Any) -> None:
        return None

    def visit_string_length(self, _node: Any) -> None:
        return None

    def visit_integer_literal(self, _node: Any) -> None:
        return None

    def visit_double_literal(self, _node: Any) -> None:
        return None

    def visit_string_literal(self, _node: Any) -> None:
        return None

    def visit_boolean_literal(self, _node: Any) -> None:
        return None

    def visit_binary_expression(self, _node: Any) -> None:
        return None

    def visit_unary_expression(self, _node: Any) -> None:
        return None

    def visit_parentheses_expression(self, _node: Any) -> None:
        return None

    def visit_set_expression(self, _node: Any) -> None:
        return None

    def visit_range_expression(self, _node: Any) -> None:
        return None

    def visit_function_call(self, _node: Any) -> None:
        return None

    def visit_array_access(self, _node: Any) -> None:
        return None

    def visit_member_access(self, _node: Any) -> None:
        return None

    def visit_condition(self, _node: Any) -> None:
        return None

    def visit_for_expression(self, _node: Any) -> None:
        return None

    def visit_for_of_expression(self, _node: Any) -> None:
        return None

    def visit_at_expression(self, _node: Any) -> None:
        return None

    def visit_in_expression(self, _node: Any) -> None:
        return None

    def visit_of_expression(self, _node: Any) -> None:
        return None

    def visit_meta(self, _node: Any) -> None:
        return None

    def visit_module_reference(self, _node: Any) -> None:
        return None

    def visit_dictionary_access(self, _node: Any) -> None:
        return None

    def visit_comment(self, _node: Any) -> None:
        return None

    def visit_comment_group(self, _node: Any) -> None:
        return None

    def visit_defined_expression(self, _node: Any) -> None:
        return None

    def visit_regex_literal(self, _node: Any) -> None:
        return None

    def visit_string_operator_expression(self, _node: Any) -> None:
        return None

    def visit_extern_import(self, _node: Any) -> None:
        return None

    def visit_extern_namespace(self, _node: Any) -> None:
        return None

    def visit_extern_rule(self, _node: Any) -> None:
        return None

    def visit_extern_rule_reference(self, _node: Any) -> None:
        return None

    def visit_in_rule_pragma(self, _node: Any) -> None:
        return None

    def visit_pragma(self, _node: Any) -> None:
        return None

    def visit_pragma_block(self, _node: Any) -> None:
        return None


class TypeValidator:
    """High-level type validation API."""

    @staticmethod
    def validate(ast: YaraFile) -> tuple[bool, list[str]]:
        """Validate types in YARA file. Returns (is_valid, errors)."""
        checker = TypeChecker()
        errors = checker.check(ast)
        return len(errors) == 0, errors

    @staticmethod
    def validate_expression(
        expr: Expression,
        env: TypeEnvironment | None = None,
    ) -> tuple[YaraType, list[str]]:
        """Validate and infer type of expression."""
        if env is None:
            env = TypeEnvironment()

        inference = TypeInference(env)
        try:
            expr_type = inference.infer(expr)
        except (AttributeError, TypeError, ValueError) as exc:
            return UnknownType(), [str(exc), *inference.errors]
        return expr_type, inference.errors
