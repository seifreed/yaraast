"""Type validation logic for YARA AST."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Expression
from yaraast.ast.rules import Import, Rule
from yaraast.visitor import BaseVisitor

from ._inference import TypeInference
from ._registry import BooleanType, IntegerType, StringIdentifierType, TypeEnvironment, YaraType


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
        if self._base_env is not None:
            return _copy_type_environment(self._base_env)
        return TypeEnvironment()

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
        return self.errors

    def visit_yara_file(self, node: YaraFile) -> None:
        # Process imports first
        for imp in node.imports:
            self.visit(imp)

        # Add all rule names first to support forward references
        for rule in node.rules:
            self.env.add_rule(rule.name)

        # Process rules
        for rule in node.rules:
            self.visit(rule)

    def visit_import(self, node: Import) -> None:
        # Use alias if provided, otherwise use module name
        name = node.alias if node.alias else node.module
        self.env.add_module(name, node.module)

    def visit_rule(self, node: Rule) -> None:
        previous_strings = set(self.env.strings)
        previous_anonymous_strings = set(self.env.anonymous_strings)

        rule_strings: set[str] = set()
        rule_anonymous_strings: set[str] = set()
        for string in node.strings:
            rule_strings.add(string.identifier)
            if getattr(string, "is_anonymous", False):
                rule_anonymous_strings.add(string.identifier)

        self.env.strings = set(rule_strings)
        self.env.anonymous_strings = set(rule_anonymous_strings)

        try:
            # Type check condition
            if node.condition:
                cond_type = self.inference.infer(node.condition)
                # In YARA, integer conditions are valid (0 = false, non-zero = true)
                # Also string counts and offsets return integers that can be used as conditions
                # String identifiers ($a, $b) are also valid as boolean conditions
                if not isinstance(
                    cond_type,
                    BooleanType | IntegerType | StringIdentifierType,
                ):
                    self.errors.append(
                        f"Rule condition must be boolean, integer, or string identifier, got {cond_type}",
                    )
        finally:
            self.env.strings = previous_strings | rule_strings
            self.env.anonymous_strings = previous_anonymous_strings | rule_anonymous_strings

    # Explicit no-ops for coverage and compatibility with tests that call visit_* directly.
    def visit_include(self, _node) -> None:
        return None

    def visit_tag(self, _node) -> None:
        return None

    def visit_string_definition(self, _node) -> None:
        return None

    def visit_plain_string(self, _node) -> None:
        return None

    def visit_hex_string(self, _node) -> None:
        return None

    def visit_regex_string(self, _node) -> None:
        return None

    def visit_string_modifier(self, _node) -> None:
        return None

    def visit_hex_token(self, _node) -> None:
        return None

    def visit_hex_byte(self, _node) -> None:
        return None

    def visit_hex_negated_byte(self, _node) -> None:
        return None

    def visit_hex_wildcard(self, _node) -> None:
        return None

    def visit_hex_jump(self, _node) -> None:
        return None

    def visit_hex_alternative(self, _node) -> None:
        return None

    def visit_hex_nibble(self, _node) -> None:
        return None

    def visit_expression(self, _node) -> None:
        return None

    def visit_identifier(self, _node) -> None:
        return None

    def visit_string_identifier(self, _node) -> None:
        return None

    def visit_string_wildcard(self, _node) -> None:
        return None

    def visit_string_count(self, _node) -> None:
        return None

    def visit_string_offset(self, _node) -> None:
        return None

    def visit_string_length(self, _node) -> None:
        return None

    def visit_integer_literal(self, _node) -> None:
        return None

    def visit_double_literal(self, _node) -> None:
        return None

    def visit_string_literal(self, _node) -> None:
        return None

    def visit_boolean_literal(self, _node) -> None:
        return None

    def visit_binary_expression(self, _node) -> None:
        return None

    def visit_unary_expression(self, _node) -> None:
        return None

    def visit_parentheses_expression(self, _node) -> None:
        return None

    def visit_set_expression(self, _node) -> None:
        return None

    def visit_range_expression(self, _node) -> None:
        return None

    def visit_function_call(self, _node) -> None:
        return None

    def visit_array_access(self, _node) -> None:
        return None

    def visit_member_access(self, _node) -> None:
        return None

    def visit_condition(self, _node) -> None:
        return None

    def visit_for_expression(self, _node) -> None:
        return None

    def visit_for_of_expression(self, _node) -> None:
        return None

    def visit_at_expression(self, _node) -> None:
        return None

    def visit_in_expression(self, _node) -> None:
        return None

    def visit_of_expression(self, _node) -> None:
        return None

    def visit_meta(self, _node) -> None:
        return None

    def visit_module_reference(self, _node) -> None:
        return None

    def visit_dictionary_access(self, _node) -> None:
        return None

    def visit_comment(self, _node) -> None:
        return None

    def visit_comment_group(self, _node) -> None:
        return None

    def visit_defined_expression(self, _node) -> None:
        return None

    def visit_regex_literal(self, _node) -> None:
        return None

    def visit_string_operator_expression(self, _node) -> None:
        return None

    def visit_extern_import(self, _node) -> None:
        return None

    def visit_extern_namespace(self, _node) -> None:
        return None

    def visit_extern_rule(self, _node) -> None:
        return None

    def visit_extern_rule_reference(self, _node) -> None:
        return None

    def visit_in_rule_pragma(self, _node) -> None:
        return None

    def visit_pragma(self, _node) -> None:
        return None

    def visit_pragma_block(self, _node) -> None:
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
        expr,
        env: TypeEnvironment | None = None,
    ) -> tuple[YaraType, list[str]]:
        """Validate and infer type of expression."""
        if env is None:
            env = TypeEnvironment()

        inference = TypeInference(env)
        expr_type = inference.infer(expr)
        return expr_type, inference.errors
