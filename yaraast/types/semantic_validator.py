"""Enhanced semantic validation for YARA AST."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.expressions import Expression, FunctionCall, MemberAccess
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import StringDefinition
from yaraast.types.module_loader import ModuleLoader
from yaraast.types.type_system import (
    FunctionDefinition,
    ModuleDefinition,
    TypeChecker,
    TypeEnvironment,
    TypeInference,
    YaraType,
)
from yaraast.visitor import ASTVisitor


@dataclass
class ValidationError:
    """Rich validation error with location information."""

    message: str
    location: Optional[Location] = None
    error_type: str = "semantic"
    severity: str = "error"  # "error", "warning", "info"
    suggestion: Optional[str] = None

    def __str__(self) -> str:
        """Format error message with location."""
        if self.location:
            return f"{self.location.file}:{self.location.line}:{self.location.column}: {self.severity}: {self.message}"
        return f"{self.severity}: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "message": self.message,
            "error_type": self.error_type,
            "severity": self.severity
        }
        if self.location:
            result["location"] = {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column
            }
        if self.suggestion:
            result["suggestion"] = self.suggestion
        return result


@dataclass
class ValidationResult:
    """Result of semantic validation."""

    is_valid: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)

    def add_error(self, message: str, location: Optional[Location] = None,
                  suggestion: Optional[str] = None) -> None:
        """Add validation error."""
        error = ValidationError(message, location, "semantic", "error", suggestion)
        self.errors.append(error)
        self.is_valid = False

    def add_warning(self, message: str, location: Optional[Location] = None,
                    suggestion: Optional[str] = None) -> None:
        """Add validation warning."""
        warning = ValidationError(message, location, "semantic", "warning", suggestion)
        self.warnings.append(warning)

    def combine(self, other: 'ValidationResult') -> None:
        """Combine with another validation result."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if not other.is_valid:
            self.is_valid = False

    @property
    def total_issues(self) -> int:
        """Total number of issues (errors + warnings)."""
        return len(self.errors) + len(self.warnings)


class StringIdentifierValidator(ASTVisitor[None]):
    """Validator for string identifier uniqueness within rules."""

    def __init__(self, result: ValidationResult):
        self.result = result
        self.current_rule_strings: Set[str] = set()
        self.current_rule_name: Optional[str] = None

    def visit_rule(self, node: Rule) -> None:
        """Validate string identifier uniqueness within rule."""
        self.current_rule_strings.clear()
        self.current_rule_name = node.name

        # Check all string definitions in the rule
        for string_def in node.strings:
            self.visit(string_def)

    def visit_string_definition(self, node: StringDefinition) -> None:
        """Check string identifier uniqueness."""
        # Remove $ prefix if present for comparison
        identifier = node.identifier
        if identifier.startswith('$'):
            identifier = identifier[1:]

        if identifier in self.current_rule_strings:
            self.result.add_error(
                f"Duplicate string identifier '${identifier}' in rule '{self.current_rule_name}'",
                node.location,
                f"String identifiers must be unique within each rule. Consider renaming to '${identifier}_2' or similar."
            )
        else:
            self.current_rule_strings.add(identifier)

    # Default implementations for other node types
    def visit_yara_file(self, node): pass
    def visit_import(self, node): pass
    def visit_include(self, node): pass
    def visit_tag(self, node): pass
    def visit_plain_string(self, node): self.visit_string_definition(node)
    def visit_hex_string(self, node): self.visit_string_definition(node)
    def visit_regex_string(self, node): self.visit_string_definition(node)
    def visit_string_modifier(self, node): pass
    def visit_hex_token(self, node): pass
    def visit_hex_byte(self, node): pass
    def visit_hex_wildcard(self, node): pass
    def visit_hex_jump(self, node): pass
    def visit_hex_alternative(self, node): pass
    def visit_hex_nibble(self, node): pass
    def visit_expression(self, node): pass
    def visit_identifier(self, node): pass
    def visit_string_identifier(self, node): pass
    def visit_string_count(self, node): pass
    def visit_string_offset(self, node): pass
    def visit_string_length(self, node): pass
    def visit_integer_literal(self, node): pass
    def visit_double_literal(self, node): pass
    def visit_string_literal(self, node): pass
    def visit_boolean_literal(self, node): pass
    def visit_binary_expression(self, node): pass
    def visit_unary_expression(self, node): pass
    def visit_parentheses_expression(self, node): pass
    def visit_set_expression(self, node): pass
    def visit_range_expression(self, node): pass
    def visit_function_call(self, node): pass
    def visit_array_access(self, node): pass
    def visit_member_access(self, node): pass
    def visit_condition(self, node): pass
    def visit_for_expression(self, node): pass
    def visit_for_of_expression(self, node): pass
    def visit_at_expression(self, node): pass
    def visit_in_expression(self, node): pass
    def visit_of_expression(self, node): pass
    def visit_meta(self, node): pass
    def visit_module_reference(self, node): pass
    def visit_dictionary_access(self, node): pass
    def visit_comment(self, node): pass
    def visit_comment_group(self, node): pass
    def visit_defined_expression(self, node): pass
    def visit_regex_literal(self, node): pass
    def visit_string_operator_expression(self, node): pass


class FunctionCallValidator(ASTVisitor[None]):
    """Validator for function calls and module function existence."""

    def __init__(self, result: ValidationResult, env: TypeEnvironment):
        self.result = result
        self.env = env
        self.module_loader = ModuleLoader()

    def visit_function_call(self, node: FunctionCall) -> None:
        """Validate function call existence and arity."""
        # Check if it's a module function call (e.g., pe.imphash)
        if '.' in node.function:
            parts = node.function.split('.', 1)
            if len(parts) == 2:
                module_name, func_name = parts
                self._validate_module_function_call(node, module_name, func_name)
        else:
            # Built-in function call
            self._validate_builtin_function_call(node)

        # Recursively validate function arguments
        for arg in node.arguments:
            self.visit(arg)

    def _validate_module_function_call(self, node: FunctionCall,
                                     module_name: str, func_name: str) -> None:
        """Validate module function call."""
        # Check if module is imported
        if not self.env.has_module(module_name):
            self.result.add_error(
                f"Module '{module_name}' not imported, cannot call '{node.function}'",
                node.location,
                f"Add 'import \"{module_name}\"' at the top of your file."
            )
            return

        # Get actual module name (handles aliases)
        actual_module = self.env.get_module_name(module_name)
        if not actual_module:
            return

        # Get module definition
        module_def = self.module_loader.get_module(actual_module)
        if not module_def:
            self.result.add_warning(
                f"Module definition for '{actual_module}' not found, cannot validate function '{func_name}'",
                node.location
            )
            return

        # Check if function exists in module
        if func_name not in module_def.functions:
            available_funcs = list(module_def.functions.keys())
            self.result.add_error(
                f"Function '{func_name}' not found in module '{actual_module}'",
                node.location,
                f"Available functions: {', '.join(available_funcs)}" if available_funcs else "No functions available"
            )
            return

        # Validate function arity and parameter types
        func_def = module_def.functions[func_name]
        self._validate_function_arity(node, func_def)

    def _validate_builtin_function_call(self, node: FunctionCall) -> None:
        """Validate built-in function call."""
        builtin_functions = {
            # Integer reading functions
            "uint8": (1, 1),   # (min_args, max_args)
            "uint16": (1, 1),
            "uint32": (1, 1),
            "int8": (1, 1),
            "int16": (1, 1),
            "int32": (1, 1),
            # Big-endian variants
            "uint8be": (1, 1),
            "uint16be": (1, 1),
            "uint32be": (1, 1),
            "int8be": (1, 1),
            "int16be": (1, 1),
            "int32be": (1, 1),
            # Little-endian variants
            "uint16le": (1, 1),
            "uint32le": (1, 1),
            "int16le": (1, 1),
            "int32le": (1, 1),
        }

        func_name = node.function
        if func_name in builtin_functions:
            min_args, max_args = builtin_functions[func_name]
            actual_args = len(node.arguments)

            if actual_args < min_args:
                self.result.add_error(
                    f"Function '{func_name}' expects at least {min_args} argument(s), got {actual_args}",
                    node.location
                )
            elif actual_args > max_args:
                self.result.add_error(
                    f"Function '{func_name}' expects at most {max_args} argument(s), got {actual_args}",
                    node.location
                )
        else:
            # Unknown function - could be user-defined or module function without prefix
            self.result.add_warning(
                f"Unknown function '{func_name}'. If this is a module function, use 'module.{func_name}' syntax.",
                node.location
            )

    def _validate_function_arity(self, node: FunctionCall, func_def: FunctionDefinition) -> None:
        """Validate function argument count and types."""
        expected_args = len(func_def.parameters)
        actual_args = len(node.arguments)

        if actual_args != expected_args:
            param_names = [p[0] for p in func_def.parameters]
            self.result.add_error(
                f"Function '{func_def.name}' expects {expected_args} argument(s) ({', '.join(param_names)}), got {actual_args}",
                node.location
            )
            return

        # TODO: Add parameter type validation
        # This would require type inference on the arguments
        # For now, we just validate arity

    # Recursive visitation methods
    def visit_binary_expression(self, node):
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node):
        self.visit(node.operand)

    def visit_member_access(self, node):
        # Don't validate module.function as function call here
        # It's handled in function_call validation
        self.visit(node.object)

    def visit_parentheses_expression(self, node):
        self.visit(node.expression)

    def visit_set_expression(self, node):
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node):
        self.visit(node.low)
        self.visit(node.high)

    def visit_array_access(self, node):
        self.visit(node.array)
        self.visit(node.index)

    def visit_for_expression(self, node):
        self.visit(node.iterable)
        self.visit(node.body)

    def visit_for_of_expression(self, node):
        self.visit(node.string_set)
        if node.condition:
            self.visit(node.condition)

    def visit_at_expression(self, node):
        self.visit(node.offset)

    def visit_in_expression(self, node):
        self.visit(node.range)

    def visit_of_expression(self, node):
        self.visit(node.quantifier)
        self.visit(node.string_set)

    # Default implementations for leaf nodes and other types
    def visit_yara_file(self, node): pass
    def visit_import(self, node): pass
    def visit_include(self, node): pass
    def visit_rule(self, node): pass
    def visit_tag(self, node): pass
    def visit_string_definition(self, node): pass
    def visit_plain_string(self, node): pass
    def visit_hex_string(self, node): pass
    def visit_regex_string(self, node): pass
    def visit_string_modifier(self, node): pass
    def visit_hex_token(self, node): pass
    def visit_hex_byte(self, node): pass
    def visit_hex_wildcard(self, node): pass
    def visit_hex_jump(self, node): pass
    def visit_hex_alternative(self, node): pass
    def visit_hex_nibble(self, node): pass
    def visit_expression(self, node): pass
    def visit_identifier(self, node): pass
    def visit_string_identifier(self, node): pass
    def visit_string_count(self, node): pass
    def visit_string_offset(self, node): pass
    def visit_string_length(self, node): pass
    def visit_integer_literal(self, node): pass
    def visit_double_literal(self, node): pass
    def visit_string_literal(self, node): pass
    def visit_boolean_literal(self, node): pass
    def visit_condition(self, node): pass
    def visit_meta(self, node): pass
    def visit_module_reference(self, node): pass
    def visit_dictionary_access(self, node): pass
    def visit_comment(self, node): pass
    def visit_comment_group(self, node): pass
    def visit_defined_expression(self, node): pass
    def visit_regex_literal(self, node): pass
    def visit_string_operator_expression(self, node): pass


class SemanticValidator:
    """Comprehensive semantic validator for YARA AST."""

    def __init__(self):
        self.module_loader = ModuleLoader()

    def validate(self, ast: YaraFile) -> ValidationResult:
        """Perform complete semantic validation on YARA file."""
        result = ValidationResult()

        # Set up type environment
        env = TypeEnvironment()

        # Process imports first to populate module environment
        for imp in ast.imports:
            alias = imp.alias if imp.alias else imp.module
            env.add_module(alias, imp.module)

        # Add string identifiers to environment for each rule
        for rule in ast.rules:
            for string_def in rule.strings:
                env.add_string(string_def.identifier)

        # 1. Validate string identifier uniqueness per rule
        string_validator = StringIdentifierValidator(result)
        for rule in ast.rules:
            string_validator.visit(rule)

        # 2. Validate function calls and module function existence
        function_validator = FunctionCallValidator(result, env)
        for rule in ast.rules:
            if rule.condition:
                function_validator.visit(rule.condition)

        # 3. Run existing type checker for comprehensive type validation
        type_checker = TypeChecker()
        type_errors = type_checker.check(ast)

        # Convert type checker errors to ValidationError objects
        for error_msg in type_errors:
            result.add_error(error_msg, suggestion="Check variable types and function signatures")

        return result

    def validate_rule(self, rule: Rule, env: Optional[TypeEnvironment] = None) -> ValidationResult:
        """Validate a single rule."""
        result = ValidationResult()

        if env is None:
            env = TypeEnvironment()

        # Add rule's string identifiers to environment
        for string_def in rule.strings:
            env.add_string(string_def.identifier)

        # Validate string uniqueness
        string_validator = StringIdentifierValidator(result)
        string_validator.visit(rule)

        # Validate function calls in condition
        if rule.condition:
            function_validator = FunctionCallValidator(result, env)
            function_validator.visit(rule.condition)

        return result

    def validate_expression(self, expr: Expression, env: Optional[TypeEnvironment] = None) -> ValidationResult:
        """Validate a single expression."""
        result = ValidationResult()

        if env is None:
            env = TypeEnvironment()

        # Validate function calls in expression
        function_validator = FunctionCallValidator(result, env)
        function_validator.visit(expr)

        return result


# Convenience functions for easy usage
def validate_yara_file(ast: YaraFile) -> ValidationResult:
    """Validate YARA file with comprehensive semantic checks."""
    validator = SemanticValidator()
    return validator.validate(ast)


def validate_yara_rule(rule: Rule, env: Optional[TypeEnvironment] = None) -> ValidationResult:
    """Validate a single YARA rule."""
    validator = SemanticValidator()
    return validator.validate_rule(rule, env)


def check_string_uniqueness(rule: Rule) -> List[ValidationError]:
    """Check string identifier uniqueness within a rule."""
    result = ValidationResult()
    validator = StringIdentifierValidator(result)
    validator.visit(rule)
    return result.errors


def check_function_calls(expr: Expression, env: TypeEnvironment) -> List[ValidationError]:
    """Check function calls in an expression."""
    result = ValidationResult()
    validator = FunctionCallValidator(result, env)
    validator.visit(expr)
    return result.errors
