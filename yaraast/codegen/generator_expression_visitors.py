"""Expression rendering helpers for CodeGenerator."""

from __future__ import annotations

from typing import Any, cast

from yaraast.codegen.generator_formatting import (
    validate_yara_identifier,
    validate_yara_identifier_path,
)
from yaraast.codegen.generator_helpers import format_string_reference_identifier

_BINARY_PRECEDENCE = {
    "or": 1,
    "and": 2,
    "==": 3,
    "!=": 3,
    "<": 3,
    "<=": 3,
    ">": 3,
    ">=": 3,
    "contains": 3,
    "matches": 3,
    "startswith": 3,
    "endswith": 3,
    "icontains": 3,
    "istartswith": 3,
    "iendswith": 3,
    "iequals": 3,
    "|": 4,
    "^": 5,
    "&": 6,
    "<<": 7,
    ">>": 7,
    "+": 8,
    "-": 8,
    "*": 9,
    "/": 9,
    "\\": 9,
    "%": 9,
}
_UNARY_OPERATORS = frozenset({"not", "-", "~"})
_NUMERIC_BINARY_OPERATORS = frozenset({"+", "-", "*", "/", "\\"})
_INTEGER_BINARY_OPERATORS = frozenset({"%", "&", "|", "^", "<<", ">>"})
_COMPARISON_BINARY_OPERATORS = frozenset({"<", "<=", ">", ">=", "==", "!="})
_STRING_BINARY_OPERATORS = frozenset(
    {
        "contains",
        "matches",
        "startswith",
        "endswith",
        "icontains",
        "istartswith",
        "iendswith",
        "iequals",
    }
)
_INTEGER_READ_FUNCTIONS = frozenset(
    {
        "int8",
        "int16",
        "int16be",
        "int32",
        "int32be",
        "int8be",
        "uint8",
        "uint16",
        "uint16be",
        "uint32",
        "uint32be",
        "uint8be",
    }
)
_UNSUPPORTED_INTEGER_READ_ALIASES = frozenset({"int16le", "int32le", "uint16le", "uint32le"})
_HASH_FUNCTIONS = frozenset({"checksum32", "crc32", "md5", "sha1", "sha256"})
_MATH_STRING_REGION_FUNCTIONS = frozenset(
    {"entropy", "mean", "monte_carlo_pi", "serial_correlation"}
)
_MATH_INTEGER_REGION_FUNCTIONS = frozenset({"count", "mode", "percentage"})


def _precedence(operator: str) -> int:
    return _BINARY_PRECEDENCE.get(operator, 100)


def _render_binary_operator(operator: str) -> str:
    if operator not in _BINARY_PRECEDENCE:
        msg = f"Invalid binary operator '{operator}' for libyara output"
        raise ValueError(msg)
    if operator == "/":
        return "\\"
    return operator


def _render_unary_operator(operator: str) -> str:
    if operator in _UNARY_OPERATORS:
        return operator
    msg = f"Invalid unary operator '{operator}' for libyara output"
    raise ValueError(msg)


def _reject_boolean_expression(value: Any, message: str) -> None:
    from yaraast.ast.expressions import BooleanLiteral, ParenthesesExpression

    if isinstance(value, bool | BooleanLiteral):
        raise ValueError(message)
    if isinstance(value, ParenthesesExpression):
        _reject_boolean_expression(value.expression, message)


def _is_definitely_non_numeric_expression(value: Any) -> bool:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringLiteral,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_definitely_non_numeric_expression(value.expression)
    return isinstance(
        value,
        bool | BooleanLiteral | StringLiteral | RegexLiteral | StringIdentifier,
    )


def _is_definitely_non_integer_expression(value: Any) -> bool:
    from yaraast.ast.expressions import DoubleLiteral, ParenthesesExpression, UnaryExpression

    if isinstance(value, ParenthesesExpression):
        return _is_definitely_non_integer_expression(value.expression)
    if isinstance(value, UnaryExpression):
        operand = _unwrap_parenthesized_expression(value.operand)
        if value.operator == "-" and isinstance(operand, DoubleLiteral | float):
            return True
    return isinstance(value, float | DoubleLiteral) or _is_definitely_non_numeric_expression(value)


def _is_definitely_non_iterable_expression(value: Any) -> bool:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        IntegerLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringLiteral,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_definitely_non_iterable_expression(value.expression)
    return isinstance(
        value,
        (
            bool,
            int,
            float,
            BooleanLiteral,
            DoubleLiteral,
            IntegerLiteral,
            RegexLiteral,
            StringIdentifier,
            StringLiteral,
        ),
    )


def _is_invalid_for_iterable_set_item(value: Any) -> bool:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringWildcard,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_invalid_for_iterable_set_item(value.expression)
    return isinstance(
        value,
        (
            bool,
            float,
            BooleanLiteral,
            DoubleLiteral,
            RegexLiteral,
            StringIdentifier,
            StringWildcard,
        ),
    )


def _reject_invalid_binary_numeric_operands(node: Any) -> None:
    if node.operator in _NUMERIC_BINARY_OPERATORS:
        if _is_definitely_non_numeric_expression(node.left):
            msg = f"Left operand of '{node.operator}' must be numeric for libyara output"
            raise ValueError(msg)
        if _is_definitely_non_numeric_expression(node.right):
            msg = f"Right operand of '{node.operator}' must be numeric for libyara output"
            raise ValueError(msg)
    if node.operator in _INTEGER_BINARY_OPERATORS:
        if _is_definitely_non_integer_expression(node.left):
            msg = f"Left operand of '{node.operator}' must be integer for libyara output"
            raise ValueError(msg)
        if _is_definitely_non_integer_expression(node.right):
            msg = f"Right operand of '{node.operator}' must be integer for libyara output"
            raise ValueError(msg)


def _unwrap_parenthesized_expression(value: Any) -> Any:
    from yaraast.ast.expressions import ParenthesesExpression

    if isinstance(value, ParenthesesExpression):
        return _unwrap_parenthesized_expression(value.expression)
    return value


def _reject_invalid_string_binary_operands(node: Any) -> None:
    if node.operator not in _STRING_BINARY_OPERATORS:
        return

    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        IntegerLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringLiteral,
    )

    left = _unwrap_parenthesized_expression(node.left)
    right = _unwrap_parenthesized_expression(node.right)
    left_type = _constant_comparison_operand_type(left)
    right_type = _constant_comparison_operand_type(right)
    invalid_left = (
        bool,
        int,
        float,
        BooleanLiteral,
        IntegerLiteral,
        DoubleLiteral,
        RegexLiteral,
        StringIdentifier,
    )
    if isinstance(left, invalid_left) or left_type in {"integer", "double"}:
        msg = (
            f"Left operand of '{node.operator}' must be string-like or array " "for libyara output"
        )
        raise ValueError(msg)
    if node.operator == "matches":
        if isinstance(node.right, ParenthesesExpression) and isinstance(right, RegexLiteral):
            msg = "Right operand of 'matches' must be regex for libyara output"
            raise ValueError(msg)
        if isinstance(
            right,
            StringLiteral | BooleanLiteral | IntegerLiteral | DoubleLiteral | StringIdentifier,
        ) or right_type in {"integer", "double"}:
            msg = "Right operand of 'matches' must be regex for libyara output"
            raise ValueError(msg)
        return
    if isinstance(
        right, bool | int | float | BooleanLiteral | IntegerLiteral | DoubleLiteral
    ) or right_type in {"integer", "double"}:
        msg = f"Right operand of '{node.operator}' must be string for libyara output"
        raise ValueError(msg)
    if isinstance(right, RegexLiteral | StringIdentifier):
        msg = f"Right operand of '{node.operator}' must be string for libyara output"
        raise ValueError(msg)


def _constant_integer_value(value: Any) -> int | None:
    from yaraast.ast.expressions import IntegerLiteral, ParenthesesExpression, UnaryExpression

    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if (
        isinstance(value, IntegerLiteral)
        and isinstance(value.value, int)
        and not isinstance(value.value, bool)
    ):
        return value.value
    if isinstance(value, ParenthesesExpression):
        return _constant_integer_value(value.expression)
    if isinstance(value, UnaryExpression):
        operand = _constant_integer_value(value.operand)
        if operand is None:
            return None
        if value.operator == "-":
            return -operand
        if value.operator == "~":
            return ~operand
    return None


def _reject_zero_integer_divisor(node: Any) -> None:
    if node.operator not in {"/", "\\", "%"}:
        return
    if _constant_integer_value(node.right) == 0:
        msg = f"Right operand of '{node.operator}' cannot be zero for libyara output"
        raise ValueError(msg)


def _reject_negative_shift_count(node: Any) -> None:
    if node.operator not in {"<<", ">>"}:
        return
    shift_count = _constant_integer_value(node.right)
    if shift_count is not None and shift_count < 0:
        msg = f"Right operand of '{node.operator}' cannot be negative for libyara output"
        raise ValueError(msg)


def _constant_comparison_operand_type(value: Any) -> str | None:
    from yaraast.ast.expressions import (
        DoubleLiteral,
        FunctionCall,
        Identifier,
        StringCount,
        StringLength,
        StringLiteral,
        StringOffset,
        UnaryExpression,
    )

    value = _unwrap_parenthesized_expression(value)
    if isinstance(value, StringLiteral | str):
        return "string"
    if _constant_integer_value(value) is not None:
        return "integer"
    if isinstance(value, Identifier) and value.name in {"entrypoint", "filesize"}:
        return "integer"
    if isinstance(value, StringCount | StringLength | StringOffset):
        return "integer"
    if (
        isinstance(value, FunctionCall)
        and value.receiver is None
        and value.function in _INTEGER_READ_FUNCTIONS
    ):
        return "integer"
    if isinstance(value, UnaryExpression):
        operand = _unwrap_parenthesized_expression(value.operand)
        if value.operator == "-" and isinstance(operand, DoubleLiteral | float):
            return "double"
    if isinstance(value, DoubleLiteral | float):
        return "double"
    return None


def _reject_invalid_comparison_operands(node: Any) -> None:
    if node.operator not in _COMPARISON_BINARY_OPERATORS:
        return

    from yaraast.ast.expressions import BooleanLiteral, RegexLiteral

    left = _unwrap_parenthesized_expression(node.left)
    right = _unwrap_parenthesized_expression(node.right)
    if isinstance(left, BooleanLiteral | bool) or isinstance(right, BooleanLiteral | bool):
        msg = f"Boolean operands cannot be used with '{node.operator}' comparisons"
        raise ValueError(msg)
    if isinstance(left, RegexLiteral) or isinstance(right, RegexLiteral):
        msg = f"Regex operands cannot be used with '{node.operator}' comparisons"
        raise ValueError(msg)
    left_type = _constant_comparison_operand_type(left)
    right_type = _constant_comparison_operand_type(right)
    if (left_type == "string" and right_type in {"integer", "double"}) or (
        right_type == "string" and left_type in {"integer", "double"}
    ):
        msg = (
            f"Incompatible types for '{node.operator}': {left_type} and {right_type} "
            "for libyara output"
        )
        raise ValueError(msg)


def validate_binary_expression_operands(node: Any) -> None:
    _reject_invalid_comparison_operands(node)
    _reject_zero_integer_divisor(node)
    _reject_negative_shift_count(node)
    _reject_invalid_binary_numeric_operands(node)
    _reject_invalid_string_binary_operands(node)


def _visit_binary_operand(generator: Any, parent: Any, operand: Any, *, is_right: bool) -> str:
    from yaraast.ast.expressions import BinaryExpression

    rendered = cast(str, generator.visit(operand))
    if isinstance(operand, BinaryExpression) and (
        _precedence(operand.operator) < _precedence(parent.operator)
        or (is_right and _precedence(operand.operator) == _precedence(parent.operator))
    ):
        return f"({rendered})"
    return rendered


def visit_binary_expression(generator: Any, node: Any) -> str:
    validate_binary_expression_operands(node)
    left = _visit_binary_operand(generator, node, node.left, is_right=False)
    right = _visit_binary_operand(generator, node, node.right, is_right=True)
    operator = _render_binary_operator(node.operator)
    return f"{left} {operator} {right}"


def visit_unary_expression(generator: Any, node: Any) -> str:
    operator = _render_unary_operator(node.operator)
    if operator == "-" and _is_definitely_non_numeric_expression(node.operand):
        msg = "Operand of '-' must be numeric for libyara output"
        raise ValueError(msg)
    if operator == "~" and _is_definitely_non_integer_expression(node.operand):
        msg = "Operand of '~' must be integer for libyara output"
        raise ValueError(msg)
    operand = generator.visit(node.operand)
    from yaraast.ast.expressions import BinaryExpression

    if isinstance(node.operand, BinaryExpression):
        operand = f"({operand})"
    if operator == "not":
        return f"not {operand}"
    return f"{operator}{operand}"


def visit_parentheses_expression(generator: Any, node: Any) -> str:
    return f"({generator.visit(node.expression)})"


def visit_set_expression(generator: Any, node: Any) -> str:
    validate_set_expression_elements(node)
    return f"({', '.join(generator.visit(elem) for elem in node.elements)})"


def validate_set_expression_elements(node: Any) -> None:
    validate_expression_collection(node.elements, "SetExpression elements")
    if not node.elements:
        msg = "Set expression must contain at least one element for libyara output"
        raise ValueError(msg)


def validate_function_call_arguments(node: Any) -> None:
    validate_expression_collection(node.arguments, "FunctionCall arguments")
    _validate_known_module_function_call(node)
    if getattr(node, "receiver", None) is not None:
        return
    function_name = node.function
    if function_name in _UNSUPPORTED_INTEGER_READ_ALIASES:
        msg = (
            f"Builtin function '{function_name}' is not supported by libyara; "
            "use the unsuffixed little-endian reader"
        )
        raise ValueError(msg)
    if function_name not in _INTEGER_READ_FUNCTIONS:
        return
    if len(node.arguments) != 1:
        msg = f"Builtin function '{function_name}' expects exactly 1 argument " "for libyara output"
        raise ValueError(msg)
    if _is_definitely_non_integer_expression(node.arguments[0]):
        msg = f"Builtin function '{function_name}' argument must be integer for libyara output"
        raise ValueError(msg)


def _known_builtin_module(module_name: str) -> Any | None:
    from yaraast.types.module_definitions import load_builtin_modules

    return load_builtin_modules().get(module_name)


def _validate_known_module_function_call(node: Any) -> None:
    resolved = node.module_and_function()
    if resolved is None:
        return
    module_name, function_name = resolved

    module_def = _known_builtin_module(module_name)
    if module_def is None:
        return
    function_def = module_def.functions.get(function_name)
    if function_def is None:
        msg = f"Module function '{module_name}.{function_name}' is not supported by libyara"
        raise ValueError(msg)

    arguments = node.arguments
    _validate_module_function_arity(module_name, function_name, function_def, arguments)

    if module_name == "hash" and function_name in _HASH_FUNCTIONS:
        _validate_hash_module_function_arguments(function_name, arguments)
        return
    if module_name == "math" and (
        function_name in _MATH_STRING_REGION_FUNCTIONS
        or function_name == "deviation"
        or function_name in _MATH_INTEGER_REGION_FUNCTIONS
    ):
        _validate_math_module_function_arguments(function_name, arguments)
        return

    _validate_generic_module_function_argument_types(
        module_name,
        function_name,
        function_def,
        arguments,
    )


def _validate_module_function_arity(
    module_name: str,
    function_name: str,
    function_def: Any,
    arguments: list[Any] | tuple[Any, ...],
) -> None:
    max_args = len(function_def.parameters)
    min_args = function_def.min_parameters if function_def.min_parameters is not None else max_args
    actual_args = len(arguments)
    qualified_name = f"{module_name}.{function_name}"
    if actual_args < min_args:
        msg = (
            f"Module function '{qualified_name}' expects at least {min_args} argument(s), "
            f"got {actual_args} for libyara output"
        )
        raise ValueError(msg)
    if not function_def.variadic and actual_args > max_args:
        msg = (
            f"Module function '{qualified_name}' expects at most {max_args} argument(s), "
            f"got {actual_args} for libyara output"
        )
        raise ValueError(msg)


def _validate_hash_module_function_arguments(
    function_name: str,
    arguments: list[Any] | tuple[Any, ...],
) -> None:
    argument_types = [_obvious_argument_type(argument) for argument in arguments]
    if any(argument_type is None for argument_type in argument_types):
        return
    valid_string_digest = len(argument_types) == 1 and argument_types[0] == "string"
    valid_region_digest = len(argument_types) == 2 and all(
        argument_type == "integer" for argument_type in argument_types
    )
    if valid_string_digest or valid_region_digest:
        return
    msg = f"Module function 'hash.{function_name}' does not accept these argument types"
    raise ValueError(msg)


def _validate_math_module_function_arguments(
    function_name: str,
    arguments: list[Any] | tuple[Any, ...],
) -> None:
    argument_types = [_obvious_argument_type(argument) for argument in arguments]
    if any(argument_type is None for argument_type in argument_types):
        return

    if function_name in _MATH_STRING_REGION_FUNCTIONS:
        valid = _matches_string_or_integer_region_arguments(argument_types)
    elif function_name == "deviation":
        valid = (
            len(argument_types) == 2
            and argument_types[0] == "string"
            and argument_types[1] == "double"
        ) or (
            len(argument_types) == 3
            and argument_types[0] == "integer"
            and argument_types[1] == "integer"
            and argument_types[2] == "double"
        )
    elif function_name in {"count", "percentage"}:
        valid = len(argument_types) in {1, 3} and all(
            argument_type == "integer" for argument_type in argument_types
        )
    else:
        valid = len(argument_types) in {0, 2} and all(
            argument_type == "integer" for argument_type in argument_types
        )

    if valid:
        return
    msg = f"Module function 'math.{function_name}' does not accept these argument types"
    raise ValueError(msg)


def _matches_string_or_integer_region_arguments(argument_types: list[str | None]) -> bool:
    return (len(argument_types) == 1 and argument_types[0] == "string") or (
        len(argument_types) == 2
        and argument_types[0] == "integer"
        and argument_types[1] == "integer"
    )


def _validate_generic_module_function_argument_types(
    module_name: str,
    function_name: str,
    function_def: Any,
    arguments: list[Any] | tuple[Any, ...],
) -> None:
    from yaraast.types._registry_primitives import (
        BooleanType,
        DoubleType,
        FloatType,
        IntegerType,
        ScalarType,
        StringType,
    )

    for argument, (_, parameter_type) in zip(arguments, function_def.parameters, strict=False):
        argument_type = _obvious_argument_type(argument)
        if argument_type is None:
            continue
        compatible = (
            (isinstance(parameter_type, IntegerType) and argument_type == "integer")
            or (isinstance(parameter_type, StringType) and argument_type == "string")
            or (isinstance(parameter_type, BooleanType) and argument_type == "boolean")
            or (
                isinstance(parameter_type, DoubleType | FloatType)
                and argument_type in {"double", "integer"}
            )
            or (
                isinstance(parameter_type, ScalarType)
                and argument_type in {"double", "integer", "string"}
            )
        )
        if compatible:
            continue
        msg = (
            f"Module function '{module_name}.{function_name}' does not accept "
            "these argument types"
        )
        raise ValueError(msg)


def _obvious_argument_type(argument: Any) -> str | None:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        FunctionCall,
        Identifier,
        IntegerLiteral,
        RegexLiteral,
        StringCount,
        StringLength,
        StringLiteral,
        StringOffset,
    )

    argument = _unwrap_parenthesized_expression(argument)
    if isinstance(argument, bool | BooleanLiteral):
        return "boolean"
    if isinstance(argument, int | IntegerLiteral) and not isinstance(argument, bool):
        return "integer"
    if isinstance(argument, float | DoubleLiteral):
        return "double"
    if isinstance(argument, str | StringLiteral):
        return "string"
    if isinstance(argument, RegexLiteral):
        return "regex"
    if isinstance(argument, Identifier) and argument.name in {"entrypoint", "filesize"}:
        return "integer"
    if isinstance(argument, StringCount | StringLength | StringOffset):
        return "integer"
    if (
        isinstance(argument, FunctionCall)
        and argument.receiver is None
        and argument.function in _INTEGER_READ_FUNCTIONS
    ):
        return "integer"
    return None


def validate_expression_collection(value: Any, field_name: str) -> None:
    if isinstance(value, list | tuple):
        return
    msg = f"{field_name} must be a list or tuple for libyara output"
    raise TypeError(msg)


def require_present_expression(value: Any, field_name: str) -> Any:
    if value is None:
        msg = f"{field_name} is required for libyara output"
        raise ValueError(msg)
    return value


def _reject_non_integer_expression(value: Any, field_name: str) -> None:
    if _is_definitely_non_integer_expression(value):
        msg = f"{field_name} must be integer for libyara output"
        raise ValueError(msg)


def visit_range_expression(generator: Any, node: Any) -> str:
    _reject_non_integer_expression(node.low, "Range low bound")
    _reject_non_integer_expression(node.high, "Range high bound")
    return f"{generator.visit(node.low)}..{generator.visit(node.high)}"


def render_function_call_callee(generator: Any, node: Any) -> str:
    """Render the callee of a function call, including an indexed receiver.

    When ``receiver`` is set the callee is ``<receiver>.<method>`` (e.g.
    ``pe.signatures[0].valid_on``); otherwise it is the dotted function name.
    """
    receiver = getattr(node, "receiver", None)
    if receiver is not None:
        method = validate_yara_identifier(node.function, "function")
        return f"{generator.visit(receiver)}.{method}"
    return validate_yara_identifier_path(node.function, "function")


def visit_function_call(generator: Any, node: Any) -> str:
    callee = render_function_call_callee(generator, node)
    validate_function_call_arguments(node)
    return f"{callee}({', '.join(generator.visit(arg) for arg in node.arguments)})"


def visit_array_access(generator: Any, node: Any) -> str:
    _reject_non_integer_expression(node.index, "Array index")
    validate_module_root_array_access(node)
    validate_known_module_array_access(generator, node)
    return f"{generator.visit(node.array)}[{generator.visit(node.index)}]"


def validate_module_root_array_access(node: Any) -> None:
    from yaraast.ast.modules import ModuleReference

    if not isinstance(node.array, ModuleReference):
        return
    msg = f"Module '{node.array.module}' cannot be indexed as an array for libyara output"
    raise ValueError(msg)


def validate_known_module_array_access(generator: Any, node: Any) -> None:
    from yaraast.types._registry_collections import ArrayType

    array_type = known_builtin_module_expression_type(node.array)
    if array_type is None or isinstance(array_type, ArrayType):
        return
    msg = (
        f"Module expression '{generator.visit(node.array)}' cannot be indexed as an array "
        "for libyara output"
    )
    raise ValueError(msg)


def visit_member_access(generator: Any, node: Any) -> str:
    member = validate_yara_identifier(node.member, "member")
    validate_builtin_module_member_access(node, member)
    validate_known_module_struct_member_access(generator, node, member)
    return f"{generator.visit(node.object)}.{member}"


def validate_builtin_module_member_access(node: Any, member: str) -> None:
    from yaraast.ast.modules import ModuleReference

    if not isinstance(node.object, ModuleReference):
        return
    module_def = _known_builtin_module(node.object.module)
    if module_def is None or member in module_def.attributes:
        return
    msg = f"Module member '{node.object.module}.{member}' is not supported by libyara"
    raise ValueError(msg)


def validate_known_module_struct_member_access(generator: Any, node: Any, member: str) -> None:
    from yaraast.ast.modules import ModuleReference
    from yaraast.types._registry_collections import StructType

    if isinstance(node.object, ModuleReference):
        return
    object_type = known_builtin_module_expression_type(node.object)
    if object_type is None:
        return
    rendered_object = generator.visit(node.object)
    if not isinstance(object_type, StructType):
        msg = (
            f"Module expression '{rendered_object}' does not support member access "
            "for libyara output"
        )
        raise ValueError(msg)
    if member in object_type.fields:
        return
    msg = f"Module member '{rendered_object}.{member}' is not supported by libyara"
    raise ValueError(msg)


def known_builtin_module_expression_type(expression: Any) -> Any | None:
    from yaraast.ast.expressions import ArrayAccess, MemberAccess, ParenthesesExpression
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType

    if isinstance(expression, ParenthesesExpression):
        return known_builtin_module_expression_type(expression.expression)
    if isinstance(expression, MemberAccess):
        if isinstance(expression.object, ModuleReference):
            module_def = _known_builtin_module(expression.object.module)
            if module_def is None:
                return None
            return module_def.attributes.get(expression.member)
        object_type = known_builtin_module_expression_type(expression.object)
        if isinstance(object_type, StructType):
            return object_type.fields.get(expression.member)
        return None
    if isinstance(expression, ArrayAccess):
        array_type = known_builtin_module_expression_type(expression.array)
        if isinstance(array_type, ArrayType):
            return array_type.element_type
        return None
    if isinstance(expression, DictionaryAccess):
        dictionary_type = known_builtin_module_expression_type(expression.object)
        if isinstance(dictionary_type, DictionaryType):
            return dictionary_type.value_type
    return None


def visit_for_expression(generator: Any, node: Any) -> str:
    from yaraast.ast.expressions import RangeExpression, SetExpression
    from yaraast.codegen.generator_expressions import _render_quantifier

    if _is_definitely_non_iterable_expression(node.iterable):
        msg = (
            "For expression iterable must be a range, set, or iterable expression "
            "for libyara output"
        )
        raise ValueError(msg)
    if isinstance(node.iterable, SetExpression) and any(
        _is_invalid_for_iterable_set_item(item) for item in node.iterable.elements
    ):
        msg = (
            "For expression iterable set items must be integer or string expressions "
            "for libyara output"
        )
        raise ValueError(msg)
    iterable = generator.visit(node.iterable)
    if isinstance(node.iterable, RangeExpression):
        iterable = f"({iterable})"
    body = generator.visit(node.body)
    quantifier = _render_quantifier(
        generator, node.quantifier, allow_percentage=False, context="for quantifier"
    )
    variable = _render_for_loop_variable(node.variable)
    return f"for {quantifier} {variable} in {iterable} : ({body})"


def _render_for_loop_variable(variable: Any) -> str:
    if not isinstance(variable, str):
        return validate_yara_identifier(variable, "loop variable")
    names = [part.strip() for part in variable.split(",")]
    if len(names) == 1:
        return validate_yara_identifier(variable, "loop variable")
    return ", ".join(validate_yara_identifier(name, "loop variable") for name in names)


def visit_at_expression(generator: Any, node: Any) -> str:
    if hasattr(node.string_id, "accept"):
        string_id = generator.visit(node.string_id)
    else:
        string_id = format_string_reference_identifier(
            node.string_id,
            allow_placeholder=getattr(generator, "_allow_string_placeholder", False),
        )
    _reject_non_integer_expression(node.offset, "At expression offset")
    return f"{string_id} at {generator.visit(node.offset)}"
