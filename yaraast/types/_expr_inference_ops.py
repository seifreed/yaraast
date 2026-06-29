"""Helper operations for expression type inference."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modules import ModuleReference
from yaraast.shared.integer_semantics import (
    integer_remainder,
    normalize_int64,
    shift_left_int64,
    shift_right_int64,
    truncate_integer_division,
)
from yaraast.string_references import normalize_string_reference_id
from yaraast.types.module_contracts import FunctionDefinition
from yaraast.types.type_environment import _normalize_identifier

from ._registry import (
    BUILTIN_INT_FUNCTIONS_1ARG,
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    FloatType,
    IntegerType,
    ModuleType,
    RangeType,
    RegexType,
    ScalarType,
    StringIdentifierType,
    StringSetType,
    StringType,
    StructType,
    UnknownType,
    YaraType,
)

_BOOLEAN_IDENTIFIER_KEYWORDS = frozenset(("false", "true"))


def infer_identifier(ctx: Any, node: Identifier) -> YaraType:
    if node.name in _BOOLEAN_IDENTIFIER_KEYWORDS:
        return BooleanType()
    if node.name in {"filesize", "entrypoint"}:
        return IntegerType()
    if node.name == "them":
        return StringSetType()
    if node.name.startswith("$"):
        return _infer_string_reference_identifier(ctx, node.name)
    try:
        _normalize_identifier(node.name, "Identifier name", "identifier")
    except (TypeError, ValueError) as exc:
        var_type = ctx.env.lookup(node.name)
        if var_type:
            is_loop_variable = False
            try:
                _normalize_identifier(node.name, "Identifier name", "loop variable")
            except (TypeError, ValueError):
                is_loop_variable = False
            else:
                is_loop_variable = True
            if is_loop_variable:
                return cast(YaraType, var_type)
        ctx.errors.append(str(exc))
        return UnknownType()
    var_type = ctx.env.lookup(node.name)
    if var_type:
        return cast(YaraType, var_type)
    if ctx.env.has_rule(node.name):
        return BooleanType()
    module_type = ctx._resolve_module_type(node.name)
    if module_type:
        return cast(YaraType, module_type)
    return UnknownType()


def _infer_string_reference_identifier(ctx: Any, name: str) -> YaraType:
    try:
        normalized = normalize_string_reference_id(name, allow_wildcard=False)
    except (TypeError, ValueError) as exc:
        ctx.errors.append(str(exc))
        return UnknownType()

    scoped_type = ctx.env.lookup(normalized)
    if scoped_type:
        return cast(YaraType, scoped_type)
    if ctx.env.has_string(normalized):
        return StringIdentifierType()
    ctx.errors.append(f"Undefined string: {normalized}")
    return UnknownType()


def infer_string_count_like(
    ctx: Any,
    string_id: str,
    label: str,
    index: Any = None,
) -> YaraType:
    if string_id in {"", "$"} and ctx.env.lookup("$"):
        if index is not None:
            _validate_string_occurrence_index(ctx, index, label)
        return IntegerType()
    try:
        normalized = ctx._normalize_string_id(string_id)
    except ValueError as exc:
        ctx.errors.append(str(exc))
        return UnknownType()
    if ctx.env.has_string(normalized) or ctx.env.has_string_pattern(normalized):
        if index is not None:
            _validate_string_occurrence_index(ctx, index, label)
        return IntegerType()
    ctx.errors.append(f"Undefined string: {normalized}")
    return UnknownType()


def _validate_string_occurrence_index(ctx: Any, index: Any, label: str) -> None:
    index_type = ctx.visit(index)
    if isinstance(index_type, BooleanType):
        ctx.errors.append(f"{label} index must not be boolean, got {index_type}")


def infer_binary_expression(ctx: Any, node: BinaryExpression) -> YaraType:
    left_type = ctx.visit(node.left)
    right_type = ctx.visit(node.right)

    if node.operator in ["and", "or"]:
        return _infer_logical_op(ctx, node.operator, left_type, right_type)

    if node.operator in ["<", "<=", ">", ">=", "==", "!="]:
        return _infer_comparison_op(
            ctx, node.operator, node.left, left_type, node.right, right_type
        )

    if node.operator in _STRING_OPS:
        return _infer_string_op(ctx, node.operator, left_type, right_type)

    if node.operator in ["+", "-", "*", "/", "\\", "%"]:
        return _infer_arithmetic_op(ctx, node.operator, left_type, right_type, node.right)

    if node.operator in ["&", "|", "^", "<<", ">>"]:
        return _infer_bitwise_op(ctx, node.operator, left_type, right_type, node.right)

    ctx.errors.append(f"Unknown binary operator: {node.operator}")
    return UnknownType()


_STRING_OPS = frozenset(
    [
        "contains",
        "matches",
        "startswith",
        "endswith",
        "icontains",
        "istartswith",
        "iendswith",
        "iequals",
    ]
)

_HASH_FUNCTIONS = frozenset(("md5", "sha1", "sha256", "checksum32", "crc32"))
_MATH_STRING_REGION_FUNCTIONS = frozenset(
    ("entropy", "mean", "serial_correlation", "monte_carlo_pi")
)
_MATH_INTEGER_REGION_FUNCTIONS = frozenset(("count", "percentage", "mode"))


def _infer_logical_op(
    ctx: Any,
    operator: str,
    left_type: YaraType,
    right_type: YaraType,
) -> YaraType:
    truthy_types = (
        BooleanType
        | StringIdentifierType
        | IntegerType
        | DoubleType
        | FloatType
        | StringType
        | RegexType
    )
    if not isinstance(left_type, truthy_types):
        ctx.errors.append(f"Left operand of '{operator}' must be truthy, got {left_type}")
    if not isinstance(right_type, truthy_types):
        ctx.errors.append(f"Right operand of '{operator}' must be truthy, got {right_type}")
    return BooleanType()


def _infer_comparison_op(
    ctx: Any,
    operator: str,
    left_node: Any,
    left_type: YaraType,
    right_node: Any,
    right_type: YaraType,
) -> YaraType:
    if _has_unknown_comparison_operand(
        ctx, operator, "Left", left_node, left_type
    ) or _has_unknown_comparison_operand(ctx, operator, "Right", right_node, right_type):
        return BooleanType()

    if isinstance(left_type, StringIdentifierType) or isinstance(right_type, StringIdentifierType):
        ctx.errors.append(f"String identifiers cannot be used with '{operator}' comparisons")
        return BooleanType()

    if _is_literal_boolean_comparison_operand(left_node) or _is_literal_boolean_comparison_operand(
        right_node
    ):
        ctx.errors.append(f"Boolean operands cannot be used with '{operator}' comparisons")
        return BooleanType()

    if isinstance(left_type, BooleanType) or isinstance(right_type, BooleanType):
        ctx.errors.append(f"Boolean operands cannot be used with '{operator}' comparisons")
        return BooleanType()

    if isinstance(left_type, RegexType) or isinstance(right_type, RegexType):
        ctx.errors.append(f"Regex operands cannot be used with '{operator}' comparisons")
        return BooleanType()

    if (
        isinstance(left_type, IntegerType | DoubleType | FloatType)
        and isinstance(right_type, IntegerType | DoubleType | FloatType)
    ) or left_type.is_compatible_with(right_type):
        return BooleanType()
    ctx.errors.append(f"Incompatible types for '{operator}': {left_type} and {right_type}")
    return BooleanType()


def _is_literal_boolean_comparison_operand(node: Any) -> bool:
    if isinstance(node, BooleanLiteral):
        return True
    if isinstance(node, bool):
        return True
    if isinstance(node, ParenthesesExpression):
        return _is_literal_boolean_comparison_operand(node.expression)
    return False


def _has_unknown_comparison_operand(
    ctx: Any,
    operator: str,
    side: str,
    operand: Any,
    operand_type: YaraType,
) -> bool:
    if not isinstance(operand_type, UnknownType):
        return False
    if isinstance(operand, StringIdentifier):
        return True
    if isinstance(operand, Identifier):
        ctx.errors.append(f"Undefined identifier: {operand.name}")
        return True
    ctx.errors.append(f"{side} operand of '{operator}' has unknown type")
    return True


def _infer_string_op(
    ctx: Any,
    operator: str,
    left_type: YaraType,
    right_type: YaraType,
) -> YaraType:
    if isinstance(left_type, StringIdentifierType):
        ctx.errors.append(f"Left operand of '{operator}' must be string, got {left_type}")
        return BooleanType()

    if operator == "contains" and isinstance(left_type, ArrayType):
        if not left_type.element_type.is_compatible_with(right_type):
            ctx.errors.append(
                f"Array element type {left_type.element_type} not compatible with {right_type}",
            )
        return BooleanType()

    if not left_type.is_string_like():
        ctx.errors.append(
            f"Left operand of '{operator}' must be string-like or array, got {left_type}",
        )
    if operator == "matches":
        if not isinstance(right_type, RegexType):
            ctx.errors.append(f"Right operand of 'matches' must be regex, got {right_type}")
    elif not isinstance(right_type, StringType):
        ctx.errors.append(f"Right operand of '{operator}' must be string, got {right_type}")
    return BooleanType()


def _constant_integer_value(node: Any) -> int | None:
    if isinstance(node, IntegerLiteral) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ParenthesesExpression):
        return _constant_integer_value(node.expression)
    if isinstance(node, UnaryExpression):
        value = _constant_integer_value(node.operand)
        if value is None:
            return None
        if node.operator == "-":
            return -value
        if node.operator == "~":
            return ~value
        return None
    if not isinstance(node, BinaryExpression):
        return None

    left = _constant_integer_value(node.left)
    right = _constant_integer_value(node.right)
    if left is None or right is None:
        return None

    if node.operator == "+":
        return normalize_int64(left + right)
    if node.operator == "-":
        return normalize_int64(left - right)
    if node.operator == "*":
        return normalize_int64(left * right)
    if node.operator in {"/", "\\"}:
        return None if right == 0 else truncate_integer_division(left, right)
    if node.operator == "%":
        return None if right == 0 else integer_remainder(left, right)
    if node.operator == "&":
        return normalize_int64(left & right)
    if node.operator == "|":
        return normalize_int64(left | right)
    if node.operator == "^":
        return normalize_int64(left ^ right)
    if node.operator == "<<":
        return None if right < 0 else shift_left_int64(left, right)
    if node.operator == ">>":
        return None if right < 0 else shift_right_int64(left, right)
    return None


def _is_zero_integer_divisor(
    operator: str,
    left_type: YaraType,
    right_type: YaraType,
    right_node: Any,
) -> bool:
    if operator not in {"/", "\\", "%"}:
        return False
    if not isinstance(left_type, IntegerType) or not isinstance(right_type, IntegerType):
        return False
    return _constant_integer_value(right_node) == 0


def _infer_arithmetic_op(
    ctx: Any,
    operator: str,
    left_type: YaraType,
    right_type: YaraType,
    right_node: Any,
) -> YaraType:
    if _is_zero_integer_divisor(operator, left_type, right_type, right_node):
        ctx.errors.append(f"Right operand of '{operator}' cannot be zero")

    if operator == "%":
        if not isinstance(left_type, IntegerType):
            ctx.errors.append(f"Left operand of '{operator}' must be integer, got {left_type}")
        if not isinstance(right_type, IntegerType):
            ctx.errors.append(f"Right operand of '{operator}' must be integer, got {right_type}")
        return IntegerType()
    if not left_type.is_numeric():
        ctx.errors.append(f"Left operand of '{operator}' must be numeric, got {left_type}")
    if not right_type.is_numeric():
        ctx.errors.append(f"Right operand of '{operator}' must be numeric, got {right_type}")
    if isinstance(left_type, DoubleType) or isinstance(right_type, DoubleType):
        return DoubleType()
    if isinstance(left_type, FloatType) or isinstance(right_type, FloatType):
        return FloatType()
    return IntegerType()


def _infer_bitwise_op(
    ctx: Any,
    operator: str,
    left_type: YaraType,
    right_type: YaraType,
    right_node: Any,
) -> YaraType:
    if not isinstance(left_type, IntegerType):
        ctx.errors.append(f"Left operand of '{operator}' must be integer, got {left_type}")
    if not isinstance(right_type, IntegerType):
        ctx.errors.append(f"Right operand of '{operator}' must be integer, got {right_type}")
    if operator in {"<<", ">>"}:
        shift_count = _constant_integer_value(right_node)
        if shift_count is not None and shift_count < 0:
            ctx.errors.append(f"Right operand of '{operator}' cannot be negative")
    return IntegerType()


def infer_unary_expression(ctx: Any, node: UnaryExpression) -> YaraType:
    operand_type = ctx.visit(node.operand)

    if node.operator == "not":
        if not isinstance(
            operand_type,
            BooleanType
            | StringIdentifierType
            | IntegerType
            | DoubleType
            | FloatType
            | StringType
            | RegexType,
        ):
            ctx.errors.append(f"Operand of 'not' must be truthy, got {operand_type}")
        return BooleanType()
    if node.operator == "-":
        if not operand_type.is_numeric():
            ctx.errors.append(f"Operand of '-' must be numeric, got {operand_type}")
        return cast(YaraType, operand_type)
    if node.operator == "~":
        if not isinstance(operand_type, IntegerType):
            ctx.errors.append(f"Operand of '~' must be integer, got {operand_type}")
        return IntegerType()
    ctx.errors.append(f"Unknown unary operator: {node.operator}")
    return UnknownType()


def infer_function_call(ctx: Any, node: FunctionCall) -> YaraType:
    function_name = _function_name_or_none(ctx, node.function)
    arguments = _function_arguments(ctx, node.arguments)
    if function_name is None:
        _visit_function_arguments(ctx, arguments)
        return UnknownType()

    receiver = getattr(node, "receiver", None)
    if not _validate_function_name(ctx, function_name, receiver=receiver):
        if receiver is not None:
            _infer_function_argument(ctx, receiver)
        _visit_function_arguments(ctx, arguments)
        return UnknownType()

    if receiver is not None:
        _infer_function_argument(ctx, receiver)

    resolved = node.module_and_function()
    if resolved is not None:
        module_name, func_name = resolved
        scoped_type = ctx.env.lookup(module_name)
        if scoped_type is not None:
            ctx.errors.append(f"Cannot call function on non-module type: {scoped_type}")
            _visit_function_arguments(ctx, arguments)
            return UnknownType()
        if ctx.env.has_module(module_name):
            actual_module = ctx.env.get_module_name(module_name)
            if actual_module:
                from yaraast.types.module_loader import ModuleLoader

                loader = ModuleLoader()
                module_def = loader.get_module(actual_module)
                if module_def and func_name in module_def.functions:
                    func_def = module_def.functions[func_name]
                    if (
                        actual_module == "pe"
                        and func_name == "signatures.valid_on"
                        and receiver is None
                    ):
                        ctx.errors.append(
                            "Function 'signatures.valid_on' requires an indexed receiver"
                        )
                        return func_def.return_type
                    if actual_module == "pe" and func_name == "imports":
                        _validate_pe_imports_arguments(ctx, arguments)
                        return func_def.return_type
                    if actual_module == "pe" and func_name in {
                        "import_rva",
                        "delayed_import_rva",
                    }:
                        _validate_pe_import_rva_arguments(ctx, func_name, arguments)
                        return func_def.return_type
                    if actual_module == "pe" and func_name == "exports":
                        _validate_pe_exports_arguments(ctx, arguments)
                        return func_def.return_type
                    if actual_module == "pe" and func_name == "exports_index":
                        _validate_pe_exports_index_arguments(ctx, arguments)
                        return func_def.return_type
                    if actual_module == "pe" and func_name == "section_index":
                        _validate_pe_section_index_arguments(ctx, arguments)
                        return func_def.return_type
                    if actual_module == "hash" and func_name in _HASH_FUNCTIONS:
                        _validate_hash_function_arguments(ctx, func_name, arguments)
                        return func_def.return_type
                    if actual_module == "math" and (
                        func_name in _MATH_STRING_REGION_FUNCTIONS
                        or func_name == "deviation"
                        or func_name in _MATH_INTEGER_REGION_FUNCTIONS
                    ):
                        _validate_math_function_arguments(ctx, func_name, arguments)
                        return func_def.return_type
                    if actual_module == "console" and func_name == "log":
                        _validate_console_log_arguments(ctx, arguments)
                        return func_def.return_type
                    if actual_module == "console" and func_name == "hex":
                        _validate_console_hex_arguments(ctx, arguments)
                        return func_def.return_type
                    min_args = (
                        func_def.min_parameters
                        if func_def.min_parameters is not None
                        else len(func_def.parameters)
                    )
                    max_args = len(func_def.parameters)
                    if len(arguments) < min_args or (
                        not func_def.variadic and len(arguments) > max_args
                    ):
                        expected = (
                            f"at least {min_args}"
                            if func_def.variadic
                            else (
                                f"{min_args} to {max_args}"
                                if min_args != max_args
                                else str(max_args)
                            )
                        )
                        ctx.errors.append(
                            f"Function '{func_name}' expects {expected} arguments, got {len(arguments)}",
                        )
                    _validate_function_argument_types(
                        ctx,
                        func_name,
                        func_def,
                        arguments,
                    )
                    return func_def.return_type
                ctx.errors.append(f"Module '{actual_module}' has no function '{func_name}'")
                _visit_function_arguments(ctx, arguments)
                return UnknownType()

    if function_name in BUILTIN_INT_FUNCTIONS_1ARG:
        if len(arguments) != 1:
            ctx.errors.append(f"{function_name}() expects 1 argument")
        _validate_function_argument_types(
            ctx,
            function_name,
            [("offset", IntegerType())],
            arguments,
        )
        return IntegerType()

    _visit_function_arguments(ctx, arguments)
    return UnknownType()


def _function_name_or_none(ctx: Any, value: Any) -> str | None:
    if isinstance(value, str):
        return value
    ctx.errors.append("Function name must be a string")
    return None


def _validate_function_name(ctx: Any, function_name: str, *, receiver: Any) -> bool:
    parts = [function_name] if receiver is not None else function_name.split(".")
    if not parts or any(part == "" for part in parts):
        ctx.errors.append(f"Invalid function identifier: {function_name}")
        return False
    for part in parts:
        try:
            _normalize_identifier(part, "Function name", "function")
        except ValueError as exc:
            ctx.errors.append(str(exc))
            return False
    return True


def _function_arguments(ctx: Any, value: Any) -> list[Any]:
    if isinstance(value, list | tuple):
        return list(value)
    ctx.errors.append("Function arguments must be a list")
    return []


def _validate_function_argument_types(
    ctx: Any,
    func_name: str,
    parameters: FunctionDefinition | list[tuple[str, YaraType]],
    arguments: list[Any],
) -> None:
    arg_types = [_infer_function_argument(ctx, argument) for argument in arguments]
    variadic = isinstance(parameters, FunctionDefinition) and parameters.variadic
    parameter_list = (
        parameters.parameters if isinstance(parameters, FunctionDefinition) else parameters
    )
    for (param_name, param_type), arg_type in zip(parameter_list, arg_types, strict=False):
        if isinstance(arg_type, UnknownType):
            continue
        if not _is_function_argument_compatible(param_type, arg_type):
            ctx.errors.append(
                f"Argument '{param_name}' to function '{func_name}' must be {param_type}, got {arg_type}"
            )
    if variadic and parameter_list:
        variadic_name, variadic_type = parameter_list[-1]
        for arg_type in arg_types[len(parameter_list) :]:
            if isinstance(arg_type, UnknownType):
                continue
            if not _is_function_argument_compatible(variadic_type, arg_type):
                ctx.errors.append(
                    f"Argument '{variadic_name}' to function '{func_name}' must be {variadic_type}, got {arg_type}"
                )


def _is_function_argument_compatible(param_type: YaraType, arg_type: YaraType) -> bool:
    if isinstance(param_type, IntegerType):
        return isinstance(arg_type, IntegerType)
    if isinstance(param_type, DoubleType | FloatType):
        return isinstance(arg_type, DoubleType | FloatType)
    if isinstance(param_type, BooleanType):
        return isinstance(arg_type, BooleanType)
    if isinstance(param_type, StringType):
        return isinstance(arg_type, StringType)
    if isinstance(param_type, ScalarType):
        return isinstance(arg_type, IntegerType | DoubleType | FloatType | StringType)
    return param_type.is_compatible_with(arg_type)


def _visit_function_arguments(ctx: Any, arguments: list[Any]) -> None:
    for argument in arguments:
        _infer_function_argument(ctx, argument)


def _argument_types(ctx: Any, arguments: list[Any]) -> list[YaraType]:
    return [_infer_function_argument(ctx, argument) for argument in arguments]


def _infer_function_argument(ctx: Any, argument: Any) -> YaraType:
    if not hasattr(argument, "accept"):
        ctx.errors.append("Function arguments item must be Expression")
        return UnknownType()
    return cast(YaraType, ctx.visit(argument))


def _all_known(arg_types: list[YaraType]) -> bool:
    return not any(isinstance(arg_type, UnknownType) for arg_type in arg_types)


def _matches_type(arg_type: YaraType, allowed_types: tuple[type[YaraType], ...]) -> bool:
    return isinstance(arg_type, allowed_types)


def _matches_signature(
    arg_types: list[YaraType],
    signature: tuple[tuple[type[YaraType], ...], ...],
) -> bool:
    if len(arg_types) != len(signature):
        return False
    return all(
        _matches_type(arg_type, allowed_types)
        for arg_type, allowed_types in zip(arg_types, signature, strict=True)
    )


def _format_argument_types(arg_types: list[YaraType]) -> str:
    return ", ".join(str(arg_type) for arg_type in arg_types)


def _is_console_log_scalar(arg_type: YaraType) -> bool:
    return isinstance(arg_type, StringType | IntegerType | DoubleType | FloatType)


def _validate_console_log_arguments(ctx: Any, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if not 1 <= len(arg_types) <= 2:
        ctx.errors.append(f"Function 'log' expects 1 to 2 arguments, got {len(arg_types)}")
        return
    if not _all_known(arg_types):
        return
    if not all(_is_console_log_scalar(arg_type) for arg_type in arg_types):
        ctx.errors.append(
            f"Function 'log' arguments must be scalar, got ({_format_argument_types(arg_types)})"
        )
    if len(arg_types) == 2 and not isinstance(arg_types[0], StringType):
        ctx.errors.append(
            "Function 'log' with two arguments requires a string first argument, got "
            f"{arg_types[0]}"
        )


def _validate_console_hex_arguments(ctx: Any, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if not 1 <= len(arg_types) <= 2:
        ctx.errors.append(f"Function 'hex' expects 1 to 2 arguments, got {len(arg_types)}")
        return
    if not _all_known(arg_types):
        return
    valid = (len(arg_types) == 1 and isinstance(arg_types[0], IntegerType)) or (
        len(arg_types) == 2
        and isinstance(arg_types[0], StringType)
        and isinstance(arg_types[1], IntegerType)
    )
    if not valid:
        ctx.errors.append(
            f"Function 'hex' does not accept argument types ({_format_argument_types(arg_types)})"
        )


def _validate_pe_exports_arguments(ctx: Any, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if len(arg_types) != 1:
        ctx.errors.append(f"Function 'exports' expects 1 arguments, got {len(arg_types)}")
        return
    if _all_known(arg_types) and not isinstance(arg_types[0], StringType | RegexType | IntegerType):
        ctx.errors.append(
            "Function 'exports' does not accept argument type "
            f"({_format_argument_types(arg_types)})"
        )


def _validate_pe_exports_index_arguments(ctx: Any, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if len(arg_types) != 1:
        ctx.errors.append(f"Function 'exports_index' expects 1 arguments, got {len(arg_types)}")
        return
    if _all_known(arg_types) and not isinstance(arg_types[0], StringType | RegexType | IntegerType):
        ctx.errors.append(
            "Function 'exports_index' does not accept argument type "
            f"({_format_argument_types(arg_types)})"
        )


def _validate_pe_section_index_arguments(ctx: Any, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if len(arg_types) != 1:
        ctx.errors.append(f"Function 'section_index' expects 1 arguments, got {len(arg_types)}")
        return
    if _all_known(arg_types) and not isinstance(arg_types[0], StringType | IntegerType):
        ctx.errors.append(
            "Function 'section_index' does not accept argument type "
            f"({_format_argument_types(arg_types)})"
        )


def _validate_pe_import_rva_arguments(ctx: Any, func_name: str, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if len(arg_types) != 2:
        ctx.errors.append(f"Function '{func_name}' expects 2 arguments, got {len(arg_types)}")
        return
    if not _all_known(arg_types):
        return
    if not (
        isinstance(arg_types[0], StringType) and isinstance(arg_types[1], StringType | IntegerType)
    ):
        ctx.errors.append(
            f"Function '{func_name}' does not accept argument types "
            f"({_format_argument_types(arg_types)})"
        )


def _validate_hash_function_arguments(ctx: Any, func_name: str, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if len(arg_types) not in {1, 2}:
        ctx.errors.append(
            f"Function '{func_name}' expects 1 string argument or 2 integer arguments, "
            f"got {len(arg_types)}"
        )
        return
    if not _all_known(arg_types):
        return
    valid_string_digest = len(arg_types) == 1 and isinstance(arg_types[0], StringType)
    valid_region_digest = len(arg_types) == 2 and all(
        isinstance(arg_type, IntegerType) for arg_type in arg_types
    )
    if not (valid_string_digest or valid_region_digest):
        ctx.errors.append(
            f"Function '{func_name}' does not accept argument types "
            f"({_format_argument_types(arg_types)})"
        )


def _validate_math_function_arguments(ctx: Any, func_name: str, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if not _all_known(arg_types):
        return

    if func_name in _MATH_STRING_REGION_FUNCTIONS:
        valid = _matches_math_string_or_region_signature(arg_types)
    elif func_name == "deviation":
        valid = _matches_math_deviation_signature(arg_types)
    elif func_name in {"count", "percentage"}:
        valid = len(arg_types) in {1, 3} and all(
            isinstance(arg_type, IntegerType) for arg_type in arg_types
        )
    else:
        valid = len(arg_types) in {0, 2} and all(
            isinstance(arg_type, IntegerType) for arg_type in arg_types
        )

    if not valid:
        ctx.errors.append(
            f"Function '{func_name}' does not accept argument types "
            f"({_format_argument_types(arg_types)})"
        )


def _matches_math_string_or_region_signature(arg_types: list[YaraType]) -> bool:
    return (len(arg_types) == 1 and isinstance(arg_types[0], StringType)) or (
        len(arg_types) == 2 and all(isinstance(arg_type, IntegerType) for arg_type in arg_types)
    )


def _matches_math_deviation_signature(arg_types: list[YaraType]) -> bool:
    if len(arg_types) == 2:
        return isinstance(arg_types[0], StringType) and isinstance(
            arg_types[1], DoubleType | FloatType
        )
    if len(arg_types) == 3:
        return (
            isinstance(arg_types[0], IntegerType)
            and isinstance(arg_types[1], IntegerType)
            and isinstance(arg_types[2], DoubleType | FloatType)
        )
    return False


def _validate_pe_imports_arguments(ctx: Any, arguments: list[Any]) -> None:
    arg_types = _argument_types(ctx, arguments)
    if not 1 <= len(arg_types) <= 3:
        ctx.errors.append(f"Function 'imports' expects 1 to 3 arguments, got {len(arg_types)}")
        return
    if not _all_known(arg_types):
        return

    string = (StringType,)
    regex = (RegexType,)
    integer = (IntegerType,)
    string_or_integer = (StringType, IntegerType)
    valid_signatures = (
        (string,),
        (string, string_or_integer),
        (regex, regex),
        (integer, string),
        (integer, string, string_or_integer),
        (integer, regex, regex),
    )
    if not any(_matches_signature(arg_types, signature) for signature in valid_signatures):
        ctx.errors.append(
            "Function 'imports' does not accept argument types "
            f"({_format_argument_types(arg_types)})"
        )


def infer_member_access(ctx: Any, node: MemberAccess) -> YaraType:
    try:
        _normalize_identifier(node.member, "Member access member", "member")
    except (TypeError, ValueError) as exc:
        ctx.errors.append(str(exc))
        return UnknownType()

    obj_type = _infer_member_object_type(ctx, node.object)

    if isinstance(obj_type, ModuleType):
        attr_type = obj_type.get_attribute_type(node.member)
        if attr_type:
            return attr_type
        ctx.errors.append(f"Module '{obj_type.module_name}' has no attribute '{node.member}'")
        return UnknownType()

    if isinstance(obj_type, StructType):
        if node.member in obj_type.fields:
            return obj_type.fields[node.member]
        ctx.errors.append(f"Struct has no field '{node.member}'")
        return UnknownType()

    ctx.errors.append(f"Cannot access member of non-module type: {obj_type}")
    return UnknownType()


def _infer_member_object_type(ctx: Any, obj: Any) -> YaraType:
    if isinstance(obj, Identifier):
        scoped_type = ctx.env.lookup(obj.name)
        if scoped_type:
            return cast(YaraType, scoped_type)
        module_type = ctx._resolve_module_type(obj.name)
        if module_type:
            return cast(YaraType, module_type)
    return cast(YaraType, ctx.visit(obj))


def infer_collection_access(ctx: Any, node: ArrayAccess | Any) -> YaraType:
    if isinstance(node, ArrayAccess):
        array_type = ctx.visit(node.array)
        index_type = ctx.visit(node.index)
        if not isinstance(index_type, IntegerType):
            ctx.errors.append(f"Array index must be integer, got {index_type}")
        if isinstance(array_type, ArrayType):
            return array_type.element_type
        ctx.errors.append(f"Cannot index non-array type: {array_type}")
        return UnknownType()

    dict_type = ctx.visit(node.object)
    if isinstance(dict_type, DictionaryType):
        if hasattr(node, "key"):
            key_type = _infer_dictionary_key_type(ctx, node.key)
            if not isinstance(key_type, dict_type.key_type.__class__):
                ctx.errors.append(f"Dictionary key must be {dict_type.key_type}, got {key_type}")
        return dict_type.value_type
    ctx.errors.append(f"Cannot access dictionary on non-dict type: {dict_type}")
    return UnknownType()


def _infer_dictionary_key_type(ctx: Any, key: Any) -> YaraType:
    if hasattr(key, "accept"):
        return cast(YaraType, ctx.visit(key))
    if isinstance(key, bool):
        return BooleanType()
    if isinstance(key, int):
        return IntegerType()
    if isinstance(key, float):
        return DoubleType()
    if isinstance(key, str):
        return StringType()
    return UnknownType()


def infer_set_or_range(ctx: Any, node: SetExpression | Any) -> YaraType:
    if isinstance(node, SetExpression):
        if _is_string_set_expression(node):
            for elem in node.elements:
                if hasattr(elem, "accept"):
                    ctx.visit(elem)
            return StringSetType()
        return ArrayType(_infer_set_element_type(ctx, node.elements))

    low_type = ctx.visit(node.low)
    high_type = ctx.visit(node.high)
    if not isinstance(low_type, IntegerType):
        ctx.errors.append(f"Range low bound must be integer, got {low_type}")
    if not isinstance(high_type, IntegerType):
        ctx.errors.append(f"Range high bound must be integer, got {high_type}")
    return RangeType()


def _infer_set_element_type(ctx: Any, elements: list[Any]) -> YaraType:
    if not elements:
        return UnknownType()

    first_type = cast(YaraType, ctx.visit(elements[0]))
    for elem in elements[1:]:
        elem_type = ctx.visit(elem)
        if not first_type.is_compatible_with(elem_type):
            ctx.errors.append(f"Set elements must have same type: {first_type} vs {elem_type}")
    return first_type


def _is_string_set_expression(node: SetExpression) -> bool:
    if not node.elements:
        return True
    return all(_is_string_set_element(element) for element in node.elements)


def _is_string_set_element(element: Any) -> bool:
    if isinstance(element, StringIdentifier | StringWildcard):
        return not isinstance(element, StringWildcard) or (
            isinstance(element.pattern, str) and element.pattern.startswith("$")
        )
    if isinstance(element, StringLiteral):
        value = element.value
        return isinstance(value, str) and (value == "them" or value.startswith("$"))
    if isinstance(element, Identifier):
        return isinstance(element.name, str) and (
            element.name == "them" or element.name.startswith("$")
        )
    return False


def _is_condition_type(value_type: YaraType) -> bool:
    return isinstance(
        value_type,
        BooleanType | IntegerType | DoubleType | FloatType | StringType | StringIdentifierType,
    )


def _infer_quantifier_value(ctx: Any, value: Any) -> YaraType:
    if isinstance(value, UnaryExpression) and value.operator == "%":
        ctx.visit(value.operand)
        return DoubleType()
    if isinstance(value, Identifier) and value.name in {"all", "any", "none"}:
        return StringType()
    if hasattr(value, "accept"):
        return cast(YaraType, ctx.visit(value))
    if isinstance(value, bool):
        return BooleanType()
    if isinstance(value, int):
        return IntegerType()
    if isinstance(value, float):
        return DoubleType()
    if isinstance(value, str):
        return StringType()
    return UnknownType()


def _validate_quantifier_value(
    ctx: Any,
    value: Any,
    *,
    context: str,
    allow_percentage: bool,
) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if value < 0:
            ctx.errors.append(f"Invalid {context} quantifier '{value}'")
        return
    if isinstance(value, float):
        if allow_percentage:
            _validate_percentage_quantifier_value(ctx, value, context)
        else:
            ctx.errors.append(f"Invalid {context} quantifier '{value}'")
        return
    if isinstance(value, IntegerLiteral):
        if isinstance(value.value, int) and not isinstance(value.value, bool) and value.value < 0:
            ctx.errors.append(f"Invalid {context} quantifier '{value.value}'")
        return
    if isinstance(value, DoubleLiteral):
        if allow_percentage:
            _validate_percentage_quantifier_value(ctx, value.value, context)
        else:
            ctx.errors.append(f"Invalid {context} quantifier '{value.value}'")
        return
    if isinstance(value, UnaryExpression) and value.operator == "%":
        if not allow_percentage:
            ctx.errors.append(f"Invalid {context} quantifier '{value.operator}'")
            return
        _validate_static_percentage_expression_quantifier(ctx, value, context)
        return
    static_value = _static_integer_value(value)
    if static_value is not None and static_value < 0:
        ctx.errors.append(f"Invalid {context} quantifier '{static_value}'")
        return
    if isinstance(value, StringLiteral):
        _validate_quantifier_text_value(
            ctx,
            value.value,
            context=context,
            allow_percentage=allow_percentage,
        )
        return
    if isinstance(value, str):
        _validate_quantifier_text_value(
            ctx,
            value,
            context=context,
            allow_percentage=allow_percentage,
        )


def _validate_percentage_quantifier_value(ctx: Any, value: float, context: str) -> None:
    if not 0 < value <= 1:
        ctx.errors.append(f"'{context}' percentage quantifier must be between 1 and 100")


def _validate_static_percentage_expression_quantifier(
    ctx: Any,
    value: UnaryExpression,
    context: str,
) -> None:
    if _has_invalid_static_percentage_operand(value.operand):
        ctx.errors.append(f"'{context}' percentage quantifier must be an integer expression")
        return
    percent = _static_integer_value(value.operand)
    if percent is not None and not 1 <= percent <= 100:
        ctx.errors.append(f"'{context}' percentage quantifier must be between 1 and 100")


def _has_invalid_static_percentage_operand(value: Any) -> bool:
    if isinstance(
        value,
        bool | float | BooleanLiteral | DoubleLiteral | RegexLiteral | StringIdentifier | str,
    ):
        return True
    if isinstance(value, StringLiteral):
        return True
    if isinstance(value, ParenthesesExpression):
        return _has_invalid_static_percentage_operand(value.expression)
    if isinstance(value, UnaryExpression):
        return _has_invalid_static_percentage_operand(value.operand)
    if isinstance(value, BinaryExpression):
        return _has_invalid_static_percentage_operand(
            value.left
        ) or _has_invalid_static_percentage_operand(value.right)
    return False


def _static_integer_value(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if (
        isinstance(value, IntegerLiteral)
        and isinstance(value.value, int)
        and not isinstance(value.value, bool)
    ):
        return value.value
    if isinstance(value, ParenthesesExpression):
        return _static_integer_value(value.expression)
    if isinstance(value, UnaryExpression):
        operand = _static_integer_value(value.operand)
        if operand is None:
            return None
        if value.operator == "-":
            return -operand
        if value.operator == "~":
            return ~operand
    if isinstance(value, BinaryExpression) and value.operator in {
        "+",
        "-",
        "*",
        "%",
        "<<",
        ">>",
        "&",
        "|",
        "^",
    }:
        right = _static_integer_value(value.right)
        if right is not None and value.operator in {"<<", ">>"}:
            if right < 0:
                return None
            if right >= 64:
                return 0
        left = _static_integer_value(value.left)
        if left is None or right is None:
            return None
        if value.operator == "+":
            return normalize_int64(left + right)
        if value.operator == "-":
            return normalize_int64(left - right)
        if value.operator == "*":
            return normalize_int64(left * right)
        if value.operator == "%":
            if right == 0:
                return None
            return integer_remainder(left, right)
        if value.operator == "<<":
            return shift_left_int64(left, right)
        if value.operator == ">>":
            return shift_right_int64(left, right)
        if value.operator == "&":
            return normalize_int64(left & right)
        if value.operator == "|":
            return normalize_int64(left | right)
        if value.operator == "^":
            return normalize_int64(left ^ right)
    return None


def _validate_quantifier_text_value(
    ctx: Any,
    value: Any,
    *,
    context: str,
    allow_percentage: bool,
) -> None:
    if not isinstance(value, str):
        return
    if value in {"all", "any", "none"}:
        return
    if value.isdigit():
        return
    if value.endswith("%"):
        percent_text = value[:-1]
        if not allow_percentage or not percent_text.isdigit():
            ctx.errors.append(f"Invalid {context} quantifier '{value}'")
            return
        percent = int(percent_text)
        if not 1 <= percent <= 100:
            ctx.errors.append(f"'{context}' percentage quantifier must be between 1 and 100")
        return
    try:
        _normalize_identifier(value, "Quantifier", "quantifier")
    except ValueError as exc:
        ctx.errors.append(str(exc))


def _infer_string_set_value(ctx: Any, value: Any) -> YaraType:
    if isinstance(value, ParenthesesExpression):
        return _infer_string_set_value(ctx, value.expression)
    if isinstance(value, SetExpression) and all(
        _is_string_set_value(element) for element in value.elements
    ):
        return StringSetType()
    if isinstance(value, StringIdentifier | StringLiteral):
        return StringSetType()
    if (
        isinstance(value, StringWildcard)
        and isinstance(value.pattern, str)
        and value.pattern.startswith("$")
    ):
        return StringSetType()
    if isinstance(value, StringWildcard):
        return UnknownType()
    if (
        isinstance(value, Identifier)
        and isinstance(value.name, str)
        and (value.name == "them" or value.name.startswith("$"))
    ):
        return StringSetType()
    if hasattr(value, "accept"):
        return cast(YaraType, ctx.visit(value))
    if isinstance(value, str | list | tuple | set | frozenset):
        return StringSetType()
    return UnknownType()


def _should_validate_raw_string_refs(ctx: Any) -> bool:
    return bool(ctx.env.strings)


def _validate_raw_string_ref(ctx: Any, value: str, *, allow_wildcard: bool = True) -> None:
    if not _should_validate_raw_string_refs(ctx):
        return
    if value in {"", "$"} and ctx.env.lookup("$"):
        return

    try:
        normalized = (
            ctx._normalize_string_id(value)
            if allow_wildcard
            else normalize_string_reference_id(value, allow_wildcard=False)
        )
    except ValueError as exc:
        ctx.errors.append(str(exc))
        return
    if normalized.endswith("*"):
        if not ctx.env.has_string_pattern(normalized):
            ctx.errors.append(f"Undefined string: {normalized}")
    elif not ctx.env.has_string(normalized):
        ctx.errors.append(f"Undefined string: {normalized}")


def _lookup_string_set_local(ctx: Any, name: str) -> YaraType | None:
    if not isinstance(name, str):
        ctx.errors.append("String reference must be a string")
        return None
    names = [name]
    if not name.startswith("$"):
        names.append(f"${name}")

    for local_name in names:
        local_type = ctx.env.lookup(local_name)
        if local_type is not None:
            return cast(YaraType, local_type)
    return None


def _validate_string_set_local_ref(ctx: Any, name: str) -> bool:
    local_type = _lookup_string_set_local(ctx, name)
    if local_type is None:
        return False
    if not isinstance(local_type, StringIdentifierType | StringSetType | StringType | UnknownType):
        ctx.errors.append(
            f"String set local '{name}' must be string or string set, got {local_type}"
        )
    return True


def _validate_string_set_refs(ctx: Any, value: Any) -> None:
    if isinstance(value, str):
        if _validate_string_set_local_ref(ctx, value):
            return
        if value != "them":
            _validate_raw_string_ref(ctx, value)
        return

    if isinstance(value, list | tuple | set | frozenset):
        for item in value:
            _validate_string_set_refs(ctx, item)
        return

    if isinstance(value, ParenthesesExpression):
        _validate_string_set_refs(ctx, value.expression)
        return

    if isinstance(value, StringLiteral):
        if not isinstance(value.value, str):
            ctx.errors.append("String reference must be a string")
            return
        _validate_string_set_refs(ctx, value.value)
        return

    if isinstance(value, StringIdentifier):
        if not isinstance(value.name, str):
            ctx.errors.append("String reference must be a string")
            return
        if _validate_string_set_local_ref(ctx, value.name):
            return
        _validate_raw_string_ref(ctx, value.name)
        return

    if isinstance(value, StringWildcard):
        if not isinstance(value.pattern, str):
            ctx.errors.append("String reference must be a string")
            return
        if value.pattern.startswith("$"):
            _validate_raw_string_ref(ctx, value.pattern)
        return

    if isinstance(value, Identifier):
        if not isinstance(value.name, str):
            ctx.errors.append("String reference must be a string")
            return
        if value.name == "them":
            return
        if value.name.startswith("$"):
            if _validate_string_set_local_ref(ctx, value.name):
                return
            _validate_raw_string_ref(ctx, value.name)
            return

    if isinstance(value, SetExpression):
        for element in value.elements:
            _validate_string_set_refs(ctx, element)
        return

    if hasattr(value, "accept"):
        ctx.visit(value)


def _classify_of_set_value(value: Any) -> str | None:
    if isinstance(value, ParenthesesExpression):
        return _classify_of_set_value(value.expression)

    if isinstance(value, SetExpression):
        return _classify_of_set_items(value.elements)

    if isinstance(value, list | tuple | set | frozenset):
        return _classify_of_set_items(value)

    if _is_string_set_value(value):
        return "string"

    if _is_rule_set_value(value):
        return "rule"

    return None


def _classify_of_set_items(values: Any) -> str | None:
    kinds = {_classify_of_set_value(value) for value in values}
    if len(kinds) == 1:
        return kinds.pop()
    if "string" in kinds and "rule" in kinds:
        return "mixed"
    return None


def _is_string_set_value(value: Any) -> bool:
    if isinstance(value, StringIdentifier):
        return True
    if isinstance(value, StringWildcard):
        return isinstance(value.pattern, str) and value.pattern.startswith("$")
    if isinstance(value, StringLiteral):
        return isinstance(value.value, str)
    if isinstance(value, Identifier):
        return isinstance(value.name, str) and (value.name == "them" or value.name.startswith("$"))
    return bool(isinstance(value, str))


def _is_rule_set_value(value: Any) -> bool:
    if isinstance(value, Identifier):
        return (
            isinstance(value.name, str) and value.name != "them" and not value.name.startswith("$")
        )
    return (
        isinstance(value, StringWildcard)
        and isinstance(value.pattern, str)
        and not value.pattern.startswith("$")
    )


def _validate_rule_set_refs(ctx: Any, value: Any) -> None:
    if isinstance(value, ParenthesesExpression):
        _validate_rule_set_refs(ctx, value.expression)
        return

    if isinstance(value, SetExpression):
        for element in value.elements:
            _validate_rule_set_refs(ctx, element)
        return

    if isinstance(value, list | tuple | set | frozenset):
        for item in value:
            _validate_rule_set_refs(ctx, item)
        return

    if isinstance(value, Identifier):
        if not isinstance(value.name, str):
            ctx.errors.append("Rule reference must be a string")
            return
        if not ctx.env.has_rule(value.name):
            ctx.errors.append(f"Undefined rule: {value.name}")
        return

    if (
        isinstance(value, StringWildcard)
        and isinstance(value.pattern, str)
        and not value.pattern.startswith("$")
        and not ctx.env.has_rule_pattern(value.pattern)
    ):
        ctx.errors.append(f"Undefined rule pattern: {value.pattern}")


def _loop_variable_names(ctx: Any, variable: Any) -> list[str]:
    if not isinstance(variable, str):
        ctx.errors.append("For-expression variable must be a string")
        return []
    names = [name.strip() for name in variable.split(",") if name.strip()]
    variable_names = names or [variable]
    valid_names: list[str] = []
    for name in variable_names:
        try:
            valid_names.append(
                _normalize_identifier(name, "For-expression variable", "loop variable")
            )
        except ValueError as exc:
            ctx.errors.append(str(exc))
    return valid_names


def _define_unknown_loop_variables(ctx: Any, variable_names: list[str]) -> None:
    for name in variable_names:
        ctx.env.define(name, UnknownType())


def _define_for_iteration_variables(
    ctx: Any,
    variable_names: list[str],
    iter_type: YaraType,
) -> None:
    if isinstance(iter_type, RangeType):
        if len(variable_names) == 1:
            ctx.env.define(variable_names[0], IntegerType())
            return
        ctx.errors.append(
            f"Cannot unpack {len(variable_names)} loop variables from type: {iter_type}"
        )
        _define_unknown_loop_variables(ctx, variable_names)
        return

    if isinstance(iter_type, ArrayType):
        if len(variable_names) == 1:
            ctx.env.define(variable_names[0], iter_type.element_type)
            return
        ctx.errors.append(
            f"Cannot unpack {len(variable_names)} loop variables from type: {iter_type}"
        )
        _define_unknown_loop_variables(ctx, variable_names)
        return

    if isinstance(iter_type, DictionaryType):
        if len(variable_names) == 1:
            ctx.env.define(variable_names[0], iter_type.key_type)
            return
        if len(variable_names) == 2:
            ctx.env.define(variable_names[0], iter_type.key_type)
            ctx.env.define(variable_names[1], iter_type.value_type)
            return
        ctx.errors.append(
            f"Cannot unpack {len(variable_names)} loop variables from type: {iter_type}"
        )
        _define_unknown_loop_variables(ctx, variable_names)
        return

    ctx.errors.append(f"Cannot iterate over type: {iter_type}")
    _define_unknown_loop_variables(ctx, variable_names)


def infer_module_or_condition(ctx: Any, node: Any) -> YaraType:
    if isinstance(node, ModuleReference) or hasattr(node, "module"):
        try:
            module_name = _normalize_identifier(node.module, "Module reference", "module")
        except (TypeError, ValueError) as exc:
            ctx.errors.append(str(exc))
            return UnknownType()

        scoped_type = ctx.env.lookup(module_name)
        if scoped_type is not None:
            return cast(YaraType, scoped_type)

        module_type = ctx._resolve_module_type(module_name)
        if module_type:
            return cast(YaraType, module_type)
        if ctx.env.has_rule(module_name):
            return BooleanType()
        ctx.errors.append(f"Module '{module_name}' not imported")
        return UnknownType()

    if isinstance(node, AtExpression):
        if isinstance(node.string_id, str):
            _validate_raw_string_ref(ctx, node.string_id, allow_wildcard=False)
        else:
            _validate_restricted_of_expression(ctx, node.string_id)
            subject_type = ctx.visit(node.string_id)
            if not isinstance(subject_type, BooleanType):
                ctx.errors.append(
                    f"'at' expression subject must be string identifier or of-expression, "
                    f"got {subject_type}"
                )
        offset_type = ctx.visit(node.offset)
        if not isinstance(offset_type, IntegerType):
            ctx.errors.append(f"Offset in 'at' expression must be integer, got {offset_type}")
        return BooleanType()

    if isinstance(node, InExpression):
        if isinstance(node.subject, str):
            _validate_raw_string_ref(ctx, node.subject, allow_wildcard=False)
            result_type: YaraType = BooleanType()
        elif isinstance(node.subject, StringCount):
            subject_type = ctx.visit(node.subject)
            if not isinstance(subject_type, IntegerType):
                ctx.errors.append(
                    f"'in' expression string count subject must be integer, got {subject_type}"
                )
            result_type = IntegerType()
        else:
            _validate_restricted_of_expression(ctx, node.subject)
            subject_type = ctx.visit(node.subject)
            if not isinstance(subject_type, BooleanType):
                ctx.errors.append(
                    f"'in' expression subject must be string identifier, string count, "
                    f"or of-expression, "
                    f"got {subject_type}"
                )
            result_type = BooleanType()
        range_type = ctx.visit(node.range)
        if not isinstance(range_type, RangeType):
            ctx.errors.append(f"'in' expression requires range, got {range_type}")
        return result_type

    if isinstance(node, OfExpression):
        _validate_quantifier_value(
            ctx,
            node.quantifier,
            context="of",
            allow_percentage=True,
        )
        quant_type = _infer_quantifier_value(ctx, node.quantifier)
        if not isinstance(quant_type, StringType | IntegerType | DoubleType):
            ctx.errors.append(
                f"'of' quantifier must be string, integer, or percentage, got {quant_type}"
            )
        set_kind = _classify_of_set_value(node.string_set)
        if set_kind == "string":
            _validate_string_set_refs(ctx, node.string_set)
            set_type = _infer_string_set_value(ctx, node.string_set)
            if not isinstance(set_type, StringSetType):
                ctx.errors.append(f"'of' requires string set, got {set_type}")
        elif set_kind == "rule":
            _validate_rule_set_refs(ctx, node.string_set)
        elif set_kind == "mixed":
            ctx.errors.append("'of' requires string set or rule set, got mixed set")
        else:
            _validate_string_set_refs(ctx, node.string_set)
            set_type = _infer_string_set_value(ctx, node.string_set)
            ctx.errors.append(f"'of' requires string set or rule set, got {set_type}")
        return BooleanType()

    if isinstance(node, ForExpression):
        _validate_quantifier_value(
            ctx,
            node.quantifier,
            context="for",
            allow_percentage=False,
        )
        quant_type = _infer_quantifier_value(ctx, node.quantifier)
        if not isinstance(quant_type, StringType | IntegerType):
            ctx.errors.append(f"'for' quantifier must be string or integer, got {quant_type}")

        variable_names = _loop_variable_names(ctx, node.variable)
        for variable_name in variable_names:
            if ctx.env.has_string(variable_name) or ctx.env.has_string(f"${variable_name}"):
                ctx.errors.append(
                    f"For-expression variable '{variable_name}' shadows a defined string identifier"
                )
        ctx.env.push_scope()
        iter_type = ctx.visit(node.iterable)
        _define_for_iteration_variables(ctx, variable_names, iter_type)
        body_type = ctx.visit(node.body)
        if not _is_condition_type(body_type):
            ctx.errors.append(f"For loop body must return scalar condition, got {body_type}")
        ctx.env.pop_scope()
        return BooleanType()

    quantifier_context = "for...of" if node.condition is not None else "of"
    quant_type = _infer_quantifier_value(ctx, node.quantifier)
    _validate_quantifier_value(
        ctx,
        node.quantifier,
        context=quantifier_context,
        allow_percentage=node.condition is None,
    )
    if not isinstance(quant_type, StringType | IntegerType | DoubleType):
        ctx.errors.append(
            f"'{quantifier_context}' quantifier must be string, integer, or percentage, "
            f"got {quant_type}"
        )
    if node.condition is None:
        set_kind = _classify_of_set_value(node.string_set)
        if set_kind == "string":
            _validate_string_set_refs(ctx, node.string_set)
            set_type = _infer_string_set_value(ctx, node.string_set)
            if not isinstance(set_type, StringSetType):
                ctx.errors.append(f"'of' requires string set, got {set_type}")
        elif set_kind == "rule":
            _validate_rule_set_refs(ctx, node.string_set)
        elif set_kind == "mixed":
            ctx.errors.append("'of' requires string set or rule set, got mixed set")
        else:
            _validate_string_set_refs(ctx, node.string_set)
            set_type = _infer_string_set_value(ctx, node.string_set)
            ctx.errors.append(f"'of' requires string set or rule set, got {set_type}")
        return BooleanType()
    _validate_string_set_refs(ctx, node.string_set)
    set_type = _infer_string_set_value(ctx, node.string_set)
    if not isinstance(set_type, StringSetType):
        ctx.errors.append(f"'for...of' requires string set, got {set_type}")
    ctx.env.push_scope()
    ctx.env.define("$", StringIdentifierType())
    try:
        cond_type = ctx.visit(node.condition)
    finally:
        ctx.env.pop_scope()
    if not _is_condition_type(cond_type):
        ctx.errors.append(f"'for...of' condition must be scalar condition, got {cond_type}")
    return BooleanType()


def _validate_restricted_of_expression(ctx: Any, node: Any) -> None:
    if not isinstance(node, OfExpression):
        return
    if _is_percentage_quantifier_value(node.quantifier):
        ctx.errors.append("Percentage of-expressions do not support 'in' or 'at' restrictions")
    set_kind = _classify_of_set_value(node.string_set)
    if set_kind in {"rule", "mixed"}:
        ctx.errors.append("Rule sets cannot use at/in restrictions")


def _is_percentage_quantifier_value(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, str):
        return value.endswith("%")
    if isinstance(value, DoubleLiteral):
        return True
    if isinstance(value, StringLiteral):
        return isinstance(value.value, str) and value.value.endswith("%")
    if isinstance(value, UnaryExpression) and value.operator == "%":
        return True
    if isinstance(value, ParenthesesExpression):
        return _is_percentage_quantifier_value(value.expression)
    return False
