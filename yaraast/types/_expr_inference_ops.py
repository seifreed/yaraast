"""Helper operations for expression type inference."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    MemberAccess,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modules import ModuleReference
from yaraast.types.module_contracts import FunctionDefinition

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


def infer_identifier(ctx, node: Identifier):
    if node.name in {"filesize", "entrypoint"}:
        return IntegerType()
    if node.name == "them":
        return StringSetType()
    if node.name in ("any", "all", "none"):
        return StringType()
    if ctx.env.has_rule(node.name):
        return BooleanType()
    module_type = ctx._resolve_module_type(node.name)
    if module_type:
        return module_type
    var_type = ctx.env.lookup(node.name)
    if var_type:
        return var_type
    return UnknownType()


def infer_string_count_like(ctx, string_id: str, label: str, index=None):
    normalized = ctx._normalize_string_id(string_id)
    if normalized == "$" and ctx.env.lookup("$"):
        return IntegerType()
    if ctx.env.has_string(normalized) or ctx.env.has_string_pattern(normalized):
        if index is not None:
            index_type = ctx.visit(index)
            if not isinstance(index_type, IntegerType):
                ctx.errors.append(f"{label} index must be integer, got {index_type}")
        return IntegerType()
    ctx.errors.append(f"Undefined string: {normalized}")
    return UnknownType()


def infer_binary_expression(ctx, node: BinaryExpression):
    left_type = ctx.visit(node.left)
    right_type = ctx.visit(node.right)

    if node.operator in ["and", "or"]:
        return _infer_logical_op(ctx, node.operator, left_type, right_type)

    if node.operator in ["<", "<=", ">", ">=", "==", "!="]:
        return _infer_comparison_op(ctx, node.operator, left_type, right_type)

    if node.operator in _STRING_OPS:
        return _infer_string_op(ctx, node.operator, left_type, right_type)

    if node.operator in ["+", "-", "*", "/", "\\", "%"]:
        return _infer_arithmetic_op(ctx, node.operator, left_type, right_type)

    if node.operator in ["&", "|", "^", "<<", ">>"]:
        return _infer_bitwise_op(ctx, node.operator, left_type, right_type)

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


def _infer_logical_op(ctx, operator, left_type, right_type):
    if not isinstance(left_type, BooleanType | StringIdentifierType):
        ctx.errors.append(f"Left operand of '{operator}' must be boolean, got {left_type}")
    if not isinstance(right_type, BooleanType | StringIdentifierType):
        ctx.errors.append(f"Right operand of '{operator}' must be boolean, got {right_type}")
    return BooleanType()


def _infer_comparison_op(ctx, operator, left_type, right_type):
    if (left_type.is_numeric() and right_type.is_numeric()) or left_type.is_compatible_with(
        right_type
    ):
        return BooleanType()
    ctx.errors.append(f"Incompatible types for '{operator}': {left_type} and {right_type}")
    return BooleanType()


def _infer_string_op(ctx, operator, left_type, right_type):
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
        if not isinstance(right_type, StringType | RegexType):
            ctx.errors.append(
                f"Right operand of 'matches' must be string or regex, got {right_type}"
            )
    elif not isinstance(right_type, StringType):
        ctx.errors.append(f"Right operand of '{operator}' must be string, got {right_type}")
    return BooleanType()


def _infer_arithmetic_op(ctx, operator, left_type, right_type):
    if not left_type.is_numeric():
        ctx.errors.append(f"Left operand of '{operator}' must be numeric, got {left_type}")
    if not right_type.is_numeric():
        ctx.errors.append(f"Right operand of '{operator}' must be numeric, got {right_type}")
    if isinstance(left_type, DoubleType) or isinstance(right_type, DoubleType):
        return DoubleType()
    return IntegerType()


def _infer_bitwise_op(ctx, operator, left_type, right_type):
    if not isinstance(left_type, IntegerType):
        ctx.errors.append(f"Left operand of '{operator}' must be integer, got {left_type}")
    if not isinstance(right_type, IntegerType):
        ctx.errors.append(f"Right operand of '{operator}' must be integer, got {right_type}")
    return IntegerType()


def infer_unary_expression(ctx, node: UnaryExpression):
    operand_type = ctx.visit(node.operand)

    if node.operator == "not":
        if not isinstance(operand_type, BooleanType):
            ctx.errors.append(f"Operand of 'not' must be boolean, got {operand_type}")
        return BooleanType()
    if node.operator == "-":
        if not operand_type.is_numeric():
            ctx.errors.append(f"Operand of '-' must be numeric, got {operand_type}")
        return operand_type
    if node.operator == "~":
        if not isinstance(operand_type, IntegerType):
            ctx.errors.append(f"Operand of '~' must be integer, got {operand_type}")
        return IntegerType()
    ctx.errors.append(f"Unknown unary operator: {node.operator}")
    return UnknownType()


def infer_function_call(ctx, node: FunctionCall):
    if "." in node.function:
        parts = node.function.split(".", 1)
        if len(parts) == 2:
            module_name, func_name = parts
            if ctx.env.has_module(module_name):
                actual_module = ctx.env.get_module_name(module_name)
                if actual_module:
                    from yaraast.types.module_loader import ModuleLoader

                    loader = ModuleLoader()
                    module_def = loader.get_module(actual_module)
                    if module_def and func_name in module_def.functions:
                        func_def = module_def.functions[func_name]
                        min_args = (
                            func_def.min_parameters
                            if func_def.min_parameters is not None
                            else len(func_def.parameters)
                        )
                        max_args = len(func_def.parameters)
                        if len(node.arguments) < min_args or (
                            not func_def.variadic and len(node.arguments) > max_args
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
                                f"Function '{func_name}' expects {expected} arguments, got {len(node.arguments)}",
                            )
                        _validate_function_argument_types(
                            ctx,
                            func_name,
                            func_def,
                            node.arguments,
                        )
                        return func_def.return_type
                    ctx.errors.append(f"Module '{actual_module}' has no function '{func_name}'")
                    _visit_function_arguments(ctx, node.arguments)
                    return UnknownType()

    if node.function in BUILTIN_INT_FUNCTIONS_1ARG:
        if len(node.arguments) != 1:
            ctx.errors.append(f"{node.function}() expects 1 argument")
        _validate_function_argument_types(
            ctx,
            node.function,
            [("offset", IntegerType())],
            node.arguments,
        )
        return IntegerType()

    _visit_function_arguments(ctx, node.arguments)
    return UnknownType()


def _validate_function_argument_types(ctx, func_name: str, parameters, arguments) -> None:
    arg_types = [ctx.visit(argument) for argument in arguments]
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


def _visit_function_arguments(ctx, arguments) -> None:
    for argument in arguments:
        ctx.visit(argument)


def infer_member_access(ctx, node: MemberAccess):
    obj_type = ctx.visit(node.object)

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


def infer_collection_access(ctx, node):
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


def _infer_dictionary_key_type(ctx, key):
    if hasattr(key, "accept"):
        return ctx.visit(key)
    if isinstance(key, bool):
        return BooleanType()
    if isinstance(key, int):
        return IntegerType()
    if isinstance(key, float):
        return DoubleType()
    if isinstance(key, str):
        return StringType()
    return UnknownType()


def infer_set_or_range(ctx, node):
    if isinstance(node, SetExpression):
        if node.elements:
            first_type = ctx.visit(node.elements[0])
            for elem in node.elements[1:]:
                elem_type = ctx.visit(elem)
                if not first_type.is_compatible_with(elem_type):
                    ctx.errors.append(
                        f"Set elements must have same type: {first_type} vs {elem_type}"
                    )
        return StringSetType()

    low_type = ctx.visit(node.low)
    high_type = ctx.visit(node.high)
    if not isinstance(low_type, IntegerType):
        ctx.errors.append(f"Range low bound must be integer, got {low_type}")
    if not isinstance(high_type, IntegerType):
        ctx.errors.append(f"Range high bound must be integer, got {high_type}")
    return RangeType()


def _infer_quantifier_value(ctx, value):
    if hasattr(value, "accept"):
        return ctx.visit(value)
    if isinstance(value, int):
        return IntegerType()
    if isinstance(value, float):
        return DoubleType()
    if isinstance(value, str):
        return StringType()
    return UnknownType()


def _infer_string_set_value(ctx, value):
    if isinstance(value, ParenthesesExpression):
        return _infer_string_set_value(ctx, value.expression)
    if isinstance(value, StringIdentifier | StringLiteral | StringWildcard):
        return StringSetType()
    if hasattr(value, "accept"):
        return ctx.visit(value)
    if isinstance(value, str | list | tuple | set | frozenset):
        return StringSetType()
    return UnknownType()


def _should_validate_raw_string_refs(ctx) -> bool:
    return bool(ctx.env.strings)


def _validate_raw_string_ref(ctx, value: str) -> None:
    if not _should_validate_raw_string_refs(ctx):
        return

    normalized = ctx._normalize_string_id(value)
    if normalized == "$" and ctx.env.lookup("$"):
        return
    if normalized.endswith("*"):
        if not ctx.env.has_string_pattern(normalized):
            ctx.errors.append(f"Undefined string: {normalized}")
    elif not ctx.env.has_string(normalized):
        ctx.errors.append(f"Undefined string: {normalized}")


def _validate_string_set_refs(ctx, value) -> None:
    if isinstance(value, str):
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
        _validate_string_set_refs(ctx, value.value)
        return

    if isinstance(value, StringIdentifier):
        _validate_raw_string_ref(ctx, value.name)
        return

    if isinstance(value, StringWildcard):
        _validate_raw_string_ref(ctx, value.pattern)
        return

    if isinstance(value, SetExpression):
        for element in value.elements:
            _validate_string_set_refs(ctx, element)
        return

    if hasattr(value, "accept"):
        ctx.visit(value)


def _percentage_quantifier_value(value):
    if isinstance(value, DoubleLiteral):
        return value.value
    if isinstance(value, float):
        return value
    return None


def _loop_variable_names(variable: str) -> list[str]:
    names = [name.strip() for name in variable.split(",") if name.strip()]
    return names or [variable]


def _define_unknown_loop_variables(ctx, variable_names: list[str]) -> None:
    for name in variable_names:
        ctx.env.define(name, UnknownType())


def _define_for_iteration_variables(ctx, variable_names: list[str], iter_type) -> None:
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


def infer_module_or_condition(ctx, node):
    if isinstance(node, ModuleReference) or hasattr(node, "module"):
        module_type = ctx._resolve_module_type(node.module)
        if module_type:
            return module_type
        ctx.errors.append(f"Module '{node.module}' not imported")
        return UnknownType()

    if isinstance(node, AtExpression):
        _validate_raw_string_ref(ctx, node.string_id)
        offset_type = ctx.visit(node.offset)
        if not isinstance(offset_type, IntegerType):
            ctx.errors.append(f"Offset in 'at' expression must be integer, got {offset_type}")
        return BooleanType()

    if isinstance(node, InExpression):
        if isinstance(node.subject, str):
            _validate_raw_string_ref(ctx, node.subject)
        else:
            subject_type = ctx.visit(node.subject)
            if not isinstance(subject_type, BooleanType):
                ctx.errors.append(
                    f"'in' expression subject must be string identifier or of-expression, "
                    f"got {subject_type}"
                )
        range_type = ctx.visit(node.range)
        if not isinstance(range_type, RangeType):
            ctx.errors.append(f"'in' expression requires range, got {range_type}")
        return BooleanType()

    if isinstance(node, OfExpression):
        quant_type = _infer_quantifier_value(ctx, node.quantifier)
        if not isinstance(quant_type, StringType | IntegerType | DoubleType):
            ctx.errors.append(
                f"'of' quantifier must be string, integer, or percentage, got {quant_type}"
            )
        percentage = _percentage_quantifier_value(node.quantifier)
        if percentage is not None and not 0 < percentage <= 1:
            ctx.errors.append("'of' percentage quantifier must be between 1 and 100")
        _validate_string_set_refs(ctx, node.string_set)
        set_type = _infer_string_set_value(ctx, node.string_set)
        if not isinstance(set_type, StringSetType):
            ctx.errors.append(f"'of' requires string set, got {set_type}")
        return BooleanType()

    if isinstance(node, ForExpression):
        quant_type = _infer_quantifier_value(ctx, node.quantifier)
        if not isinstance(quant_type, StringType | IntegerType):
            ctx.errors.append(f"'for' quantifier must be string or integer, got {quant_type}")

        variable_names = _loop_variable_names(node.variable)
        for variable_name in variable_names:
            if ctx.env.has_string(variable_name) or ctx.env.has_string(f"${variable_name}"):
                ctx.errors.append(
                    f"For-expression variable '{variable_name}' shadows a defined string identifier"
                )
        ctx.env.push_scope()
        iter_type = ctx.visit(node.iterable)
        _define_for_iteration_variables(ctx, variable_names, iter_type)
        body_type = ctx.visit(node.body)
        if not isinstance(body_type, BooleanType):
            ctx.errors.append(f"For loop body must return boolean, got {body_type}")
        ctx.env.pop_scope()
        return BooleanType()

    quant_type = _infer_quantifier_value(ctx, node.quantifier)
    if not isinstance(quant_type, StringType | IntegerType):
        ctx.errors.append(f"'for...of' quantifier must be string or integer, got {quant_type}")
    _validate_string_set_refs(ctx, node.string_set)
    set_type = _infer_string_set_value(ctx, node.string_set)
    if not isinstance(set_type, StringSetType):
        ctx.errors.append(f"'for...of' requires string set, got {set_type}")
    if node.condition:
        ctx.env.push_scope()
        ctx.env.define("$", StringIdentifierType())
        try:
            cond_type = ctx.visit(node.condition)
        finally:
            ctx.env.pop_scope()
        if not isinstance(cond_type, BooleanType | StringIdentifierType):
            ctx.errors.append(f"'for...of' condition must be boolean, got {cond_type}")
    return BooleanType()
