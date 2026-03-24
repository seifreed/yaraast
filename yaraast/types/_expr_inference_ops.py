"""Helper operations for expression type inference."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    FunctionCall,
    Identifier,
    MemberAccess,
    SetExpression,
    UnaryExpression,
)
from yaraast.ast.modules import ModuleReference

from ._registry import (
    BUILTIN_INT_FUNCTIONS_1ARG,
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    IntegerType,
    ModuleType,
    RangeType,
    RegexType,
    StringIdentifierType,
    StringSetType,
    StringType,
    StructType,
    UnknownType,
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

    if node.operator in ["+", "-", "*", "/", "%"]:
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
    if operator == "/" or isinstance(left_type, DoubleType) or isinstance(right_type, DoubleType):
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
                        if func_def.parameters is not None and len(node.arguments) != len(
                            func_def.parameters
                        ):
                            ctx.errors.append(
                                f"Function '{func_name}' expects {len(func_def.parameters)} arguments, got {len(node.arguments)}",
                            )
                        return func_def.return_type
                    ctx.errors.append(f"Module '{actual_module}' has no function '{func_name}'")
                    return UnknownType()

    if node.function in BUILTIN_INT_FUNCTIONS_1ARG:
        if len(node.arguments) != 1:
            ctx.errors.append(f"{node.function}() expects 1 argument")
        return IntegerType()

    return UnknownType()


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
        if (
            hasattr(node, "key")
            and hasattr(node.key, "__class__")
            and hasattr(node.key, "__dict__")
        ):
            key_type = ctx.visit(node.key)
            if not isinstance(key_type, dict_type.key_type.__class__):
                ctx.errors.append(f"Dictionary key must be {dict_type.key_type}, got {key_type}")
        return dict_type.value_type
    ctx.errors.append(f"Cannot access dictionary on non-dict type: {dict_type}")
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


def infer_module_or_condition(ctx, node):
    if isinstance(node, ModuleReference) or hasattr(node, "module"):
        module_type = ctx._resolve_module_type(node.module)
        if module_type:
            return module_type
        ctx.errors.append(f"Module '{node.module}' not imported")
        return UnknownType()

    if isinstance(node, AtExpression):
        offset_type = ctx.visit(node.offset)
        if not isinstance(offset_type, IntegerType):
            ctx.errors.append(f"Offset in 'at' expression must be integer, got {offset_type}")
        return BooleanType()

    if isinstance(node, InExpression):
        range_type = ctx.visit(node.range)
        if not isinstance(range_type, RangeType):
            ctx.errors.append(f"'in' expression requires range, got {range_type}")
        return BooleanType()

    if isinstance(node, OfExpression):
        quant_type = ctx.visit(node.quantifier)
        if not isinstance(quant_type, StringType | IntegerType):
            ctx.errors.append(f"'of' quantifier must be string or integer, got {quant_type}")
        set_type = ctx.visit(node.string_set)
        if not isinstance(set_type, StringSetType):
            ctx.errors.append(f"'of' requires string set, got {set_type}")
        return BooleanType()

    if isinstance(node, ForExpression):
        # Warn if loop variable shadows a defined string
        if ctx.env.has_string(node.variable) or ctx.env.has_string(f"${node.variable}"):
            ctx.errors.append(
                f"For-expression variable '{node.variable}' shadows a defined string identifier"
            )
        ctx.env.push_scope()
        iter_type = ctx.visit(node.iterable)
        if isinstance(iter_type, RangeType):
            ctx.env.define(node.variable, IntegerType())
        elif isinstance(iter_type, ArrayType):
            ctx.env.define(node.variable, iter_type.element_type)
        else:
            ctx.errors.append(f"Cannot iterate over type: {iter_type}")
            ctx.env.define(node.variable, UnknownType())
        body_type = ctx.visit(node.body)
        if not isinstance(body_type, BooleanType):
            ctx.errors.append(f"For loop body must return boolean, got {body_type}")
        ctx.env.pop_scope()
        return BooleanType()

    set_type = ctx.visit(node.string_set)
    if not isinstance(set_type, StringSetType):
        ctx.errors.append(f"'for...of' requires string set, got {set_type}")
    if node.condition:
        cond_type = ctx.visit(node.condition)
        if not isinstance(cond_type, BooleanType):
            ctx.errors.append(f"'for...of' condition must be boolean, got {cond_type}")
    return BooleanType()
