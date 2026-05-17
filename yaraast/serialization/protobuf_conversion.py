"""Conversion helpers between AST and protobuf representations."""

from __future__ import annotations

import time
from typing import Any

from yaraast.errors import SerializationError
from yaraast.serialization.modifier_values import deserialize_legacy_modifier_value
from yaraast.string_escaping import escape_string_source_value

from . import yara_ast_pb2

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _protobuf_has_field(message, field_name: str) -> bool:
    try:
        return message.HasField(field_name)
    except (AttributeError, ValueError):
        return False


def _node_has_metadata(node) -> bool:
    return bool(
        getattr(node, "location", None) is not None
        or getattr(node, "leading_comments", None)
        or getattr(node, "trailing_comment", None) is not None
    )


def _copy_location_to_protobuf(location, pb_location) -> None:
    pb_location.line = location.line
    pb_location.column = location.column
    if location.file is not None:
        pb_location.file = location.file
    if location.end_line is not None:
        pb_location.end_line = location.end_line
    if location.end_column is not None:
        pb_location.end_column = location.end_column


def _protobuf_location_to_ast(pb_location):
    from yaraast.ast.base import Location

    return Location(
        line=pb_location.line,
        column=pb_location.column,
        file=pb_location.file if _protobuf_has_field(pb_location, "file") else None,
        end_line=pb_location.end_line if _protobuf_has_field(pb_location, "end_line") else None,
        end_column=(
            pb_location.end_column if _protobuf_has_field(pb_location, "end_column") else None
        ),
    )


def _copy_comment_to_protobuf(comment, pb_comment) -> None:
    pb_comment.text = comment.text
    pb_comment.is_multiline = comment.is_multiline
    _copy_node_metadata_to_protobuf(comment, pb_comment)


def _copy_comment_metadata_to_protobuf(comment, pb_comment_metadata) -> None:
    from yaraast.ast.comments import Comment, CommentGroup

    if isinstance(comment, CommentGroup):
        pb_group = pb_comment_metadata.group
        for nested_comment in comment.comments:
            _copy_comment_to_protobuf(nested_comment, pb_group.comments.add())
        _copy_node_metadata_to_protobuf(comment, pb_group)
    elif isinstance(comment, Comment):
        _copy_comment_to_protobuf(comment, pb_comment_metadata.comment)
    else:
        pb_comment_metadata.comment.text = str(comment)


def _protobuf_comment_to_ast(pb_comment):
    from yaraast.ast.comments import Comment

    comment = Comment(
        text=pb_comment.text,
        is_multiline=pb_comment.is_multiline,
    )
    return _apply_node_metadata_from_protobuf(pb_comment, comment)


def _protobuf_comment_metadata_to_ast(pb_comment_metadata):
    from yaraast.ast.comments import CommentGroup

    if pb_comment_metadata.HasField("group"):
        group = CommentGroup(
            comments=[
                _protobuf_comment_to_ast(pb_comment)
                for pb_comment in pb_comment_metadata.group.comments
            ]
        )
        return _apply_node_metadata_from_protobuf(pb_comment_metadata.group, group)
    return _protobuf_comment_to_ast(pb_comment_metadata.comment)


def _copy_node_metadata_to_protobuf(node, pb_owner) -> None:
    if not _node_has_metadata(node) or not hasattr(pb_owner, "node_metadata"):
        return

    pb_metadata = pb_owner.node_metadata
    location = getattr(node, "location", None)
    if location is not None:
        _copy_location_to_protobuf(location, pb_metadata.location)

    for comment in getattr(node, "leading_comments", []):
        _copy_comment_metadata_to_protobuf(comment, pb_metadata.leading_comments.add())

    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment is not None:
        _copy_comment_metadata_to_protobuf(trailing_comment, pb_metadata.trailing_comment)


def _apply_node_metadata_from_protobuf(pb_owner, node):
    if not hasattr(pb_owner, "node_metadata") or not _protobuf_has_field(
        pb_owner,
        "node_metadata",
    ):
        return node

    pb_metadata = pb_owner.node_metadata
    if _protobuf_has_field(pb_metadata, "location"):
        node.location = _protobuf_location_to_ast(pb_metadata.location)

    if pb_metadata.leading_comments:
        node.leading_comments = [
            _protobuf_comment_metadata_to_ast(pb_comment)
            for pb_comment in pb_metadata.leading_comments
        ]

    if _protobuf_has_field(pb_metadata, "trailing_comment"):
        node.trailing_comment = _protobuf_comment_metadata_to_ast(pb_metadata.trailing_comment)
    return node


def ast_to_protobuf(ast, *, include_metadata: bool) -> yara_ast_pb2.YaraFile:
    """Convert an AST to its protobuf representation."""
    pb_file = yara_ast_pb2.YaraFile()

    for imp in ast.imports:
        pb_import = pb_file.imports.add()
        pb_import.module = imp.module
        if hasattr(imp, "alias") and imp.alias:
            pb_import.alias = imp.alias
        _copy_node_metadata_to_protobuf(imp, pb_import)

    for inc in ast.includes:
        pb_include = pb_file.includes.add()
        pb_include.path = inc.path
        _copy_node_metadata_to_protobuf(inc, pb_include)

    for extern_rule in ast.extern_rules:
        convert_extern_rule_to_protobuf(extern_rule, pb_file.extern_rules.add())

    for extern_import in ast.extern_imports:
        convert_extern_import_to_protobuf(extern_import, pb_file.extern_imports.add())

    for pragma in ast.pragmas:
        convert_pragma_to_protobuf(pragma, pb_file.pragmas.add())

    for namespace in ast.namespaces:
        convert_extern_namespace_to_protobuf(namespace, pb_file.namespaces.add())

    for rule in ast.rules:
        pb_rule = pb_file.rules.add()
        convert_rule_to_protobuf(rule, pb_rule)

    if include_metadata:
        pb_file.metadata.format = "yaraast-protobuf"
        pb_file.metadata.version = "1.0"
        pb_file.metadata.ast_type = "YaraFile"
        pb_file.metadata.rules_count = len(ast.rules)
        pb_file.metadata.imports_count = len(ast.imports)
        pb_file.metadata.includes_count = len(ast.includes)
        pb_file.metadata.timestamp = int(time.time())

    _copy_node_metadata_to_protobuf(ast, pb_file)
    return pb_file


def convert_rule_to_protobuf(rule, pb_rule) -> None:
    """Convert a single rule AST node to protobuf."""
    pb_rule.name = rule.name
    pb_rule.modifiers.extend(str(m) for m in rule.modifiers)
    _copy_node_metadata_to_protobuf(rule, pb_rule)

    for tag in rule.tags:
        pb_tag = pb_rule.tags.add()
        pb_tag.name = tag.name
        _copy_node_metadata_to_protobuf(tag, pb_tag)

    for entry in rule.meta:
        key = getattr(entry, "key", "")
        value = getattr(entry, "value", "")
        scope = getattr(entry, "scope", None)
        meta_val = pb_rule.meta[key]
        pb_meta_entry = pb_rule.meta_entries.add()
        pb_meta_entry.key = key
        _copy_python_value_to_meta_value(value, pb_meta_entry.value)
        _copy_node_metadata_to_protobuf(entry, pb_meta_entry)
        if scope is not None:
            scope_text = getattr(scope, "value", str(scope))
            pb_rule.meta_scopes[key] = scope_text
            pb_meta_entry.scope = scope_text
        if hasattr(entry, "location") or hasattr(entry, "leading_comments"):
            pb_meta_entry.ast_node = True
        if isinstance(value, str):
            meta_val.string_value = value
        elif isinstance(value, bool):
            meta_val.bool_value = value
        elif isinstance(value, int):
            meta_val.int_value = value
        elif isinstance(value, float):
            meta_val.double_value = value

    for string_def in rule.strings:
        pb_string = pb_rule.strings.add()
        pb_string.identifier = string_def.identifier
        convert_string_to_protobuf(string_def, pb_string)

    if rule.condition:
        convert_expression_to_protobuf(rule.condition, pb_rule.condition)

    for pragma in rule.pragmas:
        convert_in_rule_pragma_to_protobuf(pragma, pb_rule.pragmas.add())


def _copy_python_value_to_meta_value(value, pb_meta_value) -> None:
    if isinstance(value, str):
        pb_meta_value.string_value = value
    elif isinstance(value, bool):
        pb_meta_value.bool_value = value
    elif isinstance(value, int):
        pb_meta_value.int_value = value
    elif isinstance(value, float):
        pb_meta_value.double_value = value
    else:
        pb_meta_value.string_value = str(value)


def _meta_value_to_python(pb_meta_value):
    if pb_meta_value.HasField("string_value"):
        return pb_meta_value.string_value
    if pb_meta_value.HasField("bool_value"):
        return pb_meta_value.bool_value
    if pb_meta_value.HasField("int_value"):
        return pb_meta_value.int_value
    if pb_meta_value.HasField("double_value"):
        return pb_meta_value.double_value
    return ""


def protobuf_to_rule_meta_entry(pb_meta_entry):
    from yaraast.ast.meta import Meta
    from yaraast.ast.modifiers import MetaEntry

    value = _meta_value_to_python(pb_meta_entry.value)
    if pb_meta_entry.ast_node or _protobuf_has_field(pb_meta_entry, "node_metadata"):
        meta = Meta(pb_meta_entry.key, value)
        return _apply_node_metadata_from_protobuf(pb_meta_entry, meta)
    return MetaEntry.from_key_value(
        pb_meta_entry.key,
        value,
        pb_meta_entry.scope or None,
    )


def convert_extern_rule_to_protobuf(extern_rule, pb_extern_rule) -> None:
    pb_extern_rule.name = extern_rule.name
    pb_extern_rule.modifiers.extend(str(modifier) for modifier in extern_rule.modifiers)
    if extern_rule.namespace:
        pb_extern_rule.namespace = extern_rule.namespace
    _copy_node_metadata_to_protobuf(extern_rule, pb_extern_rule)


def convert_extern_import_to_protobuf(extern_import, pb_extern_import) -> None:
    pb_extern_import.module_path = extern_import.module_path
    if extern_import.alias:
        pb_extern_import.alias = extern_import.alias
    pb_extern_import.rules.extend(extern_import.rules)
    _copy_node_metadata_to_protobuf(extern_import, pb_extern_import)


def convert_extern_namespace_to_protobuf(namespace, pb_namespace) -> None:
    pb_namespace.name = namespace.name
    _copy_node_metadata_to_protobuf(namespace, pb_namespace)
    for extern_rule in namespace.extern_rules:
        convert_extern_rule_to_protobuf(extern_rule, pb_namespace.extern_rules.add())


def convert_pragma_to_protobuf(pragma, pb_pragma) -> None:
    scope = getattr(pragma, "scope", None)
    pb_pragma.pragma_type = getattr(pragma.pragma_type, "value", str(pragma.pragma_type))
    pb_pragma.name = pragma.name
    pb_pragma.arguments.extend(pragma.arguments)
    pb_pragma.scope = getattr(scope, "value", str(scope)) if scope is not None else ""

    macro_name = getattr(pragma, "macro_name", "")
    if macro_name:
        pb_pragma.macro_name = macro_name
    macro_value = getattr(pragma, "macro_value", None)
    if macro_value is not None:
        pb_pragma.macro_value = macro_value
    condition = getattr(pragma, "condition", None)
    if condition is not None:
        pb_pragma.condition = condition

    for key, value in getattr(pragma, "parameters", {}).items():
        _copy_python_value_to_meta_value(value, pb_pragma.parameters[str(key)])
    _copy_node_metadata_to_protobuf(pragma, pb_pragma)


def convert_in_rule_pragma_to_protobuf(in_rule_pragma, pb_in_rule_pragma) -> None:
    convert_pragma_to_protobuf(in_rule_pragma.pragma, pb_in_rule_pragma.pragma)
    pb_in_rule_pragma.position = in_rule_pragma.position
    _copy_node_metadata_to_protobuf(in_rule_pragma, pb_in_rule_pragma)


def _modifier_value_text(value) -> str:
    if isinstance(value, tuple) and len(value) == 2:
        return f"{value[0]}-{value[1]}"
    return str(value)


def _is_protobuf_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _format_unknown_modifier(name: str, value) -> str:
    if value is None:
        return name
    if isinstance(value, tuple) and len(value) == 2:
        return f"{name}({value[0]}-{value[1]})"
    if isinstance(value, str):
        return f'{name}("{escape_string_source_value(value)}")'
    return f"{name}({value})"


def _copy_modifier_to_protobuf(mod, pb_mod) -> None:
    pb_mod.name = getattr(mod, "name", str(mod))
    _copy_node_metadata_to_protobuf(mod, pb_mod)
    value = getattr(mod, "value", None)
    if value is None:
        return

    pb_mod.value = _modifier_value_text(value)
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and _is_protobuf_int(value[0])
        and _is_protobuf_int(value[1])
    ):
        pb_mod.tuple_value.extend([int(value[0]), int(value[1])])
    elif isinstance(value, bool):
        pb_mod.typed_value.bool_value = value
    elif isinstance(value, int):
        pb_mod.typed_value.int_value = value
    elif isinstance(value, float):
        pb_mod.typed_value.double_value = value
    elif isinstance(value, str):
        pb_mod.typed_value.string_value = value


def convert_string_to_protobuf(string_def, pb_string) -> None:
    """Convert a string definition to protobuf."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    _copy_node_metadata_to_protobuf(string_def, pb_string)
    pb_string.is_anonymous = getattr(string_def, "is_anonymous", False)
    if isinstance(string_def, PlainString):
        if isinstance(string_def.value, bytes):
            pb_string.plain.raw_value = string_def.value
        else:
            pb_string.plain.value = string_def.value
        for mod in string_def.modifiers:
            pb_mod = pb_string.plain.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)

    elif isinstance(string_def, HexString):
        for token in string_def.tokens:
            pb_token = pb_string.hex.tokens.add()
            convert_hex_token_to_protobuf(token, pb_token)

        for mod in string_def.modifiers:
            pb_mod = pb_string.hex.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)

    elif isinstance(string_def, RegexString):
        pb_string.regex.regex = string_def.regex
        for mod in string_def.modifiers:
            pb_mod = pb_string.regex.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)


def convert_hex_token_to_protobuf(token, pb_token) -> None:
    """Convert a hex token to protobuf."""
    from yaraast.ast.strings import (
        HexAlternative,
        HexByte,
        HexJump,
        HexNegatedByte,
        HexNibble,
        HexWildcard,
    )

    _copy_node_metadata_to_protobuf(token, pb_token)
    if isinstance(token, HexByte):
        pb_token.byte.value = _hex_byte_value_to_protobuf(token.value)
    elif isinstance(token, HexNegatedByte):
        pb_token.negated_byte.value = str(token.value)
    elif isinstance(token, HexWildcard):
        pb_token.wildcard.CopyFrom(yara_ast_pb2.HexWildcard())
    elif isinstance(token, HexJump):
        pb_token.jump.SetInParent()
        if token.min_jump is not None:
            pb_token.jump.min_jump = token.min_jump
        if token.max_jump is not None:
            pb_token.jump.max_jump = token.max_jump
    elif isinstance(token, HexAlternative):
        for alternative in token.alternatives:
            pb_alternative = pb_token.alternative.alternatives.add()
            for alternative_token in _coerce_hex_alternative_branch(alternative):
                convert_hex_token_to_protobuf(alternative_token, pb_alternative.tokens.add())
    elif isinstance(token, HexNibble):
        pb_token.nibble.high = token.high
        pb_token.nibble.value = _hex_nibble_value_to_protobuf(token.value)


def _hex_byte_value_to_protobuf(value: int | str) -> str:
    if isinstance(value, int):
        return str(value)
    return f"hex:{value}"


def _hex_byte_value_from_protobuf(value: str) -> int | str:
    if value.startswith("hex:"):
        raw_value = value.removeprefix("hex:")
        if len(raw_value) == 2 and all(char in _HEX_CHARS for char in raw_value):
            return raw_value
        msg = "HexByte value must be a byte"
        raise SerializationError(msg)
    try:
        byte_value = int(value)
    except ValueError:
        if len(value) == 2 and all(char in _HEX_CHARS for char in value):
            return value
        msg = "HexByte value must be a byte"
        raise SerializationError(msg) from None
    if 0 <= byte_value <= 0xFF:
        return byte_value
    msg = "HexByte value must be a byte"
    raise SerializationError(msg)


def _hex_int_value_from_protobuf(value: str) -> int:
    if value.startswith("hex:"):
        raw_value = value.removeprefix("hex:")
        if len(raw_value) == 2 and all(char in _HEX_CHARS for char in raw_value):
            return int(raw_value, 16)
        msg = "HexNegatedByte value must be a byte"
        raise SerializationError(msg)
    try:
        byte_value = int(value)
    except ValueError:
        if len(value) == 2 and all(char in _HEX_CHARS for char in value):
            byte_value = int(value, 16)
        else:
            msg = "HexNegatedByte value must be a byte"
            raise SerializationError(msg) from None
    if 0 <= byte_value <= 0xFF:
        return byte_value
    msg = "HexNegatedByte value must be a byte"
    raise SerializationError(msg)


def _hex_nibble_value_to_protobuf(value: int | str) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16)


def _protobuf_hex_nibble_value(value: int) -> int:
    if 0 <= value <= 0xF:
        return value
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


def _protobuf_hex_jump_bound(pb_jump, field: str) -> int | None:
    if not pb_jump.HasField(field):
        return None
    value = getattr(pb_jump, field)
    if value >= 0:
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise SerializationError(msg)


def _protobuf_hex_jump_bounds(pb_jump) -> tuple[int | None, int | None]:
    min_jump = _protobuf_hex_jump_bound(pb_jump, "min_jump")
    max_jump = _protobuf_hex_jump_bound(pb_jump, "max_jump")
    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise SerializationError(msg)
    return min_jump, max_jump


def _coerce_hex_alternative_branch(alternative) -> list:
    from yaraast.ast.strings import HexByte

    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def _coerce_expression(value):
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        Expression,
        Identifier,
        IntegerLiteral,
        SetExpression,
        StringIdentifier,
    )

    if isinstance(value, Expression):
        return value
    if isinstance(value, bool):
        return BooleanLiteral(value=value)
    if isinstance(value, int):
        return IntegerLiteral(value=value)
    if isinstance(value, float):
        return DoubleLiteral(value=value)
    if isinstance(value, str):
        return StringIdentifier(value) if value.startswith("$") else Identifier(value)
    if isinstance(value, list):
        return SetExpression([_coerce_expression(item) for item in value])
    return None


def _coerce_quantifier_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int | float):
        return str(value)

    raw_value = getattr(value, "value", None)
    if raw_value is not None:
        return str(raw_value)

    name = getattr(value, "name", None)
    if name is not None:
        return str(name)

    return str(value)


def _coerce_quantifier_expression(value):
    from yaraast.ast.expressions import Expression

    return value if isinstance(value, Expression) else None


def _copy_string_set_to_protobuf(value, pb_owner) -> None:
    if isinstance(value, str):
        pb_owner.string_set_text = value
        return

    if isinstance(value, list | tuple):
        pb_owner.string_set_items.extend(_string_set_item_text(item) for item in value)
        return

    if isinstance(value, set | frozenset):
        pb_owner.string_set_items.extend(
            _string_set_item_text(item) for item in sorted(value, key=str)
        )
        return

    string_set = _coerce_expression(value)
    if string_set is not None:
        convert_expression_to_protobuf(string_set, pb_owner.string_set)


def _string_set_item_text(item) -> str:
    pattern = getattr(item, "pattern", None)
    if pattern is not None:
        return str(pattern)
    name = getattr(item, "name", None)
    if name is not None:
        return str(name)
    value = getattr(item, "value", None)
    if value is not None:
        return str(value)
    return str(item)


def _restore_quantifier_text(value: str):
    lower_value = value.lower()
    if lower_value == "true":
        return True
    if lower_value == "false":
        return False
    if value.lstrip("-").isdigit() and value not in {"", "-"}:
        return int(value)
    try:
        if any(marker in value for marker in (".", "e", "E")):
            return float(value)
    except ValueError:
        pass
    return value


def _protobuf_string_set_to_ast(pb_owner):
    if pb_owner.HasField("string_set_text"):
        return pb_owner.string_set_text
    if pb_owner.string_set_items:
        return list(pb_owner.string_set_items)
    if not pb_owner.HasField("string_set"):
        return []
    return protobuf_to_expression(pb_owner.string_set)


def convert_expression_to_protobuf(expr, pb_expr) -> None:
    """Convert an AST expression to protobuf."""
    import warnings

    from yaraast.ast.conditions import (
        AtExpression,
        ForExpression,
        ForOfExpression,
        InExpression,
        OfExpression,
    )
    from yaraast.ast.expressions import (
        ArrayAccess,
        BinaryExpression,
        BooleanLiteral,
        DoubleLiteral,
        Expression,
        FunctionCall,
        Identifier,
        IntegerLiteral,
        MemberAccess,
        ParenthesesExpression,
        RangeExpression,
        RegexLiteral,
        SetExpression,
        StringCount,
        StringIdentifier,
        StringLength,
        StringLiteral,
        StringOffset,
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternRuleReference
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
    from yaraast.yarax.ast_nodes import (
        ArrayComprehension,
        DictComprehension,
        DictExpression,
        LambdaExpression,
        ListExpression,
        PatternMatch,
        SliceExpression,
        SpreadOperator,
        TupleExpression,
        TupleIndexing,
        WithStatement,
    )

    _copy_node_metadata_to_protobuf(expr, pb_expr)
    if isinstance(expr, Identifier):
        pb_expr.identifier.name = expr.name
    elif isinstance(expr, StringIdentifier):
        pb_expr.string_identifier.name = expr.name
    elif isinstance(expr, StringWildcard):
        pb_expr.string_wildcard.pattern = expr.pattern
    elif isinstance(expr, StringCount):
        pb_expr.string_count.string_id = expr.string_id
    elif isinstance(expr, StringOffset):
        pb_expr.string_offset.string_id = expr.string_id
        if expr.index is not None:
            convert_expression_to_protobuf(expr.index, pb_expr.string_offset.index)
    elif isinstance(expr, StringLength):
        pb_expr.string_length.string_id = expr.string_id
        if expr.index is not None:
            convert_expression_to_protobuf(expr.index, pb_expr.string_length.index)
    elif isinstance(expr, IntegerLiteral):
        pb_expr.integer_literal.value = expr.value
    elif isinstance(expr, DoubleLiteral):
        pb_expr.double_literal.value = expr.value
    elif isinstance(expr, StringLiteral):
        pb_expr.string_literal.value = expr.value
    elif isinstance(expr, RegexLiteral):
        pb_expr.regex_literal.pattern = expr.pattern
        pb_expr.regex_literal.modifiers = expr.modifiers
    elif isinstance(expr, BooleanLiteral):
        pb_expr.boolean_literal.value = expr.value
    elif isinstance(expr, BinaryExpression):
        pb_expr.binary_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.left, pb_expr.binary_expression.left)
        convert_expression_to_protobuf(expr.right, pb_expr.binary_expression.right)
    elif isinstance(expr, UnaryExpression):
        pb_expr.unary_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.operand, pb_expr.unary_expression.operand)
    elif isinstance(expr, ParenthesesExpression):
        convert_expression_to_protobuf(expr.expression, pb_expr.parentheses_expression.expression)
    elif isinstance(expr, SetExpression):
        for element in expr.elements:
            convert_expression_to_protobuf(element, pb_expr.set_expression.elements.add())
    elif isinstance(expr, RangeExpression):
        convert_expression_to_protobuf(expr.low, pb_expr.range_expression.low)
        convert_expression_to_protobuf(expr.high, pb_expr.range_expression.high)
    elif isinstance(expr, FunctionCall):
        pb_expr.function_call.function = expr.function
        for argument in expr.arguments:
            convert_expression_to_protobuf(argument, pb_expr.function_call.arguments.add())
    elif isinstance(expr, ArrayAccess):
        convert_expression_to_protobuf(expr.array, pb_expr.array_access.array)
        convert_expression_to_protobuf(expr.index, pb_expr.array_access.index)
    elif isinstance(expr, MemberAccess):
        convert_expression_to_protobuf(expr.object, pb_expr.member_access.object)
        pb_expr.member_access.member = expr.member
    elif isinstance(expr, ModuleReference):
        pb_expr.module_reference.module = expr.module
    elif isinstance(expr, DictionaryAccess):
        convert_expression_to_protobuf(expr.object, pb_expr.dictionary_access.object)
        if isinstance(expr.key, Expression):
            convert_expression_to_protobuf(expr.key, pb_expr.dictionary_access.key_expr)
        else:
            pb_expr.dictionary_access.key = str(expr.key)
    elif isinstance(expr, ExternRuleReference):
        pb_expr.extern_rule_reference.rule_name = expr.rule_name
        if expr.namespace:
            pb_expr.extern_rule_reference.namespace = expr.namespace
    elif isinstance(expr, ForExpression):
        pb_expr.for_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.for_expression.quantifier_expr)
        pb_expr.for_expression.variable = expr.variable
        convert_expression_to_protobuf(expr.iterable, pb_expr.for_expression.iterable)
        convert_expression_to_protobuf(expr.body, pb_expr.for_expression.body)
    elif isinstance(expr, ForOfExpression):
        pb_expr.for_of_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(
                quantifier,
                pb_expr.for_of_expression.quantifier_expr,
            )
        _copy_string_set_to_protobuf(expr.string_set, pb_expr.for_of_expression)
        if expr.condition is not None:
            convert_expression_to_protobuf(expr.condition, pb_expr.for_of_expression.condition)
    elif isinstance(expr, AtExpression):
        pb_expr.at_expression.string_id = expr.string_id
        convert_expression_to_protobuf(expr.offset, pb_expr.at_expression.offset)
    elif isinstance(expr, InExpression):
        if isinstance(expr.subject, str):
            pb_expr.in_expression.string_id = expr.subject
        else:
            convert_expression_to_protobuf(expr.subject, pb_expr.in_expression.subject)
        convert_expression_to_protobuf(expr.range, pb_expr.in_expression.range)
    elif isinstance(expr, OfExpression):
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.of_expression.quantifier)
        else:
            pb_expr.of_expression.quantifier_text = _coerce_quantifier_text(expr.quantifier)
        _copy_string_set_to_protobuf(expr.string_set, pb_expr.of_expression)
    elif isinstance(expr, DefinedExpression):
        convert_expression_to_protobuf(expr.expression, pb_expr.defined_expression.expression)
    elif isinstance(expr, StringOperatorExpression):
        convert_expression_to_protobuf(expr.left, pb_expr.string_operator_expression.left)
        pb_expr.string_operator_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.right, pb_expr.string_operator_expression.right)
    elif isinstance(expr, WithStatement):
        for declaration in expr.declarations:
            convert_with_declaration_to_protobuf(
                declaration,
                pb_expr.with_statement.declarations.add(),
            )
        convert_expression_to_protobuf(expr.body, pb_expr.with_statement.body)
    elif isinstance(expr, ArrayComprehension):
        if expr.expression is not None:
            convert_expression_to_protobuf(
                expr.expression,
                pb_expr.array_comprehension.expression,
            )
        pb_expr.array_comprehension.variable = expr.variable
        if expr.iterable is not None:
            convert_expression_to_protobuf(expr.iterable, pb_expr.array_comprehension.iterable)
        if expr.condition is not None:
            convert_expression_to_protobuf(
                expr.condition,
                pb_expr.array_comprehension.condition,
            )
    elif isinstance(expr, DictComprehension):
        if expr.key_expression is not None:
            convert_expression_to_protobuf(
                expr.key_expression,
                pb_expr.dict_comprehension.key_expression,
            )
        if expr.value_expression is not None:
            convert_expression_to_protobuf(
                expr.value_expression,
                pb_expr.dict_comprehension.value_expression,
            )
        pb_expr.dict_comprehension.key_variable = expr.key_variable
        if expr.value_variable is not None:
            pb_expr.dict_comprehension.value_variable = expr.value_variable
        if expr.iterable is not None:
            convert_expression_to_protobuf(expr.iterable, pb_expr.dict_comprehension.iterable)
        if expr.condition is not None:
            convert_expression_to_protobuf(
                expr.condition,
                pb_expr.dict_comprehension.condition,
            )
    elif isinstance(expr, TupleExpression):
        for element in expr.elements:
            convert_expression_to_protobuf(element, pb_expr.tuple_expression.elements.add())
    elif isinstance(expr, TupleIndexing):
        convert_expression_to_protobuf(expr.tuple_expr, pb_expr.tuple_indexing.tuple_expr)
        convert_expression_to_protobuf(expr.index, pb_expr.tuple_indexing.index)
    elif isinstance(expr, ListExpression):
        for element in expr.elements:
            convert_expression_to_protobuf(element, pb_expr.list_expression.elements.add())
    elif isinstance(expr, DictExpression):
        for item in expr.items:
            convert_dict_item_to_protobuf(item, pb_expr.dict_expression.items.add())
    elif isinstance(expr, SliceExpression):
        convert_expression_to_protobuf(expr.target, pb_expr.slice_expression.target)
        if expr.start is not None:
            convert_expression_to_protobuf(expr.start, pb_expr.slice_expression.start)
        if expr.stop is not None:
            convert_expression_to_protobuf(expr.stop, pb_expr.slice_expression.stop)
        if expr.step is not None:
            convert_expression_to_protobuf(expr.step, pb_expr.slice_expression.step)
    elif isinstance(expr, LambdaExpression):
        pb_expr.lambda_expression.parameters.extend(expr.parameters)
        convert_expression_to_protobuf(expr.body, pb_expr.lambda_expression.body)
    elif isinstance(expr, PatternMatch):
        convert_expression_to_protobuf(expr.value, pb_expr.pattern_match.value)
        for case in expr.cases:
            convert_match_case_to_protobuf(case, pb_expr.pattern_match.cases.add())
        if expr.default is not None:
            convert_expression_to_protobuf(expr.default, pb_expr.pattern_match.default)
    elif isinstance(expr, SpreadOperator):
        convert_expression_to_protobuf(expr.expression, pb_expr.spread_operator.expression)
        pb_expr.spread_operator.is_dict = expr.is_dict
    else:
        warnings.warn(
            f"Protobuf serialization: unsupported expression type {type(expr).__name__}, "
            "data will be lost",
            stacklevel=2,
        )


def convert_with_declaration_to_protobuf(declaration, pb_declaration) -> None:
    pb_declaration.identifier = declaration.identifier
    convert_expression_to_protobuf(declaration.value, pb_declaration.value)
    _copy_node_metadata_to_protobuf(declaration, pb_declaration)


def convert_dict_item_to_protobuf(item, pb_item) -> None:
    convert_expression_to_protobuf(item.key, pb_item.key)
    convert_expression_to_protobuf(item.value, pb_item.value)
    _copy_node_metadata_to_protobuf(item, pb_item)


def convert_match_case_to_protobuf(case, pb_case) -> None:
    convert_expression_to_protobuf(case.pattern, pb_case.pattern)
    convert_expression_to_protobuf(case.result, pb_case.result)
    _copy_node_metadata_to_protobuf(case, pb_case)


def protobuf_to_ast(pb_file: yara_ast_pb2.YaraFile):
    """Convert a protobuf message back to a basic AST."""
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Import, Include, Rule

    imports = []
    for pb_import in pb_file.imports:
        imports.append(
            _apply_node_metadata_from_protobuf(
                pb_import,
                Import(
                    module=pb_import.module,
                    alias=pb_import.alias if pb_import.alias else None,
                ),
            ),
        )

    includes = []
    for pb_include in pb_file.includes:
        includes.append(
            _apply_node_metadata_from_protobuf(
                pb_include,
                Include(path=pb_include.path),
            ),
        )

    extern_rules = [protobuf_to_extern_rule(pb_rule) for pb_rule in pb_file.extern_rules]
    extern_imports = [protobuf_to_extern_import(pb_import) for pb_import in pb_file.extern_imports]
    pragmas = [protobuf_to_pragma(pb_pragma) for pb_pragma in pb_file.pragmas]
    namespaces = [protobuf_to_extern_namespace(pb_namespace) for pb_namespace in pb_file.namespaces]

    rules = []
    for pb_rule in pb_file.rules:
        tags = []
        for pb_tag in pb_rule.tags:
            from yaraast.ast.rules import Tag

            tags.append(
                _apply_node_metadata_from_protobuf(
                    pb_tag,
                    Tag(name=pb_tag.name),
                )
            )

        if pb_rule.meta_entries:
            meta = [
                protobuf_to_rule_meta_entry(pb_meta_entry) for pb_meta_entry in pb_rule.meta_entries
            ]
        else:
            meta_values = {}
            for key, meta_val in pb_rule.meta.items():
                if meta_val.HasField("string_value"):
                    meta_values[key] = meta_val.string_value
                elif meta_val.HasField("bool_value"):
                    meta_values[key] = meta_val.bool_value
                elif meta_val.HasField("int_value"):
                    meta_values[key] = meta_val.int_value
                elif meta_val.HasField("double_value"):
                    meta_values[key] = meta_val.double_value

            from yaraast.ast.modifiers import MetaEntry

            meta = [
                MetaEntry.from_key_value(key, value, pb_rule.meta_scopes.get(key) or None)
                for key, value in sorted(meta_values.items())
            ]

        strings = []
        for pb_string in pb_rule.strings:
            string_def = protobuf_to_string(pb_string)
            if string_def is not None:
                strings.append(string_def)

        condition = (
            protobuf_to_expression(pb_rule.condition) if pb_rule.HasField("condition") else None
        )
        pragmas_for_rule = [protobuf_to_in_rule_pragma(pb_pragma) for pb_pragma in pb_rule.pragmas]

        rule = Rule(
            name=pb_rule.name,
            modifiers=list(pb_rule.modifiers),
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
            pragmas=pragmas_for_rule,
        )
        rules.append(_apply_node_metadata_from_protobuf(pb_rule, rule))

    ast = YaraFile(
        imports=imports,
        includes=includes,
        rules=rules,
        extern_rules=extern_rules,
        extern_imports=extern_imports,
        pragmas=pragmas,
        namespaces=namespaces,
    )
    return _apply_node_metadata_from_protobuf(pb_file, ast)


def protobuf_to_extern_rule(pb_extern_rule):
    from yaraast.ast.extern import ExternRule
    from yaraast.ast.modifiers import RuleModifier
    from yaraast.errors import ValidationError

    modifiers = []
    for modifier in pb_extern_rule.modifiers:
        try:
            modifiers.append(RuleModifier.from_string(modifier))
        except (ValueError, ValidationError):
            modifiers.append(modifier)

    return _apply_node_metadata_from_protobuf(
        pb_extern_rule,
        ExternRule(
            name=pb_extern_rule.name,
            modifiers=modifiers,
            namespace=pb_extern_rule.namespace or None,
        ),
    )


def protobuf_to_extern_import(pb_extern_import):
    from yaraast.ast.extern import ExternImport

    return _apply_node_metadata_from_protobuf(
        pb_extern_import,
        ExternImport(
            module_path=pb_extern_import.module_path,
            alias=pb_extern_import.alias or None,
            rules=list(pb_extern_import.rules),
        ),
    )


def protobuf_to_extern_namespace(pb_namespace):
    from yaraast.ast.extern import ExternNamespace

    return _apply_node_metadata_from_protobuf(
        pb_namespace,
        ExternNamespace(
            name=pb_namespace.name,
            extern_rules=[
                protobuf_to_extern_rule(pb_rule) for pb_rule in pb_namespace.extern_rules
            ],
        ),
    )


def _protobuf_pragma_scope(scope_text):
    from yaraast.ast.pragmas import PragmaScope

    try:
        return PragmaScope(scope_text or PragmaScope.FILE.value)
    except ValueError:
        return PragmaScope.FILE


def protobuf_to_pragma(pb_pragma):
    from yaraast.ast.pragmas import (
        ConditionalDirective,
        CustomPragma,
        DefineDirective,
        IncludeOncePragma,
        Pragma,
        PragmaType,
        UndefDirective,
    )

    pragma_type = PragmaType.from_string(
        pb_pragma.pragma_type or pb_pragma.name or PragmaType.CUSTOM.value
    )
    scope = _protobuf_pragma_scope(pb_pragma.scope)
    parameters = {
        key: _meta_value_to_python(value) for key, value in sorted(pb_pragma.parameters.items())
    }

    if pragma_type == PragmaType.INCLUDE_ONCE:
        pragma = IncludeOncePragma()
    elif pragma_type == PragmaType.DEFINE and pb_pragma.macro_name:
        pragma = DefineDirective(
            macro_name=pb_pragma.macro_name,
            macro_value=pb_pragma.macro_value if pb_pragma.HasField("macro_value") else None,
        )
    elif pragma_type == PragmaType.UNDEF and pb_pragma.macro_name:
        pragma = UndefDirective(macro_name=pb_pragma.macro_name)
    elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
        pragma = ConditionalDirective(
            pragma_type,
            condition=pb_pragma.condition if pb_pragma.HasField("condition") else None,
        )
    elif pragma_type == PragmaType.CUSTOM:
        pragma = CustomPragma(
            name=pb_pragma.name,
            arguments=list(pb_pragma.arguments),
            parameters=parameters,
            scope=scope,
        )
    else:
        pragma = Pragma(
            pragma_type=pragma_type,
            name=pb_pragma.name,
            arguments=list(pb_pragma.arguments),
            scope=scope,
        )
    pragma.scope = scope
    return _apply_node_metadata_from_protobuf(pb_pragma, pragma)


def protobuf_to_in_rule_pragma(pb_in_rule_pragma):
    from yaraast.ast.pragmas import InRulePragma

    return _apply_node_metadata_from_protobuf(
        pb_in_rule_pragma,
        InRulePragma(
            pragma=protobuf_to_pragma(pb_in_rule_pragma.pragma),
            position=pb_in_rule_pragma.position or "before_strings",
        ),
    )


def _protobuf_to_hex_token(pb_token):
    from yaraast.ast.strings import (
        HexAlternative,
        HexByte,
        HexJump,
        HexNegatedByte,
        HexNibble,
        HexWildcard,
    )

    if pb_token.HasField("byte"):
        return _apply_node_metadata_from_protobuf(
            pb_token,
            HexByte(value=_hex_byte_value_from_protobuf(pb_token.byte.value)),
        )
    if pb_token.HasField("negated_byte"):
        return _apply_node_metadata_from_protobuf(
            pb_token,
            HexNegatedByte(value=_hex_int_value_from_protobuf(pb_token.negated_byte.value)),
        )
    if pb_token.HasField("wildcard"):
        return _apply_node_metadata_from_protobuf(pb_token, HexWildcard())
    if pb_token.HasField("jump"):
        min_jump, max_jump = _protobuf_hex_jump_bounds(pb_token.jump)
        return _apply_node_metadata_from_protobuf(
            pb_token,
            HexJump(
                min_jump=min_jump,
                max_jump=max_jump,
            ),
        )
    if pb_token.HasField("alternative"):
        alternatives = []
        for pb_alternative in pb_token.alternative.alternatives:
            alternative = []
            for nested_pb_token in pb_alternative.tokens:
                token = _protobuf_to_hex_token(nested_pb_token)
                if token is not None:
                    alternative.append(token)
            alternatives.append(alternative)
        return _apply_node_metadata_from_protobuf(
            pb_token,
            HexAlternative(alternatives=alternatives),
        )
    if pb_token.HasField("nibble"):
        return _apply_node_metadata_from_protobuf(
            pb_token,
            HexNibble(
                high=pb_token.nibble.high,
                value=_protobuf_hex_nibble_value(pb_token.nibble.value),
            ),
        )
    return None


def _typed_modifier_value(pb_modifier):
    if pb_modifier.HasField("typed_value"):
        typed_value = pb_modifier.typed_value
        if typed_value.HasField("string_value"):
            return typed_value.string_value
        if typed_value.HasField("bool_value"):
            return typed_value.bool_value
        if typed_value.HasField("int_value"):
            return typed_value.int_value
        if typed_value.HasField("double_value"):
            return typed_value.double_value
    return None


def _legacy_modifier_value(name: str, value: str):
    return deserialize_legacy_modifier_value(name, value)


def _protobuf_modifier_value(pb_modifier):
    if len(pb_modifier.tuple_value) == 2:
        return (pb_modifier.tuple_value[0], pb_modifier.tuple_value[1])

    typed_value = _typed_modifier_value(pb_modifier)
    if typed_value is not None:
        return typed_value

    if pb_modifier.value:
        return _legacy_modifier_value(pb_modifier.name, pb_modifier.value)
    return None


def _protobuf_modifiers_to_ast(pb_modifiers):
    from yaraast.ast.modifiers import StringModifier
    from yaraast.errors import ValidationError

    modifiers = []
    for pb_modifier in pb_modifiers:
        name = pb_modifier.name
        value = _protobuf_modifier_value(pb_modifier)
        try:
            modifier = StringModifier.from_name_value(name, value)
        except (ValueError, ValidationError):
            modifiers.append(_format_unknown_modifier(name, value))
        else:
            modifiers.append(_apply_node_metadata_from_protobuf(pb_modifier, modifier))
    return modifiers


def protobuf_to_string(pb_string) -> Any:
    """Convert a protobuf string definition back to AST."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    if pb_string.HasField("plain"):
        modifiers = _protobuf_modifiers_to_ast(pb_string.plain.modifiers)
        value = (
            pb_string.plain.raw_value
            if _protobuf_has_field(pb_string.plain, "raw_value")
            else pb_string.plain.value
        )
        s = PlainString(
            identifier=pb_string.identifier,
            value=value,
            is_anonymous=pb_string.is_anonymous,
        )
        s.modifiers = modifiers
        return _apply_node_metadata_from_protobuf(pb_string, s)
    if pb_string.HasField("hex"):
        tokens = []
        for pb_token in pb_string.hex.tokens:
            token = _protobuf_to_hex_token(pb_token)
            if token is not None:
                tokens.append(token)
        modifiers = _protobuf_modifiers_to_ast(pb_string.hex.modifiers)
        s = HexString(
            identifier=pb_string.identifier,
            tokens=tokens,
            is_anonymous=pb_string.is_anonymous,
        )
        s.modifiers = modifiers
        return _apply_node_metadata_from_protobuf(pb_string, s)
    if pb_string.HasField("regex"):
        modifiers = _protobuf_modifiers_to_ast(pb_string.regex.modifiers)
        s = RegexString(
            identifier=pb_string.identifier,
            regex=pb_string.regex.regex,
            is_anonymous=pb_string.is_anonymous,
        )
        s.modifiers = modifiers
        return _apply_node_metadata_from_protobuf(pb_string, s)
    return None


def protobuf_to_expression(pb_expr):
    """Convert a protobuf expression back to AST."""
    from yaraast.ast.conditions import (
        AtExpression,
        ForExpression,
        ForOfExpression,
        InExpression,
        OfExpression,
    )
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
        RangeExpression,
        RegexLiteral,
        SetExpression,
        StringCount,
        StringIdentifier,
        StringLength,
        StringLiteral,
        StringOffset,
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternRuleReference
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
    from yaraast.yarax.ast_nodes import (
        ArrayComprehension,
        DictComprehension,
        DictExpression,
        LambdaExpression,
        ListExpression,
        PatternMatch,
        SliceExpression,
        SpreadOperator,
        TupleExpression,
        TupleIndexing,
        WithStatement,
    )

    def with_metadata(node):
        return _apply_node_metadata_from_protobuf(pb_expr, node)

    if pb_expr.HasField("identifier"):
        return with_metadata(Identifier(name=pb_expr.identifier.name))
    if pb_expr.HasField("string_identifier"):
        return with_metadata(StringIdentifier(name=pb_expr.string_identifier.name))
    if pb_expr.HasField("string_wildcard"):
        return with_metadata(StringWildcard(pattern=pb_expr.string_wildcard.pattern))
    if pb_expr.HasField("string_count"):
        return with_metadata(StringCount(string_id=pb_expr.string_count.string_id))
    if pb_expr.HasField("string_offset"):
        return with_metadata(
            StringOffset(
                string_id=pb_expr.string_offset.string_id,
                index=(
                    protobuf_to_expression(pb_expr.string_offset.index)
                    if pb_expr.string_offset.HasField("index")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("string_length"):
        return with_metadata(
            StringLength(
                string_id=pb_expr.string_length.string_id,
                index=(
                    protobuf_to_expression(pb_expr.string_length.index)
                    if pb_expr.string_length.HasField("index")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("integer_literal"):
        return with_metadata(IntegerLiteral(value=pb_expr.integer_literal.value))
    if pb_expr.HasField("double_literal"):
        return with_metadata(DoubleLiteral(value=pb_expr.double_literal.value))
    if pb_expr.HasField("string_literal"):
        return with_metadata(StringLiteral(value=pb_expr.string_literal.value))
    if pb_expr.HasField("regex_literal"):
        return with_metadata(
            RegexLiteral(
                pattern=pb_expr.regex_literal.pattern,
                modifiers=pb_expr.regex_literal.modifiers,
            ),
        )
    if pb_expr.HasField("boolean_literal"):
        return with_metadata(BooleanLiteral(value=pb_expr.boolean_literal.value))
    if pb_expr.HasField("binary_expression"):
        return with_metadata(
            BinaryExpression(
                left=protobuf_to_expression(pb_expr.binary_expression.left),
                operator=pb_expr.binary_expression.operator,
                right=protobuf_to_expression(pb_expr.binary_expression.right),
            ),
        )
    if pb_expr.HasField("unary_expression"):
        return with_metadata(
            UnaryExpression(
                operator=pb_expr.unary_expression.operator,
                operand=protobuf_to_expression(pb_expr.unary_expression.operand),
            ),
        )
    if pb_expr.HasField("parentheses_expression"):
        return with_metadata(
            ParenthesesExpression(
                expression=protobuf_to_expression(pb_expr.parentheses_expression.expression)
            )
        )
    if pb_expr.HasField("set_expression"):
        return with_metadata(
            SetExpression(
                elements=[
                    protobuf_to_expression(element) for element in pb_expr.set_expression.elements
                ]
            )
        )
    if pb_expr.HasField("range_expression"):
        return with_metadata(
            RangeExpression(
                low=protobuf_to_expression(pb_expr.range_expression.low),
                high=protobuf_to_expression(pb_expr.range_expression.high),
            ),
        )
    if pb_expr.HasField("function_call"):
        return with_metadata(
            FunctionCall(
                function=pb_expr.function_call.function,
                arguments=[
                    protobuf_to_expression(argument) for argument in pb_expr.function_call.arguments
                ],
            ),
        )
    if pb_expr.HasField("array_access"):
        return with_metadata(
            ArrayAccess(
                array=protobuf_to_expression(pb_expr.array_access.array),
                index=protobuf_to_expression(pb_expr.array_access.index),
            ),
        )
    if pb_expr.HasField("member_access"):
        return with_metadata(
            MemberAccess(
                object=protobuf_to_expression(pb_expr.member_access.object),
                member=pb_expr.member_access.member,
            ),
        )
    if pb_expr.HasField("module_reference"):
        return with_metadata(ModuleReference(module=pb_expr.module_reference.module))
    if pb_expr.HasField("dictionary_access"):
        return with_metadata(
            DictionaryAccess(
                object=protobuf_to_expression(pb_expr.dictionary_access.object),
                key=(
                    protobuf_to_expression(pb_expr.dictionary_access.key_expr)
                    if pb_expr.dictionary_access.HasField("key_expr")
                    else pb_expr.dictionary_access.key
                ),
            ),
        )
    if pb_expr.HasField("extern_rule_reference"):
        return with_metadata(
            ExternRuleReference(
                rule_name=pb_expr.extern_rule_reference.rule_name,
                namespace=pb_expr.extern_rule_reference.namespace or None,
            ),
        )
    if pb_expr.HasField("for_expression"):
        return with_metadata(
            ForExpression(
                quantifier=(
                    protobuf_to_expression(pb_expr.for_expression.quantifier_expr)
                    if pb_expr.for_expression.HasField("quantifier_expr")
                    else _restore_quantifier_text(pb_expr.for_expression.quantifier)
                ),
                variable=pb_expr.for_expression.variable,
                iterable=protobuf_to_expression(pb_expr.for_expression.iterable),
                body=protobuf_to_expression(pb_expr.for_expression.body),
            ),
        )
    if pb_expr.HasField("for_of_expression"):
        return with_metadata(
            ForOfExpression(
                quantifier=(
                    protobuf_to_expression(pb_expr.for_of_expression.quantifier_expr)
                    if pb_expr.for_of_expression.HasField("quantifier_expr")
                    else _restore_quantifier_text(pb_expr.for_of_expression.quantifier)
                ),
                string_set=_protobuf_string_set_to_ast(pb_expr.for_of_expression),
                condition=(
                    protobuf_to_expression(pb_expr.for_of_expression.condition)
                    if pb_expr.for_of_expression.HasField("condition")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("at_expression"):
        return with_metadata(
            AtExpression(
                string_id=pb_expr.at_expression.string_id,
                offset=protobuf_to_expression(pb_expr.at_expression.offset),
            ),
        )
    if pb_expr.HasField("in_expression"):
        subject = (
            protobuf_to_expression(pb_expr.in_expression.subject)
            if pb_expr.in_expression.HasField("subject")
            else pb_expr.in_expression.string_id
        )
        return with_metadata(
            InExpression(
                subject=subject,
                range=protobuf_to_expression(pb_expr.in_expression.range),
            ),
        )
    if pb_expr.HasField("of_expression"):
        return with_metadata(
            OfExpression(
                quantifier=(
                    _restore_quantifier_text(pb_expr.of_expression.quantifier_text)
                    if pb_expr.of_expression.HasField("quantifier_text")
                    else protobuf_to_expression(pb_expr.of_expression.quantifier)
                ),
                string_set=_protobuf_string_set_to_ast(pb_expr.of_expression),
            ),
        )
    if pb_expr.HasField("defined_expression"):
        return with_metadata(
            DefinedExpression(
                expression=protobuf_to_expression(pb_expr.defined_expression.expression)
            )
        )
    if pb_expr.HasField("string_operator_expression"):
        return with_metadata(
            StringOperatorExpression(
                left=protobuf_to_expression(pb_expr.string_operator_expression.left),
                operator=pb_expr.string_operator_expression.operator,
                right=protobuf_to_expression(pb_expr.string_operator_expression.right),
            ),
        )
    if pb_expr.HasField("with_statement"):
        return with_metadata(
            WithStatement(
                declarations=[
                    protobuf_to_with_declaration(declaration)
                    for declaration in pb_expr.with_statement.declarations
                ],
                body=protobuf_to_expression(pb_expr.with_statement.body),
            ),
        )
    if pb_expr.HasField("array_comprehension"):
        return with_metadata(
            ArrayComprehension(
                expression=(
                    protobuf_to_expression(pb_expr.array_comprehension.expression)
                    if pb_expr.array_comprehension.HasField("expression")
                    else None
                ),
                variable=pb_expr.array_comprehension.variable,
                iterable=(
                    protobuf_to_expression(pb_expr.array_comprehension.iterable)
                    if pb_expr.array_comprehension.HasField("iterable")
                    else None
                ),
                condition=(
                    protobuf_to_expression(pb_expr.array_comprehension.condition)
                    if pb_expr.array_comprehension.HasField("condition")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("dict_comprehension"):
        return with_metadata(
            DictComprehension(
                key_expression=(
                    protobuf_to_expression(pb_expr.dict_comprehension.key_expression)
                    if pb_expr.dict_comprehension.HasField("key_expression")
                    else None
                ),
                value_expression=(
                    protobuf_to_expression(pb_expr.dict_comprehension.value_expression)
                    if pb_expr.dict_comprehension.HasField("value_expression")
                    else None
                ),
                key_variable=pb_expr.dict_comprehension.key_variable,
                value_variable=(
                    pb_expr.dict_comprehension.value_variable
                    if pb_expr.dict_comprehension.HasField("value_variable")
                    else None
                ),
                iterable=(
                    protobuf_to_expression(pb_expr.dict_comprehension.iterable)
                    if pb_expr.dict_comprehension.HasField("iterable")
                    else None
                ),
                condition=(
                    protobuf_to_expression(pb_expr.dict_comprehension.condition)
                    if pb_expr.dict_comprehension.HasField("condition")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("tuple_expression"):
        return with_metadata(
            TupleExpression(
                elements=[
                    protobuf_to_expression(element) for element in pb_expr.tuple_expression.elements
                ],
            ),
        )
    if pb_expr.HasField("tuple_indexing"):
        return with_metadata(
            TupleIndexing(
                tuple_expr=protobuf_to_expression(pb_expr.tuple_indexing.tuple_expr),
                index=protobuf_to_expression(pb_expr.tuple_indexing.index),
            ),
        )
    if pb_expr.HasField("list_expression"):
        return with_metadata(
            ListExpression(
                elements=[
                    protobuf_to_expression(element) for element in pb_expr.list_expression.elements
                ],
            ),
        )
    if pb_expr.HasField("dict_expression"):
        return with_metadata(
            DictExpression(
                items=[protobuf_to_dict_item(item) for item in pb_expr.dict_expression.items],
            ),
        )
    if pb_expr.HasField("slice_expression"):
        return with_metadata(
            SliceExpression(
                target=protobuf_to_expression(pb_expr.slice_expression.target),
                start=(
                    protobuf_to_expression(pb_expr.slice_expression.start)
                    if pb_expr.slice_expression.HasField("start")
                    else None
                ),
                stop=(
                    protobuf_to_expression(pb_expr.slice_expression.stop)
                    if pb_expr.slice_expression.HasField("stop")
                    else None
                ),
                step=(
                    protobuf_to_expression(pb_expr.slice_expression.step)
                    if pb_expr.slice_expression.HasField("step")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("lambda_expression"):
        return with_metadata(
            LambdaExpression(
                parameters=list(pb_expr.lambda_expression.parameters),
                body=protobuf_to_expression(pb_expr.lambda_expression.body),
            ),
        )
    if pb_expr.HasField("pattern_match"):
        return with_metadata(
            PatternMatch(
                value=protobuf_to_expression(pb_expr.pattern_match.value),
                cases=[protobuf_to_match_case(case) for case in pb_expr.pattern_match.cases],
                default=(
                    protobuf_to_expression(pb_expr.pattern_match.default)
                    if pb_expr.pattern_match.HasField("default")
                    else None
                ),
            ),
        )
    if pb_expr.HasField("spread_operator"):
        return with_metadata(
            SpreadOperator(
                expression=protobuf_to_expression(pb_expr.spread_operator.expression),
                is_dict=pb_expr.spread_operator.is_dict,
            ),
        )
    import warnings

    warnings.warn(
        "Protobuf deserialization: unrecognized expression field, "
        "substituting BooleanLiteral(true) — data may have been lost during serialization",
        stacklevel=2,
    )
    return with_metadata(BooleanLiteral(value=True))


def protobuf_to_with_declaration(pb_declaration):
    from yaraast.yarax.ast_nodes import WithDeclaration

    return _apply_node_metadata_from_protobuf(
        pb_declaration,
        WithDeclaration(
            identifier=pb_declaration.identifier,
            value=protobuf_to_expression(pb_declaration.value),
        ),
    )


def protobuf_to_dict_item(pb_item):
    from yaraast.yarax.ast_nodes import DictItem

    return _apply_node_metadata_from_protobuf(
        pb_item,
        DictItem(
            key=protobuf_to_expression(pb_item.key),
            value=protobuf_to_expression(pb_item.value),
        ),
    )


def protobuf_to_match_case(pb_case):
    from yaraast.yarax.ast_nodes import MatchCase

    return _apply_node_metadata_from_protobuf(
        pb_case,
        MatchCase(
            pattern=protobuf_to_expression(pb_case.pattern),
            result=protobuf_to_expression(pb_case.result),
        ),
    )
