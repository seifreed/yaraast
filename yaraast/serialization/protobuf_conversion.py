"""Conversion helpers between AST and protobuf representations."""

from __future__ import annotations

from collections.abc import Mapping
import math
import time
from typing import Any

from yaraast.errors import SerializationError
from yaraast.serialization._serialization_primitives import (
    _is_empty_nonempty_text,
    _is_negated_nibble_pattern,
)
from yaraast.serialization.meta_scopes import deserialize_meta_scope, serialize_meta_scope
from yaraast.serialization.modifier_values import deserialize_legacy_modifier_value
from yaraast.serialization.pragma_scopes import deserialize_pragma_scope, serialize_pragma_scope
from yaraast.string_escaping import escape_string_source_value

from . import yara_ast_pb2

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _finite_double_value(value, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"{context} value must be numeric"
        raise SerializationError(msg)
    value = float(value)
    if not math.isfinite(value):
        msg = f"{context} value must be finite"
        raise SerializationError(msg)
    return value


def _validate_finite_quantifier(value) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        msg = "quantifier must be finite"
        raise SerializationError(msg)


def _protobuf_has_field(message, field_name: str) -> bool:
    try:
        return message.HasField(field_name)
    except ValueError:
        return False


def _node_has_metadata(node) -> bool:
    leading_comments = getattr(node, "leading_comments", None)
    return bool(
        getattr(node, "location", None) is not None
        or (leading_comments is not None and leading_comments != [])
        or getattr(node, "trailing_comment", None) is not None
    )


def _copy_location_to_protobuf(location, pb_location) -> None:
    pb_location.line = _protobuf_required_int(location.line, "Location line")
    pb_location.column = _protobuf_required_int(location.column, "Location column")
    if location.file is not None:
        pb_location.file = _protobuf_required_string(location.file, "Location file")
    if location.end_line is not None:
        pb_location.end_line = _protobuf_required_int(location.end_line, "Location end_line")
    if location.end_column is not None:
        pb_location.end_column = _protobuf_required_int(
            location.end_column,
            "Location end_column",
        )


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
    pb_comment.text = _protobuf_required_string(comment.text, "Comment text")
    pb_comment.is_multiline = _protobuf_required_bool(
        comment.is_multiline,
        "Comment is_multiline",
    )
    _copy_node_metadata_to_protobuf(comment, pb_comment)


def _protobuf_comment_list(values, context: str) -> list:
    from yaraast.ast.comments import Comment

    comments = _protobuf_list(values, context)
    for comment in comments:
        if not isinstance(comment, Comment):
            msg = f"{context} item must be Comment"
            raise SerializationError(msg)
    return comments


def _protobuf_comment_metadata_list(values, context: str) -> list:
    from yaraast.ast.comments import Comment, CommentGroup

    comments = _protobuf_list(values, context)
    for comment in comments:
        if not isinstance(comment, Comment | CommentGroup):
            msg = f"{context} item must be Comment or CommentGroup"
            raise SerializationError(msg)
    return comments


def _copy_comment_metadata_to_protobuf(
    comment,
    pb_comment_metadata,
    context: str = "Comment metadata",
) -> None:
    from yaraast.ast.comments import Comment, CommentGroup

    if isinstance(comment, CommentGroup):
        pb_group = pb_comment_metadata.group
        pb_group.SetInParent()
        for nested_comment in _protobuf_comment_list(
            comment.comments,
            "CommentGroup comments",
        ):
            _copy_comment_to_protobuf(nested_comment, pb_group.comments.add())
        _copy_node_metadata_to_protobuf(comment, pb_group)
    elif isinstance(comment, Comment):
        _copy_comment_to_protobuf(comment, pb_comment_metadata.comment)
    else:
        msg = f"{context} must be Comment or CommentGroup"
        raise SerializationError(msg)


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

    for comment in _protobuf_comment_metadata_list(
        getattr(node, "leading_comments", []),
        "leading_comments",
    ):
        _copy_comment_metadata_to_protobuf(
            comment,
            pb_metadata.leading_comments.add(),
            "leading_comments item",
        )

    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment is not None:
        _copy_comment_metadata_to_protobuf(
            trailing_comment,
            pb_metadata.trailing_comment,
            "trailing_comment",
        )


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
    from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
    from yaraast.ast.pragmas import Pragma
    from yaraast.ast.rules import Import, Include, Rule

    pb_file = yara_ast_pb2.YaraFile()

    imports = _protobuf_node_list(ast.imports, "YaraFile imports", Import)
    includes = _protobuf_node_list(ast.includes, "YaraFile includes", Include)
    extern_rules = _protobuf_node_list(ast.extern_rules, "YaraFile extern_rules", ExternRule)
    extern_imports = _protobuf_node_list(
        ast.extern_imports,
        "YaraFile extern_imports",
        ExternImport,
    )
    pragmas = _protobuf_node_list(ast.pragmas, "YaraFile pragmas", Pragma)
    namespaces = _protobuf_node_list(
        ast.namespaces,
        "YaraFile namespaces",
        ExternNamespace,
    )
    rules = _protobuf_node_list(ast.rules, "YaraFile rules", Rule)

    for imp in imports:
        pb_import = pb_file.imports.add()
        pb_import.module = _protobuf_required_nonempty_string(imp.module, "Import module")
        if hasattr(imp, "alias") and imp.alias is not None:
            pb_import.alias = _protobuf_required_nonempty_string(imp.alias, "Import alias")
        _copy_node_metadata_to_protobuf(imp, pb_import)

    for inc in includes:
        pb_include = pb_file.includes.add()
        pb_include.path = _protobuf_required_nonempty_string(inc.path, "Include path")
        _copy_node_metadata_to_protobuf(inc, pb_include)

    for extern_rule in extern_rules:
        convert_extern_rule_to_protobuf(extern_rule, pb_file.extern_rules.add())

    for extern_import in extern_imports:
        convert_extern_import_to_protobuf(extern_import, pb_file.extern_imports.add())

    for pragma in pragmas:
        convert_pragma_to_protobuf(pragma, pb_file.pragmas.add())

    for namespace in namespaces:
        convert_extern_namespace_to_protobuf(namespace, pb_file.namespaces.add())

    for rule in rules:
        pb_rule = pb_file.rules.add()
        convert_rule_to_protobuf(rule, pb_rule)

    if include_metadata:
        pb_file.metadata.format = "yaraast-protobuf"
        pb_file.metadata.version = "1.0"
        pb_file.metadata.ast_type = "YaraFile"
        pb_file.metadata.rules_count = len(rules)
        pb_file.metadata.imports_count = len(imports)
        pb_file.metadata.includes_count = len(includes)
        pb_file.metadata.timestamp = int(time.time())

    _copy_node_metadata_to_protobuf(ast, pb_file)
    return pb_file


def convert_rule_to_protobuf(rule, pb_rule) -> None:
    """Convert a single rule AST node to protobuf."""
    from yaraast.ast.meta import Meta
    from yaraast.ast.modifiers import MetaEntry
    from yaraast.ast.pragmas import InRulePragma
    from yaraast.ast.rules import Tag

    pb_rule.name = _protobuf_required_nonempty_string(rule.name, "Rule name")
    pb_rule.modifiers.extend(
        _protobuf_modifier_name(modifier, "Rule modifier")
        for modifier in _protobuf_rule_modifier_list(rule.modifiers, "Rule modifiers")
    )
    _copy_node_metadata_to_protobuf(rule, pb_rule)

    for tag in _protobuf_node_list(rule.tags, "Rule tags", Tag):
        pb_tag = pb_rule.tags.add()
        pb_tag.name = _protobuf_required_nonempty_string(tag.name, "Tag name")
        _copy_node_metadata_to_protobuf(tag, pb_tag)

    for entry in _protobuf_node_list(rule.meta, "Rule meta", (Meta, MetaEntry)):
        key = _protobuf_required_nonempty_string(getattr(entry, "key", None), "Meta key")
        value = getattr(entry, "value", "")
        scope = getattr(entry, "scope", None)
        meta_val = pb_rule.meta[key]
        pb_meta_entry = pb_rule.meta_entries.add()
        pb_meta_entry.key = key
        _copy_python_value_to_meta_value(value, pb_meta_entry.value, "Meta")
        _copy_node_metadata_to_protobuf(entry, pb_meta_entry)
        if scope is not None:
            scope_text = serialize_meta_scope(scope)
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
            meta_val.double_value = _finite_double_value(value, "Meta")

    for string_def in _protobuf_string_definition_list(rule.strings, "Rule strings"):
        pb_string = pb_rule.strings.add()
        string_context = type(string_def).__name__
        pb_string.identifier = _protobuf_required_nonempty_string(
            string_def.identifier,
            f"{string_context} identifier",
        )
        convert_string_to_protobuf(string_def, pb_string)

    if rule.condition is not None:
        convert_expression_to_protobuf(rule.condition, pb_rule.condition)

    for pragma in _protobuf_node_list(rule.pragmas, "Rule pragmas", InRulePragma):
        convert_in_rule_pragma_to_protobuf(pragma, pb_rule.pragmas.add())


def _copy_python_value_to_meta_value(value, pb_meta_value, context: str) -> None:
    if isinstance(value, str):
        pb_meta_value.string_value = value
    elif isinstance(value, bool):
        pb_meta_value.bool_value = value
    elif isinstance(value, int):
        pb_meta_value.int_value = value
    elif isinstance(value, float):
        pb_meta_value.double_value = _finite_double_value(value, context)
    else:
        msg = f"{context} value must be a string, integer, boolean, or finite float"
        raise SerializationError(msg)


def _protobuf_required_string(value, context: str) -> str:
    if isinstance(value, str):
        return value
    msg = f"{context} must be a string"
    raise SerializationError(msg)


def _protobuf_required_nonempty_string(value, context: str) -> str:
    text = _protobuf_required_string(value, context)
    if _is_empty_nonempty_text(text, context):
        msg = f"{context} must not be empty"
        raise SerializationError(msg)
    return text


def _protobuf_optional_string(value, context: str) -> str | None:
    if value is None:
        return None
    return _protobuf_required_string(value, context)


def _protobuf_required_bool(value, context: str) -> bool:
    if isinstance(value, bool):
        return value
    msg = f"{context} must be a boolean"
    raise SerializationError(msg)


def _protobuf_required_int(value, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{context} must be an integer"
        raise SerializationError(msg)
    return value


def _protobuf_pragma_type(pragma) -> str:
    pragma_type = getattr(pragma, "pragma_type", None)
    value = getattr(pragma_type, "value", pragma_type)
    if isinstance(value, str):
        return value
    msg = "Pragma pragma_type must be a string"
    raise SerializationError(msg)


def _protobuf_required_string_key(value, message: str) -> str:
    if isinstance(value, str):
        return value
    raise SerializationError(message)


def _protobuf_string_list(values, context: str) -> list[str]:
    if isinstance(values, list | tuple) and all(isinstance(item, str) for item in values):
        return list(values)
    msg = f"{context} must be a list of strings"
    raise SerializationError(msg)


def _protobuf_nonempty_string_list(values, context: str) -> list[str]:
    items = _protobuf_string_list(values, context)
    for item in items:
        if _is_empty_nonempty_text(item, context):
            msg = f"{context} item must not be empty"
            raise SerializationError(msg)
    return items


def _protobuf_node_list(values, context: str, item_type) -> list:
    if not isinstance(values, list | tuple):
        msg = f"{context} must be a list"
        raise SerializationError(msg)
    items = list(values)
    for item in items:
        if not isinstance(item, item_type):
            if isinstance(item_type, tuple):
                expected = " or ".join(node_type.__name__ for node_type in item_type)
            else:
                expected = item_type.__name__
            msg = f"{context} item must be {expected}"
            raise SerializationError(msg)
    return items


def _protobuf_list(values, context: str) -> list:
    if not isinstance(values, list | tuple):
        msg = f"{context} must be a list"
        raise SerializationError(msg)
    return list(values)


def _protobuf_mapping(values, context: str) -> Mapping:
    if not isinstance(values, Mapping):
        msg = f"{context} must be a mapping"
        raise SerializationError(msg)
    return values


def _protobuf_rule_modifier_list(values, context: str) -> list:
    from yaraast.ast.modifiers import RuleModifier

    items = _protobuf_list(values, context)
    for item in items:
        if not isinstance(item, RuleModifier | str):
            msg = f"{context} item must be RuleModifier or string"
            raise SerializationError(msg)
    return items


def _protobuf_modifier_name(modifier, context: str) -> str:
    if isinstance(modifier, str):
        return _protobuf_required_nonempty_string(modifier, f"{context} name")
    try:
        name = modifier.name
    except AttributeError as exc:
        msg = f"{context} name must be a string"
        raise SerializationError(msg) from exc
    return _protobuf_required_nonempty_string(name, f"{context} name")


def _protobuf_modifier_names_from_protobuf(values, context: str) -> list[str]:
    return [_protobuf_required_nonempty_string(value, f"{context} name") for value in values]


def _protobuf_string_modifier_list(values, context: str) -> list:
    from yaraast.ast.modifiers import StringModifier

    items = _protobuf_list(values, context)
    for item in items:
        if not isinstance(item, StringModifier | str):
            msg = f"{context} item must be StringModifier or string"
            raise SerializationError(msg)
    return items


def _protobuf_string_definition_list(values, context: str) -> list:
    from yaraast.ast.strings import StringDefinition

    items = _protobuf_list(values, context)
    for item in items:
        if not isinstance(item, StringDefinition) and not hasattr(item, "identifier"):
            msg = f"{context} item must be StringDefinition"
            raise SerializationError(msg)
    return items


def _meta_value_to_python(pb_meta_value):
    if pb_meta_value.HasField("string_value"):
        return pb_meta_value.string_value
    if pb_meta_value.HasField("bool_value"):
        return pb_meta_value.bool_value
    if pb_meta_value.HasField("int_value"):
        return pb_meta_value.int_value
    if pb_meta_value.HasField("double_value"):
        return _finite_double_value(pb_meta_value.double_value, "Meta")
    msg = "Meta value is missing a value"
    raise SerializationError(msg)


def protobuf_to_rule_meta_entry(pb_meta_entry):
    from yaraast.ast.meta import Meta
    from yaraast.ast.modifiers import MetaEntry

    key = _protobuf_required_nonempty_string(pb_meta_entry.key, "Meta key")
    value = _meta_value_to_python(pb_meta_entry.value)
    if pb_meta_entry.ast_node or _protobuf_has_field(pb_meta_entry, "node_metadata"):
        meta = Meta(key, value)
        return _apply_node_metadata_from_protobuf(pb_meta_entry, meta)
    return MetaEntry.from_key_value(
        key,
        value,
        deserialize_meta_scope(pb_meta_entry.scope or None),
    )


def convert_extern_rule_to_protobuf(extern_rule, pb_extern_rule) -> None:
    pb_extern_rule.name = _protobuf_required_nonempty_string(
        extern_rule.name,
        "ExternRule name",
    )
    pb_extern_rule.modifiers.extend(
        _protobuf_modifier_name(modifier, "ExternRule modifier")
        for modifier in _protobuf_rule_modifier_list(
            extern_rule.modifiers,
            "ExternRule modifiers",
        )
    )
    if extern_rule.namespace is not None:
        pb_extern_rule.namespace = _protobuf_required_nonempty_string(
            extern_rule.namespace,
            "ExternRule namespace",
        )
    _copy_node_metadata_to_protobuf(extern_rule, pb_extern_rule)


def convert_extern_import_to_protobuf(extern_import, pb_extern_import) -> None:
    module_path = _protobuf_required_nonempty_string(
        extern_import.module_path,
        "ExternImport module_path",
    )
    if not module_path.strip():
        msg = "ExternImport module_path must not be empty"
        raise SerializationError(msg)
    pb_extern_import.module_path = module_path
    if extern_import.alias is not None:
        alias = _protobuf_required_nonempty_string(
            extern_import.alias,
            "ExternImport alias",
        )
        if not alias.strip():
            msg = "ExternImport alias must not be empty"
            raise SerializationError(msg)
        pb_extern_import.alias = alias
    rules = _protobuf_nonempty_string_list(extern_import.rules, "ExternImport rules")
    if any(not rule.strip() for rule in rules):
        msg = "ExternImport rules item must not be empty"
        raise SerializationError(msg)
    pb_extern_import.rules.extend(rules)
    _copy_node_metadata_to_protobuf(extern_import, pb_extern_import)


def convert_extern_namespace_to_protobuf(namespace, pb_namespace) -> None:
    from yaraast.ast.extern import ExternRule

    pb_namespace.name = _protobuf_required_nonempty_string(
        namespace.name,
        "ExternNamespace name",
    )
    _copy_node_metadata_to_protobuf(namespace, pb_namespace)
    for extern_rule in _protobuf_node_list(
        namespace.extern_rules,
        "ExternNamespace extern_rules",
        ExternRule,
    ):
        convert_extern_rule_to_protobuf(extern_rule, pb_namespace.extern_rules.add())


def convert_pragma_to_protobuf(pragma, pb_pragma) -> None:
    scope = getattr(pragma, "scope", None)
    pb_pragma.pragma_type = _protobuf_pragma_type(pragma)
    pb_pragma.name = _protobuf_required_nonempty_string(pragma.name, "Pragma name")
    pb_pragma.scope = serialize_pragma_scope(scope) if scope is not None else ""

    macro_name_value = getattr(pragma, "macro_name", None)
    macro_name = None
    if macro_name_value is not None:
        macro_name = _protobuf_required_nonempty_string(
            macro_name_value,
            "Pragma macro_name",
        )
        pb_pragma.macro_name = macro_name
    macro_value = _protobuf_optional_string(
        getattr(pragma, "macro_value", None),
        "Pragma macro_value",
    )
    if macro_value is not None:
        pb_pragma.macro_value = macro_value
    condition_value = getattr(pragma, "condition", None)
    condition = (
        _protobuf_required_nonempty_string(condition_value, "Pragma condition")
        if condition_value is not None
        else None
    )
    if condition is not None:
        pb_pragma.condition = condition

    pb_pragma.arguments.extend(
        _protobuf_string_list(getattr(pragma, "arguments", []), "Pragma arguments")
    )

    parameters = _protobuf_mapping(
        getattr(pragma, "parameters", {}),
        "Pragma parameters",
    )
    for key, value in parameters.items():
        parameter_key = _protobuf_required_string_key(
            key,
            "Pragma parameters keys must be strings",
        )
        _copy_python_value_to_meta_value(
            value,
            pb_pragma.parameters[parameter_key],
            "Pragma parameter",
        )
    _copy_node_metadata_to_protobuf(pragma, pb_pragma)


def convert_in_rule_pragma_to_protobuf(in_rule_pragma, pb_in_rule_pragma) -> None:
    convert_pragma_to_protobuf(in_rule_pragma.pragma, pb_in_rule_pragma.pragma)
    pb_in_rule_pragma.position = _protobuf_required_nonempty_string(
        in_rule_pragma.position,
        "InRulePragma position",
    )
    _copy_node_metadata_to_protobuf(in_rule_pragma, pb_in_rule_pragma)


def _modifier_value_text(value) -> str:
    if isinstance(value, tuple) and len(value) == 2:
        return f"{value[0]}-{value[1]}"
    return str(value)


def _raise_invalid_modifier_value() -> None:
    msg = "String modifier value must be a string, number, tuple, or null"
    raise SerializationError(msg)


def _validate_plain_string_value_for_protobuf(value) -> None:
    if not isinstance(value, str | bytes):
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    if not value:
        msg = "PlainString must contain at least one byte"
        raise SerializationError(msg)


def _is_protobuf_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_legacy_modifier_tuple(value) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) == 2
        and all(isinstance(item, str | int | float | bool) for item in value)
    )


def _format_unknown_modifier(name: str, value) -> str:
    if value is None:
        return name
    if isinstance(value, tuple) and len(value) == 2:
        return f"{name}({value[0]}-{value[1]})"
    if isinstance(value, str):
        return f'{name}("{escape_string_source_value(value)}")'
    return f"{name}({value})"


def _copy_modifier_to_protobuf(mod, pb_mod) -> None:
    pb_mod.name = _protobuf_modifier_name(mod, "String modifier")
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
    elif _is_legacy_modifier_tuple(value):
        return
    elif isinstance(value, bool):
        _raise_invalid_modifier_value()
    elif isinstance(value, int):
        pb_mod.typed_value.int_value = value
    elif isinstance(value, float):
        pb_mod.typed_value.double_value = _finite_double_value(value, "String modifier")
    elif isinstance(value, str):
        pb_mod.typed_value.string_value = value
    else:
        _raise_invalid_modifier_value()


def convert_string_to_protobuf(string_def, pb_string) -> None:
    """Convert a string definition to protobuf."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    _copy_node_metadata_to_protobuf(string_def, pb_string)
    string_context = type(string_def).__name__
    pb_string.is_anonymous = _protobuf_required_bool(
        getattr(string_def, "is_anonymous", False),
        f"{string_context} is_anonymous",
    )
    if isinstance(string_def, PlainString):
        _validate_plain_string_value_for_protobuf(string_def.value)
        if isinstance(string_def.value, bytes):
            pb_string.plain.raw_value = string_def.value
        else:
            pb_string.plain.value = string_def.value
        for mod in _protobuf_string_modifier_list(
            string_def.modifiers,
            "PlainString modifiers",
        ):
            pb_mod = pb_string.plain.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)

    elif isinstance(string_def, HexString):
        tokens = _protobuf_list(string_def.tokens, "HexString tokens")
        if not tokens:
            msg = "HexString must contain at least one token"
            raise SerializationError(msg)
        _validate_hex_token_sequence_for_protobuf(
            tokens,
            "hex string",
            inside_alternative=False,
        )
        pb_string.hex.SetInParent()
        for token in tokens:
            pb_token = pb_string.hex.tokens.add()
            convert_hex_token_to_protobuf(token, pb_token)

        for mod in _protobuf_string_modifier_list(
            string_def.modifiers,
            "HexString modifiers",
        ):
            pb_mod = pb_string.hex.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)

    elif isinstance(string_def, RegexString):
        pb_string.regex.regex = _protobuf_required_nonempty_string(
            string_def.regex,
            "RegexString regex",
        )
        for mod in _protobuf_string_modifier_list(
            string_def.modifiers,
            "RegexString modifiers",
        ):
            pb_mod = pb_string.regex.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)
    else:
        msg = f"Unsupported protobuf string definition type: {type(string_def).__name__}"
        raise SerializationError(msg)


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
        pb_token.negated_byte.value = _hex_negated_byte_value_to_protobuf(token.value)
    elif isinstance(token, HexWildcard):
        pb_token.wildcard.CopyFrom(yara_ast_pb2.HexWildcard())
    elif isinstance(token, HexJump):
        _copy_hex_jump_to_protobuf(token, pb_token.jump)
    elif isinstance(token, HexAlternative):
        alternatives = _protobuf_list(token.alternatives, "HexAlternative alternatives")
        if not alternatives:
            msg = "HexAlternative must contain at least one branch"
            raise SerializationError(msg)
        pb_token.alternative.SetInParent()
        for alternative in alternatives:
            branch = _coerce_hex_alternative_branch(alternative)
            if not branch:
                msg = "HexAlternative branches must not be empty"
                raise SerializationError(msg)
            _validate_hex_token_sequence_for_protobuf(
                branch,
                "hex alternative branch",
                inside_alternative=True,
            )
            pb_alternative = pb_token.alternative.alternatives.add()
            for alternative_token in branch:
                convert_hex_token_to_protobuf(alternative_token, pb_alternative.tokens.add())
    elif isinstance(token, HexNibble):
        pb_token.nibble.high = _hex_nibble_high_to_protobuf(token.high)
        pb_token.nibble.value = _hex_nibble_value_to_protobuf(token.value)
    else:
        msg = f"Unsupported protobuf hex token type: {type(token).__name__}"
        raise SerializationError(msg)


def _hex_byte_value_to_protobuf(value: int | str) -> str:
    return _hex_byte_like_value_to_protobuf(value, "HexByte value")


def _hex_negated_byte_value_to_protobuf(value: int | str) -> str:
    if isinstance(value, str) and _is_negated_nibble_pattern(value):
        return value
    return _hex_byte_like_value_to_protobuf(value, "HexNegatedByte value")


def _hex_byte_like_value_to_protobuf(value: int | str, context: str) -> str:
    if isinstance(value, bool):
        msg = f"{context} must be a byte"
        raise SerializationError(msg)
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return str(value)
        msg = f"{context} must be a byte"
        raise SerializationError(msg)
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return f"hex:{value}"
    msg = f"{context} must be a byte"
    raise SerializationError(msg)


def _copy_hex_jump_to_protobuf(token, pb_jump) -> None:
    min_jump = _hex_jump_bound_to_protobuf(token.min_jump, "min_jump")
    max_jump = _hex_jump_bound_to_protobuf(token.max_jump, "max_jump")
    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise SerializationError(msg)
    pb_jump.SetInParent()
    if min_jump is not None:
        pb_jump.min_jump = min_jump
    if max_jump is not None:
        pb_jump.max_jump = max_jump


def _hex_jump_bound_to_protobuf(value: int | None, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"HexJump {field} must be a non-negative integer"
        raise SerializationError(msg)
    return value


def _hex_nibble_high_to_protobuf(value: bool) -> bool:
    if isinstance(value, bool):
        return value
    msg = "HexNibble high must be a boolean"
    raise SerializationError(msg)


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


def _hex_int_value_from_protobuf(value: str) -> int | str:
    if _is_negated_nibble_pattern(value):
        return value
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
    if isinstance(value, bool):
        msg = "HexNibble value must be a nibble"
        raise SerializationError(msg)
    if isinstance(value, int) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return int(value, 16)
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


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


def _validate_hex_token_sequence_for_protobuf(
    tokens: list,
    context: str,
    *,
    inside_alternative: bool,
) -> None:
    from yaraast.ast.strings import HexAlternative, HexJump

    if isinstance(tokens[0], HexJump) or isinstance(tokens[-1], HexJump):
        msg = f"HexJump cannot appear at the beginning or end of {context}"
        raise SerializationError(msg)

    for token in tokens:
        if isinstance(token, HexAlternative):
            for alternative in _protobuf_list(token.alternatives, "HexAlternative alternatives"):
                branch = _coerce_hex_alternative_branch(alternative)
                if not branch:
                    msg = "HexAlternative branches must not be empty"
                    raise SerializationError(msg)
                _validate_hex_token_sequence_for_protobuf(
                    branch,
                    "hex alternative branch",
                    inside_alternative=True,
                )

    if not inside_alternative:
        return

    for token in tokens:
        if isinstance(token, HexJump) and token.max_jump is None:
            msg = "Unbounded HexJump is not allowed inside hex alternatives"
            raise SerializationError(msg)


def _coerce_quantifier_text(value) -> str:
    from yaraast.ast.expressions import Expression

    if isinstance(value, str):
        if not value:
            msg = "quantifier must not be empty"
            raise SerializationError(msg)
        return value
    if isinstance(value, bool):
        msg = "quantifier must be a string, number, or expression"
        raise SerializationError(msg)
    if isinstance(value, int | float):
        _validate_finite_quantifier(value)
        return str(value)

    if isinstance(value, Expression):
        raw_value = getattr(value, "value", None)
        if raw_value is not None:
            if isinstance(raw_value, bool):
                msg = "quantifier must be a string, number, or expression"
                raise SerializationError(msg)
            _validate_finite_quantifier(raw_value)
            return str(raw_value)

        name = getattr(value, "name", None)
        if name is not None:
            return str(name)

        return ""

    msg = "quantifier must be a string, number, or expression"
    raise SerializationError(msg)


def _coerce_quantifier_expression(value):
    from yaraast.ast.expressions import Expression

    if not isinstance(value, Expression):
        return None
    raw_value = getattr(value, "value", None)
    if isinstance(raw_value, bool):
        msg = "quantifier must be a string, number, or expression"
        raise SerializationError(msg)
    return value


def _copy_string_set_to_protobuf(value, pb_owner, context: str) -> None:
    from yaraast.ast.expressions import Expression

    field_context = f"{context} string_set"
    if isinstance(value, str):
        pb_owner.string_set_text = value
        return

    if isinstance(value, list | tuple):
        _copy_string_set_items_to_protobuf(value, pb_owner, field_context)
        return

    if isinstance(value, set | frozenset):
        _copy_string_set_items_to_protobuf(sorted(value, key=str), pb_owner, field_context)
        return

    string_set_items = _expression_string_set_items(value)
    if string_set_items is not None:
        pb_owner.string_set_items.extend(string_set_items)
        return

    if isinstance(value, Expression):
        convert_expression_to_protobuf(value, pb_owner.string_set)
        return

    msg = f"{field_context} must be a string, expression, or list of strings/expressions"
    raise SerializationError(msg)


def _copy_string_set_items_to_protobuf(items, pb_owner, context: str) -> None:
    item_texts = [_string_set_item_text(item) for item in items]
    if all(item_text is not None for item_text in item_texts):
        pb_owner.string_set_items.extend(item_texts)
        return

    from yaraast.ast.expressions import SetExpression

    expression_items = [_string_set_item_expression(item, context) for item in items]
    convert_expression_to_protobuf(SetExpression(expression_items), pb_owner.string_set)


def _expression_string_set_items(value) -> list[str] | None:
    from yaraast.ast.expressions import ParenthesesExpression, SetExpression

    if isinstance(value, ParenthesesExpression):
        return _expression_string_set_items(value.expression)
    if not isinstance(value, SetExpression):
        return None

    items = []
    elements = getattr(value, "elements", None)
    if not isinstance(elements, list | tuple):
        return None
    for element in elements:
        item_text = _expression_string_set_item_text(element)
        if item_text is None:
            return None
        items.append(item_text)
    return items


def _expression_string_set_item_text(item) -> str | None:
    from yaraast.ast.expressions import StringIdentifier, StringLiteral, StringWildcard

    if isinstance(item, StringIdentifier):
        return _protobuf_required_nonempty_string(item.name, "StringIdentifier name")
    if isinstance(item, StringWildcard):
        return _protobuf_required_nonempty_string(item.pattern, "StringWildcard pattern")
    if isinstance(item, StringLiteral):
        value = _protobuf_required_string(item.value, "StringLiteral value")
        if value.startswith("$"):
            return value
    return None


def _string_set_item_text(item) -> str | None:
    if isinstance(item, str):
        return item
    return _expression_string_set_item_text(item)


def _string_set_item_expression(item, context: str):
    from yaraast.ast.expressions import Expression, Identifier, StringIdentifier

    if isinstance(item, Expression):
        return item
    if isinstance(item, str):
        return StringIdentifier(item) if item.startswith("$") else Identifier(item)
    msg = f"{context} must contain strings or expressions"
    raise SerializationError(msg)


def _restore_quantifier_text(value: str):
    if not value:
        msg = "quantifier must not be empty"
        raise SerializationError(msg)
    integer_text = value[1:] if value.startswith("-") else value
    if integer_text.isdigit():
        return int(value)
    try:
        if any(marker in value for marker in (".", "e", "E")):
            restored_value = float(value)
            _validate_finite_quantifier(restored_value)
            return restored_value
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
        DictItem,
        LambdaExpression,
        ListExpression,
        MatchCase,
        PatternMatch,
        SliceExpression,
        SpreadOperator,
        TupleExpression,
        TupleIndexing,
        WithDeclaration,
        WithStatement,
    )

    _copy_node_metadata_to_protobuf(expr, pb_expr)
    if isinstance(expr, Identifier):
        pb_expr.identifier.name = _protobuf_required_nonempty_string(expr.name, "Identifier name")
    elif isinstance(expr, StringIdentifier):
        pb_expr.string_identifier.name = _protobuf_required_nonempty_string(
            expr.name,
            "StringIdentifier name",
        )
    elif isinstance(expr, StringWildcard):
        pb_expr.string_wildcard.pattern = _protobuf_required_nonempty_string(
            expr.pattern,
            "StringWildcard pattern",
        )
    elif isinstance(expr, StringCount):
        pb_expr.string_count.string_id = _protobuf_required_nonempty_string(
            expr.string_id,
            "StringCount string_id",
        )
    elif isinstance(expr, StringOffset):
        pb_expr.string_offset.string_id = _protobuf_required_nonempty_string(
            expr.string_id,
            "StringOffset string_id",
        )
        if expr.index is not None:
            convert_expression_to_protobuf(expr.index, pb_expr.string_offset.index)
    elif isinstance(expr, StringLength):
        pb_expr.string_length.string_id = _protobuf_required_nonempty_string(
            expr.string_id,
            "StringLength string_id",
        )
        if expr.index is not None:
            convert_expression_to_protobuf(expr.index, pb_expr.string_length.index)
    elif isinstance(expr, IntegerLiteral):
        pb_expr.integer_literal.value = _protobuf_required_int(
            expr.value,
            "IntegerLiteral value",
        )
    elif isinstance(expr, DoubleLiteral):
        pb_expr.double_literal.value = _finite_double_value(expr.value, "DoubleLiteral")
    elif isinstance(expr, StringLiteral):
        pb_expr.string_literal.value = _protobuf_required_string(
            expr.value,
            "StringLiteral value",
        )
    elif isinstance(expr, RegexLiteral):
        pb_expr.regex_literal.pattern = _protobuf_required_nonempty_string(
            expr.pattern,
            "RegexLiteral pattern",
        )
        pb_expr.regex_literal.modifiers = _protobuf_required_string(
            expr.modifiers,
            "RegexLiteral modifiers",
        )
    elif isinstance(expr, BooleanLiteral):
        pb_expr.boolean_literal.value = _protobuf_required_bool(
            expr.value,
            "BooleanLiteral value",
        )
    elif isinstance(expr, BinaryExpression):
        pb_expr.binary_expression.operator = _protobuf_required_nonempty_string(
            expr.operator,
            "BinaryExpression operator",
        )
        convert_expression_to_protobuf(expr.left, pb_expr.binary_expression.left)
        convert_expression_to_protobuf(expr.right, pb_expr.binary_expression.right)
    elif isinstance(expr, UnaryExpression):
        pb_expr.unary_expression.operator = _protobuf_required_nonempty_string(
            expr.operator,
            "UnaryExpression operator",
        )
        convert_expression_to_protobuf(expr.operand, pb_expr.unary_expression.operand)
    elif isinstance(expr, ParenthesesExpression):
        convert_expression_to_protobuf(expr.expression, pb_expr.parentheses_expression.expression)
    elif isinstance(expr, SetExpression):
        pb_expr.set_expression.SetInParent()
        for element in _protobuf_node_list(expr.elements, "SetExpression elements", Expression):
            convert_expression_to_protobuf(element, pb_expr.set_expression.elements.add())
    elif isinstance(expr, RangeExpression):
        convert_expression_to_protobuf(expr.low, pb_expr.range_expression.low)
        convert_expression_to_protobuf(expr.high, pb_expr.range_expression.high)
    elif isinstance(expr, FunctionCall):
        pb_expr.function_call.function = _protobuf_required_nonempty_string(
            expr.function,
            "FunctionCall function",
        )
        for argument in _protobuf_node_list(expr.arguments, "FunctionCall arguments", Expression):
            convert_expression_to_protobuf(argument, pb_expr.function_call.arguments.add())
        if expr.receiver is not None:
            convert_expression_to_protobuf(expr.receiver, pb_expr.function_call.receiver)
    elif isinstance(expr, ArrayAccess):
        convert_expression_to_protobuf(expr.array, pb_expr.array_access.array)
        convert_expression_to_protobuf(expr.index, pb_expr.array_access.index)
    elif isinstance(expr, MemberAccess):
        convert_expression_to_protobuf(expr.object, pb_expr.member_access.object)
        pb_expr.member_access.member = _protobuf_required_nonempty_string(
            expr.member,
            "MemberAccess member",
        )
    elif isinstance(expr, ModuleReference):
        pb_expr.module_reference.module = _protobuf_required_nonempty_string(
            expr.module,
            "ModuleReference module",
        )
    elif isinstance(expr, DictionaryAccess):
        convert_expression_to_protobuf(expr.object, pb_expr.dictionary_access.object)
        if isinstance(expr.key, Expression):
            convert_expression_to_protobuf(expr.key, pb_expr.dictionary_access.key_expr)
        elif isinstance(expr.key, str):
            pb_expr.dictionary_access.key = _protobuf_required_nonempty_string(
                expr.key,
                "DictionaryAccess key",
            )
        else:
            msg = "DictionaryAccess key must be a string or expression"
            raise SerializationError(msg)
    elif isinstance(expr, ExternRuleReference):
        pb_expr.extern_rule_reference.rule_name = _protobuf_required_nonempty_string(
            expr.rule_name,
            "ExternRuleReference rule_name",
        )
        if expr.namespace is not None:
            pb_expr.extern_rule_reference.namespace = _protobuf_required_nonempty_string(
                expr.namespace,
                "ExternRuleReference namespace",
            )
    elif isinstance(expr, ForExpression):
        pb_expr.for_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.for_expression.quantifier_expr)
        pb_expr.for_expression.variable = _protobuf_required_nonempty_string(
            expr.variable,
            "ForExpression variable",
        )
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
        _copy_string_set_to_protobuf(
            expr.string_set,
            pb_expr.for_of_expression,
            "ForOfExpression",
        )
        if expr.condition is not None:
            convert_expression_to_protobuf(expr.condition, pb_expr.for_of_expression.condition)
    elif isinstance(expr, AtExpression):
        if isinstance(expr.string_id, str):
            pb_expr.at_expression.string_id = _protobuf_required_nonempty_string(
                expr.string_id,
                "AtExpression string_id",
            )
        elif isinstance(expr.string_id, Expression):
            convert_expression_to_protobuf(expr.string_id, pb_expr.at_expression.subject)
        else:
            msg = "AtExpression string_id must be a string or expression"
            raise SerializationError(msg)
        convert_expression_to_protobuf(expr.offset, pb_expr.at_expression.offset)
    elif isinstance(expr, InExpression):
        if isinstance(expr.subject, str):
            pb_expr.in_expression.string_id = _protobuf_required_nonempty_string(
                expr.subject,
                "InExpression subject",
            )
        else:
            convert_expression_to_protobuf(expr.subject, pb_expr.in_expression.subject)
        convert_expression_to_protobuf(expr.range, pb_expr.in_expression.range)
    elif isinstance(expr, OfExpression):
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.of_expression.quantifier)
        else:
            pb_expr.of_expression.quantifier_text = _coerce_quantifier_text(expr.quantifier)
        _copy_string_set_to_protobuf(
            expr.string_set,
            pb_expr.of_expression,
            "OfExpression",
        )
    elif isinstance(expr, DefinedExpression):
        convert_expression_to_protobuf(expr.expression, pb_expr.defined_expression.expression)
    elif isinstance(expr, StringOperatorExpression):
        convert_expression_to_protobuf(expr.left, pb_expr.string_operator_expression.left)
        pb_expr.string_operator_expression.operator = _protobuf_required_nonempty_string(
            expr.operator,
            "StringOperatorExpression operator",
        )
        convert_expression_to_protobuf(expr.right, pb_expr.string_operator_expression.right)
    elif isinstance(expr, WithStatement):
        for declaration in _protobuf_node_list(
            expr.declarations,
            "WithStatement declarations",
            WithDeclaration,
        ):
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
        pb_expr.array_comprehension.variable = _protobuf_required_nonempty_string(
            expr.variable,
            "ArrayComprehension variable",
        )
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
        pb_expr.dict_comprehension.key_variable = _protobuf_required_nonempty_string(
            expr.key_variable,
            "DictComprehension key_variable",
        )
        if expr.value_variable is not None:
            pb_expr.dict_comprehension.value_variable = _protobuf_required_nonempty_string(
                expr.value_variable,
                "DictComprehension value_variable",
            )
        if expr.iterable is not None:
            convert_expression_to_protobuf(expr.iterable, pb_expr.dict_comprehension.iterable)
        if expr.condition is not None:
            convert_expression_to_protobuf(
                expr.condition,
                pb_expr.dict_comprehension.condition,
            )
    elif isinstance(expr, TupleExpression):
        pb_expr.tuple_expression.SetInParent()
        for element in _protobuf_node_list(expr.elements, "TupleExpression elements", Expression):
            convert_expression_to_protobuf(element, pb_expr.tuple_expression.elements.add())
    elif isinstance(expr, TupleIndexing):
        convert_expression_to_protobuf(expr.tuple_expr, pb_expr.tuple_indexing.tuple_expr)
        convert_expression_to_protobuf(expr.index, pb_expr.tuple_indexing.index)
    elif isinstance(expr, ListExpression):
        pb_expr.list_expression.SetInParent()
        for element in _protobuf_node_list(expr.elements, "ListExpression elements", Expression):
            convert_expression_to_protobuf(element, pb_expr.list_expression.elements.add())
    elif isinstance(expr, DictExpression):
        pb_expr.dict_expression.SetInParent()
        for item in _protobuf_node_list(expr.items, "DictExpression items", DictItem):
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
        pb_expr.lambda_expression.parameters.extend(
            _protobuf_nonempty_string_list(expr.parameters, "LambdaExpression parameters")
        )
        convert_expression_to_protobuf(expr.body, pb_expr.lambda_expression.body)
    elif isinstance(expr, PatternMatch):
        convert_expression_to_protobuf(expr.value, pb_expr.pattern_match.value)
        for case in _protobuf_node_list(expr.cases, "PatternMatch cases", MatchCase):
            convert_match_case_to_protobuf(case, pb_expr.pattern_match.cases.add())
        if expr.default is not None:
            convert_expression_to_protobuf(expr.default, pb_expr.pattern_match.default)
    elif isinstance(expr, SpreadOperator):
        convert_expression_to_protobuf(expr.expression, pb_expr.spread_operator.expression)
        pb_expr.spread_operator.is_dict = _protobuf_required_bool(
            expr.is_dict,
            "SpreadOperator is_dict",
        )
    else:
        msg = f"Unsupported protobuf expression type: {type(expr).__name__}"
        raise SerializationError(msg)


def convert_with_declaration_to_protobuf(declaration, pb_declaration) -> None:
    pb_declaration.identifier = _protobuf_required_nonempty_string(
        declaration.identifier,
        "WithDeclaration identifier",
    )
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
                    module=_protobuf_required_nonempty_string(
                        pb_import.module,
                        "Import module",
                    ),
                    alias=pb_import.alias if pb_import.alias else None,
                ),
            ),
        )

    includes = []
    for pb_include in pb_file.includes:
        includes.append(
            _apply_node_metadata_from_protobuf(
                pb_include,
                Include(
                    path=_protobuf_required_nonempty_string(
                        pb_include.path,
                        "Include path",
                    ),
                ),
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
                    Tag(
                        name=_protobuf_required_nonempty_string(
                            pb_tag.name,
                            "Tag name",
                        ),
                    ),
                )
            )

        if pb_rule.meta_entries:
            meta = [
                protobuf_to_rule_meta_entry(pb_meta_entry) for pb_meta_entry in pb_rule.meta_entries
            ]
        else:
            meta_values = {}
            for key, meta_val in pb_rule.meta.items():
                meta_key = _protobuf_required_nonempty_string(key, "Meta key")
                meta_values[meta_key] = _meta_value_to_python(meta_val)

            from yaraast.ast.modifiers import MetaEntry

            meta = [
                MetaEntry.from_key_value(
                    key,
                    value,
                    deserialize_meta_scope(pb_rule.meta_scopes.get(key) or None),
                )
                for key, value in sorted(meta_values.items())
            ]

        strings = []
        for pb_string in pb_rule.strings:
            strings.append(protobuf_to_string(pb_string))

        condition = (
            protobuf_to_expression(pb_rule.condition) if pb_rule.HasField("condition") else None
        )
        pragmas_for_rule = [protobuf_to_in_rule_pragma(pb_pragma) for pb_pragma in pb_rule.pragmas]

        rule = Rule(
            name=_protobuf_required_nonempty_string(pb_rule.name, "Rule name"),
            modifiers=_protobuf_modifier_names_from_protobuf(
                pb_rule.modifiers,
                "Rule modifier",
            ),
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
    for modifier in _protobuf_modifier_names_from_protobuf(
        pb_extern_rule.modifiers,
        "ExternRule modifier",
    ):
        try:
            modifiers.append(RuleModifier.from_string(modifier))
        except (ValueError, ValidationError):
            modifiers.append(modifier)

    return _apply_node_metadata_from_protobuf(
        pb_extern_rule,
        ExternRule(
            name=_protobuf_required_nonempty_string(
                pb_extern_rule.name,
                "ExternRule name",
            ),
            modifiers=modifiers,
            namespace=pb_extern_rule.namespace or None,
        ),
    )


def protobuf_to_extern_import(pb_extern_import):
    from yaraast.ast.extern import ExternImport

    module_path = _protobuf_required_nonempty_string(
        pb_extern_import.module_path,
        "ExternImport module_path",
    )
    if not module_path.strip():
        msg = "ExternImport module_path must not be empty"
        raise SerializationError(msg)
    alias = pb_extern_import.alias or None
    if alias is not None and not alias.strip():
        msg = "ExternImport alias must not be empty"
        raise SerializationError(msg)
    rules = _protobuf_nonempty_string_list(
        list(pb_extern_import.rules),
        "ExternImport rules",
    )
    if any(not rule.strip() for rule in rules):
        msg = "ExternImport rules item must not be empty"
        raise SerializationError(msg)
    return _apply_node_metadata_from_protobuf(
        pb_extern_import,
        ExternImport(
            module_path=module_path,
            alias=alias,
            rules=rules,
        ),
    )


def protobuf_to_extern_namespace(pb_namespace):
    from yaraast.ast.extern import ExternNamespace

    return _apply_node_metadata_from_protobuf(
        pb_namespace,
        ExternNamespace(
            name=_protobuf_required_nonempty_string(
                pb_namespace.name,
                "ExternNamespace name",
            ),
            extern_rules=[
                protobuf_to_extern_rule(pb_rule) for pb_rule in pb_namespace.extern_rules
            ],
        ),
    )


def _protobuf_pragma_scope(scope_text):
    return deserialize_pragma_scope(scope_text or None)


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
    elif pragma_type == PragmaType.DEFINE:
        pragma = DefineDirective(
            macro_name=_protobuf_required_nonempty_string(
                pb_pragma.macro_name,
                "Pragma macro_name",
            ),
            macro_value=pb_pragma.macro_value if pb_pragma.HasField("macro_value") else None,
        )
    elif pragma_type == PragmaType.UNDEF:
        pragma = UndefDirective(
            macro_name=_protobuf_required_nonempty_string(
                pb_pragma.macro_name,
                "Pragma macro_name",
            )
        )
    elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}:
        pragma = ConditionalDirective(
            pragma_type,
            condition=_protobuf_required_nonempty_string(
                pb_pragma.condition if pb_pragma.HasField("condition") else "",
                "Pragma condition",
            ),
        )
    elif pragma_type == PragmaType.ENDIF:
        pragma = ConditionalDirective(pragma_type)
    elif pragma_type == PragmaType.CUSTOM:
        pragma = CustomPragma(
            name=_protobuf_required_nonempty_string(pb_pragma.name, "Pragma name"),
            arguments=list(pb_pragma.arguments),
            parameters=parameters,
            scope=scope,
        )
    else:
        pragma = Pragma(
            pragma_type=pragma_type,
            name=_protobuf_required_nonempty_string(pb_pragma.name, "Pragma name"),
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
            position=_protobuf_required_nonempty_string(
                pb_in_rule_pragma.position,
                "InRulePragma position",
            ),
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
        if not pb_token.alternative.alternatives:
            msg = "HexAlternative must contain at least one branch"
            raise SerializationError(msg)
        alternatives = []
        for pb_alternative in pb_token.alternative.alternatives:
            if not pb_alternative.tokens:
                msg = "HexAlternative branches must not be empty"
                raise SerializationError(msg)
            alternative = []
            for nested_pb_token in pb_alternative.tokens:
                alternative.append(_protobuf_to_hex_token(nested_pb_token))
            _validate_hex_token_sequence_for_protobuf(
                alternative,
                "hex alternative branch",
                inside_alternative=True,
            )
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
    msg = "Protobuf hex token is missing a token type"
    raise SerializationError(msg)


def _typed_modifier_value(pb_modifier):
    if pb_modifier.HasField("typed_value"):
        typed_value = pb_modifier.typed_value
        if typed_value.HasField("string_value"):
            return typed_value.string_value
        if typed_value.HasField("bool_value"):
            _raise_invalid_modifier_value()
        if typed_value.HasField("int_value"):
            return typed_value.int_value
        if typed_value.HasField("double_value"):
            return _finite_double_value(typed_value.double_value, "String modifier")
        msg = "String modifier typed value is missing a value"
        raise SerializationError(msg)
    return None


def _legacy_modifier_value(name: str, value: str):
    return deserialize_legacy_modifier_value(name, value)


def _protobuf_modifier_value(pb_modifier):
    if len(pb_modifier.tuple_value) == 2:
        return (pb_modifier.tuple_value[0], pb_modifier.tuple_value[1])
    if pb_modifier.tuple_value:
        msg = "String modifier tuple value must contain two integers"
        raise SerializationError(msg)

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
        name = _protobuf_required_nonempty_string(
            pb_modifier.name,
            "String modifier name",
        )
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
        _validate_plain_string_value_for_protobuf(value)
        plain_string = PlainString(
            identifier=_protobuf_required_nonempty_string(
                pb_string.identifier,
                "PlainString identifier",
            ),
            value=value,
            is_anonymous=pb_string.is_anonymous,
        )
        plain_string.modifiers = modifiers
        return _apply_node_metadata_from_protobuf(pb_string, plain_string)
    if pb_string.HasField("hex"):
        if not pb_string.hex.tokens:
            msg = "HexString must contain at least one token"
            raise SerializationError(msg)
        tokens = []
        for pb_token in pb_string.hex.tokens:
            tokens.append(_protobuf_to_hex_token(pb_token))
        _validate_hex_token_sequence_for_protobuf(
            tokens,
            "hex string",
            inside_alternative=False,
        )
        modifiers = _protobuf_modifiers_to_ast(pb_string.hex.modifiers)
        hex_string = HexString(
            identifier=_protobuf_required_nonempty_string(
                pb_string.identifier,
                "HexString identifier",
            ),
            tokens=tokens,
            is_anonymous=pb_string.is_anonymous,
        )
        hex_string.modifiers = modifiers
        return _apply_node_metadata_from_protobuf(pb_string, hex_string)
    if pb_string.HasField("regex"):
        modifiers = _protobuf_modifiers_to_ast(pb_string.regex.modifiers)
        regex_string = RegexString(
            identifier=_protobuf_required_nonempty_string(
                pb_string.identifier,
                "RegexString identifier",
            ),
            regex=_protobuf_required_nonempty_string(
                pb_string.regex.regex,
                "RegexString regex",
            ),
            is_anonymous=pb_string.is_anonymous,
        )
        regex_string.modifiers = modifiers
        return _apply_node_metadata_from_protobuf(pb_string, regex_string)
    msg = "Protobuf string definition is missing a string type"
    raise SerializationError(msg)


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
        return with_metadata(
            Identifier(
                name=_protobuf_required_nonempty_string(
                    pb_expr.identifier.name,
                    "Identifier name",
                )
            )
        )
    if pb_expr.HasField("string_identifier"):
        return with_metadata(
            StringIdentifier(
                name=_protobuf_required_nonempty_string(
                    pb_expr.string_identifier.name,
                    "StringIdentifier name",
                )
            )
        )
    if pb_expr.HasField("string_wildcard"):
        return with_metadata(
            StringWildcard(
                pattern=_protobuf_required_nonempty_string(
                    pb_expr.string_wildcard.pattern,
                    "StringWildcard pattern",
                )
            )
        )
    if pb_expr.HasField("string_count"):
        return with_metadata(
            StringCount(
                string_id=_protobuf_required_nonempty_string(
                    pb_expr.string_count.string_id,
                    "StringCount string_id",
                )
            )
        )
    if pb_expr.HasField("string_offset"):
        return with_metadata(
            StringOffset(
                string_id=_protobuf_required_nonempty_string(
                    pb_expr.string_offset.string_id,
                    "StringOffset string_id",
                ),
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
                string_id=_protobuf_required_nonempty_string(
                    pb_expr.string_length.string_id,
                    "StringLength string_id",
                ),
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
        return with_metadata(
            DoubleLiteral(value=_finite_double_value(pb_expr.double_literal.value, "DoubleLiteral"))
        )
    if pb_expr.HasField("string_literal"):
        return with_metadata(StringLiteral(value=pb_expr.string_literal.value))
    if pb_expr.HasField("regex_literal"):
        return with_metadata(
            RegexLiteral(
                pattern=_protobuf_required_nonempty_string(
                    pb_expr.regex_literal.pattern,
                    "RegexLiteral pattern",
                ),
                modifiers=pb_expr.regex_literal.modifiers,
            ),
        )
    if pb_expr.HasField("boolean_literal"):
        return with_metadata(BooleanLiteral(value=pb_expr.boolean_literal.value))
    if pb_expr.HasField("binary_expression"):
        return with_metadata(
            BinaryExpression(
                left=protobuf_to_expression(pb_expr.binary_expression.left),
                operator=_protobuf_required_nonempty_string(
                    pb_expr.binary_expression.operator,
                    "BinaryExpression operator",
                ),
                right=protobuf_to_expression(pb_expr.binary_expression.right),
            ),
        )
    if pb_expr.HasField("unary_expression"):
        return with_metadata(
            UnaryExpression(
                operator=_protobuf_required_nonempty_string(
                    pb_expr.unary_expression.operator,
                    "UnaryExpression operator",
                ),
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
                function=_protobuf_required_nonempty_string(
                    pb_expr.function_call.function,
                    "FunctionCall function",
                ),
                arguments=[
                    protobuf_to_expression(argument) for argument in pb_expr.function_call.arguments
                ],
                receiver=(
                    protobuf_to_expression(pb_expr.function_call.receiver)
                    if pb_expr.function_call.HasField("receiver")
                    else None
                ),
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
                member=_protobuf_required_nonempty_string(
                    pb_expr.member_access.member,
                    "MemberAccess member",
                ),
            ),
        )
    if pb_expr.HasField("module_reference"):
        return with_metadata(
            ModuleReference(
                module=_protobuf_required_nonempty_string(
                    pb_expr.module_reference.module,
                    "ModuleReference module",
                )
            )
        )
    if pb_expr.HasField("dictionary_access"):
        return with_metadata(
            DictionaryAccess(
                object=protobuf_to_expression(pb_expr.dictionary_access.object),
                key=(
                    protobuf_to_expression(pb_expr.dictionary_access.key_expr)
                    if pb_expr.dictionary_access.HasField("key_expr")
                    else _protobuf_required_nonempty_string(
                        pb_expr.dictionary_access.key,
                        "DictionaryAccess key",
                    )
                ),
            ),
        )
    if pb_expr.HasField("extern_rule_reference"):
        return with_metadata(
            ExternRuleReference(
                rule_name=_protobuf_required_nonempty_string(
                    pb_expr.extern_rule_reference.rule_name,
                    "ExternRuleReference rule_name",
                ),
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
                variable=_protobuf_required_nonempty_string(
                    pb_expr.for_expression.variable,
                    "ForExpression variable",
                ),
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
        subject = (
            protobuf_to_expression(pb_expr.at_expression.subject)
            if pb_expr.at_expression.HasField("subject")
            else _protobuf_required_nonempty_string(
                pb_expr.at_expression.string_id,
                "AtExpression string_id",
            )
        )
        return with_metadata(
            AtExpression(
                string_id=subject,
                offset=protobuf_to_expression(pb_expr.at_expression.offset),
            ),
        )
    if pb_expr.HasField("in_expression"):
        subject = (
            protobuf_to_expression(pb_expr.in_expression.subject)
            if pb_expr.in_expression.HasField("subject")
            else _protobuf_required_nonempty_string(
                pb_expr.in_expression.string_id,
                "InExpression subject",
            )
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
                operator=_protobuf_required_nonempty_string(
                    pb_expr.string_operator_expression.operator,
                    "StringOperatorExpression operator",
                ),
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
                variable=_protobuf_required_nonempty_string(
                    pb_expr.array_comprehension.variable,
                    "ArrayComprehension variable",
                ),
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
                key_variable=_protobuf_required_nonempty_string(
                    pb_expr.dict_comprehension.key_variable,
                    "DictComprehension key_variable",
                ),
                value_variable=(
                    _protobuf_required_nonempty_string(
                        pb_expr.dict_comprehension.value_variable,
                        "DictComprehension value_variable",
                    )
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
                parameters=_protobuf_nonempty_string_list(
                    list(pb_expr.lambda_expression.parameters),
                    "LambdaExpression parameters",
                ),
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
    msg = "Protobuf expression is missing a recognized expression field"
    raise SerializationError(msg)


def protobuf_to_with_declaration(pb_declaration):
    from yaraast.yarax.ast_nodes import WithDeclaration

    return _apply_node_metadata_from_protobuf(
        pb_declaration,
        WithDeclaration(
            identifier=_protobuf_required_nonempty_string(
                pb_declaration.identifier,
                "WithDeclaration identifier",
            ),
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
