"""Helper functions for simple roundtrip serialization."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
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
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    Pragma,
    PragmaBlock,
    PragmaScope,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.errors import SerializationError, ValidationError
from yaraast.parser.hex_parser import HexParseError, HexStringParser
from yaraast.parser.source import parse_yara_source
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
from yaraast.yarax.generator import YaraXGenerator


def _serialize_hex_token(token) -> dict[str, Any]:
    """Serialize a single hex token to a dictionary."""
    if isinstance(token, HexByte):
        return {"type": "HexByte", "value": token.value}
    if isinstance(token, HexWildcard):
        return {"type": "HexWildcard"}
    if isinstance(token, HexJump):
        return {"type": "HexJump", "min_jump": token.min_jump, "max_jump": token.max_jump}
    if isinstance(token, HexNibble):
        return {"type": "HexNibble", "high": token.high, "value": token.value}
    if isinstance(token, HexNegatedByte):
        return {"type": "HexNegatedByte", "value": token.value}
    if isinstance(token, HexAlternative):
        return {
            "type": "HexAlternative",
            "alternatives": [
                [_serialize_hex_token(t) for t in _coerce_hex_alternative_branch(alt)]
                for alt in token.alternatives
            ],
        }
    return {"type": "Unknown", "data": str(token)}


def _deserialize_hex_token(data: dict[str, Any]):
    """Deserialize a hex token from a dictionary."""
    hex_kind = data.get("type")
    if hex_kind == "HexByte":
        return HexByte(value=data["value"])
    if hex_kind == "HexWildcard":
        return HexWildcard()
    if hex_kind == "HexJump":
        return HexJump(min_jump=data.get("min_jump"), max_jump=data.get("max_jump"))
    if hex_kind == "HexNibble":
        return HexNibble(high=data["high"], value=data["value"])
    if hex_kind == "HexNegatedByte":
        return HexNegatedByte(value=data["value"])
    if hex_kind == "HexAlternative":
        alternatives = [
            [_deserialize_hex_token(t) for t in _coerce_serialized_hex_alternative_branch(alt)]
            for alt in data["alternatives"]
        ]
        return HexAlternative(alternatives=alternatives)
    msg = f"Unknown hex token type: {hex_kind}"
    raise SerializationError(msg)


def _coerce_hex_alternative_branch(alternative) -> list:
    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def _coerce_serialized_hex_alternative_branch(alternative) -> list:
    if isinstance(alternative, list):
        return alternative
    return [alternative]


def _deserialize_legacy_hex_tokens(raw_tokens: str) -> list[HexToken]:
    """Deserialize legacy hex tokens stored as YARA-style text."""
    hex_content = raw_tokens.strip()
    if hex_content.startswith("{") and hex_content.endswith("}"):
        hex_content = hex_content[1:-1]
    return HexStringParser().parse(hex_content)


def _serialize_modifier_value(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    return value


def _serialize_plain_string_value(data: dict[str, Any], value: str | bytes) -> None:
    if isinstance(value, bytes):
        data["value"] = base64.b64encode(value).decode("ascii")
        data["value_encoding"] = "base64"
        return
    data["value"] = value


def _deserialize_plain_string_value(data: dict[str, Any]) -> str | bytes:
    value = data["value"]
    if data.get("value_encoding") != "base64":
        return value
    try:
        return base64.b64decode(str(value).encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        msg = "Invalid base64-encoded plain string value"
        raise SerializationError(msg) from exc


def _deserialize_modifier_value(name: str, value: Any) -> Any:
    if name == "xor":
        if isinstance(value, list) and len(value) == 2:
            return (value[0], value[1])
        if isinstance(value, str) and "-" in value:
            low, high = value.split("-", maxsplit=1)
            if low.isdigit() and high.isdigit():
                return (int(low), int(high))
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return value


def _serialize_modifiers(modifiers: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": getattr(modifier, "name", str(modifier)),
            "value": _serialize_modifier_value(getattr(modifier, "value", None)),
        }
        for modifier in modifiers
    ]


def _format_unknown_modifier(name: str, value: Any) -> str:
    if value is None:
        return name
    if isinstance(value, tuple) and len(value) == 2:
        return f"{name}({value[0]}-{value[1]})"
    if isinstance(value, str):
        return f'{name}("{value}")'
    return f"{name}({value})"


def _deserialize_modifier(modifier: Any) -> Any:
    if isinstance(modifier, dict):
        name = str(modifier["name"])
        value = _deserialize_modifier_value(name, modifier.get("value"))
    else:
        name = str(modifier)
        value = None

    try:
        return StringModifier.from_name_value(name, value)
    except (ValueError, ValidationError):
        return _format_unknown_modifier(name, value)


def _deserialize_modifiers(modifiers: list[Any]) -> list[Any]:
    return [_deserialize_modifier(modifier) for modifier in modifiers]


def _serialize_ast_value(value: Any) -> Any:
    if isinstance(value, ASTNode):
        return serialize_node(value)
    if isinstance(value, list):
        return [_serialize_ast_value(item) for item in value]
    return value


def _deserialize_ast_value(value: Any) -> Any:
    if isinstance(value, dict):
        return deserialize_node(value)
    if isinstance(value, list):
        return [_deserialize_ast_value(item) for item in value]
    return value


def _serialize_location(location: Location) -> dict[str, Any]:
    data: dict[str, Any] = {"line": location.line, "column": location.column}
    if location.file is not None:
        data["file"] = location.file
    if location.end_line is not None:
        data["end_line"] = location.end_line
    if location.end_column is not None:
        data["end_column"] = location.end_column
    return data


def _deserialize_location(data: dict[str, Any]) -> Location:
    return Location(
        line=data["line"],
        column=data["column"],
        file=data.get("file"),
        end_line=data.get("end_line"),
        end_column=data.get("end_column"),
    )


def _with_node_metadata(node: ASTNode, data: dict[str, Any]) -> dict[str, Any]:
    if node.location is not None:
        data["location"] = _serialize_location(node.location)
    if node.leading_comments:
        data["leading_comments"] = [serialize_node(comment) for comment in node.leading_comments]
    if node.trailing_comment is not None:
        data["trailing_comment"] = serialize_node(node.trailing_comment)
    return data


def _apply_node_metadata(node: ASTNode, data: dict[str, Any]) -> ASTNode:
    location = data.get("location")
    if isinstance(location, dict):
        node.location = _deserialize_location(location)
    if data.get("leading_comments"):
        node.leading_comments = [
            cast_comment(deserialize_node(comment)) for comment in data["leading_comments"]
        ]
    trailing_comment = data.get("trailing_comment")
    if isinstance(trailing_comment, dict):
        node.trailing_comment = cast_trailing_comment(deserialize_node(trailing_comment))
    return node


def serialize_node(node: ASTNode) -> dict[str, Any]:
    return _with_node_metadata(node, _serialize_node_payload(node))


def _serialize_node_payload(node: ASTNode) -> dict[str, Any]:
    """Serialize an AST node to a dictionary."""
    if isinstance(node, YaraFile):
        return serialize_yarafile(node)
    if isinstance(node, Rule):
        return serialize_rule(node)
    if isinstance(node, Import):
        return {"type": "Import", "module": node.module, "alias": node.alias}
    if isinstance(node, Include):
        return {"type": "Include", "path": node.path}
    if isinstance(node, Tag):
        return {"type": "Tag", "name": node.name}
    if isinstance(node, Meta):
        return serialize_meta(node)
    if isinstance(node, Comment):
        return {
            "type": "Comment",
            "text": node.text,
            "is_multiline": node.is_multiline,
        }
    if isinstance(node, CommentGroup):
        return {
            "type": "CommentGroup",
            "comments": [serialize_node(comment) for comment in node.comments],
        }
    if isinstance(node, PlainString | HexString | RegexString):
        return serialize_string(node)
    if isinstance(node, HexToken):
        return _serialize_hex_token(node)
    if isinstance(node, StringModifier):
        return {
            "type": "StringModifier",
            "name": node.name,
            "value": _serialize_modifier_value(node.value),
        }
    if isinstance(node, ExternRule):
        return serialize_extern_rule(node)
    if isinstance(node, ExternRuleReference):
        return {
            "type": "ExternRuleReference",
            "rule_name": node.rule_name,
            "namespace": node.namespace,
        }
    if isinstance(node, ExternImport):
        return {
            "type": "ExternImport",
            "module_path": node.module_path,
            "alias": node.alias,
            "rules": list(node.rules),
        }
    if isinstance(node, ExternNamespace):
        return {
            "type": "ExternNamespace",
            "name": node.name,
            "extern_rules": [serialize_extern_rule(rule) for rule in node.extern_rules],
        }
    if isinstance(node, InRulePragma):
        return {
            "type": "InRulePragma",
            "pragma": serialize_pragma(node.pragma),
            "position": node.position,
        }
    if isinstance(node, PragmaBlock):
        return {
            "type": "PragmaBlock",
            "pragmas": [serialize_pragma(pragma) for pragma in node.pragmas],
            "scope": node.scope.value,
        }
    if isinstance(node, Pragma):
        return serialize_pragma(node)
    if isinstance(node, BooleanLiteral):
        return {"type": "BooleanLiteral", "value": node.value}
    if isinstance(node, IntegerLiteral):
        return {"type": "IntegerLiteral", "value": node.value}
    if isinstance(node, DoubleLiteral):
        return {"type": "DoubleLiteral", "value": node.value}
    if isinstance(node, StringLiteral):
        return {"type": "StringLiteral", "value": node.value}
    if isinstance(node, RegexLiteral):
        return {"type": "RegexLiteral", "pattern": node.pattern, "modifiers": node.modifiers}
    if isinstance(node, Identifier):
        return {"type": "Identifier", "name": node.name}
    if isinstance(node, StringIdentifier):
        return {"type": "StringIdentifier", "name": node.name}
    if isinstance(node, StringWildcard):
        return {"type": "StringWildcard", "pattern": node.pattern}
    if isinstance(node, StringCount):
        return {"type": "StringCount", "string_id": node.string_id}
    if isinstance(node, StringOffset):
        return {
            "type": "StringOffset",
            "string_id": node.string_id,
            "index": serialize_node(node.index) if node.index else None,
        }
    if isinstance(node, StringLength):
        return {
            "type": "StringLength",
            "string_id": node.string_id,
            "index": serialize_node(node.index) if node.index else None,
        }
    if isinstance(node, BinaryExpression):
        return {
            "type": "BinaryExpression",
            "left": serialize_node(node.left),
            "operator": node.operator,
            "right": serialize_node(node.right),
        }
    if isinstance(node, UnaryExpression):
        return {
            "type": "UnaryExpression",
            "operator": node.operator,
            "operand": serialize_node(node.operand),
        }
    if isinstance(node, ParenthesesExpression):
        return {"type": "ParenthesesExpression", "expression": serialize_node(node.expression)}
    if isinstance(node, SetExpression):
        return {
            "type": "SetExpression",
            "elements": [serialize_node(element) for element in node.elements],
        }
    if isinstance(node, RangeExpression):
        return {
            "type": "RangeExpression",
            "low": serialize_node(node.low),
            "high": serialize_node(node.high),
        }
    if isinstance(node, FunctionCall):
        return {
            "type": "FunctionCall",
            "function": node.function,
            "arguments": [serialize_node(argument) for argument in node.arguments],
        }
    if isinstance(node, ArrayAccess):
        return {
            "type": "ArrayAccess",
            "array": serialize_node(node.array),
            "index": serialize_node(node.index),
        }
    if isinstance(node, MemberAccess):
        return {
            "type": "MemberAccess",
            "object": serialize_node(node.object),
            "member": node.member,
        }
    if isinstance(node, ForExpression):
        return {
            "type": "ForExpression",
            "quantifier": _serialize_ast_value(node.quantifier),
            "variable": node.variable,
            "iterable": serialize_node(node.iterable),
            "body": serialize_node(node.body),
        }
    if isinstance(node, ForOfExpression):
        return {
            "type": "ForOfExpression",
            "quantifier": _serialize_ast_value(node.quantifier),
            "string_set": _serialize_ast_value(node.string_set),
            "condition": serialize_node(node.condition) if node.condition else None,
        }
    if isinstance(node, AtExpression):
        return {
            "type": "AtExpression",
            "string_id": node.string_id,
            "offset": serialize_node(node.offset),
        }
    if isinstance(node, InExpression):
        return {
            "type": "InExpression",
            "subject": _serialize_ast_value(node.subject),
            "range": serialize_node(node.range),
        }
    if isinstance(node, OfExpression):
        return {
            "type": "OfExpression",
            "quantifier": _serialize_ast_value(node.quantifier),
            "string_set": _serialize_ast_value(node.string_set),
        }
    if isinstance(node, ModuleReference):
        return {"type": "ModuleReference", "module": node.module}
    if isinstance(node, DictionaryAccess):
        return {
            "type": "DictionaryAccess",
            "object": serialize_node(node.object),
            "key": _serialize_ast_value(node.key),
        }
    if isinstance(node, DefinedExpression):
        return {"type": "DefinedExpression", "expression": serialize_node(node.expression)}
    if isinstance(node, StringOperatorExpression):
        return {
            "type": "StringOperatorExpression",
            "left": serialize_node(node.left),
            "operator": node.operator,
            "right": serialize_node(node.right),
        }
    if isinstance(node, WithStatement):
        return {
            "type": "WithStatement",
            "declarations": [serialize_node(declaration) for declaration in node.declarations],
            "body": serialize_node(node.body),
        }
    if isinstance(node, WithDeclaration):
        return {
            "type": "WithDeclaration",
            "identifier": node.identifier,
            "value": serialize_node(node.value),
        }
    if isinstance(node, ArrayComprehension):
        return {
            "type": "ArrayComprehension",
            "expression": serialize_node(node.expression) if node.expression else None,
            "variable": node.variable,
            "iterable": serialize_node(node.iterable) if node.iterable else None,
            "condition": serialize_node(node.condition) if node.condition else None,
        }
    if isinstance(node, DictComprehension):
        return {
            "type": "DictComprehension",
            "key_expression": (
                serialize_node(node.key_expression) if node.key_expression else None
            ),
            "value_expression": (
                serialize_node(node.value_expression) if node.value_expression else None
            ),
            "key_variable": node.key_variable,
            "value_variable": node.value_variable,
            "iterable": serialize_node(node.iterable) if node.iterable else None,
            "condition": serialize_node(node.condition) if node.condition else None,
        }
    if isinstance(node, TupleExpression):
        return {
            "type": "TupleExpression",
            "elements": [serialize_node(element) for element in node.elements],
        }
    if isinstance(node, TupleIndexing):
        return {
            "type": "TupleIndexing",
            "tuple_expr": serialize_node(node.tuple_expr),
            "index": serialize_node(node.index),
        }
    if isinstance(node, ListExpression):
        return {
            "type": "ListExpression",
            "elements": [serialize_node(element) for element in node.elements],
        }
    if isinstance(node, DictExpression):
        return {
            "type": "DictExpression",
            "items": [serialize_node(item) for item in node.items],
        }
    if isinstance(node, DictItem):
        return {
            "type": "DictItem",
            "key": serialize_node(node.key),
            "value": serialize_node(node.value),
        }
    if isinstance(node, SliceExpression):
        return {
            "type": "SliceExpression",
            "target": serialize_node(node.target),
            "start": serialize_node(node.start) if node.start else None,
            "stop": serialize_node(node.stop) if node.stop else None,
            "step": serialize_node(node.step) if node.step else None,
        }
    if isinstance(node, LambdaExpression):
        return {
            "type": "LambdaExpression",
            "parameters": list(node.parameters),
            "body": serialize_node(node.body),
        }
    if isinstance(node, PatternMatch):
        return {
            "type": "PatternMatch",
            "value": serialize_node(node.value),
            "cases": [serialize_node(case) for case in node.cases],
            "default": serialize_node(node.default) if node.default else None,
        }
    if isinstance(node, MatchCase):
        return {
            "type": "MatchCase",
            "pattern": serialize_node(node.pattern),
            "result": serialize_node(node.result),
        }
    if isinstance(node, SpreadOperator):
        return {
            "type": "SpreadOperator",
            "expression": serialize_node(node.expression),
            "is_dict": node.is_dict,
        }
    return {"type": type(node).__name__, "data": str(node)}


def serialize_yarafile(yf: YaraFile) -> dict[str, Any]:
    """Serialize a YaraFile."""
    data = {
        "type": "YaraFile",
        "imports": [serialize_node(imp) for imp in (yf.imports or [])],
        "includes": [serialize_node(inc) for inc in (yf.includes or [])],
        "rules": [serialize_node(rule) for rule in (yf.rules or [])],
    }
    if yf.extern_rules:
        data["extern_rules"] = [serialize_extern_rule(rule) for rule in yf.extern_rules]
    if yf.extern_imports:
        data["extern_imports"] = [serialize_node(imp) for imp in yf.extern_imports]
    if yf.pragmas:
        data["pragmas"] = [serialize_pragma(pragma) for pragma in yf.pragmas]
    if yf.namespaces:
        data["namespaces"] = [serialize_node(namespace) for namespace in yf.namespaces]
    return data


def serialize_rule(rule: Rule) -> dict[str, Any]:
    """Serialize a Rule."""
    data: dict[str, Any] = {
        "type": "Rule",
        "name": rule.name,
        "modifiers": [str(modifier) for modifier in rule.modifiers],
        "condition": serialize_node(rule.condition) if rule.condition else None,
    }

    if rule.tags:
        data["tags"] = [tag.name if hasattr(tag, "name") else tag for tag in rule.tags]

    if rule.meta:
        data["meta"] = [serialize_meta(m) for m in rule.meta]

    if rule.strings:
        data["strings"] = [serialize_string(s) for s in rule.strings]

    if rule.pragmas:
        data["pragmas"] = [serialize_node(pragma) for pragma in rule.pragmas]

    return data


def serialize_extern_rule(extern_rule: ExternRule) -> dict[str, Any]:
    return {
        "type": "ExternRule",
        "name": extern_rule.name,
        "modifiers": [str(modifier) for modifier in extern_rule.modifiers],
        "namespace": extern_rule.namespace,
    }


def serialize_pragma(pragma: Pragma) -> dict[str, Any]:
    data = {
        "type": "Pragma",
        "pragma_type": pragma.pragma_type.value,
        "name": pragma.name,
        "arguments": list(pragma.arguments),
        "scope": pragma.scope.value,
    }
    macro_name = getattr(pragma, "macro_name", "")
    if macro_name:
        data["macro_name"] = macro_name
    macro_value = getattr(pragma, "macro_value", None)
    if macro_value is not None:
        data["macro_value"] = macro_value
    condition = getattr(pragma, "condition", None)
    if condition is not None:
        data["condition"] = condition
    parameters = getattr(pragma, "parameters", None)
    if parameters:
        data["parameters"] = dict(parameters)
    return data


def serialize_meta(meta: Meta | MetaEntry) -> dict[str, Any]:
    """Serialize a Meta item."""
    data = {"type": "Meta", "key": meta.key, "value": meta.value}
    scope = getattr(meta, "scope", None)
    if scope is not None:
        data["type"] = "MetaEntry"
        data["scope"] = getattr(scope, "value", str(scope))
    if isinstance(meta, ASTNode):
        return _with_node_metadata(meta, data)
    return data


def serialize_string(string_def: Any) -> dict[str, Any]:
    """Serialize a string definition."""
    if isinstance(string_def, PlainString):
        data = {
            "type": "PlainString",
            "identifier": string_def.identifier,
            "modifiers": _serialize_modifiers(string_def.modifiers),
        }
        _serialize_plain_string_value(data, string_def.value)
        return _with_node_metadata(string_def, data)
    if isinstance(string_def, HexString):
        return _with_node_metadata(
            string_def,
            {
                "type": "HexString",
                "identifier": string_def.identifier,
                "tokens": [_serialize_hex_token(t) for t in string_def.tokens],
                "modifiers": _serialize_modifiers(string_def.modifiers),
            },
        )
    if isinstance(string_def, RegexString):
        return _with_node_metadata(
            string_def,
            {
                "type": "RegexString",
                "identifier": string_def.identifier,
                "regex": string_def.regex,
                "modifiers": _serialize_modifiers(string_def.modifiers),
            },
        )
    data = {"type": "StringDefinition", "data": str(string_def)}
    if isinstance(string_def, ASTNode):
        return _with_node_metadata(string_def, data)
    return data


def deserialize_node(data: dict[str, Any]) -> ASTNode:
    return _apply_node_metadata(_deserialize_node_payload(data), data)


def _deserialize_node_payload(data: dict[str, Any]) -> ASTNode:
    """Deserialize a dictionary to an AST node."""
    node_type = data.get("type")

    if node_type == "YaraFile":
        return deserialize_yarafile(data)
    if node_type == "Rule":
        return deserialize_rule(data)
    if node_type == "Import":
        return Import(data["module"], alias=data.get("alias"))
    if node_type == "Include":
        return Include(data["path"])
    if node_type == "Tag":
        return Tag(data["name"])
    if node_type == "Meta":
        return Meta(data["key"], data["value"])
    if node_type == "Comment":
        return Comment(data["text"], is_multiline=data.get("is_multiline", False))
    if node_type == "CommentGroup":
        return CommentGroup(
            [cast_comment(deserialize_node(comment)) for comment in data.get("comments", [])]
        )
    if node_type in {"PlainString", "HexString", "RegexString"}:
        return deserialize_string(data)
    if node_type in {
        "HexByte",
        "HexWildcard",
        "HexJump",
        "HexNibble",
        "HexNegatedByte",
        "HexAlternative",
    }:
        return _deserialize_hex_token(data)
    if node_type == "StringModifier":
        return _deserialize_modifier(data)
    if node_type == "ExternRule":
        return deserialize_extern_rule(data)
    if node_type == "ExternRuleReference":
        return ExternRuleReference(
            rule_name=data["rule_name"],
            namespace=data.get("namespace"),
        )
    if node_type == "ExternImport":
        return ExternImport(
            module_path=data["module_path"],
            alias=data.get("alias"),
            rules=list(data.get("rules", [])),
        )
    if node_type == "ExternNamespace":
        return ExternNamespace(
            name=data["name"],
            extern_rules=[deserialize_extern_rule(rule) for rule in data.get("extern_rules", [])],
        )
    if node_type == "InRulePragma":
        return InRulePragma(
            pragma=deserialize_pragma(data["pragma"]),
            position=data.get("position", "before_strings"),
        )
    if node_type == "PragmaBlock":
        return PragmaBlock(
            pragmas=[deserialize_pragma(pragma) for pragma in data.get("pragmas", [])],
            scope=_deserialize_pragma_scope(data.get("scope")),
        )
    if node_type == "Pragma":
        return deserialize_pragma(data)
    if node_type == "BooleanLiteral":
        return BooleanLiteral(data["value"])
    if node_type == "IntegerLiteral":
        return IntegerLiteral(data["value"])
    if node_type == "DoubleLiteral":
        return DoubleLiteral(data["value"])
    if node_type == "StringLiteral":
        return StringLiteral(data["value"])
    if node_type == "RegexLiteral":
        return RegexLiteral(data["pattern"], data.get("modifiers", ""))
    if node_type == "Identifier":
        return Identifier(data["name"])
    if node_type == "StringIdentifier":
        return StringIdentifier(data["name"])
    if node_type == "StringWildcard":
        return StringWildcard(data["pattern"])
    if node_type == "StringCount":
        return StringCount(data["string_id"])
    if node_type == "StringOffset":
        index = data.get("index")
        return StringOffset(data["string_id"], deserialize_node(index) if index else None)
    if node_type == "StringLength":
        index = data.get("index")
        return StringLength(data["string_id"], deserialize_node(index) if index else None)
    if node_type == "BinaryExpression":
        return BinaryExpression(
            deserialize_node(data["left"]),
            data["operator"],
            deserialize_node(data["right"]),
        )
    if node_type == "UnaryExpression":
        return UnaryExpression(data["operator"], deserialize_node(data["operand"]))
    if node_type == "ParenthesesExpression":
        return ParenthesesExpression(deserialize_node(data["expression"]))
    if node_type == "SetExpression":
        return SetExpression([deserialize_node(element) for element in data.get("elements", [])])
    if node_type == "RangeExpression":
        return RangeExpression(deserialize_node(data["low"]), deserialize_node(data["high"]))
    if node_type == "FunctionCall":
        return FunctionCall(
            data["function"],
            [deserialize_node(argument) for argument in data.get("arguments", [])],
        )
    if node_type == "ArrayAccess":
        return ArrayAccess(deserialize_node(data["array"]), deserialize_node(data["index"]))
    if node_type == "MemberAccess":
        return MemberAccess(deserialize_node(data["object"]), data["member"])
    if node_type == "ForExpression":
        return ForExpression(
            _deserialize_ast_value(data["quantifier"]),
            data.get("variable", "i"),
            deserialize_node(data["iterable"]),
            deserialize_node(data["body"]),
        )
    if node_type == "ForOfExpression":
        condition = data.get("condition")
        return ForOfExpression(
            _deserialize_ast_value(data["quantifier"]),
            _deserialize_ast_value(data["string_set"]),
            deserialize_node(condition) if condition else None,
        )
    if node_type == "AtExpression":
        return AtExpression(data["string_id"], deserialize_node(data["offset"]))
    if node_type == "InExpression":
        subject = data.get("subject")
        if subject is None and "string_id" in data:
            subject = data["string_id"]
        return InExpression(_deserialize_ast_value(subject), deserialize_node(data["range"]))
    if node_type == "OfExpression":
        return OfExpression(
            _deserialize_ast_value(data["quantifier"]),
            _deserialize_ast_value(data["string_set"]),
        )
    if node_type == "ModuleReference":
        return ModuleReference(data["module"])
    if node_type == "DictionaryAccess":
        return DictionaryAccess(
            deserialize_node(data["object"]),
            _deserialize_ast_value(data.get("key")),
        )
    if node_type == "DefinedExpression":
        expression = data.get("expression")
        if expression is None and "identifier" in data:
            expression = {"type": "Identifier", "name": data["identifier"]}
        return DefinedExpression(deserialize_node(expression))
    if node_type == "StringOperatorExpression":
        left = data.get("left")
        right = data.get("right")
        if left is None and "subject" in data:
            left = data["subject"]
        if right is None and "pattern" in data:
            right = {"type": "StringLiteral", "value": data.get("pattern", "")}
        if left is None:
            left = {"type": "Identifier", "name": "true"}
        if right is None:
            right = {"type": "Identifier", "name": "true"}
        return StringOperatorExpression(
            deserialize_node(left),
            data["operator"],
            deserialize_node(right),
        )
    if node_type == "WithStatement":
        return WithStatement(
            declarations=[
                deserialize_node(declaration) for declaration in data.get("declarations", [])
            ],
            body=deserialize_node(data["body"]),
        )
    if node_type == "WithDeclaration":
        return WithDeclaration(
            identifier=data["identifier"],
            value=deserialize_node(data["value"]),
        )
    if node_type == "ArrayComprehension":
        return ArrayComprehension(
            expression=deserialize_node(data["expression"]) if data.get("expression") else None,
            variable=data.get("variable", ""),
            iterable=deserialize_node(data["iterable"]) if data.get("iterable") else None,
            condition=deserialize_node(data["condition"]) if data.get("condition") else None,
        )
    if node_type == "DictComprehension":
        return DictComprehension(
            key_expression=(
                deserialize_node(data["key_expression"]) if data.get("key_expression") else None
            ),
            value_expression=(
                deserialize_node(data["value_expression"]) if data.get("value_expression") else None
            ),
            key_variable=data.get("key_variable", ""),
            value_variable=data.get("value_variable"),
            iterable=deserialize_node(data["iterable"]) if data.get("iterable") else None,
            condition=deserialize_node(data["condition"]) if data.get("condition") else None,
        )
    if node_type == "TupleExpression":
        return TupleExpression(
            elements=[deserialize_node(element) for element in data.get("elements", [])],
        )
    if node_type == "TupleIndexing":
        return TupleIndexing(
            tuple_expr=deserialize_node(data["tuple_expr"]),
            index=deserialize_node(data["index"]),
        )
    if node_type == "ListExpression":
        return ListExpression(
            elements=[deserialize_node(element) for element in data.get("elements", [])],
        )
    if node_type == "DictExpression":
        return DictExpression(
            items=[deserialize_node(item) for item in data.get("items", [])],
        )
    if node_type == "DictItem":
        return DictItem(
            key=deserialize_node(data["key"]),
            value=deserialize_node(data["value"]),
        )
    if node_type == "SliceExpression":
        return SliceExpression(
            target=deserialize_node(data["target"]),
            start=deserialize_node(data["start"]) if data.get("start") else None,
            stop=deserialize_node(data["stop"]) if data.get("stop") else None,
            step=deserialize_node(data["step"]) if data.get("step") else None,
        )
    if node_type == "LambdaExpression":
        return LambdaExpression(
            parameters=list(data.get("parameters", [])),
            body=deserialize_node(data["body"]),
        )
    if node_type == "PatternMatch":
        return PatternMatch(
            value=deserialize_node(data["value"]),
            cases=[deserialize_node(case) for case in data.get("cases", [])],
            default=deserialize_node(data["default"]) if data.get("default") else None,
        )
    if node_type == "MatchCase":
        return MatchCase(
            pattern=deserialize_node(data["pattern"]),
            result=deserialize_node(data["result"]),
        )
    if node_type == "SpreadOperator":
        return SpreadOperator(
            expression=deserialize_node(data["expression"]),
            is_dict=data.get("is_dict", False),
        )
    return Identifier(data.get("data", "unknown"))


def deserialize_yarafile(data: dict[str, Any]) -> YaraFile:
    """Deserialize a YaraFile."""
    yf = YaraFile()
    yf.imports = [deserialize_node(imp) for imp in data.get("imports", [])]
    yf.includes = [deserialize_node(inc) for inc in data.get("includes", [])]
    yf.rules = [deserialize_node(rule) for rule in data.get("rules", [])]
    yf.extern_rules = [deserialize_extern_rule(rule) for rule in data.get("extern_rules", [])]
    yf.extern_imports = [deserialize_node(imp) for imp in data.get("extern_imports", [])]
    yf.pragmas = [deserialize_pragma(pragma) for pragma in data.get("pragmas", [])]
    yf.namespaces = [deserialize_node(namespace) for namespace in data.get("namespaces", [])]
    return yf


def deserialize_rule(data: dict[str, Any]) -> Rule:
    """Deserialize a Rule."""
    rule = Rule(
        name=data["name"],
        modifiers=data.get("modifiers", []),
        condition=(
            deserialize_node(data["condition"]) if data.get("condition") else BooleanLiteral(True)
        ),
    )

    if "tags" in data:
        from yaraast.ast.rules import Tag

        rule.tags = [Tag(name=t) if isinstance(t, str) else t for t in data["tags"]]

    if "meta" in data:
        rule.meta = [deserialize_meta(m) for m in data["meta"]]

    if "strings" in data:
        rule.strings = [deserialize_string(s) for s in data["strings"]]

    if "pragmas" in data:
        rule.pragmas = [cast_in_rule_pragma(deserialize_node(pragma)) for pragma in data["pragmas"]]

    return rule


def _deserialize_rule_modifiers(modifiers: list[Any]) -> list[Any]:
    normalized = []
    for modifier in modifiers:
        if isinstance(modifier, str):
            try:
                normalized.append(RuleModifier.from_string(modifier))
            except (ValueError, ValidationError):
                normalized.append(modifier)
        else:
            normalized.append(modifier)
    return normalized


def deserialize_extern_rule(data: dict[str, Any]) -> ExternRule:
    return ExternRule(
        name=data["name"],
        modifiers=_deserialize_rule_modifiers(data.get("modifiers", [])),
        namespace=data.get("namespace"),
    )


def _deserialize_pragma_scope(value: Any) -> PragmaScope:
    try:
        return PragmaScope(value or PragmaScope.FILE.value)
    except ValueError:
        return PragmaScope.FILE


def deserialize_pragma(data: dict[str, Any]) -> Pragma:
    pragma_type = PragmaType.from_string(
        str(data.get("pragma_type", data.get("name", PragmaType.CUSTOM.value)))
    )
    scope = _deserialize_pragma_scope(data.get("scope"))

    if pragma_type == PragmaType.INCLUDE_ONCE:
        pragma = IncludeOncePragma()
    elif pragma_type == PragmaType.DEFINE and "macro_name" in data:
        pragma = DefineDirective(
            macro_name=str(data["macro_name"]),
            macro_value=data.get("macro_value"),
        )
    elif pragma_type == PragmaType.UNDEF and "macro_name" in data:
        pragma = UndefDirective(macro_name=str(data["macro_name"]))
    elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
        pragma = ConditionalDirective(pragma_type, condition=data.get("condition"))
    elif pragma_type == PragmaType.CUSTOM:
        pragma = CustomPragma(
            name=str(data.get("name", pragma_type.value)),
            arguments=list(data.get("arguments", [])),
            parameters=dict(data.get("parameters", {})),
            scope=scope,
        )
    else:
        pragma = Pragma(
            pragma_type=pragma_type,
            name=str(data.get("name", pragma_type.value)),
            arguments=list(data.get("arguments", [])),
            scope=scope,
        )
    pragma.scope = scope
    return pragma


def cast_in_rule_pragma(node: ASTNode) -> InRulePragma:
    if isinstance(node, InRulePragma):
        return node
    return InRulePragma(pragma=Pragma(PragmaType.CUSTOM, "custom"))


def cast_comment(node: ASTNode) -> Comment:
    if isinstance(node, Comment):
        return node
    return Comment(str(node))


def cast_trailing_comment(node: ASTNode) -> Any:
    if isinstance(node, Comment | CommentGroup):
        return node
    return Comment(str(node))


def deserialize_meta(data: dict[str, Any]) -> Meta | MetaEntry:
    """Deserialize a Meta item."""
    scope = data.get("scope")
    if data.get("type") == "MetaEntry" or scope is not None:
        return MetaEntry.from_key_value(data["key"], data["value"], scope)
    return _apply_node_metadata(Meta(data["key"], data["value"]), data)


def deserialize_string(data: dict[str, Any]) -> Any:
    """Deserialize a string definition."""
    string_type = data.get("type")

    if string_type == "PlainString":
        return _apply_node_metadata(
            PlainString(
                identifier=data["identifier"],
                value=_deserialize_plain_string_value(data),
                modifiers=_deserialize_modifiers(data.get("modifiers", [])),
            ),
            data,
        )
    if string_type == "HexString":
        raw_tokens = data.get("tokens", [])
        if isinstance(raw_tokens, list):
            tokens = [_deserialize_hex_token(t) for t in raw_tokens]
            return _apply_node_metadata(
                HexString(
                    identifier=data["identifier"],
                    tokens=tokens,
                    modifiers=_deserialize_modifiers(data.get("modifiers", [])),
                ),
                data,
            )
        if isinstance(raw_tokens, str):
            try:
                return _apply_node_metadata(
                    HexString(
                        identifier=data["identifier"],
                        tokens=_deserialize_legacy_hex_tokens(raw_tokens),
                        modifiers=_deserialize_modifiers(data.get("modifiers", [])),
                    ),
                    data,
                )
            except HexParseError:
                pass

        # Legacy format with invalid token payloads: preserve type but do not invent tokens.
        import warnings

        warnings.warn(
            f"HexString '{data['identifier']}' has non-list tokens in serialized data, "
            "tokens will be empty after deserialization",
            stacklevel=2,
        )
        return _apply_node_metadata(
            HexString(
                identifier=data["identifier"],
                tokens=[],
                modifiers=_deserialize_modifiers(data.get("modifiers", [])),
            ),
            data,
        )
    if string_type == "RegexString":
        return _apply_node_metadata(
            RegexString(
                identifier=data["identifier"],
                regex=data["regex"],
                modifiers=_deserialize_modifiers(data.get("modifiers", [])),
            ),
            data,
        )
    return _apply_node_metadata(
        PlainString(identifier=data.get("identifier", "$unknown"), value=data.get("data", "")),
        data,
    )


def serialize_to_file(node: ASTNode, file_path: str | Path) -> None:
    """Serialize an AST node to a JSON file."""
    data = serialize_node(node)
    file_path = Path(file_path)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def deserialize_from_file(file_path: str | Path) -> ASTNode:
    """Deserialize an AST node from a JSON file."""
    file_path = Path(file_path)
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    return deserialize_node(data)


def validate_roundtrip(node: ASTNode) -> tuple[bool, dict[str, Any]]:
    """Validate roundtrip serialization."""
    generator = YaraXGenerator()
    try:
        serialized = serialize_node(node)
        deserialized = deserialize_node(serialized)
        original_code = generator.generate(node)
        roundtrip_code = generator.generate(deserialized)
        is_valid = original_code.strip() == roundtrip_code.strip()
        diff = {
            "original_code": original_code,
            "roundtrip_code": roundtrip_code,
            "differences": [] if is_valid else ["Code differs after roundtrip"],
        }
        return is_valid, diff
    except Exception as e:  # serialization + codegen roundtrip errors
        return False, {"error": str(e)}


def simple_roundtrip_report(yara_source: str) -> dict[str, Any]:
    """Perform a simple roundtrip test."""
    generator = YaraXGenerator()
    try:
        original_ast = parse_yara_source(yara_source)
        reconstructed = generator.generate(original_ast)
        original_normalized = yara_source.strip()
        reconstructed_normalized = reconstructed.strip()
        success, differences = _compare_normalized(original_normalized, reconstructed_normalized)
        reconstructed_ast = parse_yara_source(reconstructed)
        return {
            "original_source": original_normalized,
            "reconstructed_source": reconstructed_normalized,
            "round_trip_successful": success,
            "differences": differences,
            "metadata": {
                "original_rule_count": len(original_ast.rules) if original_ast else 0,
                "reconstructed_rule_count": (
                    len(reconstructed_ast.rules) if reconstructed_ast else 0
                ),
            },
        }
    except Exception as e:  # parse + codegen roundtrip errors
        return {
            "original_source": yara_source,
            "reconstructed_source": "",
            "round_trip_successful": False,
            "differences": [f"Error during roundtrip: {e!s}"],
            "metadata": {},
        }


def _compare_normalized(original: str, reconstructed: str) -> tuple[bool, list[str]]:
    """Compare normalized YARA source lines."""
    differences: list[str] = []
    original_lines = [line.strip() for line in original.split("\n") if line.strip()]
    reconstructed_lines = [line.strip() for line in reconstructed.split("\n") if line.strip()]

    if original_lines == reconstructed_lines:
        return True, differences

    if len(original_lines) != len(reconstructed_lines):
        differences.append(
            f"Line count differs: {len(original_lines)} vs {len(reconstructed_lines)}",
        )

    for i, (orig, recon) in enumerate(
        zip(original_lines, reconstructed_lines, strict=False),
    ):
        if orig != recon:
            differences.append(f"Line {i + 1} differs: '{orig}' vs '{recon}'")
            if len(differences) > 5:
                differences.append("... more differences")
                break

    return False, differences
