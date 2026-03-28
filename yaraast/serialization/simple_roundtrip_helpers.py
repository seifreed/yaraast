"""Helper functions for simple roundtrip serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.parser import Parser


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
            "alternatives": [[_serialize_hex_token(t) for t in alt] for alt in token.alternatives],
        }
    return {"type": "Unknown", "data": str(token)}


def _deserialize_hex_token(data: dict[str, Any]):
    """Deserialize a hex token from a dictionary."""
    token_type = data.get("type")
    if token_type == "HexByte":
        return HexByte(value=data["value"])
    if token_type == "HexWildcard":
        return HexWildcard()
    if token_type == "HexJump":
        return HexJump(min_jump=data.get("min_jump"), max_jump=data.get("max_jump"))
    if token_type == "HexNibble":
        return HexNibble(high=data["high"], value=data["value"])
    if token_type == "HexNegatedByte":
        return HexNegatedByte(value=data["value"])
    if token_type == "HexAlternative":
        alternatives = [[_deserialize_hex_token(t) for t in alt] for alt in data["alternatives"]]
        return HexAlternative(alternatives=alternatives)
    return HexWildcard()


def serialize_node(node: ASTNode) -> dict[str, Any]:
    """Serialize an AST node to a dictionary."""
    if isinstance(node, YaraFile):
        return serialize_yarafile(node)
    if isinstance(node, Rule):
        return serialize_rule(node)
    if isinstance(node, Import):
        return {"type": "Import", "module": node.module}
    if isinstance(node, Include):
        return {"type": "Include", "path": node.path}
    if isinstance(node, BooleanLiteral):
        return {"type": "BooleanLiteral", "value": node.value}
    if isinstance(node, IntegerLiteral):
        return {"type": "IntegerLiteral", "value": node.value}
    if isinstance(node, DoubleLiteral):
        return {"type": "DoubleLiteral", "value": node.value}
    if isinstance(node, StringLiteral):
        return {"type": "StringLiteral", "value": node.value}
    if isinstance(node, Identifier):
        return {"type": "Identifier", "name": node.name}
    if isinstance(node, StringIdentifier):
        return {"type": "StringIdentifier", "name": node.name}
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
    return {"type": type(node).__name__, "data": str(node)}


def serialize_yarafile(yf: YaraFile) -> dict[str, Any]:
    """Serialize a YaraFile."""
    return {
        "type": "YaraFile",
        "imports": [serialize_node(imp) for imp in (yf.imports or [])],
        "includes": [serialize_node(inc) for inc in (yf.includes or [])],
        "rules": [serialize_node(rule) for rule in (yf.rules or [])],
    }


def serialize_rule(rule: Rule) -> dict[str, Any]:
    """Serialize a Rule."""
    data: dict[str, Any] = {
        "type": "Rule",
        "name": rule.name,
        "condition": serialize_node(rule.condition) if rule.condition else None,
    }

    if rule.tags:
        data["tags"] = [tag.name if hasattr(tag, "name") else tag for tag in rule.tags]

    if rule.meta:
        data["meta"] = [serialize_meta(m) for m in rule.meta]

    if rule.strings:
        data["strings"] = [serialize_string(s) for s in rule.strings]

    return data


def serialize_meta(meta: Meta) -> dict[str, Any]:
    """Serialize a Meta item."""
    return {"type": "Meta", "key": meta.key, "value": meta.value}


def serialize_string(string_def: Any) -> dict[str, Any]:
    """Serialize a string definition."""
    if isinstance(string_def, PlainString):
        return {
            "type": "PlainString",
            "identifier": string_def.identifier,
            "value": string_def.value,
        }
    if isinstance(string_def, HexString):
        return {
            "type": "HexString",
            "identifier": string_def.identifier,
            "tokens": [_serialize_hex_token(t) for t in string_def.tokens],
        }
    if isinstance(string_def, RegexString):
        return {
            "type": "RegexString",
            "identifier": string_def.identifier,
            "regex": string_def.regex,
        }
    return {"type": "StringDefinition", "data": str(string_def)}


def deserialize_node(data: dict[str, Any]) -> ASTNode:
    """Deserialize a dictionary to an AST node."""
    node_type = data.get("type")

    if node_type == "YaraFile":
        return deserialize_yarafile(data)
    if node_type == "Rule":
        return deserialize_rule(data)
    if node_type == "Import":
        return Import(data["module"])
    if node_type == "Include":
        return Include(data["path"])
    if node_type == "BooleanLiteral":
        return BooleanLiteral(data["value"])
    if node_type == "IntegerLiteral":
        return IntegerLiteral(data["value"])
    if node_type == "DoubleLiteral":
        return DoubleLiteral(data["value"])
    if node_type == "StringLiteral":
        return StringLiteral(data["value"])
    if node_type == "Identifier":
        return Identifier(data["name"])
    if node_type == "StringIdentifier":
        return StringIdentifier(data["name"])
    if node_type == "BinaryExpression":
        return BinaryExpression(
            deserialize_node(data["left"]),
            data["operator"],
            deserialize_node(data["right"]),
        )
    if node_type == "UnaryExpression":
        return UnaryExpression(data["operator"], deserialize_node(data["operand"]))
    return Identifier(data.get("data", "unknown"))


def deserialize_yarafile(data: dict[str, Any]) -> YaraFile:
    """Deserialize a YaraFile."""
    yf = YaraFile()
    yf.imports = [deserialize_node(imp) for imp in data.get("imports", [])]
    yf.includes = [deserialize_node(inc) for inc in data.get("includes", [])]
    yf.rules = [deserialize_node(rule) for rule in data.get("rules", [])]
    return yf


def deserialize_rule(data: dict[str, Any]) -> Rule:
    """Deserialize a Rule."""
    rule = Rule(
        name=data["name"],
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

    return rule


def deserialize_meta(data: dict[str, Any]) -> Meta:
    """Deserialize a Meta item."""
    return Meta(data["key"], data["value"])


def deserialize_string(data: dict[str, Any]) -> Any:
    """Deserialize a string definition."""
    string_type = data.get("type")

    if string_type == "PlainString":
        return PlainString(identifier=data["identifier"], value=data["value"])
    if string_type == "HexString":
        raw_tokens = data.get("tokens", [])
        if isinstance(raw_tokens, list):
            tokens = [_deserialize_hex_token(t) for t in raw_tokens]
            return HexString(identifier=data["identifier"], tokens=tokens)
        # Legacy format: tokens stored as string representation — preserve as HexString with empty tokens
        import warnings

        warnings.warn(
            f"HexString '{data['identifier']}' has non-list tokens in serialized data, "
            "tokens will be empty after deserialization",
            stacklevel=2,
        )
        return HexString(identifier=data["identifier"], tokens=[])
    if string_type == "RegexString":
        return RegexString(identifier=data["identifier"], regex=data["regex"])
    return PlainString(identifier=data.get("identifier", "$unknown"), value=data.get("data", ""))


def serialize_to_file(node: ASTNode, file_path: str | Path) -> None:
    """Serialize an AST node to a JSON file."""
    data = serialize_node(node)
    file_path = Path(file_path)
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


def deserialize_from_file(file_path: str | Path) -> ASTNode:
    """Deserialize an AST node from a JSON file."""
    file_path = Path(file_path)
    with open(file_path) as f:
        data = json.load(f)
    return deserialize_node(data)


def validate_roundtrip(node: ASTNode) -> tuple[bool, dict[str, Any]]:
    """Validate roundtrip serialization."""
    generator = CodeGenerator()
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
    parser = Parser()
    generator = CodeGenerator()
    try:
        original_ast = parser.parse(yara_source)
        reconstructed = generator.generate(original_ast)
        original_normalized = yara_source.strip()
        reconstructed_normalized = reconstructed.strip()
        success, differences = _compare_normalized(original_normalized, reconstructed_normalized)
        reconstructed_ast = parser.parse(reconstructed)
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
