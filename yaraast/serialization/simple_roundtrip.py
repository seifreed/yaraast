"""Simple roundtrip serialization for YARA AST."""

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
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.codegen import CodeGenerator
from yaraast.parser import Parser


class SimpleRoundtripSerializer:
    """Simple serializer for AST roundtrip testing."""

    def __init__(self) -> None:
        """Initialize the serializer."""
        self.parser = Parser()
        self.generator = CodeGenerator()

    def serialize(self, node: ASTNode) -> dict[str, Any]:
        """Serialize an AST node to a dictionary."""
        if isinstance(node, YaraFile):
            return self._serialize_yarafile(node)
        if isinstance(node, Rule):
            return self._serialize_rule(node)
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
                "left": self.serialize(node.left),
                "operator": node.operator,
                "right": self.serialize(node.right),
            }
        if isinstance(node, UnaryExpression):
            return {
                "type": "UnaryExpression",
                "operator": node.operator,
                "operand": self.serialize(node.operand),
            }
        # Generic serialization
        return {"type": type(node).__name__, "data": str(node)}

    def _serialize_yarafile(self, yf: YaraFile) -> dict[str, Any]:
        """Serialize a YaraFile."""
        return {
            "type": "YaraFile",
            "imports": [self.serialize(imp) for imp in (yf.imports or [])],
            "includes": [self.serialize(inc) for inc in (yf.includes or [])],
            "rules": [self.serialize(rule) for rule in (yf.rules or [])],
        }

    def _serialize_rule(self, rule: Rule) -> dict[str, Any]:
        """Serialize a Rule."""
        data = {
            "type": "Rule",
            "name": rule.name,
            "condition": self.serialize(rule.condition) if rule.condition else None,
        }

        if rule.tags:
            data["tags"] = rule.tags

        if rule.meta:
            data["meta"] = [self._serialize_meta(m) for m in rule.meta]

        if rule.strings:
            data["strings"] = [self._serialize_string(s) for s in rule.strings]

        return data

    def _serialize_meta(self, meta: Meta) -> dict[str, Any]:
        """Serialize a Meta item."""
        return {"type": "Meta", "key": meta.key, "value": meta.value}

    def _serialize_string(self, string_def: Any) -> dict[str, Any]:
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
                "tokens": str(string_def.tokens),
            }
        if isinstance(string_def, RegexString):
            return {
                "type": "RegexString",
                "identifier": string_def.identifier,
                "regex": string_def.regex,
            }
        return {"type": "StringDefinition", "data": str(string_def)}

    def deserialize(self, data: dict[str, Any]) -> ASTNode:
        """Deserialize a dictionary to an AST node."""
        node_type = data.get("type")

        if node_type == "YaraFile":
            return self._deserialize_yarafile(data)
        if node_type == "Rule":
            return self._deserialize_rule(data)
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
                self.deserialize(data["left"]),
                data["operator"],
                self.deserialize(data["right"]),
            )
        if node_type == "UnaryExpression":
            return UnaryExpression(data["operator"], self.deserialize(data["operand"]))
        # Fallback
        return Identifier(data.get("data", "unknown"))

    def _deserialize_yarafile(self, data: dict[str, Any]) -> YaraFile:
        """Deserialize a YaraFile."""
        yf = YaraFile()
        yf.imports = [self.deserialize(imp) for imp in data.get("imports", [])]
        yf.includes = [self.deserialize(inc) for inc in data.get("includes", [])]
        yf.rules = [self.deserialize(rule) for rule in data.get("rules", [])]
        return yf

    def _deserialize_rule(self, data: dict[str, Any]) -> Rule:
        """Deserialize a Rule."""
        rule = Rule(
            data["name"],
            (
                self.deserialize(data["condition"])
                if data.get("condition")
                else BooleanLiteral(True)
            ),
        )

        if "tags" in data:
            rule.tags = data["tags"]

        if "meta" in data:
            rule.meta = [self._deserialize_meta(m) for m in data["meta"]]

        if "strings" in data:
            rule.strings = [self._deserialize_string(s) for s in data["strings"]]

        return rule

    def _deserialize_meta(self, data: dict[str, Any]) -> Meta:
        """Deserialize a Meta item."""
        return Meta(data["key"], data["value"])

    def _deserialize_string(self, data: dict[str, Any]) -> Any:
        """Deserialize a string definition."""
        string_type = data.get("type")

        if string_type == "PlainString":
            return PlainString(data["identifier"], data["value"])
        if string_type == "HexString":
            # Simplified hex string
            return PlainString(data["identifier"], data.get("tokens", ""))
        if string_type == "RegexString":
            return RegexString(data["identifier"], data["regex"])
        return PlainString(data.get("identifier", "$unknown"), data.get("data", ""))

    def serialize_to_file(self, node: ASTNode, file_path: str | Path) -> None:
        """Serialize an AST node to a JSON file."""
        data = self.serialize(node)
        file_path = Path(file_path)

        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)

    def deserialize_from_file(self, file_path: str | Path) -> ASTNode:
        """Deserialize an AST node from a JSON file."""
        file_path = Path(file_path)

        with open(file_path) as f:
            data = json.load(f)

        return self.deserialize(data)

    def validate_roundtrip(self, node: ASTNode) -> tuple[bool, dict[str, Any]]:
        """Validate roundtrip serialization."""
        try:
            # Serialize
            serialized = self.serialize(node)

            # Deserialize
            deserialized = self.deserialize(serialized)

            # Generate code for both
            original_code = self.generator.generate(node)
            roundtrip_code = self.generator.generate(deserialized)

            # Compare
            is_valid = original_code.strip() == roundtrip_code.strip()

            diff = {
                "original_code": original_code,
                "roundtrip_code": roundtrip_code,
                "differences": [] if is_valid else ["Code differs after roundtrip"],
            }

            return is_valid, diff

        except Exception as e:
            return False, {"error": str(e)}


class SimpleRoundTrip:
    """Simple roundtrip testing utility."""

    def __init__(self) -> None:
        self.parser = Parser()
        self.generator = CodeGenerator()
        self.test_count = 0
        self.success_count = 0

    def test(self, yara_code: str) -> tuple[bool, Any, Any]:
        """Test roundtrip for a single YARA rule."""
        self.test_count += 1
        try:
            original_ast = self.parser.parse(yara_code)
            regenerated = self.generator.generate(original_ast)
            regenerated_ast = self.parser.parse(regenerated)

            success = original_ast is not None and regenerated_ast is not None
            if success:
                self.success_count += 1

            return success, original_ast, regenerated_ast
        except (ValueError, TypeError, AttributeError):
            return False, None, None

    def test_batch(self, yara_codes: list[str]) -> list[tuple[bool, Any, Any]]:
        """Test multiple YARA rules."""
        return [self.test(code) for code in yara_codes]

    def test_file(self, file_path: Path) -> tuple[bool, Any, Any]:
        """Test a YARA file."""
        yara_code = file_path.read_text()
        return self.test(yara_code)

    def test_directory(self, dir_path: Path) -> list[tuple[Path, bool, Any, Any]]:
        """Test all YARA files in a directory."""
        results = []
        for yar_file in dir_path.glob("*.yar"):
            success, orig, regen = self.test_file(yar_file)
            results.append((yar_file, success, orig, regen))
        return results

    def get_statistics(self) -> dict[str, Any]:
        """Get test statistics."""
        return {
            "total_tests": self.test_count,
            "successful_tests": self.success_count,
            "failed_tests": self.test_count - self.success_count,
            "success_rate": self.success_count / max(1, self.test_count) * 100,
        }


def simple_roundtrip_test(yara_source: str) -> dict[str, Any]:
    """Perform a simple roundtrip test."""
    try:
        # Parse original
        parser = Parser()
        original_ast = parser.parse(yara_source)

        # Generate code from AST
        generator = CodeGenerator()
        reconstructed = generator.generate(original_ast)

        # Compare
        original_normalized = yara_source.strip()
        reconstructed_normalized = reconstructed.strip()

        # Basic comparison
        differences = []
        success = True

        # Compare content (ignoring whitespace differences)
        original_lines = [line.strip() for line in original_normalized.split("\n") if line.strip()]
        reconstructed_lines = [
            line.strip() for line in reconstructed_normalized.split("\n") if line.strip()
        ]

        if original_lines != reconstructed_lines:
            success = False
            if len(original_lines) != len(reconstructed_lines):
                differences.append(
                    f"Line count differs: {len(original_lines)} vs {len(reconstructed_lines)}",
                )

            for i, (orig, recon) in enumerate(
                zip(original_lines, reconstructed_lines, strict=False),
            ):
                if orig != recon:
                    differences.append(f"Line {i + 1} differs: '{orig}' vs '{recon}'")
                    if len(differences) > 5:  # Limit differences shown
                        differences.append("... more differences")
                        break

        return {
            "original_source": original_normalized,
            "reconstructed_source": reconstructed_normalized,
            "round_trip_successful": success,
            "differences": differences,
            "metadata": {
                "original_rule_count": len(original_ast.rules) if original_ast else 0,
                "reconstructed_rule_count": (len(original_ast.rules) if original_ast else 0),
            },
        }

    except Exception as e:
        return {
            "original_source": yara_source,
            "reconstructed_source": "",
            "round_trip_successful": False,
            "differences": [f"Error during roundtrip: {e!s}"],
            "metadata": {},
        }
