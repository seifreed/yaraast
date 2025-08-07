"""Enhanced JSON serialization for YARA AST."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile

from pathlib import Path


class JsonSerializer(ASTVisitor[dict[str, Any]]):
    """Enhanced JSON serializer for YARA AST with metadata."""

    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = include_metadata

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> str:
        """Serialize AST to JSON format."""
        serialized = self._serialize_with_metadata(ast)
        json_str = json.dumps(serialized, indent=2, ensure_ascii=False)

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    def deserialize(
        self,
        json_str: str | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize JSON to AST."""
        if input_path:
            with Path(input_path).open(encoding="utf-8") as f:
                json_str = f.read()

        if not json_str:
            msg = "No JSON input provided"
            raise ValueError(msg)

        data = json.loads(json_str)
        return self._deserialize_ast(data)

    def _serialize_with_metadata(self, ast: YaraFile) -> dict[str, Any]:
        """Serialize with metadata."""
        result = {"ast": self.visit(ast)}

        if self.include_metadata:
            result["metadata"] = {
                "format": "yaraast-json",
                "version": "1.0",
                "ast_type": "YaraFile",
                "rules_count": len(ast.rules),
                "imports_count": len(ast.imports),
                "includes_count": len(ast.includes),
            }

        return result

    def _deserialize_ast(self, data: dict[str, Any]) -> YaraFile:
        """Deserialize JSON data to AST."""
        from yaraast.ast.base import YaraFile

        # Handle both wrapped (with metadata) and direct AST data
        ast_data = data.get("ast", data)
        if ast_data.get("type") != "YaraFile":
            msg = f"Expected YaraFile, got {ast_data.get('type')}"
            raise ValueError(msg)

        imports = [self._deserialize_import(imp) for imp in ast_data.get("imports", [])]
        includes = [self._deserialize_include(inc) for inc in ast_data.get("includes", [])]
        rules = [self._deserialize_rule(rule) for rule in ast_data.get("rules", [])]

        return YaraFile(imports=imports, includes=includes, rules=rules)

    def _deserialize_import(self, data: dict[str, Any]):
        """Deserialize Import node."""
        from yaraast.ast.rules import Import

        return Import(module=data["module"], alias=data.get("alias"))

    def _deserialize_include(self, data: dict[str, Any]):
        """Deserialize Include node."""
        from yaraast.ast.rules import Include

        return Include(path=data["path"])

    def _deserialize_rule(self, data: dict[str, Any]):
        """Deserialize Rule node."""
        from yaraast.ast.rules import Rule

        # Deserialize meta (can be dict or list)
        meta_data = data.get("meta", [])
        if isinstance(meta_data, dict):
            # Simple key-value pairs
            from yaraast.ast.meta import Meta

            meta = [Meta(key=k, value=v) for k, v in meta_data.items()]
        else:
            # List of meta objects
            meta = [self._deserialize_meta(m) for m in meta_data]

        strings = [self._deserialize_string(s) for s in data.get("strings", [])]
        condition = (
            self._deserialize_expression(data["condition"]) if data.get("condition") else None
        )

        tags = [self._deserialize_tag(t) for t in data.get("tags", [])]

        return Rule(
            name=data["name"],
            modifiers=data.get("modifiers", []),
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
        )

    def _deserialize_tag(self, data: dict[str, Any]):
        """Deserialize Tag node."""
        from yaraast.ast.rules import Tag

        return Tag(name=data["name"])

    def _deserialize_meta(self, data: dict[str, Any]):
        """Deserialize Meta node."""
        from yaraast.ast.meta import Meta

        return Meta(key=data["key"], value=data["value"])

    def _deserialize_string(self, data: dict[str, Any]):
        """Deserialize string definition."""
        string_type = data.get("type")
        modifiers = [self._deserialize_modifier(m) for m in data.get("modifiers", [])]

        if string_type == "PlainString":
            from yaraast.ast.strings import PlainString

            return PlainString(
                identifier=data["identifier"],
                value=data["value"],
                modifiers=modifiers,
            )
        if string_type == "HexString":
            from yaraast.ast.strings import HexString

            tokens = [self._deserialize_hex_token(t) for t in data.get("tokens", [])]
            return HexString(
                identifier=data["identifier"],
                tokens=tokens,
                modifiers=modifiers,
            )
        if string_type == "RegexString":
            from yaraast.ast.strings import RegexString

            return RegexString(
                identifier=data["identifier"],
                regex=data["regex"],
                modifiers=modifiers,
            )
        msg = f"Unknown string type: {string_type}"
        raise ValueError(msg)

    def _deserialize_modifier(self, data: dict[str, Any]):
        """Deserialize string modifier."""
        from yaraast.ast.strings import StringModifier

        return StringModifier(name=data["name"], value=data.get("value"))

    def _deserialize_hex_token(self, data: dict[str, Any]):
        """Deserialize hex token."""
        token_type = data.get("type")

        if token_type == "HexByte":  # nosec B105 - This is a type name, not a password
            from yaraast.ast.strings import HexByte

            return HexByte(value=data["value"])
        if token_type == "HexWildcard":  # nosec B105 - This is a type name, not a password
            from yaraast.ast.strings import HexWildcard

            return HexWildcard()
        if token_type == "HexJump":  # nosec B105 - This is a type name, not a password
            from yaraast.ast.strings import HexJump

            return HexJump(min_jump=data.get("min_jump"), max_jump=data.get("max_jump"))
        msg = f"Unknown hex token type: {token_type}"
        raise ValueError(msg)

    def _deserialize_expression(self, data: dict[str, Any]):
        """Deserialize expression."""
        if not data:
            return None

        expr_type = data.get("type")

        if expr_type == "BinaryExpression":
            from yaraast.ast.expressions import BinaryExpression

            left = self._deserialize_expression(data["left"])
            right = self._deserialize_expression(data["right"])
            return BinaryExpression(left=left, operator=data["operator"], right=right)
        if expr_type == "StringIdentifier":
            from yaraast.ast.expressions import StringIdentifier

            return StringIdentifier(name=data["name"])
        if expr_type == "Identifier":
            from yaraast.ast.expressions import Identifier

            return Identifier(name=data["name"])
        if expr_type == "BooleanLiteral":
            from yaraast.ast.expressions import BooleanLiteral

            return BooleanLiteral(value=data["value"])
        if expr_type == "IntegerLiteral":
            from yaraast.ast.expressions import IntegerLiteral

            return IntegerLiteral(value=data["value"])
        if expr_type == "AtExpression":
            from yaraast.ast.conditions import AtExpression

            return AtExpression(
                string_id=data["string_id"],
                offset=self._deserialize_expression(data["offset"]),
            )
        msg = f"Unknown expression type: {expr_type}"
        raise ValueError(msg)

    # Visitor methods for serialization
    def visit_yara_file(self, node: YaraFile) -> dict[str, Any]:
        return {
            "type": "YaraFile",
            "imports": [self.visit(imp) for imp in node.imports],
            "includes": [self.visit(inc) for inc in node.includes],
            "rules": [self.visit(rule) for rule in node.rules],
        }

    def visit_import(self, node) -> dict[str, Any]:
        return {
            "type": "Import",
            "module": node.module,
            "alias": getattr(node, "alias", None),
        }

    def visit_include(self, node) -> dict[str, Any]:
        return {"type": "Include", "path": node.path}

    def visit_rule(self, node) -> dict[str, Any]:
        return {
            "type": "Rule",
            "name": node.name,
            "modifiers": node.modifiers,
            "tags": [self.visit(tag) for tag in node.tags],
            "meta": node.meta,
            "strings": [self.visit(s) for s in node.strings],
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_tag(self, node) -> dict[str, Any]:
        return {"type": "Tag", "name": node.name}

    def visit_string_definition(self, node) -> dict[str, Any]:
        return {"type": "StringDefinition", "identifier": node.identifier}

    def visit_plain_string(self, node) -> dict[str, Any]:
        return {
            "type": "PlainString",
            "identifier": node.identifier,
            "value": node.value,
            "modifiers": [self.visit(mod) for mod in node.modifiers],
        }

    def visit_hex_string(self, node) -> dict[str, Any]:
        return {
            "type": "HexString",
            "identifier": node.identifier,
            "tokens": [self.visit(token) for token in node.tokens],
            "modifiers": [self.visit(mod) for mod in node.modifiers],
        }

    def visit_regex_string(self, node) -> dict[str, Any]:
        return {
            "type": "RegexString",
            "identifier": node.identifier,
            "regex": node.regex,
            "modifiers": [self.visit(mod) for mod in node.modifiers],
        }

    def visit_string_modifier(self, node) -> dict[str, Any]:
        return {"type": "StringModifier", "name": node.name, "value": node.value}

    def visit_hex_token(self, node) -> dict[str, Any]:
        return {"type": "HexToken"}

    def visit_hex_byte(self, node) -> dict[str, Any]:
        return {"type": "HexByte", "value": node.value}

    def visit_hex_wildcard(self, node) -> dict[str, Any]:
        return {"type": "HexWildcard"}

    def visit_hex_jump(self, node) -> dict[str, Any]:
        return {"type": "HexJump", "min_jump": node.min_jump, "max_jump": node.max_jump}

    def visit_hex_alternative(self, node) -> dict[str, Any]:
        return {
            "type": "HexAlternative",
            "alternatives": [[self.visit(token) for token in alt] for alt in node.alternatives],
        }

    def visit_hex_nibble(self, node) -> dict[str, Any]:
        return {"type": "HexNibble", "high": node.high, "value": node.value}

    # Expression visitor methods (simplified)
    def visit_expression(self, node) -> dict[str, Any]:
        return {"type": "Expression"}

    def visit_identifier(self, node) -> dict[str, Any]:
        return {"type": "Identifier", "name": node.name}

    def visit_string_identifier(self, node) -> dict[str, Any]:
        return {"type": "StringIdentifier", "name": node.name}

    def visit_string_count(self, node) -> dict[str, Any]:
        return {"type": "StringCount", "string_id": node.string_id}

    def visit_string_offset(self, node) -> dict[str, Any]:
        return {
            "type": "StringOffset",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_string_length(self, node) -> dict[str, Any]:
        return {
            "type": "StringLength",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_integer_literal(self, node) -> dict[str, Any]:
        return {"type": "IntegerLiteral", "value": node.value}

    def visit_double_literal(self, node) -> dict[str, Any]:
        return {"type": "DoubleLiteral", "value": node.value}

    def visit_string_literal(self, node) -> dict[str, Any]:
        return {"type": "StringLiteral", "value": node.value}

    def visit_regex_literal(self, node) -> dict[str, Any]:
        return {
            "type": "RegexLiteral",
            "pattern": node.pattern,
            "modifiers": node.modifiers,
        }

    def visit_boolean_literal(self, node) -> dict[str, Any]:
        return {"type": "BooleanLiteral", "value": node.value}

    def visit_binary_expression(self, node) -> dict[str, Any]:
        return {
            "type": "BinaryExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }

    def visit_unary_expression(self, node) -> dict[str, Any]:
        return {
            "type": "UnaryExpression",
            "operator": node.operator,
            "operand": self.visit(node.operand),
        }

    def visit_parentheses_expression(self, node) -> dict[str, Any]:
        return {
            "type": "ParenthesesExpression",
            "expression": self.visit(node.expression),
        }

    def visit_set_expression(self, node) -> dict[str, Any]:
        return {
            "type": "SetExpression",
            "elements": [self.visit(elem) for elem in node.elements],
        }

    def visit_range_expression(self, node) -> dict[str, Any]:
        return {
            "type": "RangeExpression",
            "low": self.visit(node.low),
            "high": self.visit(node.high),
        }

    def visit_function_call(self, node) -> dict[str, Any]:
        return {
            "type": "FunctionCall",
            "function": node.function,
            "arguments": [self.visit(arg) for arg in node.arguments],
        }

    def visit_array_access(self, node) -> dict[str, Any]:
        return {
            "type": "ArrayAccess",
            "array": self.visit(node.array),
            "index": self.visit(node.index),
        }

    def visit_member_access(self, node) -> dict[str, Any]:
        return {
            "type": "MemberAccess",
            "object": self.visit(node.object),
            "member": node.member,
        }

    def visit_condition(self, node) -> dict[str, Any]:
        return {"type": "Condition"}

    def visit_for_expression(self, node) -> dict[str, Any]:
        return {
            "type": "ForExpression",
            "quantifier": node.quantifier,
            "variable": node.variable,
            "iterable": self.visit(node.iterable),
            "body": self.visit(node.body),
        }

    def visit_for_of_expression(self, node) -> dict[str, Any]:
        return {
            "type": "ForOfExpression",
            "quantifier": (
                self.visit(node.quantifier)
                if hasattr(node.quantifier, "accept")
                else node.quantifier
            ),
            "string_set": self.visit(node.string_set),
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_at_expression(self, node) -> dict[str, Any]:
        return {
            "type": "AtExpression",
            "string_id": node.string_id,
            "offset": self.visit(node.offset),
        }

    def visit_in_expression(self, node) -> dict[str, Any]:
        return {
            "type": "InExpression",
            "string_id": node.string_id,
            "range": self.visit(node.range),
        }

    def visit_of_expression(self, node) -> dict[str, Any]:
        return {
            "type": "OfExpression",
            "quantifier": (
                self.visit(node.quantifier)
                if hasattr(node.quantifier, "accept")
                else node.quantifier
            ),
            "string_set": (
                self.visit(node.string_set)
                if hasattr(node.string_set, "accept")
                else node.string_set
            ),
        }

    def visit_meta(self, node) -> dict[str, Any]:
        return {"type": "Meta", "key": node.key, "value": node.value}

    def visit_module_reference(self, node) -> dict[str, Any]:
        return {"type": "ModuleReference", "module": node.module}

    def visit_dictionary_access(self, node) -> dict[str, Any]:
        return {
            "type": "DictionaryAccess",
            "object": self.visit(node.object),
            "key": self.visit(node.key) if hasattr(node.key, "accept") else node.key,
        }

    def visit_comment(self, node) -> dict[str, Any]:
        return {"type": "Comment", "text": node.text, "is_multiline": node.is_multiline}

    def visit_comment_group(self, node) -> dict[str, Any]:
        return {
            "type": "CommentGroup",
            "comments": [self.visit(comment) for comment in node.comments],
        }

    def visit_defined_expression(self, node) -> dict[str, Any]:
        return {"type": "DefinedExpression", "expression": self.visit(node.expression)}

    def visit_string_operator_expression(self, node) -> dict[str, Any]:
        return {
            "type": "StringOperatorExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }

    # Add missing abstract methods
    def visit_extern_import(self, node) -> dict[str, Any]:
        return {
            "type": "ExternImport",
            "module": node.module if hasattr(node, "module") else None,
        }

    def visit_extern_namespace(self, node) -> dict[str, Any]:
        return {
            "type": "ExternNamespace",
            "name": node.name if hasattr(node, "name") else None,
        }

    def visit_extern_rule(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRule",
            "name": node.name if hasattr(node, "name") else None,
        }

    def visit_extern_rule_reference(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRuleReference",
            "name": node.name if hasattr(node, "name") else None,
        }

    def visit_in_rule_pragma(self, node) -> dict[str, Any]:
        return {
            "type": "InRulePragma",
            "pragma": node.pragma if hasattr(node, "pragma") else None,
        }

    def visit_pragma(self, node) -> dict[str, Any]:
        return {
            "type": "Pragma",
            "directive": node.directive if hasattr(node, "directive") else None,
        }

    def visit_pragma_block(self, node) -> dict[str, Any]:
        return {
            "type": "PragmaBlock",
            "pragmas": ([self.visit(p) for p in node.pragmas] if hasattr(node, "pragmas") else []),
        }
