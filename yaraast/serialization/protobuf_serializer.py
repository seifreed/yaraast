"""Protobuf serialization for YARA AST."""

from __future__ import annotations

import time
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile

# Suppress protobuf version warning before import
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message=".*Protobuf gencode version.*",
    module="google.protobuf.runtime_version",
)

try:
    from yaraast.serialization import yara_ast_pb2
except ImportError:
    # Fallback if protobuf compilation failed
    yara_ast_pb2 = None


class ProtobufSerializer(ASTVisitor[Any]):
    """Protobuf serializer for YARA AST with efficient binary format."""

    def __init__(self, include_metadata: bool = True) -> None:
        if yara_ast_pb2 is None:
            msg = "Protobuf schema not compiled. Run: protoc --python_out=. yara_ast.proto"
            raise ImportError(
                msg,
            )

        self.include_metadata = include_metadata

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> bytes:
        """Serialize AST to Protobuf binary format."""
        pb_yara_file = self._ast_to_protobuf(ast)
        binary_data = pb_yara_file.SerializeToString()

        if output_path:
            with Path(output_path).open("wb") as f:
                f.write(binary_data)

        return binary_data

    def serialize_text(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize AST to Protobuf text format (for debugging)."""
        pb_yara_file = self._ast_to_protobuf(ast)
        text_data = str(pb_yara_file)

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(text_data)

        return text_data

    def deserialize(
        self,
        binary_data: bytes | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize Protobuf binary to AST."""
        if input_path:
            with Path(input_path).open("rb") as f:
                binary_data = f.read()

        if not binary_data:
            msg = "No binary data provided"
            raise ValueError(msg)

        pb_yara_file = yara_ast_pb2.YaraFile()
        pb_yara_file.ParseFromString(binary_data)

        return self._protobuf_to_ast(pb_yara_file)

    def _ast_to_protobuf(self, ast: YaraFile) -> yara_ast_pb2.YaraFile:
        """Convert AST to Protobuf message."""
        pb_file = yara_ast_pb2.YaraFile()

        # Convert imports
        for imp in ast.imports:
            pb_import = pb_file.imports.add()
            pb_import.module = imp.module
            if hasattr(imp, "alias") and imp.alias:
                pb_import.alias = imp.alias

        # Convert includes
        for inc in ast.includes:
            pb_include = pb_file.includes.add()
            pb_include.path = inc.path

        # Convert rules
        for rule in ast.rules:
            pb_rule = pb_file.rules.add()
            self._convert_rule_to_protobuf(rule, pb_rule)

        # Add metadata
        if self.include_metadata:
            pb_file.metadata.format = "yaraast-protobuf"
            pb_file.metadata.version = "1.0"
            pb_file.metadata.ast_type = "YaraFile"
            pb_file.metadata.rules_count = len(ast.rules)
            pb_file.metadata.imports_count = len(ast.imports)
            pb_file.metadata.includes_count = len(ast.includes)
            pb_file.metadata.timestamp = int(time.time())

        return pb_file

    def _convert_rule_to_protobuf(self, rule, pb_rule) -> None:
        """Convert rule AST to Protobuf."""
        pb_rule.name = rule.name
        pb_rule.modifiers.extend(rule.modifiers)

        # Convert tags
        for tag in rule.tags:
            pb_tag = pb_rule.tags.add()
            pb_tag.name = tag.name

        # Convert meta
        for key, value in rule.meta.items():
            meta_val = pb_rule.meta[key]
            if isinstance(value, str):
                meta_val.string_value = value
            elif isinstance(value, int):
                meta_val.int_value = value
            elif isinstance(value, bool):
                meta_val.bool_value = value
            elif isinstance(value, float):
                meta_val.double_value = value

        # Convert strings
        for string_def in rule.strings:
            pb_string = pb_rule.strings.add()
            pb_string.identifier = string_def.identifier
            self._convert_string_to_protobuf(string_def, pb_string)

        # Convert condition
        if rule.condition:
            self._convert_expression_to_protobuf(rule.condition, pb_rule.condition)

    def _convert_string_to_protobuf(self, string_def, pb_string) -> None:
        """Convert string definition to Protobuf."""
        from yaraast.ast.strings import HexString, PlainString, RegexString

        if isinstance(string_def, PlainString):
            pb_string.plain.value = string_def.value
            for mod in string_def.modifiers:
                pb_mod = pb_string.plain.modifiers.add()
                pb_mod.name = mod.name
                if mod.value:
                    pb_mod.value = mod.value

        elif isinstance(string_def, HexString):
            for token in string_def.tokens:
                pb_token = pb_string.hex.tokens.add()
                self._convert_hex_token_to_protobuf(token, pb_token)

            for mod in string_def.modifiers:
                pb_mod = pb_string.hex.modifiers.add()
                pb_mod.name = mod.name
                if mod.value:
                    pb_mod.value = mod.value

        elif isinstance(string_def, RegexString):
            pb_string.regex.regex = string_def.regex
            for mod in string_def.modifiers:
                pb_mod = pb_string.regex.modifiers.add()
                pb_mod.name = mod.name
                if mod.value:
                    pb_mod.value = mod.value

    def _convert_hex_token_to_protobuf(self, token, pb_token) -> None:
        """Convert hex token to Protobuf."""
        from yaraast.ast.strings import HexByte, HexJump, HexWildcard
        from yaraast.builder.hex_string_builder import HexNibble

        if isinstance(token, HexByte):
            pb_token.byte.value = str(token.value)
        elif isinstance(token, HexWildcard):
            pb_token.wildcard.CopyFrom(yara_ast_pb2.HexWildcard())
        elif isinstance(token, HexJump):
            pb_token.jump.min_jump = token.min_jump or 0
            pb_token.jump.max_jump = token.max_jump or 0
        elif isinstance(token, HexNibble):
            pb_token.nibble.high = token.high
            pb_token.nibble.value = token.value
        # Note: HexAlternative would need more complex handling

    def _convert_expression_to_protobuf(self, expr, pb_expr) -> None:
        """Convert expression to Protobuf."""
        from yaraast.ast.expressions import (
            BinaryExpression,
            BooleanLiteral,
            DoubleLiteral,
            Identifier,
            IntegerLiteral,
            StringCount,
            StringIdentifier,
            StringLiteral,
            UnaryExpression,
        )

        if isinstance(expr, Identifier):
            pb_expr.identifier.name = expr.name
        elif isinstance(expr, StringIdentifier):
            pb_expr.string_identifier.name = expr.name
        elif isinstance(expr, StringCount):
            pb_expr.string_count.string_id = expr.string_id
        elif isinstance(expr, IntegerLiteral):
            pb_expr.integer_literal.value = expr.value
        elif isinstance(expr, DoubleLiteral):
            pb_expr.double_literal.value = expr.value
        elif isinstance(expr, StringLiteral):
            pb_expr.string_literal.value = expr.value
        elif isinstance(expr, BooleanLiteral):
            pb_expr.boolean_literal.value = expr.value
        elif isinstance(expr, BinaryExpression):
            pb_expr.binary_expression.operator = expr.operator
            self._convert_expression_to_protobuf(
                expr.left,
                pb_expr.binary_expression.left,
            )
            self._convert_expression_to_protobuf(
                expr.right,
                pb_expr.binary_expression.right,
            )
        elif isinstance(expr, UnaryExpression):
            pb_expr.unary_expression.operator = expr.operator
            self._convert_expression_to_protobuf(
                expr.operand,
                pb_expr.unary_expression.operand,
            )
        # Add more expression types as needed

    def _protobuf_to_ast(self, pb_file: yara_ast_pb2.YaraFile) -> YaraFile:
        """Convert Protobuf message to AST."""
        from yaraast.ast.base import YaraFile
        from yaraast.ast.expressions import BooleanLiteral
        from yaraast.ast.rules import Import, Include, Rule

        # Reconstruct imports
        imports = []
        for pb_import in pb_file.imports:
            imports.append(
                Import(
                    module=pb_import.module,
                    alias=pb_import.alias if pb_import.alias else None,
                ),
            )

        # Reconstruct includes
        includes = []
        for pb_include in pb_file.includes:
            includes.append(Include(path=pb_include.path))

        # Reconstruct rules (basic)
        rules = []
        for pb_rule in pb_file.rules:
            # For now, create basic rules with boolean conditions
            rule = Rule(
                name=pb_rule.name,
                modifiers=list(pb_rule.modifiers),
                tags=[],
                meta={},
                strings=[],
                condition=BooleanLiteral(value=True),  # Placeholder condition
            )
            rules.append(rule)

        return YaraFile(imports=imports, includes=includes, rules=rules)

    def get_serialization_stats(self, ast: YaraFile) -> dict[str, Any]:
        """Get statistics about the serialization."""
        pb_file = self._ast_to_protobuf(ast)
        binary_size = len(pb_file.SerializeToString())
        text_size = len(str(pb_file))

        return {
            "binary_size_bytes": binary_size,
            "text_size_bytes": text_size,
            "compression_ratio": text_size / binary_size if binary_size > 0 else 0,
            "rules_count": len(ast.rules),
            "imports_count": len(ast.imports),
            "includes_count": len(ast.includes),
        }

    # Required visitor methods (simplified for now)
    def visit_yara_file(self, node) -> Any:
        return None

    def visit_import(self, node) -> Any:
        return None

    def visit_include(self, node) -> Any:
        return None

    def visit_rule(self, node) -> Any:
        return None

    def visit_tag(self, node) -> Any:
        return None

    def visit_string_definition(self, node) -> Any:
        return None

    def visit_plain_string(self, node) -> Any:
        return None

    def visit_hex_string(self, node) -> Any:
        return None

    def visit_regex_string(self, node) -> Any:
        return None

    def visit_string_modifier(self, node) -> Any:
        return None

    def visit_hex_token(self, node) -> Any:
        return None

    def visit_hex_byte(self, node) -> Any:
        return None

    def visit_hex_wildcard(self, node) -> Any:
        return None

    def visit_hex_jump(self, node) -> Any:
        return None

    def visit_hex_alternative(self, node) -> Any:
        return None

    def visit_hex_nibble(self, node) -> Any:
        return None

    def visit_expression(self, node) -> Any:
        return None

    def visit_identifier(self, node) -> Any:
        return None

    def visit_string_identifier(self, node) -> Any:
        return None

    def visit_string_count(self, node) -> Any:
        return None

    def visit_string_offset(self, node) -> Any:
        return None

    def visit_string_length(self, node) -> Any:
        return None

    def visit_integer_literal(self, node) -> Any:
        return None

    def visit_double_literal(self, node) -> Any:
        return None

    def visit_string_literal(self, node) -> Any:
        return None

    def visit_regex_literal(self, node) -> Any:
        return None

    def visit_boolean_literal(self, node) -> Any:
        return None

    def visit_binary_expression(self, node) -> Any:
        return None

    def visit_unary_expression(self, node) -> Any:
        return None

    def visit_parentheses_expression(self, node) -> Any:
        return None

    def visit_set_expression(self, node) -> Any:
        return None

    def visit_range_expression(self, node) -> Any:
        return None

    def visit_function_call(self, node) -> Any:
        return None

    def visit_array_access(self, node) -> Any:
        return None

    def visit_member_access(self, node) -> Any:
        return None

    def visit_condition(self, node) -> Any:
        return None

    def visit_for_expression(self, node) -> Any:
        return None

    def visit_for_of_expression(self, node) -> Any:
        return None

    def visit_at_expression(self, node) -> Any:
        return None

    def visit_in_expression(self, node) -> Any:
        return None

    def visit_of_expression(self, node) -> Any:
        return None

    def visit_meta(self, node) -> Any:
        return None

    def visit_module_reference(self, node) -> Any:
        return None

    def visit_dictionary_access(self, node) -> Any:
        return None

    def visit_comment(self, node) -> Any:
        return None

    def visit_comment_group(self, node) -> Any:
        return None

    def visit_defined_expression(self, node) -> Any:
        return None

    def visit_string_operator_expression(self, node) -> Any:
        return None

    def visit_extern_import(self, node) -> Any:
        """Visit ExternImport node."""
        return None

    def visit_extern_namespace(self, node) -> Any:
        """Visit ExternNamespace node."""
        return None

    def visit_extern_rule(self, node) -> Any:
        """Visit ExternRule node."""
        return None

    def visit_extern_rule_reference(self, node) -> Any:
        """Visit ExternRuleReference node."""
        return None

    def visit_in_rule_pragma(self, node) -> Any:
        """Visit InRulePragma node."""
        return None

    def visit_pragma(self, node) -> Any:
        """Visit Pragma node."""
        return None

    def visit_pragma_block(self, node) -> Any:
        """Visit PragmaBlock node."""
        return None
