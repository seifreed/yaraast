"""AST dump visitor for CLI."""

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
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
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.visitor import ASTVisitor


class ASTDumper(ASTVisitor[dict]):
    """Dump AST to dictionary format."""

    def visit_yara_file(self, node: YaraFile) -> dict:
        return {
            "type": "YaraFile",
            "imports": [self.visit(imp) for imp in node.imports],
            "includes": [self.visit(inc) for inc in node.includes],
            "rules": [self.visit(rule) for rule in node.rules],
        }

    def visit_import(self, node: Import) -> dict:
        return {"type": "Import", "module": node.module}

    def visit_include(self, node: Include) -> dict:
        return {"type": "Include", "path": node.path}

    def visit_rule(self, node: Rule) -> dict:
        tags = self._process_tags(node.tags)
        meta = self._process_meta(node.meta)
        modifiers = self._process_modifiers(node)

        return {
            "type": "Rule",
            "name": node.name,
            "modifiers": modifiers,
            "tags": tags,
            "meta": meta,
            "strings": [self.visit(s) for s in node.strings],
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def _process_tags(self, tags) -> list:
        """Process tags from rule node."""
        result = []
        for tag in tags:
            if isinstance(tag, str):
                result.append(tag)
            else:
                result.append(self.visit(tag))
        return result

    def _process_meta(self, meta) -> dict:
        """Process meta from rule node."""
        result = {}
        if isinstance(meta, list):
            for m in meta:
                if hasattr(m, "key") and hasattr(m, "value"):
                    result[m.key] = m.value
        return result

    def _process_modifiers(self, node: Rule) -> list:
        """Process modifiers from rule node."""
        modifiers = []
        if hasattr(node, "modifiers") and node.modifiers:
            if isinstance(node.modifiers, list | tuple):
                for mod in node.modifiers:
                    if isinstance(mod, str):
                        modifiers.append(mod)
                    elif hasattr(mod, "accept"):
                        modifiers.append(self.visit(mod))
                    else:
                        modifiers.append(str(mod))
            elif isinstance(node.modifiers, str):
                modifiers.append(node.modifiers)
            elif hasattr(node.modifiers, "accept"):
                pass
            else:
                modifiers.append(str(node.modifiers))
        return modifiers

    def visit_tag(self, node: Tag) -> dict:
        return {"type": "Tag", "name": node.name}

    def visit_string_definition(self, node: StringDefinition) -> dict:
        return {"type": "StringDefinition", "identifier": node.identifier}

    def visit_plain_string(self, node: PlainString) -> dict:
        modifiers = self._extract_modifiers(node)
        return {
            "type": "PlainString",
            "identifier": node.identifier,
            "value": node.value,
            "modifiers": modifiers,
        }

    def visit_hex_string(self, node: HexString) -> dict:
        modifiers = self._extract_modifiers(node)
        return {
            "type": "HexString",
            "identifier": node.identifier,
            "tokens": [self.visit(token) for token in node.tokens],
            "modifiers": modifiers,
        }

    def visit_regex_string(self, node: RegexString) -> dict:
        modifiers = self._extract_modifiers(node)
        return {
            "type": "RegexString",
            "identifier": node.identifier,
            "regex": node.regex,
            "modifiers": modifiers,
        }

    def _extract_modifiers(self, node) -> list:
        """Extract modifiers from a string node."""
        modifiers = []
        if hasattr(node, "modifiers") and node.modifiers:
            if isinstance(node.modifiers, list | tuple):
                for mod in node.modifiers:
                    if isinstance(mod, str):
                        modifiers.append(mod)
                    elif hasattr(mod, "accept"):
                        modifiers.append(self.visit(mod))
                    else:
                        modifiers.append(str(mod))
            else:
                modifiers.append(str(node.modifiers))
        return modifiers

    def visit_string_modifier(self, node: StringModifier) -> dict:
        return {"type": "StringModifier", "name": node.name, "value": node.value}

    def visit_hex_token(self, node: HexToken) -> dict:
        return {"type": "HexToken"}

    def visit_hex_byte(self, node: HexByte) -> dict:
        return {"type": "HexByte", "value": node.value}

    def visit_hex_wildcard(self, node: HexWildcard) -> dict:
        return {"type": "HexWildcard"}

    def visit_hex_jump(self, node: HexJump) -> dict:
        return {"type": "HexJump", "min_jump": node.min_jump, "max_jump": node.max_jump}

    def visit_hex_alternative(self, node: HexAlternative) -> dict:
        return {
            "type": "HexAlternative",
            "alternatives": [[self.visit(token) for token in alt] for alt in node.alternatives],
        }

    def visit_expression(self, node: Expression) -> dict:
        return {"type": "Expression"}

    def visit_identifier(self, node: Identifier) -> dict:
        return {"type": "Identifier", "name": node.name}

    def visit_string_identifier(self, node: StringIdentifier) -> dict:
        return {"type": "StringIdentifier", "name": node.name}

    def visit_string_wildcard(self, node: StringWildcard) -> dict:
        return {"type": "StringWildcard", "pattern": node.pattern}

    def visit_string_count(self, node: StringCount) -> dict:
        return {"type": "StringCount", "string_id": node.string_id}

    def visit_string_offset(self, node: StringOffset) -> dict:
        return {
            "type": "StringOffset",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_string_length(self, node: StringLength) -> dict:
        return {
            "type": "StringLength",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_integer_literal(self, node: IntegerLiteral) -> dict:
        return {"type": "IntegerLiteral", "value": node.value}

    def visit_double_literal(self, node: DoubleLiteral) -> dict:
        return {"type": "DoubleLiteral", "value": node.value}

    def visit_string_literal(self, node: StringLiteral) -> dict:
        return {"type": "StringLiteral", "value": node.value}

    def visit_boolean_literal(self, node: BooleanLiteral) -> dict:
        return {"type": "BooleanLiteral", "value": node.value}

    def visit_binary_expression(self, node: BinaryExpression) -> dict:
        return {
            "type": "BinaryExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }

    def visit_unary_expression(self, node: UnaryExpression) -> dict:
        return {
            "type": "UnaryExpression",
            "operator": node.operator,
            "operand": self.visit(node.operand),
        }

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> dict:
        return {
            "type": "ParenthesesExpression",
            "expression": self.visit(node.expression),
        }

    def visit_set_expression(self, node: SetExpression) -> dict:
        return {
            "type": "SetExpression",
            "elements": [self.visit(elem) for elem in node.elements],
        }

    def visit_range_expression(self, node: RangeExpression) -> dict:
        return {
            "type": "RangeExpression",
            "low": self.visit(node.low),
            "high": self.visit(node.high),
        }

    def visit_function_call(self, node: FunctionCall) -> dict:
        return {
            "type": "FunctionCall",
            "function": node.function,
            "arguments": [self.visit(arg) for arg in node.arguments],
        }

    def visit_array_access(self, node: ArrayAccess) -> dict:
        return {
            "type": "ArrayAccess",
            "array": self.visit(node.array),
            "index": self.visit(node.index),
        }

    def visit_member_access(self, node: MemberAccess) -> dict:
        return {
            "type": "MemberAccess",
            "object": self.visit(node.object),
            "member": node.member,
        }

    def visit_condition(self, node: Condition) -> dict:
        return {"type": "Condition"}

    def visit_for_expression(self, node: ForExpression) -> dict:
        return {
            "type": "ForExpression",
            "quantifier": node.quantifier,
            "variable": node.variable,
            "iterable": self.visit(node.iterable),
            "body": self.visit(node.body),
        }

    def visit_for_of_expression(self, node: ForOfExpression) -> dict:
        return {
            "type": "ForOfExpression",
            "quantifier": (
                node.quantifier
                if isinstance(node.quantifier, str | int)
                else self.visit(node.quantifier)
            ),
            "string_set": self.visit(node.string_set),
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_at_expression(self, node: AtExpression) -> dict:
        return {
            "type": "AtExpression",
            "string_id": node.string_id,
            "offset": self.visit(node.offset),
        }

    def visit_in_expression(self, node: InExpression) -> dict:
        return {
            "type": "InExpression",
            "string_id": node.string_id,
            "range": self.visit(node.range),
        }

    def visit_of_expression(self, node: OfExpression) -> dict:
        return {
            "type": "OfExpression",
            "quantifier": (
                node.quantifier
                if isinstance(node.quantifier, str | int)
                else self.visit(node.quantifier)
            ),
            "string_set": self.visit(node.string_set),
        }

    def visit_meta(self, node: Meta) -> dict:
        return {"type": "Meta", "key": node.key, "value": node.value}

    def visit_comment(self, node) -> dict:
        return {"type": "Comment", "text": node.text}

    def visit_comment_group(self, node) -> dict:
        return {"type": "CommentGroup", "lines": node.lines}

    def visit_defined_expression(self, node) -> dict:
        return {"type": "DefinedExpression", "expression": self.visit(node.expression)}

    def visit_dictionary_access(self, node) -> dict:
        return {
            "type": "DictionaryAccess",
            "object": self.visit(node.object),
            "key": node.key,
        }

    def visit_extern_import(self, node) -> dict:
        module_path = getattr(node, "module", None)
        if module_path is None:
            module_path = getattr(node, "module_path", None)
        return {"type": "ExternImport", "module": module_path}

    def visit_extern_namespace(self, node) -> dict:
        return {"type": "ExternNamespace", "name": node.name}

    def visit_extern_rule(self, node) -> dict:
        return {"type": "ExternRule", "name": node.name}

    def visit_extern_rule_reference(self, node) -> dict:
        rule_name = getattr(node, "name", None)
        if rule_name is None:
            rule_name = getattr(node, "rule_name", None)
        return {"type": "ExternRuleReference", "name": rule_name}

    def visit_hex_nibble(self, node) -> dict:
        return {"type": "HexNibble", "high": node.high, "value": node.value}

    def visit_in_rule_pragma(self, node) -> dict:
        return {"type": "InRulePragma", "directive": node.directive}

    def visit_module_reference(self, node) -> dict:
        return {"type": "ModuleReference", "module": node.module}

    def visit_pragma(self, node) -> dict:
        return {"type": "Pragma", "directive": node.directive}

    def visit_pragma_block(self, node) -> dict:
        return {"type": "PragmaBlock", "pragmas": [self.visit(p) for p in node.pragmas]}

    def visit_regex_literal(self, node) -> dict:
        return {
            "type": "RegexLiteral",
            "pattern": node.pattern,
            "modifiers": node.modifiers,
        }

    def visit_string_operator_expression(self, node) -> dict:
        return {
            "type": "StringOperatorExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }
