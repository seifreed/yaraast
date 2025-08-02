"""Example: Custom visitor implementations."""

from typing import Dict, List, Set

from yaraast import ASTVisitor, Parser
from yaraast.ast import *


# Visitor to collect statistics about YARA rules
class RuleStatisticsVisitor(ASTVisitor[None]):
    def __init__(self):
        self.stats = {
            "total_rules": 0,
            "private_rules": 0,
            "global_rules": 0,
            "total_strings": 0,
            "string_types": {"plain": 0, "hex": 0, "regex": 0},
            "meta_keys": set(),
            "imports": set(),
            "string_modifiers": {"nocase": 0, "wide": 0, "ascii": 0, "fullword": 0},
            "conditions": {"simple": 0, "complex": 0}
        }

    def visit_yara_file(self, node: YaraFile) -> None:
        for imp in node.imports:
            self.visit(imp)
        for rule in node.rules:
            self.visit(rule)

    def visit_import(self, node: Import) -> None:
        self.stats["imports"].add(node.module)

    def visit_rule(self, node: Rule) -> None:
        self.stats["total_rules"] += 1

        if "private" in node.modifiers:
            self.stats["private_rules"] += 1
        if "global" in node.modifiers:
            self.stats["global_rules"] += 1

        # Collect meta keys
        for key in node.meta:
            self.stats["meta_keys"].add(key)

        # Visit strings
        for string in node.strings:
            self.visit(string)

        # Analyze condition complexity
        if node.condition:
            if self._is_simple_condition(node.condition):
                self.stats["conditions"]["simple"] += 1
            else:
                self.stats["conditions"]["complex"] += 1

    def visit_plain_string(self, node: PlainString) -> None:
        self.stats["total_strings"] += 1
        self.stats["string_types"]["plain"] += 1
        self._count_modifiers(node.modifiers)

    def visit_hex_string(self, node: HexString) -> None:
        self.stats["total_strings"] += 1
        self.stats["string_types"]["hex"] += 1
        self._count_modifiers(node.modifiers)

    def visit_regex_string(self, node: RegexString) -> None:
        self.stats["total_strings"] += 1
        self.stats["string_types"]["regex"] += 1
        self._count_modifiers(node.modifiers)

    def _count_modifiers(self, modifiers: List[StringModifier]) -> None:
        for mod in modifiers:
            if mod.name in self.stats["string_modifiers"]:
                self.stats["string_modifiers"][mod.name] += 1

    def _is_simple_condition(self, condition: Expression) -> bool:
        # Simple conditions are single identifiers or simple binary expressions
        if isinstance(condition, (StringIdentifier, BooleanLiteral, Identifier)):
            return True
        if isinstance(condition, BinaryExpression):
            return isinstance(condition.left, StringIdentifier) and \
                   isinstance(condition.right, StringIdentifier)
        return False

    # Implement remaining visit methods with pass
    def visit_include(self, node): pass
    def visit_tag(self, node): pass
    def visit_string_definition(self, node): pass
    def visit_string_modifier(self, node): pass
    def visit_hex_token(self, node): pass
    def visit_hex_byte(self, node): pass
    def visit_hex_wildcard(self, node): pass
    def visit_hex_jump(self, node): pass
    def visit_hex_alternative(self, node): pass
    def visit_expression(self, node): pass
    def visit_identifier(self, node): pass
    def visit_string_identifier(self, node): pass
    def visit_string_count(self, node): pass
    def visit_string_offset(self, node): pass
    def visit_string_length(self, node): pass
    def visit_integer_literal(self, node): pass
    def visit_double_literal(self, node): pass
    def visit_string_literal(self, node): pass
    def visit_boolean_literal(self, node): pass
    def visit_binary_expression(self, node): pass
    def visit_unary_expression(self, node): pass
    def visit_parentheses_expression(self, node): pass
    def visit_set_expression(self, node): pass
    def visit_range_expression(self, node): pass
    def visit_function_call(self, node): pass
    def visit_array_access(self, node): pass
    def visit_member_access(self, node): pass
    def visit_condition(self, node): pass
    def visit_for_expression(self, node): pass
    def visit_for_of_expression(self, node): pass
    def visit_at_expression(self, node): pass
    def visit_in_expression(self, node): pass
    def visit_of_expression(self, node): pass
    def visit_meta(self, node): pass


# Visitor to extract all string values
class StringExtractorVisitor(ASTVisitor[List[str]]):
    def __init__(self):
        self.strings = []

    def visit_yara_file(self, node: YaraFile) -> List[str]:
        for rule in node.rules:
            self.visit(rule)
        return self.strings

    def visit_rule(self, node: Rule) -> List[str]:
        for string in node.strings:
            self.visit(string)
        return self.strings

    def visit_plain_string(self, node: PlainString) -> List[str]:
        self.strings.append(f"{node.identifier} = \"{node.value}\"")
        return self.strings

    def visit_hex_string(self, node: HexString) -> List[str]:
        hex_str = " ".join(f"{b.value:02X}" if isinstance(b, HexByte) else "??"
                          for b in node.tokens if isinstance(b, (HexByte, HexWildcard)))
        self.strings.append(f"{node.identifier} = {{ {hex_str} }}")
        return self.strings

    def visit_regex_string(self, node: RegexString) -> List[str]:
        self.strings.append(f"{node.identifier} = /{node.regex}/")
        return self.strings

    # Implement remaining methods returning empty list
    def visit_import(self, node): return []
    def visit_include(self, node): return []
    def visit_tag(self, node): return []
    def visit_string_definition(self, node): return []
    def visit_string_modifier(self, node): return []
    def visit_hex_token(self, node): return []
    def visit_hex_byte(self, node): return []
    def visit_hex_wildcard(self, node): return []
    def visit_hex_jump(self, node): return []
    def visit_hex_alternative(self, node): return []
    def visit_expression(self, node): return []
    def visit_identifier(self, node): return []
    def visit_string_identifier(self, node): return []
    def visit_string_count(self, node): return []
    def visit_string_offset(self, node): return []
    def visit_string_length(self, node): return []
    def visit_integer_literal(self, node): return []
    def visit_double_literal(self, node): return []
    def visit_string_literal(self, node): return []
    def visit_boolean_literal(self, node): return []
    def visit_binary_expression(self, node): return []
    def visit_unary_expression(self, node): return []
    def visit_parentheses_expression(self, node): return []
    def visit_set_expression(self, node): return []
    def visit_range_expression(self, node): return []
    def visit_function_call(self, node): return []
    def visit_array_access(self, node): return []
    def visit_member_access(self, node): return []
    def visit_condition(self, node): return []
    def visit_for_expression(self, node): return []
    def visit_for_of_expression(self, node): return []
    def visit_at_expression(self, node): return []
    def visit_in_expression(self, node): return []
    def visit_of_expression(self, node): return []
    def visit_meta(self, node): return []


# Example usage
if __name__ == "__main__":
    yara_rules = '''
    import "pe"
    import "math"

    private rule rule1 {
        meta:
            author = "Analyst"
            version = 1
        strings:
            $a = "test" nocase wide
            $b = { 48 65 6C 6C 6F }
            $c = /pattern[0-9]+/i
        condition:
            $a and $b
    }

    global rule rule2 {
        meta:
            author = "Analyst"
            severity = "high"
        strings:
            $x = "malware" fullword
            $y = "virus" ascii
        condition:
            any of them
    }
    '''

    # Parse rules
    parser = Parser(yara_rules)
    ast = parser.parse()

    # Collect statistics
    print("Rule Statistics:")
    print("=" * 50)
    stats_visitor = RuleStatisticsVisitor()
    stats_visitor.visit(ast)

    for key, value in stats_visitor.stats.items():
        if isinstance(value, set):
            print(f"{key}: {', '.join(sorted(value))}")
        elif isinstance(value, dict):
            print(f"{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"{key}: {value}")

    # Extract strings
    print("\n\nExtracted Strings:")
    print("=" * 50)
    extractor = StringExtractorVisitor()
    strings = extractor.visit(ast)
    for s in strings:
        print(f"  {s}")
