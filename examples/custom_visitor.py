"""Example: Custom visitor implementations."""

# No specific typing imports needed with Python 3.9+ built-in generics

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    StringIdentifier,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import (
    HexByte,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.parser import Parser
from yaraast.visitor import ASTVisitor


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
            "conditions": {"simple": 0, "complex": 0},
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

        if node.is_private:
            self.stats["private_rules"] += 1
        if node.is_global:
            self.stats["global_rules"] += 1

        # Collect meta keys
        for entry in node.meta:
            self.stats["meta_keys"].add(entry.key)

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

    def _count_modifiers(self, modifiers: list[StringModifier | str]) -> None:
        for mod in modifiers:
            name = mod.name if isinstance(mod, StringModifier) else str(mod)
            if name in self.stats["string_modifiers"]:
                self.stats["string_modifiers"][name] += 1

    def _is_simple_condition(self, condition: Expression) -> bool:
        # Simple conditions are single identifiers or simple binary expressions
        if isinstance(condition, StringIdentifier | BooleanLiteral | Identifier):
            return True
        if isinstance(condition, BinaryExpression):
            return isinstance(condition.left, StringIdentifier) and isinstance(
                condition.right, StringIdentifier
            )
        return False


# Visitor to extract all string values
class StringExtractorVisitor(ASTVisitor[list[str]]):
    def __init__(self):
        self.strings = []

    def visit_yara_file(self, node: YaraFile) -> list[str]:
        for rule in node.rules:
            self.visit(rule)
        return self.strings

    def visit_rule(self, node: Rule) -> list[str]:
        for string in node.strings:
            self.visit(string)
        return self.strings

    def visit_plain_string(self, node: PlainString) -> list[str]:
        self.strings.append(f'{node.identifier} = "{node.value}"')
        return self.strings

    def visit_hex_string(self, node: HexString) -> list[str]:
        hex_str = " ".join(
            f"{b.value:02X}" if isinstance(b, HexByte) else "??"
            for b in node.tokens
            if isinstance(b, HexByte | HexWildcard)
        )
        self.strings.append(f"{node.identifier} = {{ {hex_str} }}")
        return self.strings

    def visit_regex_string(self, node: RegexString) -> list[str]:
        self.strings.append(f"{node.identifier} = /{node.regex}/")
        return self.strings


# Example usage
if __name__ == "__main__":
    yara_rules = """
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
    """

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
