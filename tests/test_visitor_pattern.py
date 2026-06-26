"""Tests for visitor pattern functionality."""

from yaraast.ast.expressions import StringIdentifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser.parser import Parser
from yaraast.visitor.base import BaseVisitor


class TestVisitorPattern:
    """Test visitor pattern implementation."""

    def test_basic_visitor(self) -> None:
        """Test basic visitor traversal."""

        class CountingVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.rule_count = 0
                self.string_count = 0

            def visit_rule(self, node: Rule) -> None:
                self.rule_count += 1
                super().visit_rule(node)

            def visit_plain_string(self, node: PlainString) -> None:
                self.string_count += 1
                super().visit_plain_string(node)

        yara_code = """
        rule test1 {
            strings:
                $a = "hello"
                $b = "world"
            condition:
                $a
        }

        rule test2 {
            strings:
                $c = "test"
            condition:
                $c
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = CountingVisitor()
        visitor.visit(ast)

        assert visitor.rule_count == 2, "Should count 2 rules"
        assert visitor.string_count == 3, "Should count 3 strings"

    def test_visitor_returns_values(self) -> None:
        """Test visitor that returns values."""

        class NameCollectorVisitor(BaseVisitor[list[str]]):
            def __init__(self) -> None:
                self.names: list[str] = []

            def visit_rule(self, node: Rule) -> list[str]:
                self.names.append(node.name)
                super().visit_rule(node)
                return self.names

        yara_code = """
        rule rule_one {
            condition:
                true
        }

        rule rule_two {
            condition:
                false
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = NameCollectorVisitor()
        visitor.visit(ast)

        assert "rule_one" in visitor.names
        assert "rule_two" in visitor.names
        assert len(visitor.names) == 2

    def test_visitor_transformation(self) -> None:
        """Test visitor that transforms AST."""

        class RuleRenamerVisitor(BaseVisitor[None]):
            def __init__(self, suffix: str = "_renamed") -> None:
                self.suffix = suffix

            def visit_rule(self, node: Rule) -> None:
                # Transform rule name
                node.name = node.name + self.suffix
                super().visit_rule(node)

        yara_code = """
        rule original_name {
            condition:
                true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = RuleRenamerVisitor(suffix="_modified")
        visitor.visit(ast)

        assert ast.rules[0].name == "original_name_modified"

    def test_visitor_with_condition(self) -> None:
        """Test visitor that processes conditions."""

        class StringIdentifierCollector(BaseVisitor[None]):
            def __init__(self) -> None:
                self.string_ids: list[str] = []

            def visit_string_identifier(self, node: StringIdentifier) -> None:
                if hasattr(node, "name"):
                    self.string_ids.append(node.name)
                super().visit_string_identifier(node)

        yara_code = """
        rule test {
            strings:
                $str1 = "test"
                $str2 = "hello"
            condition:
                $str1 and $str2
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = StringIdentifierCollector()
        visitor.visit(ast)

        # Should find string references in condition
        assert len(visitor.string_ids) >= 2

    def test_visitor_inheritance(self) -> None:
        """Test that visitor methods can be inherited."""

        class CustomBaseVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[tuple[str, str]] = []

            def visit_rule(self, node: Rule) -> None:
                self.visited.append(("rule", node.name))
                super().visit_rule(node)

        class ExtendedVisitor(CustomBaseVisitor):
            def visit_plain_string(self, node: PlainString) -> None:
                self.visited.append(("string", node.identifier))
                super().visit_plain_string(node)

        yara_code = """
        rule test {
            strings:
                $a = "test"
            condition:
                $a
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = ExtendedVisitor()
        visitor.visit(ast)

        # Should have both rule and string visits
        rule_visits = [v for v in visitor.visited if v[0] == "rule"]
        string_visits = [v for v in visitor.visited if v[0] == "string"]

        assert len(rule_visits) == 1
        assert len(string_visits) == 1

    def test_visitor_early_exit(self) -> None:
        """Test visitor can exit early."""

        class EarlyExitVisitor(BaseVisitor[None]):
            def __init__(self, target_rule: str) -> None:
                self.target_rule = target_rule
                self.found = False
                self.rules_visited = 0

            def visit_rule(self, node: Rule) -> None:
                self.rules_visited += 1
                if node.name == self.target_rule:
                    self.found = True
                    # Don't visit children
                    return
                super().visit_rule(node)

        yara_code = """
        rule first {
            condition:
                true
        }

        rule second {
            condition:
                true
        }

        rule third {
            condition:
                true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = EarlyExitVisitor("second")
        visitor.visit(ast)

        assert visitor.found is True
        assert visitor.rules_visited >= 2  # Visited at least until "second"


class TestVisitorPatternAdvanced:
    """Advanced visitor pattern tests."""

    def test_visitor_with_meta_collection(self) -> None:
        """Test collecting metadata."""

        class MetaCollectorVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.meta_data: dict[str, dict[str, object]] = {}

            def visit_rule(self, node: Rule) -> None:
                if node.meta:
                    self.meta_data[node.name] = (
                        {getattr(m, "key", ""): getattr(m, "value", "") for m in node.meta}
                        if node.meta
                        else {}
                    )
                super().visit_rule(node)

        yara_code = """
        rule with_meta {
            meta:
                author = "test"
                version = 1
            condition:
                true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = MetaCollectorVisitor()
        visitor.visit(ast)

        assert "with_meta" in visitor.meta_data
        assert visitor.meta_data["with_meta"].get("author") == "test"

    def test_visitor_exception_handling(self) -> None:
        """Test visitor handles exceptions gracefully."""

        class FailingVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.errors: list[str] = []

            def visit_rule(self, node: Rule) -> None:
                try:
                    # Simulate an error
                    if node.name == "bad_rule":
                        raise ValueError("Bad rule!")
                    super().visit_rule(node)
                except ValueError as e:
                    self.errors.append(str(e))

        yara_code = """
        rule good_rule {
            condition:
                true
        }

        rule bad_rule {
            condition:
                false
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = FailingVisitor()
        visitor.visit(ast)

        assert len(visitor.errors) == 1
        assert "Bad rule!" in visitor.errors[0]
