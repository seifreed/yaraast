"""Additional tests for comment-preserving lexer and resolution dependency graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Identifier
from yaraast.ast.rules import Import, Include, Rule
from yaraast.errors import ValidationError
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import TokenType
from yaraast.parser import Parser
from yaraast.resolution.dependency_graph import DependencyGraph, DependencyNode


def test_comment_preserving_lexer_helpers_and_preserve_toggle() -> None:
    lexer = CommentPreservingLexer("// first\nrule a { /* block */ condition: true }")
    tokens = lexer.tokenize()

    original_comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(original_comments) == 2
    assert lexer.get_comments() == original_comments
    comments_snapshot = lexer.get_comments()

    line_comment = CommentPreservingLexer("// line")
    token = line_comment._read_line_comment()
    assert token is not None
    assert token.type == TokenType.COMMENT
    assert token.value == "// line"

    block_comment = CommentPreservingLexer("/* block */")
    token = block_comment._read_block_comment()
    assert token is not None
    assert token.type == TokenType.COMMENT
    assert token.value == "/* block */"

    unterminated = CommentPreservingLexer("/* block")
    token = unterminated._read_block_comment()
    assert token is not None
    assert token.value == "/* block"

    multiline = CommentPreservingLexer("/* one\nline */rule c { condition: true }")
    tokens = multiline.tokenize()
    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert comments[0].line == 1
    assert comments[0].column == 1

    no_preserve = CommentPreservingLexer("// c1\n/* c2 */rule b { condition: true }")
    no_preserve.set_preserve_comments(False)
    tokens = no_preserve.tokenize()
    assert all(t.type != TokenType.COMMENT for t in tokens)
    assert no_preserve.get_comments() == []

    no_preserve.set_preserve_comments(True)
    assert no_preserve.preserve_comments is True

    lexer.clear_comments()
    assert lexer.get_comments() == []
    assert comments_snapshot == original_comments


def test_comment_preserving_lexer_ignores_comment_markers_inside_strings() -> None:
    lexer = CommentPreservingLexer(
        'rule urls { strings: $url = "http://example.test/*literal*/" condition: $url }'
    )

    tokens = lexer.tokenize()

    assert lexer.get_comments() == []
    assert [token.value for token in tokens if token.type == TokenType.STRING] == [
        "http://example.test/*literal*/"
    ]


def test_dependency_graph_transitive_queries_cycles_and_export() -> None:
    graph = DependencyGraph()
    file_path = Path("file.yar")
    ast = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="shared.yar")],
        rules=[Rule(name='rule:"x"', modifiers=["private"], tags=[])],
    )
    graph.add_file(file_path, ast)

    assert str(file_path) in graph.nodes
    assert graph.get_rule_dependencies('rule:"x"') == set()
    assert graph.get_rule_dependencies("missing") == set()

    graph.nodes["shared.yar"] = DependencyNode("shared.yar", "file")
    graph.nodes["shared.yar"].dependents.add(str(file_path))
    graph.nodes['rule:rule:"x"'].dependencies.add("shared.yar")
    graph.nodes["shared.yar"].dependents.add('rule:rule:"x"')

    deps = graph.get_file_dependencies(str(file_path))
    assert "pe" in deps
    assert "shared.yar" in deps
    assert 'rule:rule:"x"' in deps

    dependents = graph.get_file_dependents("shared.yar")
    assert str(file_path) in dependents or 'rule:rule:"x"' in dependents

    graph.nodes["isolated"] = DependencyNode("isolated", "mystery")
    assert "isolated" in graph.get_isolated_nodes()

    cycle_graph = DependencyGraph()
    cycle_graph.nodes["A"] = DependencyNode("A", "file", dependencies={"B"})
    cycle_graph.nodes["B"] = DependencyNode("B", "file", dependencies={"A"})
    cycles = cycle_graph.find_cycles()
    assert cycles

    stats = graph.get_statistics()
    assert stats["file_count"] >= 1
    assert stats["rule_count"] == 1
    assert stats["module_count"] == 1

    dot = graph.export_dot()
    assert 'label="rule:\\"x\\""' in dot
    assert "shape=folder" in dot
    assert "shape=component" in dot
    assert '"isolated" [label="isolated",' in dot

    resolved = graph.get_file_dependencies(".")
    assert isinstance(resolved, set)
    assert graph.get_file_dependents("missing") == set()


def test_dependency_graph_traverses_falsy_present_nodes() -> None:
    class FalsyDependencyNode(DependencyNode):
        def __bool__(self) -> bool:
            return False

    graph = DependencyGraph()
    graph.nodes["A"] = FalsyDependencyNode("A", "rule", dependencies={"B"})
    graph.nodes["B"] = DependencyNode("B", "rule", dependencies={"C"})
    graph.nodes["C"] = DependencyNode("C", "rule")

    assert graph._get_transitive_dependencies("A") == {"B", "C"}

    dependent_graph = DependencyGraph()
    dependent_graph.nodes["A"] = FalsyDependencyNode("A", "rule", dependents={"B"})
    dependent_graph.nodes["B"] = DependencyNode("B", "rule", dependents={"C"})
    dependent_graph.nodes["C"] = DependencyNode("C", "rule")

    assert dependent_graph._get_transitive_dependents("A") == {"B", "C"}


def test_rule_dependency_getter_does_not_expose_internal_set() -> None:
    graph = DependencyGraph()
    graph.nodes["rule:test"] = DependencyNode("test", "rule", dependencies={"dep"})

    dependencies = graph.get_rule_dependencies("test")
    dependencies.add("mutated")

    assert graph.nodes["rule:test"].dependencies == {"dep"}


def test_dependency_graph_analyzes_rule_module_and_duplicate_dependencies() -> None:
    ast = Parser().parse("""
import "pe"

rule dup_first {
    condition:
        true
}

rule dup_second {
    condition:
        helper
}

rule helper {
    condition:
        true
}

rule caller {
    condition:
        dup and pe.number_of_sections > 0
}
""")
    ast.rules[0].name = "dup"
    ast.rules[1].name = "dup"
    graph = DependencyGraph()

    graph.add_file(Path("rules.yar"), ast)

    assert {"rule:dup#1", "rule:dup#2", "rule:helper", "rule:caller"}.issubset(graph.nodes)
    assert graph.file_rules["rules.yar"] == {"dup#1", "dup#2", "helper", "caller"}
    assert graph.rule_files["dup#1"] == "rules.yar"
    assert graph.get_rule_dependencies("dup#2") == {"rule:helper"}
    assert graph.get_rule_dependencies("caller") == {"rule:dup#1", "rule:dup#2", "pe"}
    assert "rule:caller" in graph.nodes["pe"].dependents
    assert "rule:caller" in graph.nodes["rule:dup#1"].dependents


def test_dependency_graph_resolves_import_module_dependencies() -> None:
    ast = Parser().parse("""
import "pe"

rule caller {
    condition:
        pe.number_of_sections > 0
}
""")
    graph = DependencyGraph()

    graph.add_file(Path("aliased.yar"), ast)

    assert graph.get_rule_dependencies("caller") == {"pe"}
    assert "rule:caller" in graph.nodes["pe"].dependents


def test_dependency_graph_analyzes_falsy_present_rule_condition() -> None:
    class FalsyIdentifier(Identifier):
        def __bool__(self) -> bool:
            return False

    ast = YaraFile(
        rules=[
            Rule(name="helper", condition=Identifier("true")),
            Rule(name="caller", condition=FalsyIdentifier("helper")),
        ]
    )
    graph = DependencyGraph()

    graph.add_file(Path("rules.yar"), ast)

    assert graph.get_rule_dependencies("caller") == {"rule:helper"}
    assert "rule:caller" in graph.nodes["rule:helper"].dependents


def test_transitive_graph_queries_do_not_return_start_node_in_cycles() -> None:
    graph = DependencyGraph()
    graph.nodes["A"] = DependencyNode("A", "file", dependencies={"B"}, dependents={"B"})
    graph.nodes["B"] = DependencyNode("B", "file", dependencies={"A"}, dependents={"A"})

    assert graph.get_file_dependencies("A") == {"B"}
    assert graph.get_file_dependents("A") == {"B"}


def test_dependency_graph_find_cycles_returns_all_disjoint_cycles() -> None:
    graph = DependencyGraph()
    graph.nodes["A"] = DependencyNode("A", "file", dependencies={"B"})
    graph.nodes["B"] = DependencyNode("B", "file", dependencies={"A"})
    graph.nodes["C"] = DependencyNode("C", "file", dependencies={"D"})
    graph.nodes["D"] = DependencyNode("D", "file", dependencies={"C"})

    assert graph.find_cycles() == [["A", "B", "A"], ["C", "D", "C"]]


def test_dependency_graph_readding_file_removes_stale_nodes_and_edges() -> None:
    graph = DependencyGraph()
    file_path = Path("rules.yar")

    graph.add_file(
        file_path,
        YaraFile(
            imports=[Import(module="pe")],
            includes=[Include(path="old.yar")],
            rules=[Rule(name="old_rule")],
        ),
    )
    graph.add_file(
        file_path,
        YaraFile(
            includes=[Include(path="new.yar")],
            rules=[Rule(name="new_rule")],
        ),
    )

    dependencies = graph.get_file_dependencies(str(file_path))
    assert "old.yar" not in dependencies
    assert "pe" not in dependencies
    assert "rule:old_rule" not in graph.nodes
    assert graph.get_statistics()["rule_count"] == 1
    assert {"new.yar", "rule:new_rule"}.issubset(dependencies)


def test_dependency_graph_add_file_rejects_invalid_inputs_without_partial_update() -> None:
    graph = DependencyGraph()
    graph.add_file(Path("existing.yar"), YaraFile(rules=[Rule(name="existing")]))

    original_nodes = set(graph.nodes)
    original_file_rules = {key: set(value) for key, value in graph.file_rules.items()}
    original_rule_files = dict(graph.rule_files)

    invalid_cases: list[tuple[tuple[Any, ...], str]] = [
        ((object(), YaraFile()), "DependencyGraph file_path must be a path"),
        (("bad_ast.yar", object()), "DependencyGraph ast must be a YaraFile"),
        (
            ("bad_import.yar", YaraFile(imports=[Import(module=cast(Any, object()))])),
            "DependencyGraph import module must be a string",
        ),
        (
            ("bad_include.yar", YaraFile(includes=[Include(path=cast(Any, object()))])),
            "DependencyGraph include path must be a string or path",
        ),
        (
            ("bad_rule.yar", YaraFile(rules=[Rule(name=cast(Any, object()))])),
            "DependencyGraph rule name must be a string",
        ),
        (
            ("bad_resolution.yar", YaraFile(includes=[Include(path="shared.yar")]), "not-map"),
            "DependencyGraph include resolutions must be a mapping",
        ),
    ]

    for args, message in invalid_cases:
        with pytest.raises(ValidationError, match=message):
            graph.add_file(*args)

    assert set(graph.nodes) == original_nodes
    assert graph.file_rules == original_file_rules
    assert graph.rule_files == original_rule_files


def test_resolution_dependency_graph_public_outputs_are_stably_sorted() -> None:
    graph = DependencyGraph()
    graph.nodes["z_rule"] = DependencyNode("z_rule", "rule", dependencies={"z_dep", "a_dep"})
    graph.nodes["a_rule"] = DependencyNode("a_rule", "rule")

    assert graph.export_dot().splitlines() == [
        "digraph YaraDependencies {",
        "  rankdir=LR;",
        "  node [shape=box];",
        '  "a_rule" [label="a_rule",shape=box,style=filled,fillcolor=lightgreen];',
        '  "z_rule" [label="z_rule",shape=box,style=filled,fillcolor=lightgreen];',
        '  "z_rule" -> "a_dep";',
        '  "z_rule" -> "z_dep";',
        "}",
    ]

    cycle_graph = DependencyGraph()
    cycle_graph.nodes["b_rule"] = DependencyNode("b_rule", "file", dependencies={"c_rule"})
    cycle_graph.nodes["c_rule"] = DependencyNode("c_rule", "file", dependencies={"a_rule"})
    cycle_graph.nodes["a_rule"] = DependencyNode("a_rule", "file", dependencies={"b_rule"})

    assert cycle_graph.find_cycles() == [["a_rule", "b_rule", "c_rule", "a_rule"]]
