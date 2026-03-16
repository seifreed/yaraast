"""Additional tests for comment-preserving lexer and resolution dependency graph."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include, Rule
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import TokenType
from yaraast.resolution.dependency_graph import DependencyGraph, DependencyNode


def test_comment_preserving_lexer_helpers_and_preserve_toggle() -> None:
    lexer = CommentPreservingLexer("// first\nrule a { /* block */ condition: true }")
    tokens = lexer.tokenize()

    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comments) == 2
    assert lexer.get_comments() == comments

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
