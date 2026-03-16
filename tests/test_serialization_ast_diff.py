"""Real tests for AST diffing (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser import Parser
from yaraast.serialization.ast_diff import AstDiff, AstHasher, DiffType


def _parse_yara(code: str):
    parser = Parser()
    return parser.parse(dedent(code))


def test_ast_hasher_stable_hash_and_node_hash() -> None:
    code = """
    rule alpha {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    hasher = AstHasher()

    hash1 = hasher.hash_ast(ast)
    hash2 = hasher.hash_ast(ast)

    assert hash1 == hash2
    assert len(hash1) == 16

    rule = ast.rules[0]
    node_hash = hasher.hash_node(rule, "/rules/alpha")
    assert len(node_hash) == 12
    assert hasher._node_hashes["/rules/alpha"] == node_hash


def test_ast_diff_detects_imports_rules_and_modifications(tmp_path) -> None:
    old_code = """
    import "pe"
    include "base.yar"

    rule alpha : t1 {
        meta:
            author = "a"
        strings:
            $a = "abc"
        condition:
            $a
    }

    rule beta {
        condition:
            true
    }
    """

    new_code = """
    import "pe"
    include "base.yar"

    rule alpha : t2 {
        meta:
            author = "b"
        strings:
            $a = "abcd"
            $b = /xyz/i
        condition:
            any of them
    }

    rule gamma {
        condition:
            false
    }
    """

    old_ast = _parse_yara(old_code)
    new_ast = _parse_yara(new_code)

    # Simulate import alias change without relying on parser support.
    old_ast.imports[0].alias = None
    new_ast.imports[0].alias = "pe_alias"

    differ = AstDiff()
    result = differ.compare(old_ast, new_ast)

    assert result.has_changes is True
    assert result.statistics["old_rules_count"] == 2
    assert result.statistics["new_rules_count"] == 2

    summary = result.change_summary
    assert summary[DiffType.MODIFIED.value] >= 1
    assert summary[DiffType.ADDED.value] >= 1
    assert summary[DiffType.REMOVED.value] >= 1

    import_alias_changes = [
        diff
        for diff in result.differences
        if diff.path == "/imports/pe/alias" and diff.diff_type == DiffType.MODIFIED
    ]
    assert import_alias_changes

    added_rules = [diff for diff in result.differences if diff.diff_type == DiffType.ADDED]
    removed_rules = [diff for diff in result.differences if diff.diff_type == DiffType.REMOVED]
    assert any(diff.path == "/rules/gamma" for diff in added_rules)
    assert any(diff.path == "/rules/beta" for diff in removed_rules)

    patch_path = tmp_path / "diff.json"
    patch = differ.create_patch(result, output_path=str(patch_path))
    assert patch_path.exists()
    assert patch["patch_format"] == "yaraast-diff-v1"
    assert patch["changes"]["has_changes"] is True
