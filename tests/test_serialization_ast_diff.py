"""Real tests for AST diffing (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.pragmas import CustomPragma, InRulePragma
from yaraast.ast.rules import Rule
from yaraast.parser import Parser
from yaraast.serialization.ast_diff import AstDiff, AstHasher, DiffType


def _parse_yara(code: str) -> YaraFile:
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


def test_ast_diff_detects_meta_scope_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="meta_scope",
                meta=[MetaEntry.from_key_value("secret", "token", "public")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="meta_scope",
                meta=[MetaEntry.from_key_value("secret", "token", "private")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.has_changes
    meta_diff = next(diff for diff in result.differences if diff.path == "/rules/meta_scope/meta")
    assert isinstance(meta_diff.old_value, dict)
    assert isinstance(meta_diff.new_value, dict)
    assert meta_diff.old_value["secret"]["scope"] == "public"
    assert meta_diff.new_value["secret"]["scope"] == "private"


def test_ast_diff_detects_extended_file_field_changes() -> None:
    old_ast = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="ext")],
        extern_rules=[ExternRule(name="RemoteRule")],
        pragmas=[CustomPragma(name="vendor", parameters={"level": "strict"})],
        namespaces=[ExternNamespace(name="corp", extern_rules=[ExternRule(name="Nested")])],
        rules=[Rule(name="stable", condition=BooleanLiteral(value=True))],
    )
    new_ast = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="renamed")],
        extern_rules=[ExternRule(name="OtherRule")],
        pragmas=[CustomPragma(name="vendor", parameters={"level": "relaxed"})],
        namespaces=[ExternNamespace(name="corp", extern_rules=[ExternRule(name="Changed")])],
        rules=[Rule(name="stable", condition=BooleanLiteral(value=True))],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/extern_imports/external.yar"].diff_type == DiffType.MODIFIED
    assert by_path["/extern_rules/RemoteRule"].diff_type == DiffType.REMOVED
    assert by_path["/extern_rules/OtherRule"].diff_type == DiffType.ADDED
    assert by_path["/pragmas/custom:vendor:"].diff_type == DiffType.MODIFIED
    assert by_path["/namespaces/corp"].diff_type == DiffType.MODIFIED
    assert result.has_changes
    assert result.statistics["total_changes"] == len(result.differences)


def test_ast_diff_detects_in_rule_pragma_changes() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(
                        pragma=CustomPragma("vendor", parameters={"level": "strict"}),
                        position="before_condition",
                    ),
                ],
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(
                        pragma=CustomPragma("vendor", parameters={"level": "relaxed"}),
                        position="before_condition",
                    ),
                ],
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    by_path = {diff.path: diff for diff in result.differences}
    assert by_path["/rules/stable/pragmas/before_condition:custom:vendor:"].diff_type == (
        DiffType.MODIFIED
    )
    assert result.has_changes


def test_ast_diff_treats_in_rule_pragma_reordering_as_unchanged() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(CustomPragma("vendor_b"), position="before_condition"),
                    InRulePragma(CustomPragma("vendor_a"), position="before_strings"),
                ],
            ),
        ],
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="stable",
                condition=BooleanLiteral(value=True),
                pragmas=[
                    InRulePragma(CustomPragma("vendor_a"), position="before_strings"),
                    InRulePragma(CustomPragma("vendor_b"), position="before_condition"),
                ],
            ),
        ],
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_extended_file_field_reordering_as_unchanged() -> None:
    cases = [
        (
            YaraFile(extern_imports=[ExternImport("b.yar"), ExternImport("a.yar")]),
            YaraFile(extern_imports=[ExternImport("a.yar"), ExternImport("b.yar")]),
        ),
        (
            YaraFile(extern_rules=[ExternRule("Beta"), ExternRule("Alpha")]),
            YaraFile(extern_rules=[ExternRule("Alpha"), ExternRule("Beta")]),
        ),
        (
            YaraFile(pragmas=[CustomPragma("vendor_b"), CustomPragma("vendor_a")]),
            YaraFile(pragmas=[CustomPragma("vendor_a"), CustomPragma("vendor_b")]),
        ),
        (
            YaraFile(namespaces=[ExternNamespace("beta"), ExternNamespace("alpha")]),
            YaraFile(namespaces=[ExternNamespace("alpha"), ExternNamespace("beta")]),
        ),
    ]

    for old_ast, new_ast in cases:
        result = AstDiff().compare(old_ast, new_ast)

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_treats_tag_reordering_as_unchanged() -> None:
    old_ast = _parse_yara(
        """
        rule tagged : beta alpha {
            condition:
                true
        }
        """,
    )
    new_ast = _parse_yara(
        """
        rule tagged : alpha beta {
            condition:
                true
        }
        """,
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_meta_reordering_as_unchanged() -> None:
    old_ast = _parse_yara(
        """
        rule meta_order {
            meta:
                b = 2
                a = 1
            condition:
                true
        }
        """,
    )
    new_ast = _parse_yara(
        """
        rule meta_order {
            meta:
                a = 1
                b = 2
            condition:
                true
        }
        """,
    )

    result = AstDiff().compare(old_ast, new_ast)

    assert result.old_ast_hash == result.new_ast_hash
    assert not result.has_changes
    assert result.differences == []


def test_ast_diff_treats_top_level_reordering_as_unchanged() -> None:
    cases = [
        (
            """
            import "pe"
            import "elf"
            rule stable {
                condition:
                    true
            }
            """,
            """
            import "elf"
            import "pe"
            rule stable {
                condition:
                    true
            }
            """,
        ),
        (
            """
            include "b.yar"
            include "a.yar"
            rule stable {
                condition:
                    true
            }
            """,
            """
            include "a.yar"
            include "b.yar"
            rule stable {
                condition:
                    true
            }
            """,
        ),
        (
            """
            rule beta {
                condition:
                    true
            }
            rule alpha {
                condition:
                    false
            }
            """,
            """
            rule alpha {
                condition:
                    false
            }
            rule beta {
                condition:
                    true
            }
            """,
        ),
    ]

    for old_code, new_code in cases:
        result = AstDiff().compare(_parse_yara(old_code), _parse_yara(new_code))

        assert result.old_ast_hash == result.new_ast_hash
        assert not result.has_changes
        assert result.differences == []


def test_ast_diff_detects_imports_rules_and_modifications(tmp_path: Path) -> None:
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
