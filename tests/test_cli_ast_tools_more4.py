"""More coverage for AST CLI tools."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.tree import Tree

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.cli import ast_tools as at


def test_ast_formatter_more_styles_and_check_paths(tmp_path) -> None:
    path = tmp_path / "rule.yar"
    path.write_text(
        'rule x {\n    strings:\n        $a = "abc"\n    condition:\n        $a\n}\n',
        encoding="utf-8",
    )

    formatter = at.ASTFormatter()

    ok_pretty, pretty = formatter.format_file(path, None, "pretty")
    ok_verbose, verbose = formatter.format_file(path, None, "verbose")
    ok_default, default = formatter.format_file(path, None, "default")
    ok_weird, weird = formatter.format_file(path, None, "weird")

    assert ok_pretty is True and "rule x" in pretty
    assert ok_verbose is True and "rule x" in verbose
    assert ok_default is True and "rule x" in default
    assert ok_weird is True and "rule x" in weird

    needs_format, issues = formatter.check_format(path)
    assert needs_format is True
    assert issues

    formatted = tmp_path / "formatted.yar"
    formatted.write_text(default, encoding="utf-8")
    clean, clean_issues = formatter.check_format(formatted)
    assert clean is False
    assert clean_issues == []


def test_print_ast_default_console_and_visualize_dict() -> None:
    ast = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="common.yar")],
        rules=[Rule(name="demo", condition=BooleanLiteral(value=True))],
    )
    at.print_ast(ast)
    dict_out = at.visualize_ast(ast, "dict")
    assert '"imports"' in dict_out
    assert "\n" not in dict_out


def test_tree_helpers_cover_empty_and_non_dict_meta_paths() -> None:
    root = Tree("root")

    at._add_imports_to_tree(root, [])
    at._add_includes_to_tree(root, [])
    at._add_rules_to_tree(root, [])

    rule = Rule(
        name="r1",
        modifiers=["private"],
        tags=[Tag(name="t1"), "t2"],  # type: ignore[list-item]
        meta=[MetaEntry.from_key_value("author", "me"), object()],  # type: ignore[list-item]
        strings=[PlainString(identifier="$a", value="abc")],
        condition=BooleanLiteral(value=True),
    )

    rules_branch = root.add("rules")
    rule_branch = at._create_rule_branch(rules_branch, rule)
    at._add_tags_to_rule(rule_branch, rule)
    at._add_meta_to_rule(rule_branch, rule)
    at._add_strings_to_rule(rule_branch, rule)
    at._add_condition_to_rule(rule_branch, rule)

    txt_console = Console(file=StringIO(), record=True, force_terminal=False)
    txt_console.print(root)
    txt = txt_console.export_text()
    assert "private rule r1" in txt
    assert "t1" in txt and "t2" in txt
    assert "author = me" in txt
    assert "$a (PlainString)" in txt
    assert "BooleanLiteral" in txt

    empty_rule = Rule(name="empty")
    empty_branch = rules_branch.add("empty")
    at._add_tags_to_rule(empty_branch, empty_rule)
    at._add_meta_to_rule(empty_branch, empty_rule)
    at._add_strings_to_rule(empty_branch, empty_rule)
    at._add_condition_to_rule(empty_branch, empty_rule)


def test_add_meta_to_rule_with_dict_meta(tmp_path) -> None:
    root = Tree("root")
    branch = root.add("rule")
    rule = Rule(name="dict_meta", meta={"author": "me", "version": 1})
    at._add_meta_to_rule(branch, rule)

    console = Console(file=StringIO(), record=True, force_terminal=False)
    console.print(root)
    txt = console.export_text()
    assert "author = me" in txt
    assert "version = 1" in txt
