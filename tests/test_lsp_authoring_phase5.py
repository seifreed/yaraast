from __future__ import annotations

from lsprotocol.types import CodeActionKind, Diagnostic, Position, Range

from yaraast.lsp.authoring import AuthoringActions
from yaraast.lsp.code_actions import CodeActionsProvider


def _range(line: int, start: int, end: int) -> Range:
    return Range(start=Position(line=line, character=start), end=Position(line=line, character=end))


def test_create_missing_string_action_adds_strings_section_when_missing() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    condition:
        $missing
}
""".lstrip()
    diag = Diagnostic(range=_range(2, 8, 16), message="undefined variable $missing")

    actions = provider.get_code_actions(text, _range(2, 8, 16), [diag], "file://test.yar")
    titles = {action.title for action in actions}
    assert "Add string definition for $missing" in titles

    action = next(
        action for action in actions if action.title == "Add string definition for $missing"
    )
    edit = action.edit.changes["file://test.yar"][0]
    assert "strings:" in edit.new_text
    assert '$missing = ""' in edit.new_text


def test_normalize_string_modifiers_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "abc" wide nocase wide ascii
    condition:
        $a
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(2, 8, 36), [], "file://test.yar")
    action = next(action for action in actions if action.title == "Normalize string modifiers")
    assert action.kind == CodeActionKind.RefactorRewrite
    edit = action.edit.changes["file://test.yar"][0]
    assert edit.new_text.strip().endswith('"abc" ascii wide nocase')


def test_convert_plain_string_to_hex_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "ABC"
    condition:
        $a
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(2, 8, 18), [], "file://test.yar")
    action = next(action for action in actions if action.title == "Convert string to hex")
    assert action.kind == CodeActionKind.RefactorRewrite
    edit = action.edit.changes["file://test.yar"][0]
    assert edit.new_text.strip().endswith("{ 41 42 43 }")


def test_convert_to_hex_not_offered_for_string_with_modifiers() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "ABC" wide
    condition:
        $a
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(2, 8, 23), [], "file://test.yar")
    titles = {action.title for action in actions}
    assert "Convert string to hex" not in titles


def test_simplify_rule_condition_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "x"
    condition:
        true and $a
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(4, 8, 19), [], "file://test.yar")
    action = next(action for action in actions if action.title == "Simplify rule condition")
    assert action.kind == CodeActionKind.RefactorRewrite
    edit = action.edit.changes["file://test.yar"][0]
    assert "true and" not in edit.new_text
    assert "$a" in edit.new_text


def test_roundtrip_rewrite_rule_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = 'rule demo{ strings: $a = "x" condition: $a }'

    actions = provider.get_code_actions(text, _range(0, 5, 20), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Normalize rule via round-trip")
    )
    assert action.kind == CodeActionKind.RefactorRewrite
    edit = action.edit.changes["file://test.yar"][0]
    assert "rule demo" in edit.new_text
    assert "strings:" in edit.new_text
    assert "condition:" in edit.new_text
    assert "Round-trip rewrite validated by AST diff" in action.data["preview"]


def test_deduplicate_identical_strings_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "abc"
        $b = "abc"
    condition:
        $a or $b
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(4, 8, 17), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Deduplicate identical strings")
    )
    assert "(1 merged" in action.title
    assert "$b->$a" in action.title
    edit = action.edit.changes["file://test.yar"][0]
    assert '$b = "abc"' not in edit.new_text
    assert "$a or $a" in edit.new_text


def test_sort_strings_by_identifier_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $z = "z"
        $a = "a"
    condition:
        $z or $a
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(2, 8, 18), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Sort strings by identifier")
    )
    assert "(2 entries" in action.title
    assert "$z->$a" in action.title
    edit = action.edit.changes["file://test.yar"][0]
    assert edit.new_text.index('$a = "a"') < edit.new_text.index('$z = "z"')


def test_sort_meta_by_key_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    meta:
        z = "z"
        a = "a"
    condition:
        true
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(2, 8, 15), [], "file://test.yar")
    action = next(action for action in actions if action.title.startswith("Sort meta by key"))
    assert "(2 entries" in action.title
    assert "z->a" in action.title
    edit = action.edit.changes["file://test.yar"][0]
    assert edit.new_text.index('a = "a"') < edit.new_text.index('z = "z"')


def test_sort_tags_alphabetically_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo : ztag atag {
    condition:
        true
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(0, 12, 22), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Sort tags alphabetically")
    )
    assert "(2 tags" in action.title
    assert "ztag->atag" in action.title
    edit = action.edit.changes["file://test.yar"][0]
    assert "rule demo : atag ztag" in edit.new_text


def test_canonicalize_rule_structure_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo : ztag atag {
    condition:
        $z or $a
    meta:
        z = "2"
        a = "1"
    strings:
        $z = "z"
        $a = "a"
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(1, 0, 20), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Canonicalize rule structure")
    )
    edit = action.edit.changes["file://test.yar"][0]
    assert edit.new_text.index("meta:") < edit.new_text.index("strings:")
    assert edit.new_text.index("strings:") < edit.new_text.index("condition:")
    assert edit.new_text.index('a = "1"') < edit.new_text.index('z = "2"')
    assert edit.new_text.index('$a = "a"') < edit.new_text.index('$z = "z"')
    assert "Canonical section/meta/string order" in action.data["preview"]


def test_pretty_print_rule_with_ast_formatter_action() -> None:
    provider = CodeActionsProvider()
    text = 'rule demo{ strings: $a = "x" condition: $a }'

    actions = provider.get_code_actions(text, _range(0, 0, 10), [], "file://test.yar")
    action = next(
        action
        for action in actions
        if action.title.startswith("Pretty-print rule with AST formatter")
    )
    edit = action.edit.changes["file://test.yar"][0]
    assert "rule demo" in edit.new_text
    assert "strings:" in edit.new_text
    assert "condition:" in edit.new_text
    assert "(safe rewrite)" in action.title or "(style-only)" in action.title
    assert "Pretty printer rewrite validated by AST diff" in action.data["preview"]


def test_expand_of_them_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "a"
        $b = "b"
    condition:
        any of them
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(5, 8, 19), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Expand 'of them' to explicit set")
    )
    assert "(2 strings" in action.title
    assert "$a..." in action.title
    edit = action.edit.changes["file://test.yar"][0]
    assert "any of ($a, $b)" in edit.new_text


def test_compress_of_them_refactor_action() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "a"
        $b = "b"
    condition:
        all of ($a, $b)
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(5, 8, 24), [], "file://test.yar")
    action = next(
        action
        for action in actions
        if action.title.startswith("Compress explicit set to 'of them'")
    )
    assert "(2 strings" in action.title
    assert "$a..." in action.title
    edit = action.edit.changes["file://test.yar"][0]
    assert "all of them" in edit.new_text


def test_deduplicate_identical_strings_rewrites_count_offset_length_and_in_at() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "abc"
        $b = "abc"
    condition:
        #b > 0 and @b[1] > 0 and !b[1] > 0 and $b at 0 and $b in (0..filesize)
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(5, 8, 70), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Deduplicate identical strings")
    )
    edit = action.edit.changes["file://test.yar"][0]
    assert "#a > 0" in edit.new_text
    assert "@a[1] > 0" in edit.new_text
    assert "!a[1] > 0" in edit.new_text
    assert "$b at" not in edit.new_text
    assert "$b in" not in edit.new_text
    assert "$a at 0" in edit.new_text
    assert "$a in (0..filesize)" in edit.new_text


def test_authoring_helpers_cover_edge_cases() -> None:
    actions = AuthoringActions()
    text = """
rule demo {
    strings:
        $a = "abc"
    condition:
        any of them
}
""".lstrip()

    assert actions._find_rule_start(text.split("\n"), 0) == 0
    assert actions._find_rule_start(text.split("\n"), 4) == 0
    assert actions._find_rule_start(["meta:", "a = 1"], 1) == -1
    assert actions._get_rule_context("meta:\n a = 1", 0) is None
    assert actions._find_rule_end(["rule demo {", '  $a = "{"', "}"], 0) == 2
    assert actions._find_rule_end(["rule demo {", "  /* x } */", "}"], 0) == 2
    assert actions._find_rule_end(["rule demo {", "  /a\\/b/", "}"], 0) == 2
    assert actions._find_section_line(text.split("\n"), "strings:", 0) == 1
    assert actions._find_section_line(text.split("\n"), "meta:", 0) == -1
    assert actions._modifier_start('"abc" wide nocase') is not None
    assert actions._modifier_start("{ 41 42 } ascii") is not None
    assert actions._modifier_start("/abc/i nocase") is not None
    assert actions._modifier_start('"abc"') is None
    assert actions._normalize_modifiers(["wide", "ascii", "wide", "nocase"]) == [
        "ascii",
        "wide",
        "nocase",
    ]


def test_authoring_noop_paths_return_none() -> None:
    actions = AuthoringActions()
    text = """
rule demo {
    strings:
        $a = "abc"
    condition:
        $a
}
    """.lstrip()

    assert actions.normalize_string_modifiers(text, _range(2, 8, 18)) is None
    assert actions.convert_plain_string_to_hex(text, _range(2, 8, 18)) is not None
    assert actions.optimize_rule("meta:\n a = 1", _range(0, 0, 4)) is None
    first_roundtrip = actions.roundtrip_rewrite_rule(text, _range(0, 0, 4))
    assert first_roundtrip is not None
    assert actions.roundtrip_rewrite_rule(first_roundtrip.edit.new_text, _range(0, 0, 4)) is None
    assert actions.deduplicate_identical_strings(text, _range(2, 8, 18)) is None
    assert actions.sort_strings_by_identifier(text, _range(2, 8, 18)) is None
    assert actions.sort_meta_by_key(text, _range(0, 0, 4)) is None
    assert actions.sort_tags_alphabetically(text, _range(0, 0, 4)) is None
    assert actions.compress_of_them(text, _range(4, 8, 10)) is None


def test_create_missing_string_action_appends_to_existing_strings_section() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "x"
    condition:
        $missing
}
""".lstrip()
    diag = Diagnostic(range=_range(4, 8, 16), message="undefined variable $missing")

    actions = provider.get_code_actions(text, _range(4, 8, 16), [diag], "file://test.yar")
    action = next(
        action for action in actions if action.title == "Add string definition for $missing"
    )
    edit = action.edit.changes["file://test.yar"][0]
    assert edit.new_text.strip() == '$missing = ""'
