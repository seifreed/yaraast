"""More tests for LSP references provider (no mocks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from lsprotocol.types import Position
import pytest

from yaraast.ast.expressions import StringCount, StringLength, StringOffset
from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.document_query_reference_ast import string_reference_name
from yaraast.lsp.document_query_reference_text import section_for_occurrence
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_references_rejects_non_string_text(text: Any) -> None:
    provider = ReferencesProvider()

    with pytest.raises(TypeError, match="References text must be a string"):
        provider.get_references(cast(str, text), _pos(0, 0), "file://test.yar")


def test_references_rejects_non_position_inputs() -> None:
    provider = ReferencesProvider()

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.get_references(
            "rule a { condition: true }", cast(Any, object()), "file://test.yar"
        )


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_rename_rejects_non_string_text(text: Any) -> None:
    provider = RenameProvider()

    with pytest.raises(TypeError, match="Rename text must be a string"):
        provider.prepare_rename(cast(str, text), _pos(0, 0), "file://test.yar")

    with pytest.raises(TypeError, match="Rename text must be a string"):
        provider.rename(cast(str, text), _pos(0, 0), "b", "file://test.yar")


def test_rename_rejects_non_position_inputs() -> None:
    provider = RenameProvider()

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.prepare_rename("rule a { condition: true }", cast(Any, object()))

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.rename(
            "rule a { condition: true }",
            cast(Any, object()),
            "b",
            "file://test.yar",
        )


def test_rename_rejects_non_string_new_name() -> None:
    provider = RenameProvider()

    with pytest.raises(TypeError, match="Rename new_name must be a string"):
        provider.rename(
            "rule a { condition: true }", _pos(0, 5), cast(str, object()), "file://test.yar"
        )


def test_references_string_variants() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a and #a > 0 and @a == 1 and !a
}
""".lstrip()

    provider = ReferencesProvider()
    locations = provider.get_references(text, _pos(4, 6), "file://test.yar")
    assert len(locations) >= 4


def test_references_include_at_expression_string_subject() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a at 0
}
""".lstrip()

    locations = ReferencesProvider().get_references(text, _pos(4, 6), "file://test.yar")

    assert [(loc.range.start.line, loc.range.start.character) for loc in locations] == [
        (2, 4),
        (4, 4),
    ]


def test_references_rule_name() -> None:
    text = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()

    provider = ReferencesProvider()
    locations = provider.get_references(text, _pos(1, 20), "file://test.yar")
    assert len(locations) >= 2


def test_references_provider_uses_local_structured_resolution_without_runtime() -> None:
    text = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()

    provider = ReferencesProvider()
    records = provider.get_reference_records(text, _pos(1, 20), "file://test.yar")
    assert {record.role for record in records} == {"declaration", "use"}


def test_references_empty_and_prefixed_identifier() -> None:
    provider = ReferencesProvider()
    assert (
        provider.get_references("rule a { condition: true }", _pos(2, 0), "file://test.yar") == []
    )

    text = """
rule a {
  strings:
    $a = "x"
  condition:
    #a > 0 and @a == 1 and !a
}
""".lstrip()
    locations = provider.get_references(text, _pos(4, 5), "file://test.yar")
    assert len(locations) >= 4


def test_ast_string_reference_names_do_not_double_prefix_dollar() -> None:
    assert string_reference_name(StringCount("$a")) == "$a"
    assert string_reference_name(StringOffset("$a")) == "$a"
    assert string_reference_name(StringLength("$a")) == "$a"


def test_references_ignore_comment_positions() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a and true
    // $a should not resolve
    /* $a should not resolve */
}
""".lstrip()

    provider = ReferencesProvider()

    assert provider.get_references(text, _pos(5, 8), "file://test.yar") == []
    assert provider.get_references(text, _pos(6, 8), "file://test.yar") == []


def test_references_ignore_regex_literal_positions() -> None:
    text = """
rule helper { condition: true }
rule a {
  strings:
    $r = /helper/
  condition:
    $r
}
""".lstrip()

    provider = ReferencesProvider()

    assert provider.get_references(text, _pos(3, 10), "file://test.yar") == []


def test_lsp_string_navigation_ignores_yarax_local_string_shadowing() -> None:
    text = """
rule shadowed {
  strings:
    $a = "x"
  condition:
    with $a = 1:
      $a > 0
}
""".lstrip()
    uri = "file://test.yar"

    references = ReferencesProvider().get_references(text, _pos(2, 5), uri)
    assert [(ref.range.start.line, ref.range.end.line) for ref in references] == [(2, 2)]

    assert DefinitionProvider().get_definition(text, _pos(5, 7), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(5, 7), uri) is None
    assert DefinitionProvider().get_definition(text, _pos(4, 10), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 10), uri) is None

    edit = RenameProvider().rename(text, _pos(2, 5), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [2]


def test_lsp_rule_navigation_ignores_yarax_comprehension_local_declaration() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    [helper for helper in (1, 2) if helper > 0]
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(3, 17), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(3, 17), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_multiline_yarax_comprehension_local_declaration() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    [helper for helper
      in (1, 2) if helper > 0]
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(3, 17), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(3, 17), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_yarax_comprehension_local_after_for_newline() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    [helper for
      helper in (1, 2) if helper > 0]
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(4, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_split_yarax_comprehension_local_after_for_newline() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    [helper for
      helper
      in (1, 2) if helper > 0]
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(4, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_yarax_dict_value_local_after_newline() -> None:
    text = """
rule value { condition: true }
rule local_ref {
  condition:
    {key: value for key,
      value in dict if value > 0}
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(4, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_split_yarax_dict_value_local_after_newline() -> None:
    text = """
rule value { condition: true }
rule local_ref {
  condition:
    {key: value for
      key,
      value in dict if value > 0}
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(5, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(5, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_string_navigation_ignores_multiline_yarax_with_declaration() -> None:
    text = """
rule shadowed {
  strings:
    $a = "x"
  condition:
    with $a =
      1:
      $a > 0
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(4, 10), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 10), uri) is None

    edit = RenameProvider().rename(text, _pos(2, 5), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [2]


def test_lsp_rule_navigation_ignores_yarax_lambda_parameter_declaration() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    lambda helper: helper
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(3, 13), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(3, 13), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_multiline_yarax_lambda_parameter_declaration() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    lambda helper:
      helper
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(3, 13), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(3, 13), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_yarax_lambda_parameter_after_newline() -> None:
    text = """
rule helper { condition: true }
rule local_ref {
  condition:
    lambda
      helper: helper
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(4, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_yarax_second_lambda_parameter_after_newline() -> None:
    text = """
rule value { condition: true }
rule local_ref {
  condition:
    lambda key,
      value: value
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(4, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(4, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_lsp_rule_navigation_ignores_split_yarax_second_lambda_parameter_after_newline() -> None:
    text = """
rule value { condition: true }
rule local_ref {
  condition:
    lambda
      key,
      value: value
}
""".lstrip()
    uri = "file://test.yar"

    assert DefinitionProvider().get_definition(text, _pos(5, 8), uri) is None
    assert RenameProvider().prepare_rename(text, _pos(5, 8), uri) is None

    edit = RenameProvider().rename(text, _pos(0, 7), "renamed", uri)
    assert edit is not None
    assert edit.changes is not None
    assert [text_edit.range.start.line for text_edit in edit.changes[uri]] == [0]


def test_reference_section_lookup_ignores_inline_markers_inside_literals() -> None:
    line = 'rule r { condition: "strings:" and $a }'
    col = line.index("$a")

    assert section_for_occurrence([line], 0, 0, col) == "condition"


def test_references_provider_exposes_typed_records_cross_file(tmp_path: Path) -> None:
    common = tmp_path / "common.yar"
    user = tmp_path / "user.yar"
    common.write_text("rule shared_rule { condition: true }\n", encoding="utf-8")
    user.write_text(
        """
rule local_rule {
  condition:
    shared_rule
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    provider = ReferencesProvider(runtime)

    text = user.read_text(encoding="utf-8")
    records = provider.get_reference_records(text, _pos(2, 6), path_to_uri(user))
    assert {record.role for record in records} == {"declaration", "use"}
    assert {record.location.uri for record in records} == {path_to_uri(common), path_to_uri(user)}
