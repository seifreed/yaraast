"""More tests for LSP references provider (no mocks)."""

from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.document_query_reference_text import section_for_occurrence
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


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
