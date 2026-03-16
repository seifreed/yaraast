"""More tests for LSP rename provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.rename import RenameProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_prepare_rename_string_identifier() -> None:
    text = "rule a { condition: $a }"
    provider = RenameProvider()
    rng = provider.prepare_rename(text, _pos(0, 20))
    assert rng is not None


def test_rename_string_identifier_variants() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a and #a > 0 and @a == 1 and !a
}
""".lstrip()
    provider = RenameProvider()
    edit = provider.rename(text, _pos(4, 5), "b", "file://test.yar")
    assert edit is not None
    changes = next(iter(edit.changes.values()))
    assert len(changes) >= 4


def test_rename_rule_name_line_without_brace() -> None:
    text = """
rule a
{
  condition: true
}
rule b
{
  condition: a
}
""".lstrip()
    provider = RenameProvider()
    rng = provider.prepare_rename(text, _pos(0, 5))
    assert rng is not None

    edit = provider.rename(text, _pos(0, 5), "c", "file://test.yar")
    assert edit is not None


def test_rename_rule_reference_without_runtime_uses_structured_resolution() -> None:
    text = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()
    provider = RenameProvider()
    edit = provider.rename(text, _pos(1, 20), "renamed", "file://test.yar")
    assert edit is not None
    changes = next(iter(edit.changes.values()))
    assert any(change.new_text == "renamed" for change in changes)


def test_rename_non_renameable_and_empty_cases() -> None:
    provider = RenameProvider()
    text = "rule a { condition: true }"

    assert provider.prepare_rename(text, _pos(10, 0)) is None
    assert provider.prepare_rename(text, _pos(0, 4)) is None
    assert provider.rename(text, _pos(0, 4), "x", "file://test.yar") is None
    assert provider.rename(text, _pos(10, 0), "x", "file://test.yar") is None
    assert provider._is_rule_name(text, _pos(10, 0)) is False


def test_rename_string_identifier_with_prefixed_new_name() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a and #a > 0 and @a == 1 and !a
}
""".lstrip()
    provider = RenameProvider()
    edit = provider.rename(text, _pos(4, 5), "$renamed", "file://test.yar")
    assert edit is not None
    changes = next(iter(edit.changes.values()))
    assert any(change.new_text == "$renamed" for change in changes)
    assert any(change.new_text == "#renamed" for change in changes)


def test_prepare_rename_and_rename_prefixed_string_with_runtime(tmp_path) -> None:
    from pathlib import Path

    from yaraast.lsp.runtime import LspRuntime, path_to_uri

    sample = Path(tmp_path) / "sample.yar"
    sample.write_text(
        """
rule a {
  strings:
    $a = "x"
  condition:
    #a > 0 and @a[1] > 0 and !a[1] > 0
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    uri = path_to_uri(sample)
    text = sample.read_text(encoding="utf-8")
    runtime.open_document(uri, text)

    provider = RenameProvider(runtime)
    rng = provider.prepare_rename(text, _pos(4, 5), uri)
    assert rng is not None

    edit = provider.rename(text, _pos(4, 5), "renamed", uri)
    assert edit is not None
    changes = next(iter(edit.changes.values()))
    assert any(change.new_text == "$renamed" for change in changes)
    assert any(change.new_text == "#renamed" for change in changes)
    assert any(change.new_text == "@renamed" for change in changes)
    assert any(change.new_text == "!renamed" for change in changes)


def test_rename_rule_cross_file_with_runtime(tmp_path) -> None:
    from yaraast.lsp.runtime import LspRuntime, path_to_uri

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
    provider = RenameProvider(runtime)
    user_uri = path_to_uri(user)
    text = user.read_text(encoding="utf-8")

    edit = provider.rename(text, _pos(2, 6), "renamed_rule", user_uri)
    assert edit is not None and edit.changes is not None
    assert set(edit.changes) == {path_to_uri(common), user_uri}
    assert all(
        change.new_text == "renamed_rule" for edits in edit.changes.values() for change in edits
    )
