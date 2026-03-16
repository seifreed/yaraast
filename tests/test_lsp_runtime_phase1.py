"""Phase 1 tests for the shared LSP runtime."""

from __future__ import annotations

from pathlib import Path

from lsprotocol.types import FileChangeType, FileEvent, Position, Range

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.selection_range import SelectionRangeProvider
from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider


def test_runtime_cross_file_definition_references_and_rename(tmp_path: Path) -> None:
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

    def_provider = DefinitionProvider(runtime)
    ref_provider = ReferencesProvider(runtime)
    rename_provider = RenameProvider(runtime)

    user_uri = path_to_uri(user)
    user_text = user.read_text(encoding="utf-8")

    definition = def_provider.get_definition(
        user_text,
        Position(line=2, character=6),
        user_uri,
    )
    assert definition is not None
    assert definition.uri == path_to_uri(common)

    refs = ref_provider.get_references(
        user_text,
        Position(line=2, character=6),
        user_uri,
        include_declaration=True,
    )
    assert {ref.uri for ref in refs} == {path_to_uri(common), user_uri}

    edit = rename_provider.rename(
        user_text,
        Position(line=2, character=6),
        "renamed_rule",
        user_uri,
    )
    assert edit is not None and edit.changes is not None
    assert set(edit.changes) == {path_to_uri(common), user_uri}


def test_workspace_symbols_provider_uses_runtime_index(tmp_path: Path) -> None:
    alpha = tmp_path / "alpha.yar"
    beta = tmp_path / "beta.yara"
    alpha.write_text('import "pe"\nrule alpha { condition: true }\n', encoding="utf-8")
    beta.write_text(
        """
rule beta {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    provider = WorkspaceSymbolsProvider(runtime)

    symbols = provider.get_workspace_symbols("")
    names = {symbol.name for symbol in symbols}
    assert {"alpha", "beta", "$a", "pe"} <= names

    filtered = provider.get_workspace_symbols("bet")
    assert all("bet" in symbol.name.lower() for symbol in filtered)


def test_selection_range_provider_returns_progressive_ranges() -> None:
    text = """
rule sample {
  condition:
    filesize < 10
}
""".lstrip()
    runtime = LspRuntime()
    uri = "file:///sample.yar"
    runtime.open_document(uri, text)
    provider = SelectionRangeProvider(runtime)

    selections = provider.get_selection_ranges(text, [Position(line=2, character=6)], uri)
    assert len(selections) == 1
    selection = selections[0]
    assert selection.range == Range(
        start=Position(line=2, character=4),
        end=Position(line=2, character=12),
    )
    assert selection.parent is not None
    assert selection.parent.parent is not None


def test_runtime_resolve_symbol_classifies_string_rule_and_module_member(tmp_path: Path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text(
        """
import "pe"
rule sample {
  strings:
    $a = "x"
  condition:
    $a and other_rule and pe.imphash()
}
rule other_rule { condition: true }
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    uri = path_to_uri(sample)
    text = sample.read_text(encoding="utf-8")
    runtime.open_document(uri, text)

    string_symbol = runtime.resolve_symbol(uri, text, Position(line=5, character=6))
    assert string_symbol is not None
    assert string_symbol.kind == "string"
    assert string_symbol.normalized_name == "$a"

    rule_symbol = runtime.resolve_symbol(uri, text, Position(line=5, character=13))
    assert rule_symbol is not None
    assert rule_symbol.kind == "rule"
    assert rule_symbol.normalized_name == "other_rule"

    member_symbol = runtime.resolve_symbol(uri, text, Position(line=5, character=28))
    assert member_symbol is not None
    assert member_symbol.kind == "module_member"
    assert member_symbol.normalized_name == "pe.imphash"


def test_runtime_config_document_cache_and_watched_files(tmp_path: Path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text("rule sample { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(sample)

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    loaded = runtime.get_document(uri)
    assert loaded is not None
    assert loaded.text.startswith("rule sample")

    runtime.update_config({"YARA": {"cacheWorkspace": False}})
    assert runtime.config.cache_workspace is False
    runtime.close_document(uri)
    assert runtime.get_document(uri, load_workspace=False) is None

    sample.write_text("rule sample { condition: false }\n", encoding="utf-8")
    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Changed)])
    assert runtime.get_document(uri, load_workspace=False) is None

    runtime.update_config({"YARA": {"cacheWorkspace": True}})
    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Changed)])
    reloaded = runtime.get_document(uri, load_workspace=False)
    assert reloaded is not None
    assert "false" in reloaded.text

    sample.unlink()
    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Deleted)])
    assert runtime.get_document(uri, load_workspace=False) is None


def test_runtime_rule_reference_records_include_roles(tmp_path: Path) -> None:
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
    records = runtime.find_rule_reference_records("shared_rule", current_uri=path_to_uri(user))
    assert {record.role for record in records} == {"declaration", "use"}


def test_runtime_rename_rule_builds_cross_file_edits(tmp_path: Path) -> None:
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

    changes = runtime.rename_rule("shared_rule", "renamed_rule")
    assert set(changes) == {path_to_uri(common), path_to_uri(user)}
    assert all(change.new_text == "renamed_rule" for edits in changes.values() for change in edits)


def test_selection_range_provider_handles_blank_and_outside_rule() -> None:
    text = 'import "pe"\n\nrule sample { condition: true }\n'
    provider = SelectionRangeProvider()

    blank_selection = provider.get_selection_ranges(text, [Position(line=1, character=0)])
    assert len(blank_selection) == 1
    assert blank_selection[0].range.start.line == 1
    assert blank_selection[0].parent is None

    outside_rule = provider.get_selection_ranges(text, [Position(line=0, character=3)])
    assert len(outside_rule) == 1
    assert outside_rule[0].range.start.line == 0


def test_selection_range_provider_includes_section_range() -> None:
    text = """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    runtime = LspRuntime()
    uri = "file:///sample.yar"
    runtime.open_document(uri, text)
    provider = SelectionRangeProvider(runtime)

    selections = provider.get_selection_ranges(text, [Position(line=2, character=6)], uri)
    assert len(selections) == 1
    selection = selections[0]
    # Hierarchy: word → line → section → rule
    assert selection.parent is not None  # line range
    assert selection.parent.parent is not None  # section range
    assert selection.parent.parent.range.start.line == 1  # strings section starts at line 1
    assert selection.parent.parent.parent is not None  # rule range
