"""Phase 1 tests for the shared LSP runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from lsprotocol.types import FileChangeType, FileEvent, Location, MarkupContent, Position, Range
import pytest

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import DocumentContext, LspRuntime, path_to_uri
from yaraast.lsp.selection_range import SelectionRangeProvider
from yaraast.lsp.utf16 import utf8_col_to_utf16
from yaraast.lsp.workspace_index import WorkspaceIndex
from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider


def _single_location(location: Location | list[Location]) -> Location:
    assert not isinstance(location, list)
    return location


def test_symbol_record_from_dict_rejects_non_object_payload() -> None:
    with pytest.raises(ValueError, match="SymbolRecord data must be an object"):
        SymbolRecord.from_dict(cast(Any, []))


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_selection_ranges_rejects_non_string_text(text: Any) -> None:
    provider = SelectionRangeProvider()

    with pytest.raises(TypeError, match="Selection range text must be a string"):
        provider.get_selection_ranges(cast(str, text), [Position(line=0, character=0)])


def test_selection_ranges_rejects_invalid_positions() -> None:
    provider = SelectionRangeProvider()

    with pytest.raises(TypeError, match="positions must be a list of LSP Position values"):
        provider.get_selection_ranges("rule a { condition: true }", cast(Any, object()))

    with pytest.raises(TypeError, match="positions must be a list of LSP Position values"):
        provider.get_selection_ranges("rule a { condition: true }", [cast(Any, object())])


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
    definition = _single_location(definition)
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


def test_navigation_and_rename_keep_working_in_partially_broken_documents(
    tmp_path: Path,
) -> None:
    rule_file = tmp_path / "broken_tail.yar"
    rule_file.write_text(
        """
rule good {
  condition: true
}

rule broken {
  condition:
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    uri = path_to_uri(rule_file)
    text = rule_file.read_text(encoding="utf-8")
    position = Position(line=0, character=5)

    definition = DefinitionProvider(runtime).get_definition(text, position, uri)
    assert definition is not None
    assert not isinstance(definition, list)
    assert definition.uri == uri

    references = ReferencesProvider(runtime).get_references(text, position, uri)
    assert references
    assert {location.uri for location in references} == {uri}

    prepare = RenameProvider(runtime).prepare_rename(text, position, uri)
    assert prepare == Range(Position(line=0, character=5), Position(line=0, character=9))

    edit = RenameProvider(runtime).rename(text, position, "renamed_good", uri)
    assert edit is not None and edit.changes is not None
    assert set(edit.changes) == {uri}


def test_include_navigation_uses_workspace_search_paths(tmp_path: Path) -> None:
    lib = tmp_path / "lib"
    src = tmp_path / "src"
    lib.mkdir()
    src.mkdir()

    target = lib / "common.yar"
    target.write_text("rule common { condition: true }\n", encoding="utf-8")
    main = src / "main.yar"
    main.write_text('include "common.yar"\nrule main { condition: true }\n', encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    uri = path_to_uri(main)
    text = main.read_text(encoding="utf-8")
    position = Position(line=0, character=10)
    target_uri = path_to_uri(target)

    definition = DefinitionProvider(runtime).get_definition(text, position, uri)
    assert definition == Location(
        uri=target_uri,
        range=Range(Position(line=0, character=0), Position(line=0, character=0)),
    )

    links = DocumentLinksProvider(runtime).get_document_links(text, uri)
    assert any(link.target == target_uri for link in links)

    hover = HoverProvider(runtime).get_hover(text, position, uri)
    assert hover is not None
    assert isinstance(hover.contents, MarkupContent)
    assert target_uri in hover.contents.value


def test_include_navigation_uses_direct_sibling_resolution(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()

    target = src / "common.yar"
    target.write_text("rule common { condition: true }\n", encoding="utf-8")
    main = src / "main.yar"
    main.write_text('include "common.yar"\nrule main { condition: true }\n', encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    uri = path_to_uri(main)
    text = main.read_text(encoding="utf-8")
    position = Position(line=0, character=10)
    target_uri = path_to_uri(target)

    definition = DefinitionProvider(runtime).get_definition(text, position, uri)
    assert definition == Location(
        uri=target_uri,
        range=Range(Position(line=0, character=0), Position(line=0, character=0)),
    )

    links = DocumentLinksProvider(runtime).get_document_links(text, uri)
    assert any(link.target == target_uri for link in links)

    hover = HoverProvider(runtime).get_hover(text, position, uri)
    assert hover is not None
    assert isinstance(hover.contents, MarkupContent)
    assert target_uri in hover.contents.value


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


def test_workspace_index_discovers_multidialect_extensions(tmp_path: Path) -> None:
    for name in ("classic.yar", "classic_alt.yara", "native.yaral", "native.yarax"):
        (tmp_path / name).write_text("rule sample { condition: true }\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("rule ignored { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert {path.name for path in index.iter_candidate_files()} == {
        "classic.yar",
        "classic_alt.yara",
        "native.yaral",
        "native.yarax",
    }


def test_workspace_index_search_rejects_invalid_query_and_exclusions(
    tmp_path: Path,
) -> None:
    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])
    uri = "file:///sample.yar"
    index.persisted_symbols[uri] = [
        SymbolRecord(
            "sample",
            "rule",
            uri,
            Range(Position(line=0, character=0), Position(line=0, character=6)),
        ),
        SymbolRecord(
            "sample",
            "rule_block",
            uri,
            Range(Position(line=0, character=0), Position(line=0, character=6)),
        ),
    ]

    with pytest.raises(TypeError, match="Workspace symbol query must be a string"):
        index.search(cast(Any, object()))
    with pytest.raises(TypeError, match="Workspace symbol query must be a string"):
        index.search_records(cast(Any, object()))

    with pytest.raises(TypeError, match="Excluded workspace symbol URIs must be a set of strings"):
        index.search_records("", exclude_uris=cast(Any, uri))
    with pytest.raises(TypeError, match="Excluded workspace symbol URIs must be a set of strings"):
        index.search_records("", exclude_uris=cast(Any, {object()}))

    assert [record.name for record in index.search_records("")] == ["sample"]
    assert all(record.kind == "rule" for record in index.search_records(""))


def test_workspace_index_rejects_invalid_document_mutation_inputs(
    tmp_path: Path,
) -> None:
    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])
    uri = "file:///sample.yar"
    index.persisted_symbols[uri] = [
        SymbolRecord(
            "sample",
            "rule",
            uri,
            Range(Position(line=0, character=0), Position(line=0, character=6)),
        )
    ]

    with pytest.raises(TypeError, match="Workspace index document must be a DocumentContext"):
        index.update_document(cast(Any, object()))
    with pytest.raises(TypeError, match="Workspace index URI must be a string"):
        index.remove_document(cast(Any, object()))

    assert [record.name for record in index.search_records("")] == ["sample"]

    index.update_document(DocumentContext(uri, "rule updated { condition: true }\n"))
    updated_names = {record.name for record in index.search_records("")}
    assert "updated" in updated_names
    assert "sample" not in updated_names

    index.remove_document(uri)
    assert index.search_records("") == []


def test_workspace_index_search_returns_empty_without_workspace_folders() -> None:
    index = WorkspaceIndex()
    uri = "file:///sample.yar"
    index.persisted_symbols[uri] = [
        SymbolRecord(
            "sample",
            "rule",
            uri,
            Range(Position(line=0, character=0), Position(line=0, character=6)),
        )
    ]

    assert index.search_records("") == []


def test_workspace_index_persists_each_workspace_root_independently(
    tmp_path: Path,
) -> None:
    root_one = tmp_path / "one"
    root_two = tmp_path / "two"
    root_one.mkdir()
    root_two.mkdir()
    one = root_one / "alpha.yar"
    two = root_two / "beta.yar"
    one.write_text("rule alpha { condition: true }\n", encoding="utf-8")
    two.write_text("rule beta { condition: true }\n", encoding="utf-8")

    index = WorkspaceIndex()
    index.set_workspace_folders([str(root_one), str(root_two)])
    index.update_document(DocumentContext(path_to_uri(one), one.read_text(encoding="utf-8")))
    index.update_document(DocumentContext(path_to_uri(two), two.read_text(encoding="utf-8")))

    cache_one = json.loads(
        (root_one / ".yaraast" / "lsp-workspace-index.json").read_text(encoding="utf-8")
    )
    cache_two = json.loads(
        (root_two / ".yaraast" / "lsp-workspace-index.json").read_text(encoding="utf-8")
    )

    assert set(cache_one["symbols"]) == {path_to_uri(one)}
    assert set(cache_two["symbols"]) == {path_to_uri(two)}

    restored = WorkspaceIndex()
    restored.set_workspace_folders([str(root_one), str(root_two)])
    assert {record.name for record in restored.search_records("") if record.kind == "rule"} == {
        "alpha",
        "beta",
    }


def test_workspace_index_ignores_stale_parent_cache_for_nested_roots(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    child = parent / "child"
    parent.mkdir()
    child.mkdir()

    document = child / "alpha.yar"
    uri = path_to_uri(document)
    document.write_text("rule alpha { condition: true }\n", encoding="utf-8")
    stale_record = SymbolRecord(
        "alpha_stale",
        "rule",
        uri,
        Range(Position(line=0, character=0), Position(line=0, character=5)),
    )
    current_record = SymbolRecord(
        "alpha",
        "rule",
        uri,
        Range(Position(line=0, character=0), Position(line=0, character=5)),
    )

    parent_cache = parent / ".yaraast" / "lsp-workspace-index.json"
    child_cache = child / ".yaraast" / "lsp-workspace-index.json"
    parent_cache.parent.mkdir(parents=True, exist_ok=True)
    child_cache.parent.mkdir(parents=True, exist_ok=True)
    parent_cache.write_text(
        json.dumps({"symbols": {uri: [stale_record.to_dict()]}}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    child_cache.write_text(
        json.dumps({"symbols": {uri: [current_record.to_dict()]}}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(parent), str(child)])

    assert [record.name for record in index.search_records("") if record.kind == "rule"] == [
        "alpha"
    ]


def test_workspace_index_ignores_persisted_symbols_outside_workspace_roots(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    other = tmp_path / "other"
    root.mkdir()
    other.mkdir()
    orphan = other / "orphan.yar"
    orphan.write_text("rule orphan { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(orphan)

    index = WorkspaceIndex()
    index.set_workspace_folders([str(root)])
    index.persisted_symbols[uri] = [
        SymbolRecord(
            "orphan",
            "rule",
            uri,
            Range(Position(line=0, character=0), Position(line=0, character=6)),
        )
    ]

    assert index.search_records("") == []


@pytest.mark.parametrize(
    ("persisted_symbols", "message"),
    [
        (cast(Any, []), "Workspace index persisted_symbols must be a dictionary"),
        ({cast(Any, object()): []}, "Workspace index URI must be a string"),
        ({"file:///sample.yar": cast(Any, object())}, "Workspace index symbols must be a list"),
        (
            {"file:///sample.yar": [cast(Any, object())]},
            "Workspace index symbol must be a SymbolRecord",
        ),
    ],
)
def test_workspace_index_save_rejects_invalid_persisted_symbols(
    tmp_path: Path,
    persisted_symbols: Any,
    message: str,
) -> None:
    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])
    index.persisted_symbols = persisted_symbols

    with pytest.raises(TypeError, match=message):
        index.save()


def test_workspace_folder_setters_reject_invalid_inputs_without_partial_update(
    tmp_path: Path,
) -> None:
    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    with pytest.raises(TypeError, match="Workspace folders must be a list of strings"):
        index.set_workspace_folders(cast(Any, str(tmp_path)))
    with pytest.raises(TypeError, match="Workspace folders must be a list of strings"):
        index.set_workspace_folders(cast(Any, [str(tmp_path), object()]))
    with pytest.raises(ValueError, match="Workspace folder paths must not be empty"):
        index.set_workspace_folders([""])
    with pytest.raises(ValueError, match="Workspace folder paths must not be empty"):
        index.set_workspace_folders(["   "])
    with pytest.raises(ValueError, match="Workspace folder paths must not be empty"):
        index.set_workspace_folders(["\t"])

    assert index.workspace_folders == [tmp_path]

    symlink_root = tmp_path / "linked"
    symlink_root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="Workspace folder paths must not be a symlink"):
        index.set_workspace_folders([str(symlink_root)])

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    with pytest.raises(TypeError, match="Workspace folders must be a list of strings"):
        runtime.set_workspace_folders(cast(Any, str(tmp_path)))
    with pytest.raises(ValueError, match="Workspace folder paths must not be empty"):
        runtime.set_workspace_folders([""])
    with pytest.raises(ValueError, match="Workspace folder paths must not be empty"):
        runtime.set_workspace_folders(["   "])
    with pytest.raises(ValueError, match="Workspace folder paths must not be a symlink"):
        runtime.set_workspace_folders([str(symlink_root)])

    assert runtime.index.workspace_folders == [tmp_path]


def test_workspace_index_treats_inaccessible_workspace_folders_as_empty() -> None:
    inaccessible_root = "a" * 5000
    index = WorkspaceIndex()

    index.set_workspace_folders([inaccessible_root])

    assert index.workspace_folders == [Path(inaccessible_root)]
    assert index.iter_candidate_files() == []

    runtime = LspRuntime()
    runtime.set_workspace_folders([inaccessible_root])
    runtime.open_document("file:///sample.yar", "rule sample { condition: true }\n")

    assert runtime.workspace_symbols("sample")


def test_workspace_index_skips_malformed_cached_symbols(tmp_path: Path) -> None:
    cache_dir = tmp_path / ".yaraast"
    cache_dir.mkdir()
    good = tmp_path / "good.yar"
    good.write_text("rule good { condition: true }\n", encoding="utf-8")
    good_uri = path_to_uri(good)
    cache_file = cache_dir / "lsp-workspace-index.json"
    cache_file.write_text(
        """
{
  "symbols": {
    "file:///bad-kind.yar": [
      {
        "name": "bad_kind",
        "kind": "bogus",
        "uri": "file:///bad-kind.yar",
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": 0, "character": 8}
        }
      }
    ],
    "file:///bad-name.yar": [
      {
        "name": ["bad"],
        "kind": "rule",
        "uri": "file:///bad-name.yar",
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": 0, "character": 3}
        }
      }
    ],
    "file:///blank-name.yar": [
      {
        "name": "   ",
        "kind": "rule",
        "uri": "file:///blank-name.yar",
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": 0, "character": 3}
        }
      }
    ],
    "file:///bad.yar": [
      {
        "name": "bad",
        "kind": "rule",
        "uri": "file:///bad.yar",
        "range": {
          "start": {"line": "not-an-int", "character": 0},
          "end": {"line": 0, "character": 3}
        }
      }
    ],
    "GOOD_URI": [
      {
        "name": "good",
        "kind": "rule",
        "uri": "GOOD_URI",
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": 0, "character": 4}
        }
      }
    ]
  }
}
""".replace("GOOD_URI", good_uri).strip(),
        encoding="utf-8",
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert [symbol.name for symbol in index.search_records("")] == ["good"]


def test_workspace_index_skips_cached_symbols_with_invalid_position_scalars(
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / ".yaraast"
    cache_dir.mkdir()
    good = tmp_path / "good.yar"
    good.write_text("rule good { condition: true }\n", encoding="utf-8")
    good_uri = path_to_uri(good)
    cache_file = cache_dir / "lsp-workspace-index.json"
    cache_file.write_text(
        """
{
  "symbols": {
    "file:///bool.yar": [
      {
        "name": "bool_pos",
        "kind": "rule",
        "uri": "file:///bool.yar",
        "range": {
          "start": {"line": true, "character": 0},
          "end": {"line": 0, "character": 3}
        }
      }
    ],
    "file:///negative.yar": [
      {
        "name": "negative_pos",
        "kind": "rule",
        "uri": "file:///negative.yar",
        "range": {
          "start": {"line": -1, "character": 0},
          "end": {"line": 0, "character": 3}
        }
      }
    ],
    "GOOD_URI": [
      {
        "name": "good",
        "kind": "rule",
        "uri": "GOOD_URI",
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": 0, "character": 4}
        }
      }
    ]
  }
}
""".replace("GOOD_URI", good_uri).strip(),
        encoding="utf-8",
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert [symbol.name for symbol in index.search_records("")] == ["good"]


def test_workspace_index_skips_cached_symbols_with_inverted_ranges(tmp_path: Path) -> None:
    cache_dir = tmp_path / ".yaraast"
    cache_dir.mkdir()
    good = tmp_path / "good.yar"
    good.write_text("rule good { condition: true }\n", encoding="utf-8")
    good_uri = path_to_uri(good)
    cache_file = cache_dir / "lsp-workspace-index.json"
    cache_file.write_text(
        """
{
  "symbols": {
    "file:///inverted-line.yar": [
      {
        "name": "inverted_line",
        "kind": "rule",
        "uri": "file:///inverted-line.yar",
        "range": {
          "start": {"line": 2, "character": 0},
          "end": {"line": 1, "character": 0}
        }
      }
    ],
    "file:///inverted-character.yar": [
      {
        "name": "inverted_character",
        "kind": "rule",
        "uri": "file:///inverted-character.yar",
        "range": {
          "start": {"line": 0, "character": 5},
          "end": {"line": 0, "character": 4}
        }
      }
    ],
    "GOOD_URI": [
      {
        "name": "good",
        "kind": "rule",
        "uri": "GOOD_URI",
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": 0, "character": 4}
        }
      }
    ]
  }
}
""".replace("GOOD_URI", good_uri).strip(),
        encoding="utf-8",
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert [symbol.name for symbol in index.search_records("")] == ["good"]


def test_workspace_index_skips_cached_symbols_with_mismatched_uri(
    tmp_path: Path,
) -> None:
    open_file = tmp_path / "open.yar"
    other_file = tmp_path / "other.yar"
    open_file.write_text("rule disk { condition: true }\n", encoding="utf-8")
    other_file.write_text("rule other { condition: true }\n", encoding="utf-8")
    open_uri = path_to_uri(open_file)
    other_uri = path_to_uri(other_file)
    cache_dir = tmp_path / ".yaraast"
    cache_dir.mkdir()
    cache_file = cache_dir / "lsp-workspace-index.json"
    cache_file.write_text(
        f"""
{{
  "symbols": {{
    "{other_uri}": [
      {{
        "name": "stale_open",
        "kind": "rule",
        "uri": "{open_uri}",
        "range": {{
          "start": {{"line": 0, "character": 0}},
          "end": {{"line": 0, "character": 10}}
        }}
      }}
    ],
    "{open_uri}": [
      {{
        "name": "good_open",
        "kind": "rule",
        "uri": "{open_uri}",
        "range": {{
          "start": {{"line": 0, "character": 0}},
          "end": {{"line": 0, "character": 9}}
        }}
      }}
    ]
  }}
}}
""".strip(),
        encoding="utf-8",
    )

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert index.search_records("", exclude_uris={open_uri}) == []


def test_workspace_index_ignores_non_object_cache_payload(tmp_path: Path) -> None:
    cache_dir = tmp_path / ".yaraast"
    cache_dir.mkdir()
    cache_file = cache_dir / "lsp-workspace-index.json"
    cache_file.write_text('["not", "an", "index"]', encoding="utf-8")

    index = WorkspaceIndex()
    index.set_workspace_folders([str(tmp_path)])

    assert index.search_records("") == []


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


def test_selection_range_provider_uses_buffer_text_over_disk_contents(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text(
        """
rule sample {
  condition:
    true
}
""".lstrip(),
        encoding="utf-8",
    )
    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    provider = SelectionRangeProvider(runtime)
    uri = path_to_uri(sample)
    buffer_text = """
rule sample {
  meta:
    one = 1
    two = 2
  condition:
    true
}
""".lstrip()

    selections = provider.get_selection_ranges(buffer_text, [Position(line=2, character=6)], uri)
    assert len(selections) == 1
    selection = selections[0]
    assert selection.parent is not None
    assert selection.parent.parent is not None
    assert selection.parent.parent.range == Range(
        start=Position(line=1, character=0),
        end=Position(line=3, character=11),
    )


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


def test_runtime_config_parses_string_cache_workspace_setting() -> None:
    runtime = LspRuntime()

    runtime.update_config({"YARA": {"cacheWorkspace": "false"}})
    assert runtime.config.cache_workspace is False

    runtime.update_config({"YARA": {"cacheWorkspace": "true"}})
    assert runtime.config.cache_workspace is True


def test_runtime_config_rejects_invalid_diagnostics_debounce_scalars() -> None:
    runtime = LspRuntime()
    default_debounce = runtime.config.diagnostics_debounce_ms

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": True}})
    assert runtime.config.diagnostics_debounce_ms == default_debounce

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": 1.5}})
    assert runtime.config.diagnostics_debounce_ms == default_debounce

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": 150}})
    assert runtime.config.diagnostics_debounce_ms == 150

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": True}})
    assert runtime.config.diagnostics_debounce_ms == 150

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": 1.5}})
    assert runtime.config.diagnostics_debounce_ms == 150

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": "250"}})
    assert runtime.config.diagnostics_debounce_ms == 250

    runtime.update_config({"YARA": {"diagnosticsDebounceMs": "-5"}})
    assert runtime.config.diagnostics_debounce_ms == 0


def test_runtime_watched_file_does_not_replace_open_document(tmp_path: Path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text("rule disk_version { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(sample)

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    open_doc = runtime.open_document(
        uri,
        "rule unsaved_version { condition: false }\n",
        version=2,
    )

    sample.write_text("rule changed_on_disk { condition: true }\n", encoding="utf-8")
    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Changed)])

    current = runtime.get_document(uri, load_workspace=False)
    assert current is open_doc
    assert current is not None
    assert current.is_open is True
    assert "unsaved_version" in current.text
    assert "changed_on_disk" not in current.text
    assert "unsaved_version" in {symbol.name for symbol in runtime.workspace_symbols("")}


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
    assert selection.parent.range == Range(
        start=Position(line=2, character=0),
        end=Position(line=2, character=12),
    )
    assert selection.parent.parent is not None  # section range
    assert selection.parent.parent.range.start.line == 1  # strings section starts at line 1
    assert selection.parent.parent.parent is not None  # rule range


def test_selection_range_provider_parent_ranges_use_utf16_columns() -> None:
    text = """
rule sample {
  condition:
    /* 😀😀 */ true
}
""".lstrip()
    line = text.splitlines()[2]
    runtime = LspRuntime()
    uri = "file:///utf16-selection.yar"
    runtime.open_document(uri, text)
    provider = SelectionRangeProvider(runtime)

    selections = provider.get_selection_ranges(
        text,
        [Position(line=2, character=utf8_col_to_utf16(line, line.index("true")))],
        uri,
    )

    assert len(selections) == 1
    selection = selections[0]
    assert selection.parent is not None
    assert selection.parent.range.end.character == utf8_col_to_utf16(line, len(line))
    assert selection.parent.parent is not None
    assert selection.parent.parent.range.end.character == utf8_col_to_utf16(line, len(line))
