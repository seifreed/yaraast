from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position, Range

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.document_highlight import DocumentHighlightProvider
from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.selection_range import SelectionRangeProvider
from yaraast.lsp.semantic_tokens import SemanticTokensProvider
from yaraast.lsp.symbols import SymbolsProvider

FIXTURES = Path(__file__).parent / "fixtures" / "lsp_parity"


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _run_matrix(folder: str, dialect: str, position: Position) -> dict[str, object]:
    root = FIXTURES / folder
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": dialect}})
    runtime.set_workspace_folders([str(root)])
    user = root / "user.yar"
    text = user.read_text(encoding="utf-8")
    uri = path_to_uri(user)
    runtime.open_document(uri, text)

    hover = HoverProvider(runtime).get_hover(text, position, uri)
    definition = DefinitionProvider(runtime).get_definition(text, position, uri)
    references = ReferencesProvider(runtime).get_references(text, position, uri)
    rename = RenameProvider(runtime).rename(text, position, "renamed_symbol", uri)
    symbols = SymbolsProvider(runtime).get_symbols(text, uri)
    links = DocumentLinksProvider(runtime).get_document_links(text, uri)
    highlights = DocumentHighlightProvider().get_highlights(text, position)
    selection = SelectionRangeProvider().get_selection_ranges(text, [position])
    semantic_range = SemanticTokensProvider(runtime).get_semantic_tokens_range(
        text,
        Range(start=position, end=position),
        uri,
    )

    return {
        "hover": hover is not None,
        "definition": definition is not None,
        "references": len(references),
        "rename_files": len(rename.changes) if rename and rename.changes else 0,
        "symbols": len(symbols),
        "document_links": len(links),
        "highlights": len(highlights),
        "selection_ranges": len(selection),
        "semantic_tokens_range": len(semantic_range.data) if semantic_range else 0,
    }


def test_lsp_parity_e2e_request_matrix() -> None:
    classic = _run_matrix("classic", "yara", _pos(4, 10))
    yaral = _run_matrix("yaral", "yaral", _pos(2, 10))
    yarax = _run_matrix("yarax", "yarax", _pos(3, 8))

    for result in [classic, yaral, yarax]:
        assert result["hover"] is True
        assert result["definition"] is True
        assert result["references"] >= 2
        assert result["rename_files"] >= 2
        assert result["symbols"] >= 1
        assert result["highlights"] >= 1
        assert result["selection_ranges"] >= 1
        assert result["semantic_tokens_range"] >= 1

    assert classic["document_links"] >= 2


def test_lsp_parity_e2e_module_and_include_paths() -> None:
    classic_root = FIXTURES / "classic"
    classic_runtime = LspRuntime()
    classic_runtime.update_config({"YARA": {"dialectMode": "yara"}})
    classic_runtime.set_workspace_folders([str(classic_root)])
    classic_common = classic_root / "common.yar"
    classic_text = classic_common.read_text(encoding="utf-8")
    classic_uri = path_to_uri(classic_common)
    classic_runtime.open_document(classic_uri, classic_text)

    module_hover = HoverProvider(classic_runtime).get_hover(classic_text, _pos(0, 9), classic_uri)
    assert module_hover is not None

    yaral_root = FIXTURES / "yaral"
    yaral_runtime = LspRuntime()
    yaral_runtime.update_config({"YARA": {"dialectMode": "yaral"}})
    yaral_runtime.set_workspace_folders([str(yaral_root)])
    yaral_text = (yaral_root / "common.yar").read_text(encoding="utf-8")
    yaral_uri = path_to_uri(yaral_root / "common.yar")
    yaral_runtime.open_document(yaral_uri, yaral_text)
    yaral_symbols = SymbolsProvider(yaral_runtime).get_symbols(yaral_text, yaral_uri)
    assert any(symbol.name == "events" for symbol in yaral_symbols[0].children or [])

    yarax_root = FIXTURES / "yarax"
    yarax_runtime = LspRuntime()
    yarax_runtime.update_config({"YARA": {"dialectMode": "yarax"}})
    yarax_runtime.set_workspace_folders([str(yarax_root)])
    yarax_text = (yarax_root / "user.yar").read_text(encoding="utf-8")
    yarax_uri = path_to_uri(yarax_root / "user.yar")
    yarax_runtime.open_document(yarax_uri, yarax_text)
    references = ReferencesProvider(yarax_runtime).get_references(yarax_text, _pos(3, 8), yarax_uri)
    assert len(references) >= 2


def test_lsp_parity_e2e_cross_file_include_and_module_edges() -> None:
    classic_root = FIXTURES / "classic"
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yara"}})
    runtime.set_workspace_folders([str(classic_root)])
    user = classic_root / "user.yar"
    common = classic_root / "common.yar"
    user_text = user.read_text(encoding="utf-8")
    common_text = common.read_text(encoding="utf-8")
    user_uri = path_to_uri(user)
    common_uri = path_to_uri(common)
    runtime.open_document(user_uri, user_text)
    runtime.open_document(common_uri, common_text)

    include_hover = HoverProvider(runtime).get_hover(user_text, _pos(0, 11), user_uri)
    assert include_hover is not None

    include_def = DefinitionProvider(runtime).get_definition(user_text, _pos(0, 11), user_uri)
    assert include_def is not None
    assert include_def.uri.endswith("/common.yar")

    module_hover = HoverProvider(runtime).get_hover(common_text, _pos(0, 9), common_uri)
    assert module_hover is not None

    links = DocumentLinksProvider(runtime).get_document_links(user_text, user_uri)
    assert len(links) >= 2


def test_lsp_parity_e2e_yaral_cross_file_navigation_and_rename() -> None:
    root = FIXTURES / "yaral"
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yaral"}})
    runtime.set_workspace_folders([str(root)])
    common = root / "common.yar"
    user = root / "user.yar"
    common_text = common.read_text(encoding="utf-8")
    user_text = user.read_text(encoding="utf-8")
    common_uri = path_to_uri(common)
    user_uri = path_to_uri(user)
    runtime.open_document(common_uri, common_text)
    runtime.open_document(user_uri, user_text)

    hover = HoverProvider(runtime).get_hover(user_text, _pos(2, 10), user_uri)
    assert hover is not None

    definition = DefinitionProvider(runtime).get_definition(user_text, _pos(2, 10), user_uri)
    assert definition is not None
    assert definition.uri.endswith("/common.yar")

    references = ReferencesProvider(runtime).get_references(user_text, _pos(2, 10), user_uri)
    assert len(references) >= 2

    rename = RenameProvider(runtime).rename(user_text, _pos(2, 10), "detect_login_v2", user_uri)
    assert rename is not None
    assert len(rename.changes or {}) >= 2


def test_lsp_parity_e2e_classic_module_member_and_outline_edges() -> None:
    root = FIXTURES / "classic"
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yara"}})
    runtime.set_workspace_folders([str(root)])
    common = root / "common.yar"
    text = common.read_text(encoding="utf-8")
    uri = path_to_uri(common)
    runtime.open_document(uri, text)

    hover = HoverProvider(runtime).get_hover(text, _pos(0, 9), uri)
    assert hover is not None

    symbols = SymbolsProvider(runtime).get_symbols(text, uri)
    assert any(symbol.name == 'import "pe"' for symbol in symbols)
    assert any(symbol.name == "shared_rule" for symbol in symbols)

    links = DocumentLinksProvider(runtime).get_document_links(text, uri)
    assert any("pe.html" in (link.target or "") for link in links)
