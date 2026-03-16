from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.symbols import SymbolsProvider

FIXTURES = Path(__file__).parent / "fixtures" / "lsp_parity"


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _runtime_for(folder: Path, dialect: str) -> tuple[LspRuntime, str, str]:
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": dialect}})
    runtime.set_workspace_folders([str(folder)])
    user = folder / "user.yar"
    text = user.read_text(encoding="utf-8")
    uri = path_to_uri(user)
    runtime.open_document(uri, text)
    return runtime, text, uri


def test_lsp_parity_classic_requests() -> None:
    runtime, text, uri = _runtime_for(FIXTURES / "classic", "yara")
    hover = HoverProvider(runtime).get_hover(text, _pos(4, 10), uri)
    assert hover is not None and "**shared_rule**" in hover.contents.value

    definition = DefinitionProvider(runtime).get_definition(text, _pos(4, 10), uri)
    assert definition is not None
    assert definition.uri.endswith("/common.yar")

    refs = ReferencesProvider(runtime).get_references(text, _pos(4, 10), uri)
    assert len(refs) >= 2

    rename = RenameProvider(runtime).rename(text, _pos(4, 10), "renamed_rule", uri)
    assert rename is not None and rename.changes is not None
    assert len(rename.changes) == 2

    symbols = SymbolsProvider(runtime).get_symbols(text, uri)
    assert any(symbol.name == "wrapper" for symbol in symbols)


def test_lsp_parity_yaral_requests() -> None:
    runtime, text, uri = _runtime_for(FIXTURES / "yaral", "yaral")
    hover = HoverProvider(runtime).get_hover(text, _pos(2, 10), uri)
    assert hover is not None and "**detect_login**" in hover.contents.value

    definition = DefinitionProvider(runtime).get_definition(text, _pos(2, 10), uri)
    assert definition is not None
    assert definition.uri.endswith("/common.yar")

    refs = ReferencesProvider(runtime).get_references(text, _pos(2, 10), uri)
    assert len(refs) >= 2

    rename = RenameProvider(runtime).rename(text, _pos(2, 10), "detect_login_new", uri)
    assert rename is not None and rename.changes is not None
    assert len(rename.changes) == 2

    symbols = SymbolsProvider(runtime).get_symbols(text, uri)
    child_names = {child.name for child in (symbols[0].children or [])}
    assert {"condition"} <= child_names


def test_lsp_parity_yarax_requests() -> None:
    runtime, text, uri = _runtime_for(FIXTURES / "yarax", "yarax")
    hover = HoverProvider(runtime).get_hover(text, _pos(3, 8), uri)
    assert hover is not None and "**helper**" in hover.contents.value

    definition = DefinitionProvider(runtime).get_definition(text, _pos(3, 8), uri)
    assert definition is not None
    assert definition.uri.endswith("/common.yar")

    refs = ReferencesProvider(runtime).get_references(text, _pos(3, 8), uri)
    assert len(refs) >= 2

    rename = RenameProvider(runtime).rename(text, _pos(3, 8), "helper_new", uri)
    assert rename is not None and rename.changes is not None
    assert len(rename.changes) == 2

    symbols = SymbolsProvider(runtime).get_symbols(text, uri)
    assert symbols and symbols[0].name == "sample"
