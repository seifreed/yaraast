"""Additional branch coverage for workspace symbols provider (no mocks)."""

from __future__ import annotations

from pathlib import Path
from stat import S_IFREG
from tempfile import TemporaryDirectory
from typing import Any, cast

from lsprotocol.types import Position, Range, SymbolInformation
import pytest

from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider


def test_workspace_symbols_empty_and_exception_paths() -> None:
    provider = WorkspaceSymbolsProvider()
    assert provider.get_workspace_symbols("x") == []

    provider.set_workspace_root("/definitely/not/found")
    assert provider.get_workspace_symbols("x") == []

    class ExplodingProvider(WorkspaceSymbolsProvider):
        def _get_symbols_from_file(self, file_path: Path) -> list[SymbolInformation]:
            raise RuntimeError("boom")

    with TemporaryDirectory() as tmp:
        p = Path(tmp)
        (p / "a.yar").write_text("rule a { condition: true }", encoding="utf-8")
        exp = ExplodingProvider()
        exp.set_workspace_root(tmp)
        assert exp.get_workspace_symbols("") == []


@pytest.mark.parametrize("root_path", ["", "   ", "\t"])
def test_workspace_symbols_rejects_empty_workspace_root(root_path: str) -> None:
    provider = WorkspaceSymbolsProvider()

    with pytest.raises(ValueError, match="root_path must not be empty"):
        provider.set_workspace_root(root_path)


@pytest.mark.parametrize("root_path", [None, False, 123, object(), b"."])
def test_workspace_symbols_rejects_invalid_workspace_root_types(root_path: Any) -> None:
    provider = WorkspaceSymbolsProvider()

    with pytest.raises(TypeError, match="root_path must be a string or path-like object"):
        provider.set_workspace_root(cast(Any, root_path))


def test_workspace_symbols_rejects_file_workspace_root(tmp_path: Path) -> None:
    root_path = tmp_path / "not_a_directory"
    root_path.write_text("not a directory", encoding="utf-8")
    provider = WorkspaceSymbolsProvider()

    with pytest.raises(ValueError, match="root_path must not be a file"):
        provider.set_workspace_root(root_path)


def test_workspace_symbols_rejects_inaccessible_workspace_root() -> None:
    provider = WorkspaceSymbolsProvider()

    with pytest.raises(ValueError, match="path could not be accessed"):
        provider.set_workspace_root("a" * 5000)


def test_workspace_symbols_accepts_pathlike_workspace_root(tmp_path: Path) -> None:
    provider = WorkspaceSymbolsProvider()

    provider.set_workspace_root(tmp_path)

    assert provider.workspace_root == tmp_path


def test_workspace_symbols_cache_helpers_and_not_found_paths() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        f = root / "s.yar"
        f.write_text(
            """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip(),
            encoding="utf-8",
        )
        yarax = root / "native.yarax"
        yarax.write_text("rule native_yarax { condition: true }\n", encoding="utf-8")
        bad = root / "bad.yar"
        bad.write_text('rule bad { strings: $a = "x" condition: }', encoding="utf-8")

        provider = WorkspaceSymbolsProvider()
        provider.set_workspace_root(tmp)

        syms = provider.get_workspace_symbols("")
        assert syms
        names = {s.name for s in syms}
        assert "sample" in names
        assert "native_yarax" in names
        assert "$a" in names

        # Cache hit path
        first = provider._get_symbols_from_file(f)
        second = provider._get_symbols_from_file(f)
        assert first == second
        first.clear()
        assert provider._get_symbols_from_file(f) == second

        # Parse failure path inside _get_symbols_from_file should be swallowed.
        assert provider._get_symbols_from_file(bad) == []
        assert provider._get_symbols_from_file(Path("a" * 5000)) == []

        # Query filter path
        filtered = provider.get_workspace_symbols("sam")
        assert all("sam" in s.name.lower() for s in filtered)

        # Not found path through public query filter
        assert provider.get_workspace_symbols("missing-symbol") == []

        # Cache mutation helpers
        key = str(f)
        assert key in provider.symbol_cache
        provider.invalidate_file(Path(key))
        assert key not in provider.symbol_cache
        provider.clear_cache()
        assert provider.symbol_cache == {}


def test_workspace_symbols_discovers_uppercase_suffix_files() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        upper = root / "UPPER.YAR"
        upper.write_text("rule upper { condition: true }\n", encoding="utf-8")

        provider = WorkspaceSymbolsProvider()
        provider.set_workspace_root(tmp)

        names = {symbol.name for symbol in provider.get_workspace_symbols("")}
        assert "upper" in names


def test_workspace_symbols_cache_uses_nanosecond_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yara_file = tmp_path / "sample.yar"
    yara_file.write_text("rule one { condition: true }\n", encoding="utf-8")

    provider = WorkspaceSymbolsProvider()
    provider.set_workspace_root(tmp_path)

    first = {symbol.name for symbol in provider.get_workspace_symbols("")}
    assert "one" in first

    original_stat = Path.stat
    cached_ns = yara_file.stat().st_mtime_ns

    class _FixedStat:
        st_mode = S_IFREG
        st_mtime = 1.0
        st_mtime_ns = cached_ns + 1

    def fake_stat(self: Path, *, follow_symlinks: bool = True) -> object:
        if self == yara_file:
            return _FixedStat()
        return original_stat(self, follow_symlinks=follow_symlinks)

    yara_file.write_text("rule two { condition: true }\n", encoding="utf-8")
    monkeypatch.setattr(Path, "stat", fake_stat)

    second = {symbol.name for symbol in provider.get_workspace_symbols("")}

    assert "two" in second
    assert "one" not in second


def test_workspace_symbols_returns_empty_list_on_mid_file_symbol_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yara_file = tmp_path / "sample.yar"
    yara_file.write_text("rule sample { condition: true }\n", encoding="utf-8")

    provider = WorkspaceSymbolsProvider()
    provider.set_workspace_root(tmp_path)

    class _BrokenSymbol:
        kind = "rule"
        name = "broken"
        container_name = None

        def to_symbol_information(self) -> SymbolInformation:
            raise RuntimeError("boom")

    def fake_symbols(self: object) -> list[object]:
        return [
            SymbolRecord(
                "sample",
                "rule",
                f"file://{yara_file}",
                Range(Position(line=0, character=0), Position(line=0, character=6)),
            ),
            _BrokenSymbol(),
        ]

    monkeypatch.setattr("yaraast.lsp.document_context.DocumentContext.symbols", fake_symbols)

    assert provider._get_symbols_from_file(yara_file) == []
    assert provider.symbol_cache == {}


@pytest.mark.parametrize("file_path", ["", "   ", "\t"])
def test_workspace_symbols_rejects_empty_invalidate_file_path(file_path: str) -> None:
    provider = WorkspaceSymbolsProvider()

    with pytest.raises(ValueError, match="file_path must not be empty"):
        provider.invalidate_file(file_path)


@pytest.mark.parametrize("file_path", [None, False, 123, object(), b"sample.yar"])
def test_workspace_symbols_rejects_invalid_invalidate_file_path_types(file_path: Any) -> None:
    provider = WorkspaceSymbolsProvider()

    with pytest.raises(TypeError, match="file_path must be a string or path-like object"):
        provider.invalidate_file(cast(Any, file_path))


def test_workspace_symbols_rejects_non_string_query_before_scanning(tmp_path: Path) -> None:
    yara_file = tmp_path / "a.yar"
    yara_file.write_text("rule a { condition: true }\n", encoding="utf-8")

    provider = WorkspaceSymbolsProvider()
    provider.set_workspace_root(str(tmp_path))

    with pytest.raises(TypeError, match="Workspace symbol query must be a string"):
        provider.get_workspace_symbols(cast(Any, object()))

    assert provider.symbol_cache == {}

    runtime_provider = WorkspaceSymbolsProvider(LspRuntime())
    with pytest.raises(TypeError, match="Workspace symbol query must be a string"):
        runtime_provider.get_workspace_symbols(cast(Any, object()))


def test_workspace_symbols_runtime_provider_clear_cache_clears_runtime_cache() -> None:
    runtime = LspRuntime()
    runtime.open_document("file:///sample.yar", "rule sample { condition: true }\n")
    provider = WorkspaceSymbolsProvider(runtime)

    assert provider.get_workspace_symbols("")
    assert runtime.cache.workspace_symbol_cache

    provider.clear_cache()

    assert runtime.cache.workspace_symbol_cache == {}


def test_workspace_symbols_runtime_provider_invalidate_file_clears_runtime_cache() -> None:
    uri = "file:///sample.yar"
    runtime = LspRuntime()
    runtime.open_document(uri, "rule sample { condition: true }\n")
    provider = WorkspaceSymbolsProvider(runtime)

    assert provider.get_workspace_symbols("")
    assert runtime.cache.workspace_symbol_cache

    provider.invalidate_file(uri)

    assert runtime.cache.workspace_symbol_cache == {}
