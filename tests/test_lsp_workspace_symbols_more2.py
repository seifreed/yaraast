"""Additional branch coverage for workspace symbols provider (no mocks)."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider


def test_workspace_symbols_empty_and_exception_paths() -> None:
    provider = WorkspaceSymbolsProvider()
    assert provider.get_workspace_symbols("x") == []

    provider.set_workspace_root("/definitely/not/found")
    assert provider.get_workspace_symbols("x") == []

    class ExplodingProvider(WorkspaceSymbolsProvider):
        def _get_symbols_from_file(self, file_path: Path):
            raise RuntimeError("boom")

    with TemporaryDirectory() as tmp:
        p = Path(tmp)
        (p / "a.yar").write_text("rule a { condition: true }", encoding="utf-8")
        exp = ExplodingProvider()
        exp.set_workspace_root(tmp)
        assert exp.get_workspace_symbols("") == []


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
        bad = root / "bad.yar"
        bad.write_text('rule bad { strings: $a = "x" condition: }', encoding="utf-8")

        provider = WorkspaceSymbolsProvider()
        provider.set_workspace_root(tmp)

        syms = provider.get_workspace_symbols("")
        assert syms
        names = {s.name for s in syms}
        assert "sample" in names
        assert "$a" in names

        # Cache hit path
        first = provider._get_symbols_from_file(f)
        second = provider._get_symbols_from_file(f)
        assert first == second

        # Parse failure path inside _get_symbols_from_file should be swallowed.
        assert provider._get_symbols_from_file(bad) == []

        # Query filter path
        filtered = provider.get_workspace_symbols("sam")
        assert all("sam" in s.name.lower() for s in filtered)

        # Not found path through public query filter
        assert provider.get_workspace_symbols("missing-symbol") == []

        # Cache mutation helpers
        key = str(f)
        assert key in provider.symbol_cache
        provider.invalidate_file(key)
        assert key not in provider.symbol_cache
        provider.clear_cache()
        assert provider.symbol_cache == {}
