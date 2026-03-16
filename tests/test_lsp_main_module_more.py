"""Real tests for LSP __main__ module (no mocks)."""

from __future__ import annotations

import importlib


def test_lsp_main_importable() -> None:
    mod = importlib.import_module("yaraast.lsp.__main__")
    assert hasattr(mod, "main")
