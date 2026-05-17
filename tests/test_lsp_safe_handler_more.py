"""Additional tests for LSP safe handler behavior."""

from __future__ import annotations

from typing import Any

from yaraast.lsp.safe_handler import lsp_safe_handler


def test_lsp_safe_handler_returns_fresh_mutable_defaults() -> None:
    @lsp_safe_handler(default=[])
    def failing_handler() -> list[str]:
        raise ValueError("boom")

    first = failing_handler()
    first.append("leaked")

    second = failing_handler()

    assert first == ["leaked"]
    assert second == []
    assert second is not first


def test_lsp_safe_handler_preserves_immutable_default_identity() -> None:
    sentinel: Any = object()

    @lsp_safe_handler(default=sentinel)
    def failing_handler() -> Any:
        raise ValueError("boom")

    assert failing_handler() is sentinel
