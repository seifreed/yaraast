"""CLI module for YARA AST."""

from __future__ import annotations

from typing import Any

__all__ = ["cli"]


def __getattr__(name: str) -> Any:
    if name == "cli":
        from yaraast.cli.main import cli

        return cli
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
