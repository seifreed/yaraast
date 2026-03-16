"""Workspace reporting helpers (IO-only formatting)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click


def print_include_tree(tree: dict[str, Any], indent: int = 0) -> None:
    """Print include tree."""
    prefix = "  " * indent
    click.echo(f"{prefix}- {Path(tree['path']).name}")
    for include in tree["includes"]:
        print_include_tree(include, indent + 1)
