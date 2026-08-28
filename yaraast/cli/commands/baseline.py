"""Baseline management commands."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.baseline import Baseline
from yaraast.check import check_path
from yaraast.project_config import ProjectConfig


@click.group()
def baseline() -> None:
    """Manage diagnostic baselines."""


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", "-o", required=True, type=click.Path(path_type=Path))
def create(path: Path, output_path: Path) -> None:
    """Create a baseline from the current diagnostics."""
    config = ProjectConfig.load(path if path.is_dir() else path.parent)
    result = check_path(path, config)
    baseline_result = Baseline.from_result(result)
    content_path = output_path
    baseline_result.write(content_path, result.diagnostics)
    click.echo(f"Baseline written to: {content_path}")
