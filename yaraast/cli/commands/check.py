"""Repository check command."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.check import check_passes, check_path
from yaraast.cli.utils import write_text
from yaraast.diagnostics import Severity
from yaraast.project_config import ProjectConfig
from yaraast.reporters import REPORTERS


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--profile", default="default", show_default=True, help="Configuration profile")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(sorted(REPORTERS)),
    default="text",
    show_default=True,
    help="Diagnostic output format",
)
@click.option("--output", "output_path", type=click.Path(path_type=Path), help="Report file")
@click.option(
    "--fail-on",
    type=click.Choice([severity.value for severity in Severity]),
    help="Override the configured quality-gate severity",
)
def check(
    path: Path,
    profile: str,
    output_format: str,
    output_path: Path | None,
    fail_on: str | None,
) -> None:
    """Parse and validate a rule file or repository."""
    config = ProjectConfig.load(path if path.is_dir() else path.parent, profile)
    if fail_on is not None:
        from dataclasses import replace

        config = replace(
            config,
            quality_gate=replace(config.quality_gate, fail_on=Severity(fail_on)),
        )
    result = check_path(path, config, profile=profile)
    rendered = REPORTERS[output_format]().render(result)
    if output_path is None:
        click.echo(rendered, nl=False)
    else:
        write_text(output_path, rendered)
    if not check_passes(result, config):
        raise click.exceptions.Exit(1)
