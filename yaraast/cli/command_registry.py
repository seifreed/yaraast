"""Registration helpers for the root CLI command tree."""

from __future__ import annotations

import click

from yaraast.cli.commands.analyze import analyze
from yaraast.cli.commands.bench_cmd import bench
from yaraast.cli.commands.diff_cmd import diff
from yaraast.cli.commands.fluent import fluent
from yaraast.cli.commands.fmt_cmd import fmt
from yaraast.cli.commands.format_cmd import format_yara, validate_syntax
from yaraast.cli.commands.libyara_cmd import libyara
from yaraast.cli.commands.lsp import lsp
from yaraast.cli.commands.metrics import metrics
from yaraast.cli.commands.optimize import optimize_cmd
from yaraast.cli.commands.parse_cmd import parse
from yaraast.cli.commands.performance import performance
from yaraast.cli.commands.performance_check import performance_check_cmd
from yaraast.cli.commands.roundtrip import roundtrip
from yaraast.cli.commands.semantic import semantic
from yaraast.cli.commands.serialize import serialize
from yaraast.cli.commands.validate import validate
from yaraast.cli.commands.workspace import workspace
from yaraast.cli.commands.yaral import yaral
from yaraast.cli.commands.yarax import yarax

CLI_COMMANDS = (
    parse,
    (format_yara, "format"),
    fmt,
    validate,
    validate_syntax,
    analyze,
    metrics,
    semantic,
    performance,
    performance_check_cmd,
    bench,
    diff,
    optimize_cmd,
    libyara,
    serialize,
    roundtrip,
    yaral,
    yarax,
    workspace,
    fluent,
    lsp,
)


def register_commands(cli: click.Group) -> None:
    """Register all top-level commands on the root Click group."""
    for command in CLI_COMMANDS:
        if isinstance(command, tuple):
            cli.add_command(command[0], name=command[1])
        else:
            cli.add_command(command)
