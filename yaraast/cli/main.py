"""CLI interface for YARA AST - Router and command delegation.

This module serves as the main CLI entry point, delegating to specific command modules.
The actual command implementations are in cli/commands/ subdirectory.
"""

import logging
from time import perf_counter
from typing import Any

import click

from yaraast import __version__
from yaraast.cli.command_registry import register_commands
from yaraast.logging_config import configure_logging, log_context

__all__ = ["cli"]


logger = logging.getLogger(__name__)


class LoggingGroup(click.Group):
    """Record one operational event around each CLI command invocation."""

    def invoke(self, ctx: click.Context) -> Any:
        operation = "cli"
        started = perf_counter()
        configure_logging(str(ctx.params["log_level"]), str(ctx.params["log_format"]))
        with log_context(operation=operation):
            try:
                result = super().invoke(ctx)
            except click.Abort as exc:
                operation = ctx.invoked_subcommand or operation
                with log_context(operation=operation):
                    logger.warning(
                        "CLI command aborted",
                        extra={
                            "event_name": "cli.command.failed",
                            "outcome": "error",
                            "duration_ms": (perf_counter() - started) * 1000,
                            "error_type": type(exc).__name__,
                        },
                        exc_info=logger.isEnabledFor(logging.DEBUG),
                    )
                raise
            except click.ClickException as exc:
                operation = ctx.invoked_subcommand or operation
                with log_context(operation=operation):
                    logger.warning(
                        "CLI command failed",
                        extra={
                            "event_name": "cli.command.failed",
                            "outcome": "error",
                            "duration_ms": (perf_counter() - started) * 1000,
                            "error_type": type(exc).__name__,
                        },
                        exc_info=logger.isEnabledFor(logging.DEBUG),
                    )
                raise
            except (click.exceptions.Exit, SystemExit) as exc:
                operation = ctx.invoked_subcommand or operation
                exit_code = exc.exit_code if isinstance(exc, click.exceptions.Exit) else exc.code
                outcome = "success" if exit_code in (None, 0) else "error"
                with log_context(operation=operation):
                    logger.log(
                        logging.INFO if outcome == "success" else logging.WARNING,
                        "CLI command exited",
                        extra={
                            "event_name": "cli.command.exited",
                            "outcome": outcome,
                            "duration_ms": (perf_counter() - started) * 1000,
                            "error_type": type(exc).__name__,
                            "error_code": exit_code,
                        },
                    )
                raise
            except Exception:
                operation = ctx.invoked_subcommand or operation
                with log_context(operation=operation):
                    logger.exception(
                        "CLI command failed unexpectedly",
                        extra={
                            "event_name": "cli.command.failed",
                            "outcome": "error",
                            "duration_ms": (perf_counter() - started) * 1000,
                        },
                    )
                raise
            operation = ctx.invoked_subcommand or "help"
            with log_context(operation=operation):
                logger.info(
                    "CLI command completed",
                    extra={
                        "event_name": "cli.command.completed",
                        "outcome": "success",
                        "duration_ms": (perf_counter() - started) * 1000,
                    },
                )
            return result


@click.group(cls=LoggingGroup)
@click.version_option(version=__version__, prog_name="yaraast")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False),
    default="WARNING",
    envvar="YARAAST_LOG_LEVEL",
    show_default=True,
    help="Set the diagnostic log level.",
)
@click.option(
    "--log-format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    envvar="YARAAST_LOG_FORMAT",
    show_default=True,
    help="Set the diagnostic log format.",
)
def cli(log_level: str, log_format: str) -> None:
    """YARA AST - Parse and manipulate YARA rules."""
    operation = click.get_current_context().invoked_subcommand or "help"
    logger.info(
        "CLI command started",
        extra={
            "event_name": "cli.command.started",
            "operation": operation,
        },
    )


register_commands(cli)


if __name__ == "__main__":
    cli()
