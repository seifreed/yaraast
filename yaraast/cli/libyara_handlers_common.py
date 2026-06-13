"""Common handler utilities for libyara commands."""

from __future__ import annotations

from collections.abc import Callable
import contextlib
from typing import Any

import click

from yaraast.cli.libyara_reporting import LibYaraCommandError, handle_libyara_error


def run_or_abort[**P, R](
    fn: Callable[P, R],
    console: Any,
    *args: P.args,
    **kwargs: P.kwargs,
) -> R:
    """Run a callable, aborting on libyara errors."""
    try:
        return fn(*args, **kwargs)
    except LibYaraCommandError as error:
        raise click.Abort from error
    except Exception as error:
        with contextlib.suppress(LibYaraCommandError):
            handle_libyara_error(console, error)
        raise click.Abort from error
