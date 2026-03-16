"""Common handler utilities for libyara commands."""

from __future__ import annotations

import contextlib

import click

from yaraast.cli.libyara_reporting import LibYaraCommandError, handle_libyara_error


def run_or_abort(fn, console, *args, **kwargs):
    """Run a callable, aborting on libyara errors."""
    try:
        return fn(*args, **kwargs)
    except LibYaraCommandError:
        raise click.Abort from None
    except Exception as error:
        with contextlib.suppress(LibYaraCommandError):
            handle_libyara_error(console, error)
        raise click.Abort from None
