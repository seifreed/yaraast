"""Handlers for libyara CLI commands."""

from __future__ import annotations

from yaraast.cli.libyara_handlers_common import run_or_abort
from yaraast.cli.libyara_handlers_compile import handle_compile
from yaraast.cli.libyara_handlers_optimize import handle_optimize
from yaraast.cli.libyara_handlers_scan import handle_scan

__all__ = [
    "handle_compile",
    "handle_optimize",
    "handle_scan",
    "run_or_abort",
]
