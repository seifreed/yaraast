"""Helpers for tracking YARA loop-local variable scopes.

YARA ``for`` expressions can declare several loop variables at once
(``for any i, j in ...``). Splitting such a declaration into its individual
names is needed by every visitor that tracks local scopes, so the splitter is
defined once here instead of copied into each analyzer.
"""

from __future__ import annotations


def local_name_variants(name: str) -> set[str]:
    """Split a (possibly comma-joined) loop declaration into its variable names."""
    if not isinstance(name, str):
        msg = "Local variable name must be a string"
        raise TypeError(msg)
    names = [part.strip() for part in name.split(",")]
    return {local_name for local_name in names if local_name}
