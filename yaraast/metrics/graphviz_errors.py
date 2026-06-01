"""Graphviz error classification helpers."""

from __future__ import annotations


def is_graphviz_error(error: Exception) -> bool:
    """Check if an exception is caused by missing or failed Graphviz execution."""
    if isinstance(error, ModuleNotFoundError) and error.name == "graphviz":
        return True

    error_type = type(error).__name__
    if error_type in ("ExecutableNotFound", "CalledProcessError"):
        return True

    error_text = str(error).lower()
    graphviz_indicators = [
        "executablenotfound",
        "failed to execute",
        "requires the 'graphviz' python package",
        "graphviz executables",
    ]
    if any(indicator in error_text for indicator in graphviz_indicators):
        return True

    return "no such file or directory" in error_text and (
        "posixpath('dot')" in error_text
        or '"dot"' in error_text
        or "'dot'" in error_text
        or "graphviz" in error_text
    )
