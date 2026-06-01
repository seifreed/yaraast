"""Optional yara-python import helpers."""

from __future__ import annotations


def is_missing_yara_import(exc: ImportError) -> bool:
    """Return whether an ImportError means the optional yara module itself is missing."""
    return (exc.name or "") == "yara"
