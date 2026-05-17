"""Shared helpers for string diagram modules."""

from __future__ import annotations


def modifier_names(modifiers) -> list[str]:
    """Return modifier names preserving compatibility with string/object inputs."""
    names: list[str] = []
    for mod in modifiers:
        if hasattr(mod, "name") and getattr(mod, "value", None) is None:
            names.append(mod.name)
        else:
            names.append(str(mod))
    return names
