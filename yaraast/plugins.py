"""Local plugin discovery and contracts for YARAAST extensions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Protocol

PLUGIN_API_VERSION = "1"
PLUGIN_GROUPS = (
    "yaraast.diagnostics",
    "yaraast.policies",
    "yaraast.reporters",
    "yaraast.targets",
    "yaraast.test_providers",
    "yaraast.transforms",
)


class DiagnosticProvider(Protocol):
    """Plugin contract for custom diagnostic providers."""

    api_version: str

    def analyze(self, project: Any, context: Any) -> Iterable[Any]:
        """Return diagnostics for a project analysis context."""


@dataclass(frozen=True)
class PluginInfo:
    """Metadata and optional validation error for one installed plugin."""

    name: str
    group: str
    value: str
    api_version: str | None = None
    error: str | None = None


def discover_plugins() -> tuple[PluginInfo, ...]:
    """Discover installed YARAAST plugins without importing their code."""
    plugins = [
        PluginInfo(item.name, group, item.value)
        for group in PLUGIN_GROUPS
        for item in _group_entry_points(group)
    ]
    return tuple(sorted(plugins, key=lambda item: (item.group, item.name)))


def inspect_plugin(name: str) -> PluginInfo:
    """Load and validate one plugin by entry-point name."""
    matches = tuple(item for item in _all_entry_points() if item.name == name)
    if not matches:
        raise ValueError(f"plugin not found: {name}")
    if len(matches) > 1:
        groups = ", ".join(sorted(item.group for item in matches))
        raise ValueError(f"plugin name is ambiguous across groups: {groups}")
    item = matches[0]
    try:
        loaded = item.load()
        version = getattr(loaded, "api_version", None)
        if not isinstance(version, str) or not version:
            raise ValueError("plugin must declare a non-empty api_version")
        _validate_api_version(version)
    except Exception as exc:
        return PluginInfo(item.name, item.group, item.value, error=str(exc))
    return PluginInfo(item.name, item.group, item.value, api_version=version)


def doctor_plugins() -> tuple[PluginInfo, ...]:
    """Load and validate every installed plugin."""
    return tuple(inspect_plugin(item.name) for item in discover_plugins())


def _all_entry_points() -> tuple[EntryPoint, ...]:
    return tuple(item for group in PLUGIN_GROUPS for item in _group_entry_points(group))


def _group_entry_points(group: str) -> tuple[EntryPoint, ...]:
    return tuple(entry_points(group=group))


def _validate_api_version(version: str) -> None:
    if version.split(".", 1)[0] != PLUGIN_API_VERSION:
        raise ValueError(
            f"plugin api_version {version!r} is incompatible with SDK {PLUGIN_API_VERSION}"
        )
