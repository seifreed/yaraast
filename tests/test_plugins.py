"""Regression tests for local plugin discovery and validation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast import plugins


def test_plugin_discovery_is_grouped_and_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    points = {
        "yaraast.diagnostics": [SimpleNamespace(name="z", value="mod:z")],
        "yaraast.policies": [SimpleNamespace(name="a", value="mod:a")],
    }
    monkeypatch.setattr(plugins, "entry_points", lambda group: points.get(group, ()))

    assert [(item.group, item.name) for item in plugins.discover_plugins()] == [
        ("yaraast.diagnostics", "z"),
        ("yaraast.policies", "a"),
    ]


def test_plugin_doctor_reports_missing_api_version(monkeypatch: pytest.MonkeyPatch) -> None:
    entry_point = SimpleNamespace(
        name="broken",
        group="yaraast.diagnostics",
        value="mod:broken",
        load=lambda: object(),
    )
    monkeypatch.setattr(
        plugins, "entry_points", lambda group: (entry_point,) if group == entry_point.group else ()
    )

    result = plugins.doctor_plugins()

    assert result[0].error == "plugin must declare a non-empty api_version"
