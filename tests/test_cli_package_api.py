"""Tests for the top-level yaraast.cli package API."""

from __future__ import annotations

import importlib

import pytest


def test_cli_package_no_longer_exposes_cli_attribute() -> None:
    module = importlib.import_module("yaraast.cli")
    with pytest.raises(AttributeError):
        _ = module.cli
