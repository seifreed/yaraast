"""Compatibility wrappers for calling LSP providers with optional URI support."""

from __future__ import annotations


def call_with_optional_uri(method, text: str, uri: str):
    """Call a provider method, falling back when the implementation lacks URI support."""
    try:
        return method(text, uri)
    except TypeError:
        return method(text)


def call_range_with_optional_uri(method, text: str, range_, uri: str):
    """Call a range provider method, falling back when URI is unsupported."""
    try:
        return method(text, range_, uri)
    except TypeError:
        return method(text, range_)
