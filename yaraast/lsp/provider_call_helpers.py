"""Compatibility wrappers for calling LSP providers with optional URI support."""

from __future__ import annotations

from collections.abc import Callable
import inspect
from typing import Any


def _accepts_positional_count(method: Callable[..., Any], count: int) -> bool:
    signature = inspect.signature(method)
    parameters = signature.parameters.values()
    positional = {
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    }
    required = 0
    accepted = 0
    for parameter in parameters:
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            return True
        if parameter.kind not in positional:
            continue
        accepted += 1
        if parameter.default is inspect.Parameter.empty:
            required += 1
    return required <= count <= accepted


def call_with_optional_uri(method: Callable[..., Any], text: str, uri: str) -> Any:
    """Call a provider method, falling back when the implementation lacks URI support."""
    if _accepts_positional_count(method, 2):
        return method(text, uri)
    return method(text)


def call_range_with_optional_uri(
    method: Callable[..., Any],
    text: str,
    range_: Any,
    uri: str,
) -> Any:
    """Call a range provider method, falling back when URI is unsupported."""
    if _accepts_positional_count(method, 3):
        return method(text, range_, uri)
    return method(text, range_)
