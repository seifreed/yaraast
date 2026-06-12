"""Helpers for tracking YARA loop-local variable scopes.

YARA ``for`` expressions can declare several loop variables at once
(``for any i, j in ...``). Splitting such a declaration into its individual
names is needed by every visitor that tracks local scopes, so the splitter is
defined once here instead of copied into each analyzer.
"""

from __future__ import annotations

import re

from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH
from yaraast.string_references import normalize_string_reference_id

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)
_YARA_CONTEXTUAL_LOCAL_KEYWORDS = frozenset({"as", "include"})


def _validate_local_identifier(name: str) -> str:
    if (
        len(name) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(name) is not None
        and (name not in _YARA_KEYWORDS or name in _YARA_CONTEXTUAL_LOCAL_KEYWORDS)
    ):
        return name
    msg = f"Invalid local variable identifier: {name}"
    raise ValueError(msg)


def validate_local_identifier(name: object, *, allow_string_identifier: bool = False) -> str:
    """Validate one local variable name and return its normalized spelling."""
    if not isinstance(name, str):
        msg = "Local variable name must be a string"
        raise TypeError(msg)
    if not name.strip():
        msg = "Local variable name must not be empty"
        raise ValueError(msg)
    if allow_string_identifier and name.startswith("$"):
        try:
            return normalize_string_reference_id(name, allow_wildcard=False)
        except ValueError:
            msg = f"Invalid local variable identifier: {name}"
            raise ValueError(msg) from None
    return _validate_local_identifier(name)


def local_name_variants(name: str, *, allow_string_identifier: bool = False) -> set[str]:
    """Split a (possibly comma-joined) loop declaration into its variable names."""
    if not isinstance(name, str):
        msg = "Local variable name must be a string"
        raise TypeError(msg)
    if not name.strip():
        msg = "Local variable name must not be empty"
        raise ValueError(msg)
    names = [part.strip() for part in name.split(",")]
    if any(not local_name for local_name in names):
        msg = f"Local variable declaration must not contain empty entries: {name}"
        raise ValueError(msg)
    variants: set[str] = set()
    for local_name in names:
        variants.add(
            validate_local_identifier(
                local_name,
                allow_string_identifier=allow_string_identifier,
            )
        )
    return variants
