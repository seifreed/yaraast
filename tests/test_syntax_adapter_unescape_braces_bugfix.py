"""Regression tests for escape-aware brace unescaping in the YARA-X adapter.

The previous implementation used a blind ``str.replace`` that matched a
``\\{`` substring even when the leading backslash was itself the second half
of an escaped-backslash (``\\\\``). That corrupted a quantifier applied to a
literal backslash, e.g. ``\\\\{2,3}`` (two-or-three backslashes) became
``\\{2,3}`` (an escaped brace followed by ``2,3}``).
"""

from __future__ import annotations

from yaraast.ast.strings import RegexString
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.syntax_adapter import YaraXSyntaxAdapter


def _adapter() -> YaraXSyntaxAdapter:
    return YaraXSyntaxAdapter(YaraXFeatures.yara_compatible(), target="yara")


def test_escaped_literal_braces_are_unescaped() -> None:
    # Documented behaviour: a backslash that escapes a brace is removed.
    assert _adapter()._unescape_braces(r"\{x\}") == "{x}"


def test_quantified_literal_backslash_is_preserved() -> None:
    # "\\{2,3}" is two-or-three literal backslashes; the brace is a quantifier
    # and must not be touched, nor may either backslash be dropped.
    assert _adapter()._unescape_braces(r"\\{2,3}") == r"\\{2,3}"


def test_escaped_backslash_then_escaped_brace() -> None:
    # "\\\{" is a literal backslash followed by an escaped literal brace.
    assert _adapter()._unescape_braces(r"\\\{") == r"\\{"


def test_trailing_lone_backslash_is_kept() -> None:
    assert _adapter()._unescape_braces("\\") == "\\"


def test_visit_regex_string_preserves_quantified_backslash() -> None:
    adapter = _adapter()
    node = RegexString(identifier="$r", regex=r"\\{2,3}", modifiers=[])
    adapted = adapter.visit_regex_string(node)
    assert adapted.regex == r"\\{2,3}"
