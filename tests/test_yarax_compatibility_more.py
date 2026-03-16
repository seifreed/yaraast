"""Real tests for YARA-X compatibility checker (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser import Parser
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures


def _parse_yara(code: str):
    return Parser().parse(dedent(code))


def test_compatibility_duplicate_modifiers() -> None:
    code = """
    private private rule dup_mods {
        condition:
            true
    }
    """
    ast = _parse_yara(code)
    checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())
    issues = checker.check(ast)

    assert any(i.issue_type == "duplicate_modifier" for i in issues)


def test_compatibility_base64_length() -> None:
    code = """
    rule short_base64 {
        strings:
            $a = "aa" base64
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    features = YaraXFeatures.yarax_strict()
    features.minimum_base64_length = 3
    checker = YaraXCompatibilityChecker(features)

    issues = checker.check(ast)
    assert any(i.issue_type == "base64_too_short" for i in issues)


def test_compatibility_regex_unescaped_brace() -> None:
    code = r"""
    rule bad_regex {
        strings:
            $a = /a{b/
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())

    issues = checker.check(ast)
    assert any(i.issue_type == "unescaped_brace" for i in issues)
