"""Real tests for YARA-X syntax adapter (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser import Parser
from yaraast.yarax.compatibility_checker import CompatibilityIssue
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.syntax_adapter import YaraXSyntaxAdapter


def _parse_yara(code: str):
    return Parser().parse(dedent(code))


def test_syntax_adapter_removes_duplicate_modifiers() -> None:
    code = """
    private private rule dup_mods {
        condition:
            true
    }
    """
    ast = _parse_yara(code)

    adapter = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")
    adapted, count = adapter.adapt(ast)

    assert count >= 1
    assert adapted.rules[0].modifiers.count("private") == 1


def test_syntax_adapter_pads_base64() -> None:
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
    features.minimum_base64_length = 4
    adapter = YaraXSyntaxAdapter(features, target="yarax")
    adapted, count = adapter.adapt(ast)

    assert count >= 1
    string_def = adapted.rules[0].strings[0]
    assert len(string_def.value) >= 4


def test_syntax_adapter_escapes_regex_braces() -> None:
    code = r"""
    rule bad_regex {
        strings:
            $a = /a{b/
        condition:
            $a
    }
    """
    ast = _parse_yara(code)

    adapter = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")
    adapted, count = adapter.adapt(ast)

    assert count >= 1
    string_def = adapted.rules[0].strings[0]
    assert "\\{" in string_def.regex


def test_generate_migration_guide() -> None:
    adapter = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")
    issues = [
        CompatibilityIssue("error", None, "duplicate_modifier", "Duplicate", ""),
        CompatibilityIssue("error", None, "base64_too_short", "Base64", ""),
        CompatibilityIssue("error", None, "unescaped_brace", "Unescaped", ""),
    ]
    guide = adapter.generate_migration_guide(issues)

    assert "Migration Guide" in guide
    assert "Duplicate Modifiers" in guide
    assert "Base64 Pattern Length" in guide
    assert "Regex Brace Escaping" in guide
