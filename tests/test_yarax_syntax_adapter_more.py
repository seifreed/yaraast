"""Real tests for YARA-X syntax adapter (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.ast.base import YaraFile
from yaraast.ast.strings import PlainString, RegexString
from yaraast.parser import Parser
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.syntax_adapter import YaraXSyntaxAdapter


def _parse_yara(code: str) -> YaraFile:
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
    assert sum(1 for m in adapted.rules[0].modifiers if str(m) == "private") == 1


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
    assert isinstance(string_def, PlainString)
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
    assert isinstance(string_def, RegexString)
    assert "\\{" in string_def.regex
