"""Coverage for RuleTransformer.rename_strings across expression node types.

Renaming strings traverses at/in/of/for-of, binary/unary/parenthesised
expressions, wildcards, counts/offsets/lengths and string sets. Driving a rule
whose condition uses all of them exercises the rename traversal helpers.
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.builder.ast_transformer import RuleTransformer
from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.source import parse_yara_source

RICH_RULE = """rule r {
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        $a at 0 and $a in (0..10) and any of ($a, $b) and
        for any of ($a*) : ( $ ) and #a > 0 and !a > 0 and @a[1] > 0 and
        not ($b) and ($a and $b)
}"""


def test_rename_strings_rewrites_all_reference_forms() -> None:
    rule = parse_yara_source(RICH_RULE).rules[0]

    renamed = RuleTransformer(rule).rename_strings({"$a": "$alpha", "$b": "$beta"}).build()

    generated = CodeGenerator().generate(YaraFile(rules=[renamed]))
    assert "$alpha" in generated
    assert "$beta" in generated
    # Original string definitions are renamed too, so no bare $a/$b token remains.
    assert "$a " not in generated
    assert "$b " not in generated


def test_rename_strings_noop_when_mapping_absent() -> None:
    rule = parse_yara_source(RICH_RULE).rules[0]

    renamed = RuleTransformer(rule).rename_strings({"$missing": "$other"}).build()

    generated = CodeGenerator().generate(YaraFile(rules=[renamed]))
    assert "$a" in generated
    assert "$b" in generated
