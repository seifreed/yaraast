"""Coverage for the memory-optimizer AST visitors across diverse node types.

Running ``MemoryOptimizer`` over a rule that uses the full breadth of YARA
expression and string constructs drives the per-node-type pooling visitors in
``yaraast.performance.memory_transformer_visitors`` and verifies they preserve
the AST (the regenerated source is unchanged).
"""

from __future__ import annotations

from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.source import parse_yara_source
from yaraast.performance.memory_optimizer import MemoryOptimizer

RICH_SOURCE = r"""import "pe"
import "math"

rule rich : tag1 tag2 {
    meta:
        author = "alice"
        score = 5
        active = true
    strings:
        $a = "hello" nocase wide
        $b = { 4D 5A ?? F? [2-4] ( 90 | 91 ) }
        $c = /ab[0-9]+/ nocase
        $d = "world" xor(0x10-0x20)
    condition:
        #a == 2 and @a[1] < 100 and !a > 0 and
        $a at 0 and $b in (0..filesize) and
        any of ($a, $c) and all of them and
        for any i in (1..3) : ( i > 0 ) and
        for all of ($a*) : ( $ ) and
        ($a and $b) or (not $c) and
        pe.number_of_sections > 3 and
        defined pe.entry_point and
        pe.version_info["CompanyName"] contains "x" and
        math.entropy(0, filesize) > 7.0 and
        "abc" matches /a.c/
}
"""


def test_optimize_preserves_rich_rule() -> None:
    ast = parse_yara_source(RICH_SOURCE)
    before = CodeGenerator().generate(ast)

    optimized = MemoryOptimizer().optimize(parse_yara_source(RICH_SOURCE))
    after = CodeGenerator().generate(optimized)

    assert after == before


def test_optimize_rule_and_rules_preserve_rich_rule() -> None:
    optimizer = MemoryOptimizer()
    ast = parse_yara_source(RICH_SOURCE)
    expected = CodeGenerator().generate(ast)

    single = optimizer.optimize_rule(parse_yara_source(RICH_SOURCE).rules[0])
    assert single.name == "rich"

    optimized_rules = [
        optimizer.optimize_rule(rule) for rule in parse_yara_source(RICH_SOURCE).rules
    ]
    rebuilt = parse_yara_source(RICH_SOURCE)
    rebuilt.rules = optimized_rules
    assert CodeGenerator().generate(rebuilt) == expected

    stats = optimizer.get_statistics()
    assert stats["nodes_processed"] > 0
    assert stats["strings_pooled"] > 0
