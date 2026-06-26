"""Test optimization functionality."""

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import BinaryExpression, IntegerLiteral, RangeExpression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.codegen import CodeGenerator
from yaraast.optimization import DeadCodeEliminator, ExpressionOptimizer, RuleOptimizer
from yaraast.parser import Parser


def test_constant_folding() -> None:
    """Test constant folding optimization."""
    yara_code = """
rule constant_folding_test {
    condition:
        (2 + 3) * 4 == 20 and
        10 - 5 > 3 and
        true and false or true
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = ExpressionOptimizer()
    optimized, count = optimizer.optimize(ast)

    # Should optimize arithmetic and boolean expressions
    assert count > 0

    # Generate code to verify
    generator = CodeGenerator()
    output = generator.generate(optimized)

    # Should have simplified expressions
    assert "20 == 20" in output or "true" in output


def test_boolean_simplification() -> None:
    """Test boolean expression simplification."""
    yara_code = """
rule boolean_test {
    strings:
        $a = "test"

    condition:
        true and $a and      // true and X => X
        $a or false and      // X or false => X
        not not $a           // not not X => X
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = ExpressionOptimizer()
    _, count = optimizer.optimize(ast)

    assert count >= 3  # At least 3 simplifications


def test_dead_code_elimination() -> None:
    """Test dead code elimination."""
    yara_code = """
rule dead_code_test {
    strings:
        $used = "used"
        $unused1 = "not used"
        $unused2 = { 00 01 02 }

    condition:
        $used
}

rule always_false_rule {
    condition:
        false
}

rule normal_rule {
    condition:
        true
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    eliminator = DeadCodeEliminator()
    optimized, count = eliminator.eliminate(ast)

    # Should remove unused strings and always-false rule
    assert count >= 3  # 2 unused strings + 1 false rule
    assert len(optimized.rules) == 2  # always_false_rule removed

    # Check that unused strings were removed
    dead_code_rule = next(r for r in optimized.rules if r.name == "dead_code_test")
    assert len(dead_code_rule.strings) == 1
    assert dead_code_rule.strings[0].identifier == "$used"


def test_comprehensive_optimization() -> None:
    """Test comprehensive optimization with multiple passes."""
    yara_code = """
rule optimize_me {
    meta:
        version = 2
        author = "test"

    strings:
        $a = "used"
        $b = "unused"
        $c = "also unused"

    condition:
        (true and $a) and
        (false or $a) and
        not (not $a) and
        (10 + 5 > 14)
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = RuleOptimizer()
    optimized, stats = optimizer.optimize(ast)

    # Should have multiple optimizations
    assert stats["total_optimizations"] > 0
    assert stats["expression_optimizations"] > 0
    assert stats["dead_code_eliminations"] > 0

    original_strings = sum(len(rule.strings) for rule in ast.rules)
    optimized_strings = sum(len(rule.strings) for rule in optimized.rules)
    report = {
        "summary": stats,
        "size_reduction": {
            "rules": f"{stats['rules_eliminated']} rules removed",
            "strings": f"{original_strings - optimized_strings} strings removed",
            "percentage": (
                f"{(1 - len(optimized.rules) / len(ast.rules)) * 100:.1f}%" if ast.rules else "0%"
            ),
        },
        "optimization_breakdown": {
            "constant_folding": "Evaluated constant expressions",
            "boolean_simplification": "Simplified boolean logic",
            "dead_code_removal": "Removed unreachable code",
            "unused_string_removal": "Removed unused string definitions",
        },
    }
    assert "size_reduction" in report
    assert "optimization_breakdown" in report


def test_nested_expression_optimization() -> None:
    """Test optimization of nested expressions."""
    yara_code = """
rule nested_test {
    condition:
        ((true and (false or true)) or false) and
        not (not (not false)) and
        (((1 + 2) * 3) == 9)
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = ExpressionOptimizer()
    optimized, count = optimizer.optimize(ast)

    # Should optimize nested expressions
    assert count > 0

    # The condition should simplify significantly
    generator = CodeGenerator()
    output = generator.generate(optimized)

    # Should be much simpler than original
    assert len(output) < len(yara_code)


def test_range_optimization() -> None:
    """Test range expression optimization."""
    ast = YaraFile(
        rules=[
            Rule(
                name="range_test",
                strings=[PlainString("$a", value="test")],
                condition=BinaryExpression(
                    InExpression("$a", RangeExpression(IntegerLiteral(100), IntegerLiteral(50))),
                    "or",
                    InExpression("$a", RangeExpression(IntegerLiteral(0), IntegerLiteral(1000))),
                ),
            )
        ]
    )

    optimizer = RuleOptimizer()
    _, stats = optimizer.optimize(ast)

    # Should optimize the invalid range
    assert stats["expression_optimizations"] > 0


def test_set_expression_duplicates_are_preserved() -> None:
    """Set duplicates are semantic for for-in quantifiers."""
    yara_code = """
rule set_test {
    condition:
        for 2 i in (1, 1) : (i == 1)
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = ExpressionOptimizer()
    optimized, count = optimizer.optimize(ast)

    output = CodeGenerator().generate(optimized)

    assert count == 0
    assert "(1, 1)" in output
