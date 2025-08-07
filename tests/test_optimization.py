"""Test optimization functionality."""

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
        version = 1 + 1
        unused = ""

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
    _, stats = optimizer.optimize(ast)

    # Should have multiple optimizations
    assert stats["total_optimizations"] > 0
    assert stats["expression_optimizations"] > 0
    assert stats["dead_code_eliminations"] > 0

    # Generate report
    report = optimizer.get_optimization_report(ast)
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
    yara_code = """
rule range_test {
    strings:
        $a = "test"

    condition:
        $a in (100..50) or    // Invalid range, always false
        $a in (0..1000)
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = RuleOptimizer()
    _, stats = optimizer.optimize(ast)

    # Should optimize the invalid range
    assert stats["expression_optimizations"] > 0


def test_set_expression_optimization() -> None:
    """Test set expression optimization."""
    yara_code = """
rule set_test {
    condition:
        any of (1, 2, 1, 3, 2, 3)  // Duplicates should be removed
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    optimizer = ExpressionOptimizer()
    _, count = optimizer.optimize(ast)

    # Should remove duplicates
    assert count > 0


if __name__ == "__main__":
    test_constant_folding()
    test_boolean_simplification()
    test_dead_code_elimination()
    test_comprehensive_optimization()
    test_nested_expression_optimization()
    test_range_optimization()
    test_set_expression_optimization()
    print("✓ All optimization tests passed")
