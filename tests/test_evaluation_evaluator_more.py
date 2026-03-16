"""Real tests for YARA evaluator (no mocks)."""

from __future__ import annotations

from yaraast.evaluation import YaraEvaluator
from yaraast.parser import Parser


def test_evaluator_basic_string_match() -> None:
    code = """
    rule eval_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = Parser().parse(code)
    evaluator = YaraEvaluator(b"xxabcxx")
    results = evaluator.evaluate_file(ast)
    assert results["eval_rule"] is True


def test_evaluator_string_count_and_offset() -> None:
    code = """
    rule eval_rule2 {
        strings:
            $a = "abc"
        condition:
            #a == 2 and @a[0] == 2
    }
    """
    ast = Parser().parse(code)
    evaluator = YaraEvaluator(b"xxabcxxabc")
    results = evaluator.evaluate_file(ast)
    assert results["eval_rule2"] is True
