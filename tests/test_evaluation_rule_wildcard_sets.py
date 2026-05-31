from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.parser import Parser


def test_evaluator_resolves_rule_wildcard_sets_before_string_wildcards() -> None:
    ast = Parser().parse("""
rule alpha_one {
    condition:
        false
}

rule alpha_two {
    condition:
        false
}

rule holder {
    strings:
        $alpha_local = "needle"
    condition:
        any of (alpha*)
}
""")

    assert YaraEvaluator(data=b"needle").evaluate_file(ast) == {
        "alpha_one": False,
        "alpha_two": False,
        "holder": False,
    }


def test_evaluator_preserves_dollar_prefixed_string_wildcards() -> None:
    ast = Parser().parse("""
rule alpha_one {
    condition:
        false
}

rule holder {
    strings:
        $alpha_local = "needle"
    condition:
        any of ($alpha*)
}
""")

    assert YaraEvaluator(data=b"needle").evaluate_file(ast) == {
        "alpha_one": False,
        "holder": True,
    }


def test_evaluator_raw_string_set_text_stays_string_reference_when_rule_name_matches() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="alpha", condition=BooleanLiteral(False)),
            Rule(
                name="holder",
                strings=[PlainString(identifier="$alpha", value="needle")],
                condition=OfExpression("any", "alpha"),
            ),
        ]
    )

    assert YaraEvaluator(data=b"needle").evaluate_file(ast) == {
        "alpha": False,
        "holder": True,
    }


def test_evaluator_for_of_resolves_rule_wildcard_sets_before_string_wildcards() -> None:
    ast = Parser().parse("""
rule alpha_one {
    condition:
        false
}

rule alpha_two {
    condition:
        false
}

rule holder {
    strings:
        $alpha_local = "needle"
    condition:
        for any of (alpha*) : ( true )
}
""")

    assert YaraEvaluator(data=b"needle").evaluate_file(ast) == {
        "alpha_one": False,
        "alpha_two": False,
        "holder": False,
    }


def test_evaluator_for_of_counts_matching_rules() -> None:
    ast = Parser().parse("""
rule alpha_one {
    condition:
        true
}

rule alpha_two {
    condition:
        false
}

rule holder {
    condition:
        for any of (alpha*) : ( true )
}
""")

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {
        "alpha_one": True,
        "alpha_two": False,
        "holder": True,
    }
