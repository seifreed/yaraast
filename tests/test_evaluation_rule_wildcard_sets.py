from __future__ import annotations

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
