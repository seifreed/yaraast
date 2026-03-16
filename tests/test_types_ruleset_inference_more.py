"""Additional branch coverage for ruleset type inference (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import PlainString
from yaraast.types._registry import TypeEnvironment
from yaraast.types._ruleset_inference import RulesetTypeInference


def test_ruleset_inference_populates_modules_rules_and_strings() -> None:
    ast = YaraFile(
        imports=[Import(module="pe"), Import(module="math", alias="m")],
        rules=[
            Rule(
                name="alpha",
                strings=[PlainString(identifier="$a", value="abc")],
                condition=BooleanLiteral(value=True),
            ),
            Rule(name="beta", strings=[], condition=BooleanLiteral(value=False)),
        ],
    )

    env = TypeEnvironment()
    out = RulesetTypeInference(env).infer(ast)

    assert out is env
    assert env.has_module("pe")
    assert env.has_module("m")
    assert env.get_module_name("m") == "math"
    assert env.has_rule("alpha")
    assert env.has_rule("beta")
    assert env.has_string("$a")


def test_ruleset_inference_handles_empty_ruleset() -> None:
    env = TypeEnvironment()
    inf = RulesetTypeInference(env)
    out = inf.infer(YaraFile(imports=[], rules=[]))
    assert out is env
    assert env.modules == set()
    assert env.rules == set()
    assert env.strings == set()
