from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.rules import Rule
from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.cross_validator import CrossValidator, ValidationResult
from yaraast.parser import Parser


def test_validation_result_properties_zero_and_non_zero() -> None:
    v = ValidationResult(valid=True)
    assert v.total_time == 0.0
    assert v.match_rate == 0.0

    v.yaraast_time = 0.1
    v.libyara_compile_time = 0.2
    v.libyara_scan_time = 0.3
    v.rules_tested = 4
    v.rules_matched = 3
    assert v.total_time == pytest.approx(0.6)
    assert v.match_rate == 75.0


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_cross_validator_error_and_mismatch_paths() -> None:
    validator = CrossValidator()

    externals_ast = Parser().parse("rule ext_rule { condition: true }")
    externals_result = validator.validate(externals_ast, b"payload", externals={"threshold": 3})
    assert externals_result.valid is True
    assert validator.compiler.externals == {"threshold": 3}

    # Unknown identifiers now evaluate gracefully to False (rule references)
    eval_graceful_ast = YaraFile(
        rules=[Rule(name="eval_graceful", condition=Identifier("missing_id"))]
    )
    eval_graceful = validator.validate(eval_graceful_ast, b"data")
    assert eval_graceful.yaraast_results.get("eval_graceful") is False

    # Step 2 failure: AST evaluates but generated source cannot compile.
    compile_fail_ast = YaraFile(rules=[Rule(name="bad name", condition=BooleanLiteral(True))])
    compile_fail = validator.validate(compile_fail_ast, b"data")
    assert compile_fail.valid is False
    assert compile_fail.errors

    # validate_batch compile failure path returns one error result per sample.
    batch = validator.validate_batch(compile_fail_ast, [b"a", b"b"])
    assert len(batch) == 2
    assert all(not r.valid for r in batch)

    # _validate_single mismatch path: evaluate one AST, scan with compiled rules from another.
    ast_true = Parser().parse("rule same { condition: true }")
    ast_false = Parser().parse("rule same { condition: false }")
    compiled = validator.compiler.compile_ast(ast_true)
    assert compiled.success is True

    mismatch = validator._validate_single(ast_false, b"payload", compiled.compiled_rules)
    assert mismatch.valid is False
    assert mismatch.rules_differ

    # validate() mismatch path with real evaluation/scan disagreement.
    pe_ast = Parser().parse('import "pe" rule pe_rule { condition: pe.is_pe }')
    validate_mismatch = validator.validate(pe_ast, b"MZ" + (b"0" * 100))
    assert validate_mismatch.valid is False
    assert validate_mismatch.rules_differ == ["pe_rule: yaraast=True, libyara=False"]

    # _validate_single scan exception path with invalid compiled_rules object.
    scan_error = validator._validate_single(ast_true, b"payload", None)
    assert scan_error.valid is False
    assert scan_error.errors

    # validate() scan_result.success path with evaluator success but libyara scan failure.
    validate_scan_error = validator.validate(externals_ast, ["bad-data"])  # type: ignore[list-item]
    assert validate_scan_error.valid is False
    assert validate_scan_error.errors

    # _validate_single with unknown identifier evaluates gracefully
    single_eval = validator._validate_single(eval_graceful_ast, b"payload", compiled.compiled_rules)
    assert single_eval.yaraast_results.get("eval_graceful") is False
