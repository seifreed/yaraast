from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.codegen import CodeGenerator
from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.equivalence import EquivalenceResult, EquivalenceTester
from yaraast.libyara.scanner import YARA_AVAILABLE as SCANNER_AVAILABLE
from yaraast.libyara.scanner import MatchInfo, ScanResult
from yaraast.parser import Parser


def _tester_without_libyara_init() -> EquivalenceTester:
    tester = object.__new__(EquivalenceTester)
    tester.parser = Parser()
    tester.codegen = CodeGenerator()
    return tester


def test_compare_code_normalizes_whitespace_only() -> None:
    tester = _tester_without_libyara_init()

    code1 = "rule r {\ncondition:\n true\n}\n"
    code2 = "  rule r {  \n  condition:   \n   true\n}\n\n"
    code3 = "rule r2 {\ncondition:\n true\n}\n"

    assert tester._compare_code(code1, code2) is True
    assert tester._compare_code(code1, code3) is False


def test_equivalence_result_recording_helpers() -> None:
    tester = _tester_without_libyara_init()

    regen_result = EquivalenceResult(equivalent=True)
    tester._record_regeneration_failure(regen_result, ValueError("boom"))
    assert regen_result.equivalent is False
    assert regen_result.code_equivalent is False
    assert regen_result.ast_differences == ["Re-generation failed: boom"]

    code_result = EquivalenceResult(equivalent=True)
    tester._record_code_difference(code_result, "a", "b")
    assert code_result.equivalent is False
    assert code_result.code_equivalent is False
    assert code_result.ast_differences == ["Generated code differs after round-trip"]

    same_code_result = EquivalenceResult(equivalent=True)
    tester._record_code_difference(same_code_result, "x", "x")
    assert same_code_result.equivalent is True
    assert same_code_result.ast_differences == []

    ast_result = EquivalenceResult(equivalent=True)
    tester._record_ast_differences(ast_result, ["a", "b"])
    assert ast_result.equivalent is False
    assert ast_result.ast_equivalent is False
    assert ast_result.ast_differences == ["a", "b"]

    scan_result = EquivalenceResult(equivalent=True)
    tester._record_scan_differences(scan_result, ["scan"])
    assert scan_result.equivalent is False
    assert scan_result.scan_equivalent is False
    assert scan_result.scan_differences == ["scan"]

    eval_result = EquivalenceResult(equivalent=True)
    tester._record_eval_differences(eval_result, ["eval"])
    assert eval_result.equivalent is False
    assert eval_result.eval_equivalent is False
    assert eval_result.eval_differences == ["eval"]


def test_generate_regenerated_code_helper_records_failure() -> None:
    tester = _tester_without_libyara_init()
    result = EquivalenceResult(equivalent=True)

    regenerated = tester._generate_regenerated_code("not-an-ast", result)  # type: ignore[arg-type]

    assert regenerated is None
    assert result.equivalent is False
    assert result.code_equivalent is False
    assert result.ast_differences == [
        "Re-generation failed: 'str' object has no attribute 'accept'"
    ]


def test_compare_ast_and_scans_report_differences() -> None:
    tester = _tester_without_libyara_init()
    parser = Parser()

    ast1 = parser.parse(
        'import "pe"\nrule one { strings: $a = "x" condition: $a }',
    )
    ast2 = parser.parse("rule two { condition: true }")

    ast_diffs = tester._compare_ast(ast1, ast2)
    assert any("Imports differ" in d or "Import count differs" in d for d in ast_diffs)
    assert any("name differs" in d for d in ast_diffs)
    assert any("string count differs" in d or "string" in d.lower() for d in ast_diffs)

    scan1 = ScanResult(
        success=True,
        matches=[MatchInfo(rule="one", namespace="default", tags=[], meta={}, strings=[])],
    )
    scan2 = ScanResult(
        success=False,
        matches=[MatchInfo(rule="two", namespace="default", tags=[], meta={}, strings=[])],
    )

    scan_diffs = tester._compare_scans(scan1, scan2)
    assert any("Scan success differs" in d for d in scan_diffs)
    assert any("only in original" in d for d in scan_diffs)
    assert any("only in regenerated" in d for d in scan_diffs)


def test_compare_ast_reports_rule_count_difference() -> None:
    tester = _tester_without_libyara_init()
    parser = Parser()

    ast1 = parser.parse("rule one { condition: true } rule two { condition: true }")
    ast2 = parser.parse("rule one { condition: true }")

    ast_diffs = tester._compare_ast(ast1, ast2)
    assert any("Rule count differs" in d for d in ast_diffs)


def test_compare_scans_reports_one_sided_differences() -> None:
    tester = _tester_without_libyara_init()

    only_original = tester._compare_scans(
        ScanResult(
            success=True,
            matches=[MatchInfo(rule="a", namespace="default", tags=[], meta={}, strings=[])],
        ),
        ScanResult(success=True, matches=[]),
    )
    assert any("only in original" in d for d in only_original)

    only_regenerated = tester._compare_scans(
        ScanResult(success=True, matches=[]),
        ScanResult(
            success=True,
            matches=[MatchInfo(rule="b", namespace="default", tags=[], meta={}, strings=[])],
        ),
    )
    assert any("only in regenerated" in d for d in only_regenerated)


def test_compare_evaluation_captures_real_failure() -> None:
    tester = _tester_without_libyara_init()
    ast = Parser().parse("rule ok { condition: true }")

    diffs = tester._compare_evaluation(ast, None, b"data")  # type: ignore[arg-type]

    assert len(diffs) == 1
    assert diffs[0].startswith("Evaluation comparison failed:")


def test_file_round_trip_missing_file_returns_error_result() -> None:
    tester = _tester_without_libyara_init()

    result = tester.test_file_round_trip("/definitely/missing/file.yar")

    assert result.equivalent is False
    assert result.ast_differences
    assert "Failed to parse file" in result.ast_differences[0]


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_file_round_trip_success_path_with_real_equivalence_tester() -> None:
    tester = EquivalenceTester()
    tmp = Path("tests/.tmp_equivalence_success.yar")
    tmp.write_text('rule ok { strings: $a = "abc" condition: $a }', encoding="utf-8")
    try:
        result = tester.test_file_round_trip(str(tmp))
    finally:
        tmp.unlink(missing_ok=True)

    assert result.equivalent is True
    assert result.original_code is not None
    assert result.regenerated_code is not None


def test_round_trip_handles_codegen_failure_without_libyara_dependency() -> None:
    tester = _tester_without_libyara_init()

    result = tester.test_round_trip("not-an-ast")  # type: ignore[arg-type]

    assert result.equivalent is False
    assert result.code_equivalent is False
    assert any("Code generation failed" in d for d in result.ast_differences)


def test_round_trip_handles_reparse_failure_with_real_codegen() -> None:
    tester = _tester_without_libyara_init()
    invalid_name_ast = YaraFile(
        rules=[Rule(name="bad name", condition=BooleanLiteral(value=True))],
    )

    result = tester.test_round_trip(invalid_name_ast)

    assert result.equivalent is False
    assert result.ast_equivalent is False
    assert any("Re-parsing failed" in d for d in result.ast_differences)


def test_compare_evaluation_reports_missing_and_different_rules() -> None:
    tester = _tester_without_libyara_init()

    only_a = Parser().parse("rule same { condition: true }")
    only_b = Parser().parse("rule other { condition: true }")
    missing_diffs = tester._compare_evaluation(only_a, only_b, b"sample")
    assert any("missing in original evaluation" in d for d in missing_diffs)
    assert any("missing in regenerated evaluation" in d for d in missing_diffs)

    true_rule = Parser().parse("rule same { condition: true }")
    false_rule = Parser().parse("rule same { condition: false }")
    value_diffs = tester._compare_evaluation(true_rule, false_rule, b"sample")
    assert any("evaluation differs" in d for d in value_diffs)


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_round_trip_records_real_compilation_errors() -> None:
    tester = EquivalenceTester()
    # Parser/codegen accept this, but libyara compilation fails (undefined identifier).
    ast = Parser().parse("rule bad_compile { condition: unknown_identifier }")

    result = tester.test_round_trip(ast)

    assert result.original_compiles is False
    assert result.regenerated_compiles is False
    assert result.compilation_errors


@pytest.mark.skipif(
    not (COMPILER_AVAILABLE and SCANNER_AVAILABLE),
    reason="yara-python not available",
)
def test_round_trip_with_real_libyara_compilation_and_scanning() -> None:
    ast = Parser().parse(
        'rule eq_real { strings: $a = "abc" condition: $a }',
    )
    tester = EquivalenceTester()

    result = tester.test_round_trip(ast, test_data=b"xxabcxx")

    assert result.original_compiles is True
    assert result.regenerated_compiles is True
    assert result.scan_equivalent is True


@pytest.mark.skipif(
    not (COMPILER_AVAILABLE and SCANNER_AVAILABLE),
    reason="yara-python not available",
)
def test_round_trip_records_real_evaluation_difference_for_for_of_them() -> None:
    ast = Parser().parse(
        """
        rule r {
            strings:
                $a = "a"
                $b = "b"
            condition:
                for any of them : ($)
        }
        """,
    )
    tester = EquivalenceTester()

    result = tester.test_round_trip(ast, test_data=b"a")

    # With the evaluator now handling for..of..them correctly, roundtrip is equivalent
    assert result.equivalent is True
    assert result.eval_equivalent is True


@pytest.mark.skipif(
    not (COMPILER_AVAILABLE and SCANNER_AVAILABLE),
    reason="yara-python not available",
)
def test_file_round_trip_records_real_evaluation_difference_from_example_file() -> None:
    tester = EquivalenceTester()
    result = tester.test_file_round_trip(
        "examples/multi-file/common/strings.yar",
        test_data=b"CreateRemoteThread powershell -enc",
    )

    # Roundtrip should be equivalent — evaluator handles all patterns correctly
    assert result.equivalent is True
    assert result.eval_equivalent is True
