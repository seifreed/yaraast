from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.codegen import CodeGenerator
from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.equivalence import EquivalenceResult, EquivalenceTester
from yaraast.libyara.scanner import YARA_AVAILABLE as SCANNER_AVAILABLE, MatchInfo, ScanResult
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


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


@pytest.mark.parametrize("filepath", ["", "   ", "\t"])
def test_file_round_trip_rejects_empty_filepath(filepath: str) -> None:
    tester = _tester_without_libyara_init()

    result = tester.test_file_round_trip(filepath)

    assert result.equivalent is False
    assert result.ast_differences == ["Failed to parse file: filepath must not be empty"]


@pytest.mark.parametrize("filepath", [None, False, 123, object(), b"rule.yar"])
def test_file_round_trip_rejects_invalid_filepath_types(filepath: Any) -> None:
    tester = _tester_without_libyara_init()

    result = tester.test_file_round_trip(cast(Any, filepath))

    assert result.equivalent is False
    assert result.ast_differences == [
        "Failed to parse file: filepath must be a string or path-like object"
    ]


def test_file_round_trip_rejects_invalid_utf8(tmp_path: Path) -> None:
    tester = _tester_without_libyara_init()
    rule_file = tmp_path / "bad.yar"
    rule_file.write_bytes(b"\xff")

    result = tester.test_file_round_trip(rule_file)

    assert result.equivalent is False
    assert result.ast_differences == [
        "Failed to parse file: YARA file must contain valid UTF-8 text"
    ]


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


def test_generate_regenerated_code_helper_records_failure() -> None:
    tester = _tester_without_libyara_init()
    result = EquivalenceResult(equivalent=True)

    regenerated = tester._generate_regenerated_code(cast(Any, "not-an-ast"), result)

    assert regenerated is None
    assert result.equivalent is False
    assert result.code_equivalent is False
    assert result.ast_differences == ["Re-generation failed: Visitor node must be an ASTNode"]


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


def test_compare_scan_differences_are_stably_sorted() -> None:
    tester = _tester_without_libyara_init()

    scan_diffs = tester._compare_scans(
        ScanResult(
            success=True,
            matches=[
                MatchInfo(rule="z_rule", namespace="default", tags=[], meta={}, strings=[]),
                MatchInfo(rule="a_rule", namespace="default", tags=[], meta={}, strings=[]),
                MatchInfo(rule="m_rule", namespace="default", tags=[], meta={}, strings=[]),
            ],
        ),
        ScanResult(success=True, matches=[]),
    )
    assert scan_diffs == ["Rules matched only in original: ['a_rule', 'm_rule', 'z_rule']"]


def test_file_round_trip_missing_file_returns_error_result() -> None:
    tester = _tester_without_libyara_init()

    result = tester.test_file_round_trip("/definitely/missing/file.yar")

    assert result.equivalent is False
    assert result.ast_equivalent is False
    assert result.code_equivalent is False
    assert result.original_compiles is False
    assert result.regenerated_compiles is False
    assert result.ast_differences
    assert "Failed to parse file" in result.ast_differences[0]


def test_round_trip_rejects_yarax_only_ast_before_codegen() -> None:
    tester = _tester_without_libyara_init()
    ast = parse_yara_source(
        "rule x { condition: with xs = [1]: match xs { _ => true } }",
    )

    result = tester.test_round_trip(ast)

    assert result.equivalent is False
    assert result.ast_equivalent is False
    assert result.code_equivalent is False
    assert result.original_compiles is False
    assert result.regenerated_compiles is False
    assert result.original_code is None
    assert result.ast_differences == [
        "Cannot test libyara round-trip for YARA-X-only syntax: list expressions, "
        "pattern matching, with statements"
    ]


def test_file_round_trip_parses_yarax_before_libyara_compatibility_check(tmp_path: Path) -> None:
    tester = _tester_without_libyara_init()
    rule_file = tmp_path / "native_yarax.yar"
    rule_file.write_text(
        "rule x { condition: with xs = [1]: match xs { _ => true } }",
        encoding="utf-8",
    )

    result = tester.test_file_round_trip(str(rule_file))

    assert result.equivalent is False
    assert "Cannot test libyara round-trip for YARA-X-only syntax" in result.ast_differences[0]
    assert "Failed to parse file" not in result.ast_differences[0]


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

    result = tester.test_round_trip(cast(Any, "not-an-ast"))

    assert result.equivalent is False
    assert result.code_equivalent is False
    assert any("Code generation failed" in d for d in result.ast_differences)


def test_round_trip_handles_invalid_rule_name_codegen_failure() -> None:
    tester = _tester_without_libyara_init()
    invalid_name_ast = YaraFile(
        rules=[Rule(name="bad name", condition=BooleanLiteral(value=True))],
    )

    result = tester.test_round_trip(invalid_name_ast)

    assert result.equivalent is False
    assert result.ast_equivalent is False
    assert any("Code generation failed" in d for d in result.ast_differences)


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_round_trip_records_real_compilation_errors() -> None:
    tester = EquivalenceTester()
    # Parser/codegen accept this, but libyara compilation fails (undefined identifier).
    ast = Parser().parse("rule bad_compile { condition: unknown_identifier }")

    result = tester.test_round_trip(ast)

    assert result.equivalent is False
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
def test_round_trip_equivalent_for_for_of_them() -> None:
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

    assert result.equivalent is True
    assert result.scan_equivalent is True


@pytest.mark.skipif(
    not (COMPILER_AVAILABLE and SCANNER_AVAILABLE),
    reason="yara-python not available",
)
def test_file_round_trip_equivalent_from_example_file() -> None:
    tester = EquivalenceTester()
    result = tester.test_file_round_trip(
        "examples/multi-file/common/strings.yar",
        test_data=b"CreateRemoteThread powershell -enc",
    )

    assert result.equivalent is True
    assert result.scan_equivalent is True
