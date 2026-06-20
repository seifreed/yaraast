"""Type-inference validation coverage for module-function and operator argument checks.

Exercises the argument-validation branches in
``yaraast.types._expr_inference_ops`` by validating real YARA sources and
asserting the diagnostics they produce.
"""

from __future__ import annotations

import pytest

from yaraast.parser.source import parse_yara_source
from yaraast.types.semantic_validator import SemanticValidator


def _errors(source: str) -> list[str]:
    ast = parse_yara_source(source)
    return [error.message for error in SemanticValidator().validate(ast).errors]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'import "pe"\nrule r { condition: pe.exports(true) }',
            "Function 'exports' does not accept argument type (boolean)",
        ),
        (
            'import "pe"\nrule r { condition: pe.exports_index(true) }',
            "Function 'exports_index' does not accept argument type (boolean)",
        ),
        (
            'import "pe"\nrule r { condition: pe.section_index(true) }',
            "Function 'section_index' does not accept argument type (boolean)",
        ),
        (
            'import "pe"\nrule r { condition: pe.import_rva("k") }',
            "Function 'import_rva' expects 2 arguments, got 1",
        ),
        (
            'import "pe"\nrule r { condition: pe.imports() }',
            "Function 'imports' expects 1 to 3 arguments, got 0",
        ),
        (
            'import "hash"\nrule r { condition: hash.md5(0) == "x" }',
            "Function 'md5' does not accept argument types (integer)",
        ),
        (
            'import "hash"\nrule r { condition: hash.checksum32(true) == 0 }',
            "Function 'checksum32' does not accept argument types (boolean)",
        ),
        (
            'import "math"\nrule r { condition: math.entropy(0, 1, 2) > 0 }',
            "Function 'entropy' does not accept argument types (integer, integer, integer)",
        ),
        (
            'import "math"\nrule r { condition: math.mean(1, 2, 3) > 0.0 }',
            "Function 'mean' does not accept argument types (integer, integer, integer)",
        ),
        (
            'import "math"\nrule r { condition: math.deviation(0, 1) > 0.0 }',
            "Function 'deviation' does not accept argument types (integer, integer)",
        ),
        (
            'import "math"\nrule r { condition: math.in_range("a", 1.0, 2.0) }',
            "Argument 'test' to function 'in_range' must be double, got string",
        ),
        (
            'import "console"\nrule r { condition: console.log() }',
            "Function 'log' expects 1 to 2 arguments, got 0",
        ),
        (
            'import "console"\nrule r { condition: console.hex("a") }',
            "Function 'hex' does not accept argument types (string)",
        ),
        (
            "rule r { condition: (1 \\ 0) > 0 }",
            "Right operand of '\\' cannot be zero",
        ),
        (
            "rule r { condition: (5 % 0) > 0 }",
            "Right operand of '%' cannot be zero",
        ),
        (
            'rule r { condition: "abc" matches "def" }',
            "Right operand of 'matches' must be regex, got string",
        ),
        (
            "rule r { condition: 1 contains 2 }",
            "Right operand of 'contains' must be string, got integer",
        ),
        (
            'rule r { condition: ("a" + 1) > 0 }',
            "Left operand of '+' must be numeric, got string",
        ),
        (
            "rule r { condition: (1.0 & 2) > 0 }",
            "Left operand of '&' must be integer, got double",
        ),
        (
            'rule r { condition: (-"a") > 0 }',
            "Operand of '-' must be numeric, got string",
        ),
    ],
)
def test_invalid_expression_reports_expected_diagnostic(source: str, expected: str) -> None:
    assert any(expected in message for message in _errors(source))


@pytest.mark.parametrize(
    "source",
    [
        'import "pe"\nrule r { condition: pe.exports("kernel32.dll") }',
        'import "hash"\nrule r { condition: hash.md5(0, filesize) == "x" }',
        'import "math"\nrule r { condition: math.entropy(0, filesize) > 0.0 }',
        'import "console"\nrule r { condition: console.log("message") }',
        "rule r { condition: (1 + 2) * 3 > 0 }",
    ],
)
def test_valid_expression_has_no_argument_errors(source: str) -> None:
    messages = _errors(source)
    assert not any("does not accept" in message for message in messages)
    assert not any("cannot be zero" in message for message in messages)
