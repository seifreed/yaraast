"""Differential regression tests for module function signatures.

These cover accept/reject disagreements between this library's TypeChecker
and real libyara for module *functions* (arity and argument types). The
motivating false positive: ``pe.calculate_checksum()`` is a valid libyara
function but was missing from the module spec, so the TypeChecker wrongly
rejected it. When yara-python is installed every case is cross-checked
against libyara so the spec stays aligned with the engine.
"""

from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE
from yaraast.parser import Parser
from yaraast.types import TypeChecker

# (module, condition) calls that libyara accepts.
ACCEPTED_CALLS: list[tuple[str, str]] = [
    # pe functions
    ("pe", 'pe.imports("kernel32.dll")'),
    ("pe", 'pe.imports("kernel32.dll", "CreateFileA")'),
    ("pe", "pe.imports(/kernel32/, /CreateFile/)"),
    ("pe", 'pe.imports(1, "CreateFileA")'),
    ("pe", 'pe.exports("main")'),
    ("pe", "pe.exports(1)"),
    ("pe", "pe.exports(/main/)"),
    ("pe", 'pe.imphash() == "x"'),
    ("pe", 'pe.section_index(".text") == 0'),
    ("pe", "pe.section_index(0) == 0"),
    ("pe", "pe.rva_to_offset(0) == 0"),
    ("pe", "pe.is_dll()"),
    ("pe", "pe.is_32bit()"),
    ("pe", "pe.is_64bit()"),
    ("pe", "pe.calculate_checksum() == 0"),
    ("pe", "pe.calculate_checksum() == pe.checksum"),
    # hash functions: 2-int region form and 1-string digest form
    ("hash", 'hash.md5(0, 1) == "x"'),
    ("hash", 'hash.md5("abc") == "x"'),
    ("hash", 'hash.sha1(0, 1) == "x"'),
    ("hash", 'hash.sha256(0, 1) == "x"'),
    ("hash", "hash.checksum32(0, 1) == 0"),
    ("hash", "hash.crc32(0, 1) == 0"),
    ("hash", 'hash.crc32("abc") == 0'),
    # math functions
    ("math", "math.entropy(0, 1) > 0"),
    ("math", 'math.entropy("s") > 0'),
    ("math", "math.serial_correlation(0, 1) > 0"),
    ("math", "math.monte_carlo_pi(0, 1) > 0"),
    ("math", "math.mean(0, 1) > 0"),
    ("math", "math.deviation(0, 1, 2.0) > 0"),
    ("math", 'math.deviation("s", 2.0) > 0'),
    ("math", "math.to_number(true) > 0"),
    ("math", 'math.to_string(10) == "x"'),
    ("math", 'math.to_string(10, 16) == "x"'),
    ("math", "math.abs(-5) > 0"),
    ("math", "math.min(1, 2) > 0"),
    ("math", "math.max(1, 2) > 0"),
    # time
    ("time", "time.now() > 0"),
]

# Calls that are genuine type/arity errors: libyara rejects them and the
# validator must keep rejecting them so the fix introduces no false negatives.
REJECTED_CALLS: list[tuple[str, str]] = [
    ("pe", "pe.calculate_checksum(1) == 0"),
    ("pe", "pe.imports(/kernel32/)"),
    ("pe", 'pe.import_rva("kernel32.dll", 1.5) == 0'),
    ("pe", 'pe.delayed_import_rva("kernel32.dll", 1.5) == 0'),
    ("pe", 'pe.imphash("x") == "x"'),
    ("pe", 'pe.rva_to_offset("x") == 0'),
    ("pe", "pe.section_index(/r/) == 0"),
    ("pe", "pe.signatures.valid_on(0)"),
    ("hash", 'hash.md5(0, 1, 2) == "x"'),
    ("hash", 'hash.crc32("a", "b") == 0'),
    ("math", 'math.abs("x") > 0'),
    ("math", "math.to_number(1.5) > 0"),
    ("math", "math.min(1, 2, 3) > 0"),
    ("math", "math.deviation(0, 1, 2) > 0"),
    ("time", "time.now(1) > 0"),
]


def _function_errors(module: str, condition: str) -> list[str]:
    source = f'import "{module}"\nrule t {{ condition: {condition} }}'
    ast = Parser().parse(source)
    return TypeChecker().check(ast)


@pytest.mark.parametrize(("module", "condition"), ACCEPTED_CALLS)
def test_module_function_call_is_accepted(module: str, condition: str) -> None:
    assert _function_errors(module, condition) == []


@pytest.mark.parametrize(("module", "condition"), REJECTED_CALLS)
def test_invalid_module_function_call_is_rejected(module: str, condition: str) -> None:
    assert _function_errors(module, condition) != []


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
@pytest.mark.parametrize(("module", "condition"), ACCEPTED_CALLS)
def test_accepted_call_matches_libyara(module: str, condition: str) -> None:
    import yara

    source = f'import "{module}"\nrule t {{ condition: {condition} }}'
    yara.compile(source=source)
    assert _function_errors(module, condition) == []


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
@pytest.mark.parametrize(("module", "condition"), REJECTED_CALLS)
def test_rejected_call_matches_libyara(module: str, condition: str) -> None:
    import yara

    source = f'import "{module}"\nrule t {{ condition: {condition} }}'
    with pytest.raises(yara.SyntaxError):
        yara.compile(source=source)
    assert _function_errors(module, condition) != []
