"""Conformance gate: every declared module constant must exist in libyara.

The builtin module type definitions in ``module_definitions.py`` are maintained
by hand. This test pins the declared constants to the installed libyara so the
type system can never silently over-declare a constant that the real engine
rejects (the kind of drift that shipped MACHINE_RISCV*/ET_LOPROC before this
gate). The ``vt`` module is VirusTotal-private and absent from open-source
libyara, so it is excluded.
"""

from __future__ import annotations

import pytest

from yaraast.types.module_definitions import _MODULE_SPECS

yara = pytest.importorskip("yara")

_EXCLUDED_MODULES = frozenset({"vt"})


def _probe_condition(module: str, name: str, type_code: str) -> str:
    if type_code in ("i", "d"):
        return f"{module}.{name} >= 0"
    return f"{module}.{name} == {module}.{name}"


def _declared_consts() -> list[tuple[str, str, str]]:
    cases: list[tuple[str, str, str]] = []
    for module, spec in _MODULE_SPECS.items():
        if module in _EXCLUDED_MODULES:
            continue
        for name, type_code in spec.get("consts", {}).items():
            cases.append((module, name, type_code))
    return cases


@pytest.mark.parametrize(
    ("module", "name", "type_code"),
    _declared_consts(),
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_declared_module_const_is_accepted_by_libyara(
    module: str, name: str, type_code: str
) -> None:
    source = (
        f'import "{module}"\nrule t {{ condition: {_probe_condition(module, name, type_code)} }}'
    )
    try:
        yara.compile(source=source)
    except yara.SyntaxError as exc:
        pytest.fail(
            f"module_definitions declares {module}.{name} ({type_code!r}) but "
            f"libyara {yara.YARA_VERSION} rejects it: {exc}"
        )
