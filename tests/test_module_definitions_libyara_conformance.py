"""Bidirectional conformance gate: declared module surface == libyara 4.5.4.

The builtin module type definitions in ``module_definitions.py`` are maintained
by hand, so they drift from the real engine in both directions:

* over-declaration -- declaring a constant/attribute/function that libyara
  rejects (the kind of drift that shipped MACHINE_RISCV*/ET_LOPROC,
  ``elf.number_of_symbols`` and ``dotnet.memberrefs`` before this gate);
* sub-declaration -- omitting a member that libyara provides, which turns valid
  rules into false positives (the kind that hid ``elf.telfhash``,
  ``pe.exports_index`` and the whole authenticode ``signatures`` subtree);
* return-type drift -- typing a function ``boolean`` when libyara declares it
  ``integer`` (so ``console.log(...) + 1`` was wrongly rejected).

Over-declaration is pinned against the *installed* libyara through the live
oracle (``yara.compile``) so the type system can never declare something the
real engine refuses. Sub-declaration and return types are pinned against an
embedded canonical function table transcribed from the libyara 4.5.4 module
sources, each entry re-validated against the installed oracle so the snapshot
itself cannot silently rot. The ``vt`` module is VirusTotal-private and
``cuckoo`` is not built into stock libyara, so both are excluded from oracle
checks (``cuckoo`` is still pinned structurally from source).
"""

from __future__ import annotations

import pytest

from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType
from yaraast.types._registry_primitives import (
    AnyType,
    BooleanType,
    DoubleType,
    FloatType,
    IntegerType,
    RegexType,
    ScalarType,
    StringType,
)
from yaraast.types.module_definitions import _MODULE_SPECS, load_builtin_modules

yara = pytest.importorskip("yara")

# Modules absent from stock open-source libyara: cannot be probed with the oracle.
_NO_ORACLE = frozenset({"vt", "cuckoo"})

# Canonical function surface transcribed from libyara 4.5.4 module C sources
# (libyara/modules/<name>/<name>.c, ``declare_function`` declarations). Value is
# the libyara return-type code: "i"=int, "s"=string, "f"=float. Function
# overloads collapse to a single name with one return type in libyara.
_CANONICAL_FUNCS: dict[str, dict[str, str]] = {
    "pe": {
        "imphash": "s",
        "section_index": "i",
        "exports": "i",
        "exports_index": "i",
        "imports": "i",
        "import_rva": "i",
        "delayed_import_rva": "i",
        "locale": "i",
        "language": "i",
        "is_dll": "i",
        "is_32bit": "i",
        "is_64bit": "i",
        "calculate_checksum": "i",
        "rva_to_offset": "i",
        "rich_signature.version": "i",
        "rich_signature.toolid": "i",
        "signatures.valid_on": "i",
    },
    "elf": {"import_md5": "s", "telfhash": "s"},
    "math": {
        "in_range": "i",
        "deviation": "f",
        "mean": "f",
        "serial_correlation": "f",
        "monte_carlo_pi": "f",
        "entropy": "f",
        "min": "i",
        "max": "i",
        "to_number": "i",
        "abs": "i",
        "count": "i",
        "percentage": "f",
        "mode": "i",
        "to_string": "s",
    },
    "hash": {
        "md5": "s",
        "sha1": "s",
        "sha256": "s",
        "checksum32": "i",
        "crc32": "i",
    },
    "dotnet": {},
    "time": {"now": "i"},
    "console": {"log": "i", "hex": "i"},
    "string": {"to_int": "i", "length": "i"},
    "cuckoo": {
        "network.http_request": "i",
        "network.http_get": "i",
        "network.http_post": "i",
        "network.http_user_agent": "i",
        "network.dns_lookup": "i",
        "network.host": "i",
        "network.tcp": "i",
        "network.udp": "i",
        "registry.key_access": "i",
        "filesystem.file_access": "i",
        "sync.mutex": "i",
    },
}

# Newly recovered libyara members whose presence must never regress.
_REQUIRED_ATTRS: dict[str, tuple[str, ...]] = {
    "pe": (
        "is_signed",
        "number_of_rva_and_sizes",
        "resource_version",
        "export_details",
        "import_details",
        "delayed_import_details",
    ),
}

_RETURN_CODE: dict[type, str] = {
    IntegerType: "i",
    StringType: "s",
    FloatType: "f",
    DoubleType: "f",
    BooleanType: "b",
    RegexType: "r",
    ScalarType: "scalar",
    AnyType: "any",
}


def _return_code(return_type: object) -> str:
    return _RETURN_CODE.get(type(return_type), type(return_type).__name__)


def _leaf_paths(type_obj: object, prefix: str) -> list[tuple[str, str]]:
    """Yield ``(access_expression, leaf_code)`` for every scalar leaf reachable.

    Struct arrays are indexed with ``[0]``, dictionaries with ``["k"]`` so the
    generated expression is one libyara accepts when the member exists.
    """
    if isinstance(type_obj, StructType):
        paths: list[tuple[str, str]] = []
        for name, field in type_obj.fields.items():
            paths.extend(_leaf_paths(field, f"{prefix}.{name}"))
        return paths
    if isinstance(type_obj, ArrayType):
        return _leaf_paths(type_obj.element_type, f"{prefix}[0]")
    if isinstance(type_obj, DictionaryType):
        return _leaf_paths(type_obj.value_type, f'{prefix}["k"]')
    return [(prefix, _return_code(type_obj))]


def _declared_attr_leaves() -> list[tuple[str, str, str]]:
    cases: list[tuple[str, str, str]] = []
    for module, definition in load_builtin_modules().items():
        if module in _NO_ORACLE:
            continue
        for name, type_obj in definition.attributes.items():
            for expr, code in _leaf_paths(type_obj, f"{module}.{name}"):
                cases.append((module, expr, code))
    return cases


def _leaf_condition(expr: str, code: str) -> str:
    if code in ("i", "f"):
        return f"{expr} >= 0"
    if code == "s":
        return f'{expr} == "x"'
    return expr


@pytest.mark.parametrize(
    ("module", "expr", "code"),
    _declared_attr_leaves(),
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_declared_attribute_is_accepted_by_libyara(module: str, expr: str, code: str) -> None:
    """Over-declaration gate: no declared attribute is refused by libyara."""
    source = f'import "{module}"\nrule t {{ condition: {_leaf_condition(expr, code)} }}'
    try:
        yara.compile(source=source)
    except yara.SyntaxError as exc:
        pytest.fail(
            f"module_definitions declares {expr} but libyara {yara.YARA_VERSION} rejects it: {exc}"
        )


def _our_func_codes(module: str) -> dict[str, str]:
    definition = load_builtin_modules()[module]
    return {name: _return_code(fn.return_type) for name, fn in definition.functions.items()}


@pytest.mark.parametrize("module", sorted(_CANONICAL_FUNCS))
def test_declared_functions_match_libyara_surface(module: str) -> None:
    """Function names and return types match the libyara 4.5.4 surface exactly."""
    canonical = _CANONICAL_FUNCS[module]
    ours = _our_func_codes(module)

    assert set(ours) == set(canonical), (
        f"{module} function surface drift: "
        f"missing={sorted(set(canonical) - set(ours))} "
        f"extra={sorted(set(ours) - set(canonical))}"
    )
    for name, expected in canonical.items():
        actual = ours[name]
        if expected == "f":
            assert actual == "f", f"{module}.{name} return: libyara=float ours={actual}"
        else:
            assert actual == expected, (
                f"{module}.{name} return: libyara={expected!r} ours={actual!r}"
            )


@pytest.mark.parametrize("module", sorted(set(_CANONICAL_FUNCS) - _NO_ORACLE))
def test_canonical_function_names_exist_in_libyara(module: str) -> None:
    """The embedded canonical snapshot is itself pinned to the installed libyara.

    Referencing an unknown member yields ``invalid field name``; a real function
    referenced without its call yields ``wrong usage of identifier`` instead, so
    the absence of ``invalid field name`` proves the name is recognized. This
    fails loudly if the snapshot ever names a function the engine has dropped.
    ``signatures.valid_on`` lives inside a struct array, so it is probed with a
    proper indexed call that must compile cleanly.
    """
    for name in _CANONICAL_FUNCS[module]:
        if name == "signatures.valid_on":
            source = (
                f'import "{module}"\nrule t {{ condition: {module}.signatures[0].valid_on(0) }}'
            )
            yara.compile(source=source)
            continue
        source = f'import "{module}"\nrule t {{ condition: {module}.{name} }}'
        with pytest.raises(yara.SyntaxError) as excinfo:
            yara.compile(source=source)
        assert "invalid field name" not in str(excinfo.value), (
            f"{module}.{name} is not a recognized libyara function: {excinfo.value}"
        )


@pytest.mark.parametrize(
    ("module", "attr"),
    [(module, attr) for module, attrs in _REQUIRED_ATTRS.items() for attr in attrs],
)
def test_required_attribute_is_declared(module: str, attr: str) -> None:
    """Sub-declaration anchors: recovered libyara members must stay declared."""
    assert attr in load_builtin_modules()[module].attributes, (
        f"{module}.{attr} is declared by libyara but missing from module_definitions"
    )


def test_no_module_overdeclares_a_function() -> None:
    """Every declared function exists in the canonical libyara surface."""
    for module in sorted(set(_MODULE_SPECS) - {"vt"}):
        declared = set(load_builtin_modules()[module].functions)
        canonical = set(_CANONICAL_FUNCS.get(module, {}))
        extra = declared - canonical
        assert not extra, f"{module} declares non-libyara functions: {sorted(extra)}"


def _probe_condition(module: str, name: str, type_code: str) -> str:
    if type_code in ("i", "d"):
        return f"{module}.{name} >= 0"
    return f"{module}.{name} == {module}.{name}"


def _declared_consts() -> list[tuple[str, str, str]]:
    cases: list[tuple[str, str, str]] = []
    for module, spec in _MODULE_SPECS.items():
        if module in _NO_ORACLE:
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
    """Over-declaration gate for constants (kept granular for clear failures)."""
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
