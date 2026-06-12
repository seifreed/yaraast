"""Additional tests for pragma nodes (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    Pragma,
    PragmaBlock,
    PragmaScope,
    PragmaType,
    UndefDirective,
    create_define,
    create_endif,
    create_ifdef,
    create_ifndef,
    create_in_rule_pragma,
    create_include_once,
    create_pragma,
    create_undef,
)


def test_pragma_string_reprs_and_flags() -> None:
    assert PragmaType.from_string("not_known") == PragmaType.CUSTOM

    generic = Pragma(PragmaType.UNDEF, "undef", ["X"])
    assert str(generic) == "#undef X"

    pragma_style = Pragma(PragmaType.PRAGMA, "optimize", ["fast"])
    assert str(pragma_style) == "#pragma optimize fast"

    include_once = IncludeOncePragma()
    assert include_once.is_include_once is True
    assert str(include_once) == "#include_once"

    define = DefineDirective("X", "1")
    assert define.is_define is True
    assert str(define) == "#define X 1"
    assert str(DefineDirective("ONLY_NAME")) == "#define ONLY_NAME"

    undef = UndefDirective("X")
    assert str(undef) == "#undef X"

    ifdef = ConditionalDirective.ifdef("FOO")
    ifndef = ConditionalDirective.ifndef("BAR")
    endif = ConditionalDirective.endif()
    assert str(ifdef) == "#ifdef FOO"
    assert str(ifndef) == "#ifndef BAR"
    assert str(endif) == "#endif"


def test_pragma_string_reprs_reject_invalid_arguments() -> None:
    generic = Pragma(PragmaType.PRAGMA, "vendor", cast(Any, "on"))
    custom = CustomPragma("vendor", arguments=cast(Any, "on"))

    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        str(generic)

    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        str(custom)


def test_custom_pragma_and_block_helpers() -> None:
    custom = CustomPragma(name="vendor", arguments=["x", "y"], scope=PragmaScope.FILE)
    custom.set_parameter("level", 3)
    assert custom.get_parameter("level") == 3
    assert str(custom).startswith("#pragma vendor")

    block = PragmaBlock(scope=PragmaScope.RULE)
    block.add_pragma(custom)
    assert block.has_pragma(PragmaType.CUSTOM) is True
    assert block.get_pragmas_by_type(PragmaType.CUSTOM) == [custom]
    assert block.get_pragmas_by_type(PragmaType.DEFINE) == []
    assert str(block) == str(custom)


@pytest.mark.parametrize("pragma_type", [None, 1, "custom", object()])
def test_pragma_block_rejects_invalid_lookup_types(pragma_type: Any) -> None:
    block = PragmaBlock(scope=PragmaScope.RULE)

    with pytest.raises(TypeError, match="Pragma type must be a PragmaType"):
        block.get_pragmas_by_type(cast(PragmaType, pragma_type))
    with pytest.raises(TypeError, match="Pragma type must be a PragmaType"):
        block.has_pragma(cast(PragmaType, pragma_type))


def test_custom_pragma_parameter_keys_must_be_strings_without_partial_update() -> None:
    custom = CustomPragma(name="vendor", arguments=["x"], scope=PragmaScope.FILE)
    custom.set_parameter("level", 3)

    with pytest.raises(TypeError, match="Pragma parameter key must be a string"):
        custom.set_parameter(cast(Any, object()), 4)

    with pytest.raises(TypeError, match="Pragma parameter key must be a string"):
        custom.get_parameter(cast(Any, object()))

    assert custom.parameters == {"level": 3}


def test_pragma_block_rejects_invalid_pragmas_without_partial_update() -> None:
    custom = CustomPragma(name="vendor", arguments=["x"], scope=PragmaScope.FILE)
    block = PragmaBlock(scope=PragmaScope.RULE)
    block.add_pragma(custom)

    with pytest.raises(TypeError, match="Pragma input must be a Pragma"):
        block.add_pragma(cast(Any, object()))

    assert block.pragmas == [custom]


def test_create_helpers_and_in_rule_positions() -> None:
    pragma = create_pragma("define", ["X", "2"])
    assert isinstance(pragma, Pragma)
    assert pragma.pragma_type == PragmaType.DEFINE

    include_once = create_include_once()
    define = create_define("FLAG")
    undef = create_undef("OLD")
    ifdef = create_ifdef("FEATURE")
    ifndef = create_ifndef("NO_FEATURE")
    endif = create_endif()
    assert isinstance(include_once, IncludeOncePragma)
    assert isinstance(define, DefineDirective)
    assert isinstance(undef, UndefDirective)
    assert isinstance(ifdef, ConditionalDirective)
    assert isinstance(ifndef, ConditionalDirective)
    assert isinstance(endif, ConditionalDirective)

    custom = create_pragma("vendor_specific", ["x"], scope=PragmaScope.LOCAL)
    assert isinstance(custom, CustomPragma)
    assert custom.scope == PragmaScope.LOCAL

    in_rule = InRulePragma(pragma=pragma, position="before_strings")
    assert in_rule.is_before_strings is True
    assert in_rule.is_after_strings is False
    assert in_rule.is_before_condition is False
    assert str(in_rule) == str(pragma)

    in_rule2 = create_in_rule_pragma(pragma, "before_condition")
    assert in_rule2.is_before_condition is True


def test_pragma_helpers_reject_invalid_inputs_at_creation_time() -> None:
    pragma = create_pragma("vendor")

    invalid_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: PragmaType.from_string(cast(Any, object())),
            "Pragma type input must be a string",
        ),
        (
            lambda: create_pragma(cast(Any, object())),
            "Pragma name must be a string",
        ),
        (
            lambda: create_pragma("vendor", cast(Any, "on")),
            "Pragma arguments must be a list of strings",
        ),
        (
            lambda: create_pragma("vendor", cast(Any, ["on", object()])),
            "Pragma arguments must be a list of strings",
        ),
        (
            lambda: create_pragma("vendor", scope=cast(Any, "file")),
            "Pragma scope must be a PragmaScope",
        ),
        (
            lambda: create_define(cast(Any, object())),
            "Pragma macro_name must be a string",
        ),
        (
            lambda: create_define("FLAG", cast(Any, object())),
            "Pragma macro_value must be a string",
        ),
        (
            lambda: create_undef(cast(Any, object())),
            "Pragma macro_name must be a string",
        ),
        (
            lambda: create_ifdef(cast(Any, object())),
            "Pragma condition must be a string",
        ),
        (
            lambda: create_ifndef(cast(Any, object())),
            "Pragma condition must be a string",
        ),
        (
            lambda: create_in_rule_pragma(cast(Any, object())),
            "InRulePragma pragma must be a Pragma",
        ),
        (
            lambda: create_in_rule_pragma(pragma, cast(Any, object())),
            "InRulePragma position must be a string",
        ),
    ]

    for factory, message in invalid_cases:
        with pytest.raises(TypeError, match=message):
            factory()

    empty_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: PragmaType.from_string("   "),
            "Pragma type input cannot be empty",
        ),
        (
            lambda: create_pragma(""),
            "Pragma type input cannot be empty",
        ),
    ]
    for factory, message in empty_cases:
        with pytest.raises(ValueError, match=message):
            factory()


def test_pragma_accept_methods() -> None:
    class _Visitor:
        def visit_pragma(self, node: Pragma) -> tuple[str, str]:
            return ("pragma", node.name)

        def visit_in_rule_pragma(self, node: InRulePragma) -> tuple[str, str]:
            return ("in_rule", node.position)

        def visit_pragma_block(self, node: PragmaBlock) -> tuple[str, int]:
            return ("block", len(node.pragmas))

    visitor = _Visitor()
    pragma = Pragma(PragmaType.DEFINE, "define", ["X"])
    in_rule = InRulePragma(pragma=pragma, position="after_strings")
    block = PragmaBlock(pragmas=[pragma])

    assert pragma.accept(visitor) == ("pragma", "define")
    assert in_rule.accept(visitor) == ("in_rule", "after_strings")
    assert block.accept(visitor) == ("block", 1)
