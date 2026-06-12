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


def test_define_directive_preserves_empty_macro_value_argument() -> None:
    directive = DefineDirective("EMPTY", "")

    assert directive.macro_value == ""
    assert directive.arguments == ["EMPTY", ""]


@pytest.mark.parametrize(
    ("pragma", "property_name"),
    [
        (Pragma(cast(Any, "include_once"), "include_once"), "is_include_once"),
        (Pragma(cast(Any, "define"), "define"), "is_define"),
    ],
)
def test_pragma_flag_properties_reject_invalid_internal_state(
    pragma: Pragma,
    property_name: str,
) -> None:
    with pytest.raises(TypeError, match="Pragma type must be a PragmaType"):
        _ = pragma.is_include_once if property_name == "is_include_once" else pragma.is_define


def test_pragma_string_reprs_reject_invalid_arguments() -> None:
    generic = Pragma(PragmaType.PRAGMA, "vendor", cast(Any, "on"))
    custom = CustomPragma("vendor", arguments=cast(Any, "on"))

    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        str(generic)

    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        str(custom)


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Pragma(PragmaType.PRAGMA, ""), "Pragma name cannot be empty"),
        (CustomPragma(""), "Pragma name cannot be empty"),
        (DefineDirective(""), "Pragma macro_name cannot be empty"),
        (UndefDirective(""), "Pragma macro_name cannot be empty"),
    ],
)
def test_pragma_string_reprs_reject_empty_required_names(
    node: Pragma,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        str(node)


def test_define_string_repr_rejects_invalid_macro_value() -> None:
    directive = DefineDirective("FLAG", cast(Any, False))

    with pytest.raises(TypeError, match="Pragma macro_value must be a string"):
        str(directive)


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (
            InRulePragma(cast(Any, "bad")),
            TypeError,
            "InRulePragma pragma must be a Pragma",
        ),
        (
            InRulePragma(Pragma(PragmaType.PRAGMA, "vendor"), ""),
            ValueError,
            "InRulePragma position cannot be empty",
        ),
        (
            PragmaBlock(cast(Any, "bad")),
            TypeError,
            "PragmaBlock pragmas must be a list or tuple",
        ),
        (
            PragmaBlock(cast(Any, ["bad"])),
            TypeError,
            "PragmaBlock pragmas must contain Pragma nodes",
        ),
        (
            PragmaBlock([Pragma(PragmaType.PRAGMA, "vendor")], scope=cast(Any, "file")),
            TypeError,
            "Pragma scope must be a PragmaScope",
        ),
    ],
)
def test_pragma_container_string_reprs_reject_invalid_fields(
    node: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        str(node)


@pytest.mark.parametrize(
    ("pragma_type", "condition", "error_type", "message"),
    [
        (PragmaType.IFDEF, "", ValueError, "Pragma condition cannot be empty"),
        (PragmaType.IFNDEF, "   ", ValueError, "Pragma condition cannot be empty"),
        (PragmaType.IFDEF, False, TypeError, "Pragma condition must be a string"),
        (PragmaType.IFNDEF, 0, TypeError, "Pragma condition must be a string"),
    ],
)
def test_conditional_directive_string_rejects_invalid_required_conditions(
    pragma_type: PragmaType,
    condition: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    directive = ConditionalDirective(pragma_type, cast(Any, condition))

    with pytest.raises(error_type, match=message):
        str(directive)


@pytest.mark.parametrize("arguments", ["", (), False])
def test_custom_pragma_preserves_invalid_falsy_arguments(arguments: Any) -> None:
    custom = CustomPragma("vendor", arguments=cast(Any, arguments))

    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        custom.validate_structure()


@pytest.mark.parametrize("parameters", [False, [], ()])
def test_custom_pragma_preserves_invalid_falsy_parameters(parameters: Any) -> None:
    custom = CustomPragma("vendor", parameters=cast(Any, parameters))

    with pytest.raises(TypeError, match="Pragma parameters must be a dictionary"):
        custom.validate_structure()


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


@pytest.mark.parametrize(
    ("value", "operation", "message"),
    [
        (
            cast(Any, "bad"),
            "get_pragmas_by_type",
            "PragmaBlock pragmas must be a list or tuple",
        ),
        (
            [cast(Any, object())],
            "get_pragmas_by_type",
            "PragmaBlock pragmas must contain Pragma nodes",
        ),
        (
            [Pragma(cast(Any, "bad"), "vendor")],
            "get_pragmas_by_type",
            "Pragma type must be a PragmaType",
        ),
        (
            cast(Any, "bad"),
            "has_pragma",
            "PragmaBlock pragmas must be a list or tuple",
        ),
        (
            [cast(Any, object())],
            "has_pragma",
            "PragmaBlock pragmas must contain Pragma nodes",
        ),
        (
            [Pragma(cast(Any, "bad"), "vendor")],
            "has_pragma",
            "Pragma type must be a PragmaType",
        ),
    ],
)
def test_pragma_block_lookup_helpers_reject_invalid_internal_state(
    value: Any,
    operation: str,
    message: str,
) -> None:
    block = PragmaBlock(scope=PragmaScope.RULE)
    block.pragmas = value

    with pytest.raises(TypeError, match=message):
        if operation == "get_pragmas_by_type":
            block.get_pragmas_by_type(PragmaType.PRAGMA)
        else:
            block.has_pragma(PragmaType.PRAGMA)


def test_custom_pragma_parameter_keys_must_be_strings_without_partial_update() -> None:
    custom = CustomPragma(name="vendor", arguments=["x"], scope=PragmaScope.FILE)
    custom.set_parameter("level", 3)

    with pytest.raises(TypeError, match="Pragma parameter key must be a string"):
        custom.set_parameter(cast(Any, object()), 4)

    with pytest.raises(TypeError, match="Pragma parameter key must be a string"):
        custom.get_parameter(cast(Any, object()))

    assert custom.parameters == {"level": 3}


def test_custom_pragma_parameter_helpers_reject_invalid_parameter_state() -> None:
    custom = CustomPragma(name="vendor", arguments=["x"], scope=PragmaScope.FILE)
    custom.parameters = cast(Any, [])

    with pytest.raises(TypeError, match="Pragma parameters must be a dictionary"):
        custom.get_parameter("level")

    with pytest.raises(TypeError, match="Pragma parameters must be a dictionary"):
        custom.set_parameter("level", 3)

    assert custom.parameters == cast(Any, [])


def test_custom_pragma_set_parameter_rejects_invalid_values_without_partial_update() -> None:
    custom = CustomPragma(name="vendor", arguments=["x"], scope=PragmaScope.FILE)
    custom.set_parameter("level", 3)

    with pytest.raises(TypeError, match="Pragma parameter value must be"):
        custom.set_parameter("next", object())

    assert custom.parameters == {"level": 3}


def test_pragma_block_rejects_invalid_pragmas_without_partial_update() -> None:
    custom = CustomPragma(name="vendor", arguments=["x"], scope=PragmaScope.FILE)
    block = PragmaBlock(scope=PragmaScope.RULE)
    block.add_pragma(custom)

    with pytest.raises(TypeError, match="Pragma input must be a Pragma"):
        block.add_pragma(cast(Any, object()))

    assert block.pragmas == [custom]


def test_pragma_block_add_pragma_rejects_invalid_scope_without_partial_update() -> None:
    block = PragmaBlock(scope=cast(Any, "file"))
    pragma = Pragma(PragmaType.PRAGMA, "vendor")

    with pytest.raises(TypeError, match="Pragma scope must be a PragmaScope"):
        block.add_pragma(pragma)

    assert block.pragmas == []
    assert pragma.scope == PragmaScope.FILE


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


@pytest.mark.parametrize(
    ("in_rule_pragma", "property_name", "error_type", "message"),
    [
        (
            InRulePragma(cast(Any, object())),
            "is_before_strings",
            TypeError,
            "InRulePragma pragma must be a Pragma",
        ),
        (
            InRulePragma(Pragma(PragmaType.PRAGMA, "vendor"), cast(Any, object())),
            "is_before_strings",
            TypeError,
            "InRulePragma position must be a string",
        ),
        (
            InRulePragma(Pragma(PragmaType.PRAGMA, "vendor"), ""),
            "is_after_strings",
            ValueError,
            "InRulePragma position cannot be empty",
        ),
        (
            InRulePragma(Pragma(PragmaType.PRAGMA, "vendor"), "   "),
            "is_before_condition",
            ValueError,
            "InRulePragma position cannot be empty",
        ),
    ],
)
def test_in_rule_pragma_position_properties_reject_invalid_internal_state(
    in_rule_pragma: InRulePragma,
    property_name: str,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        if property_name == "is_before_strings":
            _ = in_rule_pragma.is_before_strings
        elif property_name == "is_after_strings":
            _ = in_rule_pragma.is_after_strings
        else:
            _ = in_rule_pragma.is_before_condition


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
        (
            lambda: create_define(""),
            "Pragma macro_name cannot be empty",
        ),
        (
            lambda: create_undef(""),
            "Pragma macro_name cannot be empty",
        ),
        (
            lambda: create_ifdef(""),
            "Pragma condition cannot be empty",
        ),
        (
            lambda: create_ifndef("   "),
            "Pragma condition cannot be empty",
        ),
        (
            lambda: create_in_rule_pragma(pragma, ""),
            "InRulePragma position cannot be empty",
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
