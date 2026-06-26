"""Additional tests for pragma nodes (no mocks)."""

from __future__ import annotations

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


def test_custom_pragma_and_block_string_output() -> None:
    custom = CustomPragma(
        name="vendor",
        arguments=["x", "y"],
        parameters={"level": 3},
        scope=PragmaScope.FILE,
    )
    assert custom.parameters["level"] == 3
    assert str(custom).startswith("#pragma vendor")

    block = PragmaBlock([custom], scope=PragmaScope.RULE)
    assert str(block) == str(custom)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (
            cast(Any, "bad"),
            "PragmaBlock pragmas must be a list or tuple",
        ),
        (
            [cast(Any, object())],
            "PragmaBlock pragmas must contain Pragma nodes",
        ),
        (
            [Pragma(cast(Any, "bad"), "vendor")],
            "Pragma type must be a PragmaType",
        ),
    ],
)
def test_pragma_block_string_rejects_invalid_internal_state(
    value: Any,
    message: str,
) -> None:
    block = PragmaBlock(scope=PragmaScope.RULE)
    block.pragmas = value

    with pytest.raises(TypeError, match=message):
        str(block)


def test_in_rule_pragma_positions() -> None:
    pragma = Pragma(PragmaType.DEFINE, "define", ["X", "2"])
    in_rule = InRulePragma(pragma=pragma, position="before_strings")
    assert in_rule.is_before_strings is True
    assert in_rule.is_after_strings is False
    assert in_rule.is_before_condition is False
    assert str(in_rule) == str(pragma)

    in_rule2 = InRulePragma(pragma, "before_condition")
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
