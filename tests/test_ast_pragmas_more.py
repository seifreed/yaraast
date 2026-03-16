"""Additional tests for pragma nodes (no mocks)."""

from __future__ import annotations

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


def test_pragma_accept_methods() -> None:
    class _Visitor:
        def visit_pragma(self, node):
            return ("pragma", node.name)

        def visit_in_rule_pragma(self, node):
            return ("in_rule", node.position)

        def visit_pragma_block(self, node):
            return ("block", len(node.pragmas))

    visitor = _Visitor()
    pragma = Pragma(PragmaType.DEFINE, "define", ["X"])
    in_rule = InRulePragma(pragma=pragma, position="after_strings")
    block = PragmaBlock(pragmas=[pragma])

    assert pragma.accept(visitor) == ("pragma", "define")
    assert in_rule.accept(visitor) == ("in_rule", "after_strings")
    assert block.accept(visitor) == ("block", 1)
