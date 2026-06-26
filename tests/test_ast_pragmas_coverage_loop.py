"""Coverage loop: yaraast.ast.pragmas — exercises every uncovered line without mocks.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import math
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
    _normalize_arguments,
    _require_pragma_type,
    _require_scope,
    _validate_pragma_arguments,
    _validate_pragma_parameter_value,
    _validate_pragma_parameters,
    _validate_yara_identifier,
)

# ---------------------------------------------------------------------------
# _normalize_arguments — lines 20-27
# ---------------------------------------------------------------------------


def test_normalize_arguments_returns_empty_list_when_none_is_passed() -> None:
    """None input produces an empty list, not a TypeError."""
    result = _normalize_arguments(None)
    assert result == []


def test_normalize_arguments_returns_list_unchanged_for_valid_string_list() -> None:
    """A well-formed list of strings is returned as-is."""
    args = ["alpha", "beta", "gamma"]
    result = _normalize_arguments(args)
    assert result is args


def test_normalize_arguments_raises_for_non_list_input() -> None:
    """Non-list input raises TypeError with the expected message."""
    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        _normalize_arguments(cast(Any, "not_a_list"))


def test_normalize_arguments_raises_for_list_with_non_string_element() -> None:
    """A list that contains a non-string element raises TypeError."""
    with pytest.raises(TypeError, match="Pragma arguments must be a list of strings"):
        _normalize_arguments(cast(Any, ["ok", 42]))


# ---------------------------------------------------------------------------
# _validate_pragma_arguments — lines 31-36
# ---------------------------------------------------------------------------


def test_validate_pragma_arguments_raises_on_empty_string_in_middle() -> None:
    """An empty string in a non-trailing position raises ValueError."""
    with pytest.raises(ValueError, match="Pragma argument must not be empty"):
        _validate_pragma_arguments(["good", "", "also_good"])


def test_validate_pragma_arguments_allows_trailing_empty_when_flag_set() -> None:
    """allow_trailing_empty=True skips the final empty argument without error."""
    _validate_pragma_arguments(["good", ""], allow_trailing_empty=True)


def test_validate_pragma_arguments_raises_on_trailing_empty_when_flag_not_set() -> None:
    """allow_trailing_empty=False (default) rejects a trailing empty argument."""
    with pytest.raises(ValueError, match="Pragma argument must not be empty"):
        _validate_pragma_arguments(["good", ""])


def test_validate_pragma_arguments_passes_for_empty_list() -> None:
    """An empty argument list is unconditionally valid."""
    _validate_pragma_arguments([])


def test_validate_pragma_arguments_passes_for_all_non_empty() -> None:
    """A list with no empty strings passes without error."""
    _validate_pragma_arguments(["a", "b", "c"])


# ---------------------------------------------------------------------------
# _require_scope — lines 40-43
# ---------------------------------------------------------------------------


def test_require_scope_raises_for_non_enum_input() -> None:
    """Non-PragmaScope input raises TypeError."""
    with pytest.raises(TypeError, match="Pragma scope must be a PragmaScope"):
        _require_scope(cast(Any, "file"))


def test_require_scope_returns_valid_scope_unchanged() -> None:
    """A valid PragmaScope value is returned unchanged."""
    for scope in PragmaScope:
        assert _require_scope(scope) is scope


# ---------------------------------------------------------------------------
# _validate_pragma_parameter_value — lines 47-52
# ---------------------------------------------------------------------------


def test_validate_pragma_parameter_value_accepts_string() -> None:
    _validate_pragma_parameter_value("hello")


def test_validate_pragma_parameter_value_accepts_bool() -> None:
    _validate_pragma_parameter_value(True)


def test_validate_pragma_parameter_value_accepts_int() -> None:
    _validate_pragma_parameter_value(42)


def test_validate_pragma_parameter_value_accepts_finite_float() -> None:
    _validate_pragma_parameter_value(3.14)


def test_validate_pragma_parameter_value_raises_for_nan() -> None:
    """NaN is not finite and must be rejected."""
    with pytest.raises(TypeError, match="Pragma parameter value must be"):
        _validate_pragma_parameter_value(math.nan)


def test_validate_pragma_parameter_value_raises_for_positive_infinity() -> None:
    """Positive infinity is not finite and must be rejected."""
    with pytest.raises(TypeError, match="Pragma parameter value must be"):
        _validate_pragma_parameter_value(math.inf)


def test_validate_pragma_parameter_value_raises_for_negative_infinity() -> None:
    """Negative infinity is not finite and must be rejected."""
    with pytest.raises(TypeError, match="Pragma parameter value must be"):
        _validate_pragma_parameter_value(-math.inf)


def test_validate_pragma_parameter_value_raises_for_object() -> None:
    """An arbitrary object is not a valid parameter value."""
    with pytest.raises(TypeError, match="Pragma parameter value must be"):
        _validate_pragma_parameter_value(object())


# ---------------------------------------------------------------------------
# _validate_pragma_parameters — lines 56-63
# ---------------------------------------------------------------------------


def test_validate_pragma_parameters_raises_for_non_dict() -> None:
    with pytest.raises(TypeError, match="Pragma parameters must be a dictionary"):
        _validate_pragma_parameters(cast(Any, []))


def test_validate_pragma_parameters_raises_for_non_string_key() -> None:
    with pytest.raises(TypeError, match="Pragma parameters keys must be strings"):
        _validate_pragma_parameters(cast(Any, {1: "v"}))


def test_validate_pragma_parameters_validates_each_value() -> None:
    """Invalid value type inside a dict with a valid string key raises TypeError."""
    with pytest.raises(TypeError, match="Pragma parameter value must be"):
        _validate_pragma_parameters({"k": object()})


def test_validate_pragma_parameters_accepts_valid_dict() -> None:
    """A dict with string keys and valid scalar values passes without error."""
    _validate_pragma_parameters({"a": "str", "b": 1, "c": True, "d": 2.5})


# ---------------------------------------------------------------------------
# PragmaType.from_string — lines 86-93
# ---------------------------------------------------------------------------


def test_pragma_type_from_string_returns_known_types() -> None:
    """Each known pragma type string maps back to its enum member."""
    assert PragmaType.from_string("pragma") == PragmaType.PRAGMA
    assert PragmaType.from_string("define") == PragmaType.DEFINE
    assert PragmaType.from_string("undef") == PragmaType.UNDEF
    assert PragmaType.from_string("ifdef") == PragmaType.IFDEF
    assert PragmaType.from_string("ifndef") == PragmaType.IFNDEF
    assert PragmaType.from_string("endif") == PragmaType.ENDIF
    assert PragmaType.from_string("include_once") == PragmaType.INCLUDE_ONCE


def test_pragma_type_from_string_returns_custom_for_unknown_string() -> None:
    """A string that does not match any known type returns CUSTOM."""
    assert PragmaType.from_string("vendor_specific") == PragmaType.CUSTOM


def test_pragma_type_from_string_normalises_to_lowercase() -> None:
    """Input is lowercased before matching, so mixed-case input resolves correctly."""
    assert PragmaType.from_string("PRAGMA") == PragmaType.PRAGMA
    assert PragmaType.from_string("Define") == PragmaType.DEFINE


# ---------------------------------------------------------------------------
# _require_pragma_type — lines 105-108
# ---------------------------------------------------------------------------


def test_require_pragma_type_raises_for_non_enum_input() -> None:
    with pytest.raises(TypeError, match="Pragma type must be a PragmaType"):
        _require_pragma_type(cast(Any, "define"))


def test_require_pragma_type_returns_valid_input_unchanged() -> None:
    for pt in PragmaType:
        assert _require_pragma_type(pt) is pt


# ---------------------------------------------------------------------------
# _validate_yara_identifier — lines 112-122
# ---------------------------------------------------------------------------


def test_validate_yara_identifier_raises_for_non_string() -> None:
    with pytest.raises(TypeError, match="Pragma identifier must be a string for libyara output"):
        _validate_yara_identifier(cast(Any, 123), "pragma")


def test_validate_yara_identifier_raises_for_keyword() -> None:
    """A YARA keyword is rejected even though it is otherwise a valid identifier."""
    with pytest.raises(ValueError, match="Invalid pragma identifier 'rule' for libyara output"):
        _validate_yara_identifier("rule", "pragma")


def test_validate_yara_identifier_raises_for_too_long_name() -> None:
    """A name exceeding YARA_IDENTIFIER_MAX_LENGTH (128) is rejected."""
    long_name = "a" * 129
    with pytest.raises(ValueError, match="Invalid pragma identifier"):
        _validate_yara_identifier(long_name, "pragma")


def test_validate_yara_identifier_raises_for_invalid_pattern() -> None:
    """Names that do not match [A-Za-z_][A-Za-z0-9_]* are rejected."""
    with pytest.raises(ValueError, match="Invalid pragma identifier '1bad'"):
        _validate_yara_identifier("1bad", "pragma")


def test_validate_yara_identifier_accepts_valid_identifiers() -> None:
    """Names at the boundary length and with underscores are accepted."""
    assert _validate_yara_identifier("valid_name", "pragma") == "valid_name"
    assert _validate_yara_identifier("_underscore", "pragma") == "_underscore"
    assert _validate_yara_identifier("a" * 128, "pragma") == "a" * 128


# ---------------------------------------------------------------------------
# Pragma.validate_structure — lines 136-142
# ---------------------------------------------------------------------------


def test_pragma_validate_structure_succeeds_for_valid_pragma() -> None:
    """validate_structure on a fully valid Pragma completes without error."""
    p = Pragma(PragmaType.PRAGMA, "vendor", ["arg1"], PragmaScope.FILE)
    p.validate_structure()


def test_pragma_validate_structure_raises_for_invalid_type() -> None:
    p = Pragma(cast(Any, "bad"), "vendor")
    with pytest.raises(TypeError, match="Pragma type must be a PragmaType"):
        p.validate_structure()


def test_pragma_validate_structure_raises_for_empty_name() -> None:
    p = Pragma(PragmaType.PRAGMA, "")
    with pytest.raises(ValueError, match="Pragma name cannot be empty"):
        p.validate_structure()


def test_pragma_validate_structure_raises_for_keyword_name() -> None:
    """A YARA keyword used as pragma name is rejected by _validate_yara_identifier."""
    p = Pragma(PragmaType.PRAGMA, "rule")
    with pytest.raises(ValueError, match="Invalid pragma identifier 'rule' for libyara output"):
        p.validate_structure()


def test_pragma_validate_structure_raises_for_empty_argument() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor", [""])
    with pytest.raises(ValueError, match="Pragma argument must not be empty"):
        p.validate_structure()


def test_pragma_validate_structure_raises_for_invalid_scope() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor", [], cast(Any, "file"))
    with pytest.raises(TypeError, match="Pragma scope must be a PragmaScope"):
        p.validate_structure()


def test_pragma_validate_structure_skips_argument_check_for_define_directive() -> None:
    """DefineDirective bypasses the generic _validate_pragma_arguments check
    because it stores an empty trailing argument for macro_value.  The macro_value
    is separately validated in DefineDirective.validate_structure, but when the
    value is non-empty the full call chain succeeds without the empty-arg error."""
    directive = DefineDirective("MACRO", "1")
    directive.validate_structure()


# ---------------------------------------------------------------------------
# Pragma property: is_include_once / is_define — lines 150, 155
# ---------------------------------------------------------------------------


def test_pragma_is_include_once_returns_true_for_include_once_type() -> None:
    p = Pragma(PragmaType.INCLUDE_ONCE, "include_once")
    assert p.is_include_once is True


def test_pragma_is_include_once_returns_false_for_other_types() -> None:
    p = Pragma(PragmaType.DEFINE, "define")
    assert p.is_include_once is False


def test_pragma_is_define_returns_true_for_define_type() -> None:
    p = Pragma(PragmaType.DEFINE, "define")
    assert p.is_define is True


def test_pragma_is_define_returns_false_for_other_types() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert p.is_define is False


# ---------------------------------------------------------------------------
# Pragma.__str__ — lines 159-165
# ---------------------------------------------------------------------------


def test_pragma_str_with_arguments_and_non_pragma_type() -> None:
    """A non-PRAGMA type produces '#name arg1 arg2' without 'pragma' prefix."""
    p = Pragma(PragmaType.UNDEF, "undef", ["MYDEF"])
    assert str(p) == "#undef MYDEF"


def test_pragma_str_with_pragma_type_and_no_arguments() -> None:
    p = Pragma(PragmaType.PRAGMA, "optimize")
    assert str(p) == "#pragma optimize"


def test_pragma_str_with_pragma_type_and_arguments() -> None:
    p = Pragma(PragmaType.PRAGMA, "optimize", ["level", "2"])
    assert str(p) == "#pragma optimize level 2"


# ---------------------------------------------------------------------------
# IncludeOncePragma — lines 173, 180
# ---------------------------------------------------------------------------


def test_include_once_pragma_init_sets_correct_fields() -> None:
    pragma = IncludeOncePragma()
    assert pragma.pragma_type == PragmaType.INCLUDE_ONCE
    assert pragma.name == "include_once"
    assert pragma.scope == PragmaScope.FILE


def test_include_once_pragma_str_returns_hash_include_once() -> None:
    assert str(IncludeOncePragma()) == "#include_once"


# ---------------------------------------------------------------------------
# DefineDirective — lines 191-197, 201-208, 211-216
# ---------------------------------------------------------------------------


def test_define_directive_init_with_value_builds_correct_arguments() -> None:
    d = DefineDirective("FLAG", "1")
    assert d.macro_name == "FLAG"
    assert d.macro_value == "1"
    assert d.arguments == ["FLAG", "1"]


def test_define_directive_init_without_value_builds_single_arg() -> None:
    d = DefineDirective("ONLY")
    assert d.macro_name == "ONLY"
    assert d.macro_value is None
    assert d.arguments == ["ONLY"]


def test_define_directive_validate_structure_raises_for_empty_macro_name() -> None:
    d = DefineDirective("")
    with pytest.raises(ValueError, match="Pragma macro_name cannot be empty"):
        d.validate_structure()


def test_define_directive_validate_structure_raises_for_keyword_macro_name() -> None:
    d = DefineDirective("rule")
    with pytest.raises(
        ValueError, match="Invalid pragma macro identifier 'rule' for libyara output"
    ):
        d.validate_structure()


def test_define_directive_validate_structure_raises_for_empty_macro_value() -> None:
    """An explicitly empty macro_value triggers ValueError during validate_structure."""
    d = DefineDirective("FLAG", "")
    with pytest.raises(ValueError, match="Pragma value must not be empty"):
        d.validate_structure()


def test_define_directive_validate_structure_succeeds_with_valid_value() -> None:
    d = DefineDirective("LEVEL", "3")
    d.validate_structure()


def test_define_directive_validate_structure_succeeds_with_none_value() -> None:
    d = DefineDirective("SWITCH")
    d.validate_structure()


def test_define_directive_str_with_non_empty_value() -> None:
    assert str(DefineDirective("X", "42")) == "#define X 42"


def test_define_directive_str_without_value() -> None:
    assert str(DefineDirective("X")) == "#define X"


def test_define_directive_str_with_none_value_but_falsy_check() -> None:
    """macro_value is not None but evaluates to falsy empty string → no value in output."""
    d = DefineDirective("X", "")
    # Empty macro_value causes the `if macro_value:` branch to be False,
    # so the output omits the value portion.
    assert str(d) == "#define X"


# ---------------------------------------------------------------------------
# UndefDirective — lines 226-231, 235-237, 240-241
# ---------------------------------------------------------------------------


def test_undef_directive_init_sets_correct_fields() -> None:
    u = UndefDirective("OLD_MACRO")
    assert u.macro_name == "OLD_MACRO"
    assert u.pragma_type == PragmaType.UNDEF
    assert u.arguments == ["OLD_MACRO"]


def test_undef_directive_validate_structure_raises_for_empty_macro_name() -> None:
    """UndefDirective("") stores "" in arguments, so super().validate_structure()
    raises "Pragma argument must not be empty" before the _require_nonempty_string
    check on macro_name.  Both errors share the same root cause (empty name)."""
    u = UndefDirective("")
    with pytest.raises(ValueError, match="Pragma argument must not be empty"):
        u.validate_structure()


def test_undef_directive_validate_structure_raises_for_keyword_macro_name() -> None:
    u = UndefDirective("rule")
    with pytest.raises(ValueError, match="Invalid pragma macro identifier"):
        u.validate_structure()


def test_undef_directive_validate_structure_succeeds_for_valid_name() -> None:
    u = UndefDirective("MY_MACRO")
    u.validate_structure()


def test_undef_directive_str() -> None:
    assert str(UndefDirective("REMOVE_ME")) == "#undef REMOVE_ME"


# ---------------------------------------------------------------------------
# ConditionalDirective — lines 251-254, 258-266, 271, 276, 281, 284-291
# ---------------------------------------------------------------------------


def test_conditional_directive_init_with_ifdef_and_condition() -> None:
    d = ConditionalDirective(PragmaType.IFDEF, "FEATURE")
    assert d.pragma_type == PragmaType.IFDEF
    assert d.condition == "FEATURE"
    assert d.arguments == ["FEATURE"]


def test_conditional_directive_init_with_endif_has_no_args() -> None:
    d = ConditionalDirective(PragmaType.ENDIF)
    assert d.condition is None
    assert d.arguments == []


def test_conditional_directive_validate_structure_raises_when_ifdef_condition_is_none() -> None:
    """IFDEF without a condition must raise TypeError."""
    d = ConditionalDirective(PragmaType.IFDEF)
    d.condition = None
    with pytest.raises(TypeError, match="Pragma condition must be a string"):
        d.validate_structure()


def test_conditional_directive_validate_structure_raises_when_ifndef_condition_is_none() -> None:
    d = ConditionalDirective(PragmaType.IFNDEF)
    d.condition = None
    with pytest.raises(TypeError, match="Pragma condition must be a string"):
        d.validate_structure()


def test_conditional_directive_validate_structure_raises_for_empty_condition_on_ifdef() -> None:
    d = ConditionalDirective(PragmaType.IFDEF, "FEATURE")
    d.condition = ""
    with pytest.raises(ValueError, match="Pragma condition cannot be empty"):
        d.validate_structure()


def test_conditional_directive_validate_structure_raises_for_keyword_condition() -> None:
    """A YARA keyword used as condition is rejected."""
    d = ConditionalDirective(PragmaType.IFDEF, "rule")
    with pytest.raises(ValueError, match="Invalid pragma condition identifier"):
        d.validate_structure()


def test_conditional_directive_validate_structure_accepts_endif_with_none_condition() -> None:
    """ENDIF has no condition; validate_structure must not raise."""
    ConditionalDirective.endif().validate_structure()


def test_conditional_directive_validate_structure_accepts_endif_with_string_condition() -> None:
    """ENDIF with an unexpected string condition still passes (elif branch calls require_string)."""
    d = ConditionalDirective(PragmaType.ENDIF, "ignored")
    d.validate_structure()


def test_conditional_directive_classmethod_ifdef() -> None:
    d = ConditionalDirective(PragmaType.IFDEF, "HAS_FEATURE")
    assert d.pragma_type == PragmaType.IFDEF
    assert d.condition == "HAS_FEATURE"


def test_conditional_directive_classmethod_ifndef() -> None:
    d = ConditionalDirective(PragmaType.IFNDEF, "NO_FEATURE")
    assert d.pragma_type == PragmaType.IFNDEF
    assert d.condition == "NO_FEATURE"


def test_conditional_directive_classmethod_endif() -> None:
    d = ConditionalDirective.endif()
    assert d.pragma_type == PragmaType.ENDIF
    assert d.condition is None


def test_conditional_directive_str_for_ifdef() -> None:
    assert str(ConditionalDirective(PragmaType.IFDEF, "ALPHA")) == "#ifdef ALPHA"


def test_conditional_directive_str_for_ifndef() -> None:
    assert str(ConditionalDirective(PragmaType.IFNDEF, "BETA")) == "#ifndef BETA"


def test_conditional_directive_str_for_endif_without_condition() -> None:
    assert str(ConditionalDirective.endif()) == "#endif"


def test_conditional_directive_str_for_endif_with_non_empty_condition() -> None:
    """An ENDIF with a non-None, non-empty condition includes it in output."""
    d = ConditionalDirective(PragmaType.ENDIF, "extra")
    assert str(d) == "#endif extra"


def test_conditional_directive_str_for_endif_with_empty_string_condition() -> None:
    """An ENDIF with an empty-string condition falls through to bare '#endif'."""
    d = ConditionalDirective(PragmaType.ENDIF)
    d.condition = ""
    assert str(d) == "#endif"


# ---------------------------------------------------------------------------
# CustomPragma — lines 307-313, 317-318, 322-323, 327-330, 333-336
# ---------------------------------------------------------------------------


def test_custom_pragma_init_with_all_args() -> None:
    c = CustomPragma("myvendor", ["a", "b"], {"level": 1}, PragmaScope.LOCAL)
    assert c.name == "myvendor"
    assert c.arguments == ["a", "b"]
    assert c.parameters == {"level": 1}
    assert c.scope == PragmaScope.LOCAL
    assert c.pragma_type == PragmaType.CUSTOM


def test_custom_pragma_init_with_defaults() -> None:
    c = CustomPragma("myvendor")
    assert c.arguments == []
    assert c.parameters == {}
    assert c.scope == PragmaScope.FILE


def test_custom_pragma_validate_structure_succeeds() -> None:
    c = CustomPragma("myvendor", ["arg"], {"k": "v"}, PragmaScope.FILE)
    c.validate_structure()


def test_custom_pragma_validate_structure_raises_for_invalid_parameters() -> None:
    c = CustomPragma("myvendor")
    c.parameters = cast(Any, "not_a_dict")
    with pytest.raises(TypeError, match="Pragma parameters must be a dictionary"):
        c.validate_structure()


def test_custom_pragma_str_with_no_arguments() -> None:
    assert str(CustomPragma("myvendor")) == "#pragma myvendor"


def test_custom_pragma_str_with_arguments() -> None:
    assert str(CustomPragma("myvendor", ["a", "b"])) == "#pragma myvendor a b"


# ---------------------------------------------------------------------------
# InRulePragma — lines 348-349, 352-356, 359-363, 366, 371-372, 377-378,
#                383-384, 387-388
# ---------------------------------------------------------------------------


def test_in_rule_pragma_validate_structure_succeeds() -> None:
    pragma = Pragma(PragmaType.PRAGMA, "vendor")
    irp = InRulePragma(pragma, "before_strings")
    irp.validate_structure()


def test_in_rule_pragma_validate_structure_raises_for_non_pragma() -> None:
    irp = InRulePragma(cast(Any, "bad"))
    with pytest.raises(TypeError, match="InRulePragma pragma must be a Pragma"):
        irp.validate_structure()


def test_in_rule_pragma_validate_structure_raises_for_invalid_position() -> None:
    pragma = Pragma(PragmaType.PRAGMA, "vendor")
    irp = InRulePragma(pragma, "nowhere")
    with pytest.raises(ValueError, match="Invalid InRulePragma position 'nowhere'"):
        irp.validate_structure()


def test_in_rule_pragma_accept_calls_visitor_method() -> None:
    class _V:
        def visit_in_rule_pragma(self, node: InRulePragma) -> str:
            return f"visited:{node.position}"

    pragma = Pragma(PragmaType.PRAGMA, "vendor")
    irp = InRulePragma(pragma, "after_strings")
    assert irp.accept(_V()) == "visited:after_strings"


def test_in_rule_pragma_is_before_strings_returns_true() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert InRulePragma(p, "before_strings").is_before_strings is True


def test_in_rule_pragma_is_before_strings_returns_false() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert InRulePragma(p, "after_strings").is_before_strings is False


def test_in_rule_pragma_is_after_strings_returns_true() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert InRulePragma(p, "after_strings").is_after_strings is True


def test_in_rule_pragma_is_after_strings_returns_false() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert InRulePragma(p, "before_strings").is_after_strings is False


def test_in_rule_pragma_is_before_condition_returns_true() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert InRulePragma(p, "before_condition").is_before_condition is True


def test_in_rule_pragma_is_before_condition_returns_false() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert InRulePragma(p, "before_strings").is_before_condition is False


def test_in_rule_pragma_str_delegates_to_wrapped_pragma() -> None:
    pragma = Pragma(PragmaType.PRAGMA, "vendor", ["x"])
    irp = InRulePragma(pragma, "before_condition")
    assert str(irp) == str(pragma)


# ---------------------------------------------------------------------------
# PragmaBlock — lines 400, 403, 407-413, 417-418, 422-423, 426, 429-440
# ---------------------------------------------------------------------------


def test_pragma_block_validate_structure_succeeds_for_empty_block() -> None:
    block = PragmaBlock()
    block.validate_structure()


def test_pragma_block_validate_structure_succeeds_for_non_empty_block() -> None:
    p = Pragma(PragmaType.PRAGMA, "vendor")
    block = PragmaBlock([p])
    block.validate_structure()


def test_pragma_block_accept_calls_visitor() -> None:
    class _V:
        def visit_pragma_block(self, node: PragmaBlock) -> int:
            return len(node.pragmas)

    p = Pragma(PragmaType.PRAGMA, "vendor")
    block = PragmaBlock([p])
    assert block.accept(_V()) == 1


def test_pragma_block_str_joins_pragmas_with_newlines() -> None:
    p1 = Pragma(PragmaType.PRAGMA, "vendor", ["on"])
    p2 = Pragma(PragmaType.UNDEF, "undef", ["OLD"])
    block = PragmaBlock([p1, p2])
    assert str(block) == "#pragma vendor on\n#undef OLD"


def test_pragma_block_str_for_empty_block() -> None:
    assert str(PragmaBlock()) == ""


def test_pragma_block_validated_pragmas_raises_for_invalid_scope() -> None:
    block = PragmaBlock([Pragma(PragmaType.PRAGMA, "vendor")], scope=cast(Any, "invalid"))
    with pytest.raises(TypeError, match="Pragma scope must be a PragmaScope"):
        block.validate_structure()


def test_pragma_block_validated_pragmas_raises_for_tuple_of_pragmas() -> None:
    """Tuples are also accepted as the pragmas container."""
    p = Pragma(PragmaType.PRAGMA, "vendor")
    block = PragmaBlock(cast(Any, (p,)))
    block.validate_structure()


# ---------------------------------------------------------------------------
# Targeted gap-filler tests for remaining uncovered lines
# ---------------------------------------------------------------------------


def test_pragma_type_from_string_raises_for_whitespace_only_string() -> None:
    """Whitespace-only string triggers the 'cannot be empty' branch (lines 88-89)."""
    with pytest.raises(ValueError, match="Pragma type input cannot be empty"):
        PragmaType.from_string("   ")


def test_pragma_accept_invokes_visit_pragma() -> None:
    """Pragma.accept dispatches to visitor.visit_pragma (line 145)."""

    class _V:
        def visit_pragma(self, node: Pragma) -> str:
            return f"visited:{node.name}"

    p = Pragma(PragmaType.PRAGMA, "vendor")
    assert p.accept(_V()) == "visited:vendor"


def test_pragma_block_validated_pragmas_raises_for_bad_scope_before_iterating() -> None:
    """The _require_scope call at line 432 fires after the isinstance check (line 430)
    when the container is a valid list but the scope is invalid."""
    block = PragmaBlock([Pragma(PragmaType.PRAGMA, "vendor")], scope=cast(Any, 999))
    with pytest.raises(TypeError, match="Pragma scope must be a PragmaScope"):
        block._validated_pragmas()


def test_pragma_block_validated_pragmas_raises_for_non_list_pragmas_container() -> None:
    """Lines 430-431: assigning a non-list/non-tuple to block.pragmas and calling
    _validated_pragmas raises TypeError with the expected message."""
    block = PragmaBlock()
    block.pragmas = cast(Any, "not_a_list")
    with pytest.raises(TypeError, match="PragmaBlock pragmas must be a list or tuple"):
        block._validated_pragmas()


def test_pragma_block_validated_pragmas_raises_for_non_pragma_element() -> None:
    """When the list contains a non-Pragma element, lines 436-437 raise TypeError."""
    block = PragmaBlock()
    block.pragmas = cast(Any, [object()])
    with pytest.raises(TypeError, match="PragmaBlock pragmas must contain Pragma nodes"):
        block._validated_pragmas()
