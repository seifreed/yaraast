"""Regression tests for yaraast.performance.memory_transformer_visitors.

Each test exercises a specific execution path that was not reached by the
existing suite.  All tests run real production code through the public
MemoryOptimizer / MemoryOptimizerTransformer API or the visitor helpers
directly.  No mocks or test doubles are used.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    StringIdentifier,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import (
    ExternImport,
    ExternNamespace,
    ExternRule,
    ExternRuleReference,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.operators import StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaScope, PragmaType
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import HexString, RegexString
from yaraast.parser.source import parse_yara_source
from yaraast.performance.memory_optimizer import MemoryOptimizer, MemoryOptimizerTransformer
from yaraast.performance.memory_transformer_visitors import (
    _pool_parameter_value,
    visit_extern_namespace,
    visit_hex_string,
    visit_identifier,
    visit_import,
    visit_in_rule_pragma,
    visit_include,
    visit_meta,
    visit_plain_string,
    visit_pragma,
    visit_pragma_block,
    visit_regex_string,
    visit_rule,
    visit_string_identifier,
    visit_string_literal,
    visit_string_modifier,
    visit_string_operator_expression,
    visit_string_wildcard,
    visit_tag,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_transformer(aggressive: bool = False) -> MemoryOptimizerTransformer:
    """Return a MemoryOptimizerTransformer with an empty string pool."""
    return MemoryOptimizerTransformer({}, aggressive=aggressive)


# ---------------------------------------------------------------------------
# _pool_parameter_value — list, tuple, set, frozenset, dict, scalar branches
# ---------------------------------------------------------------------------


def test_pool_parameter_value_list_branch() -> None:
    """_pool_parameter_value pools each element of a plain list."""
    t = _make_transformer()
    result = _pool_parameter_value(t, ["alpha", "beta"])
    assert isinstance(result, list)
    assert result == ["alpha", "beta"]
    assert result[0] is t.string_pool["alpha"]
    assert result[1] is t.string_pool["beta"]


def test_pool_parameter_value_tuple_branch() -> None:
    """_pool_parameter_value returns a tuple when the input is a tuple."""
    t = _make_transformer()
    result = _pool_parameter_value(t, ("x", "y"))
    assert isinstance(result, tuple)
    assert result == ("x", "y")


def test_pool_parameter_value_set_branch() -> None:
    """_pool_parameter_value returns a set when the input is a set."""
    t = _make_transformer()
    result = _pool_parameter_value(t, {"a", "b"})
    assert isinstance(result, set)
    assert result == {"a", "b"}


def test_pool_parameter_value_frozenset_branch() -> None:
    """_pool_parameter_value returns a frozenset when the input is a frozenset."""
    t = _make_transformer()
    result = _pool_parameter_value(t, frozenset({"p", "q"}))
    assert isinstance(result, frozenset)
    assert result == frozenset({"p", "q"})


def test_pool_parameter_value_dict_branch() -> None:
    """_pool_parameter_value recurses over dict keys and values."""
    t = _make_transformer()
    result = _pool_parameter_value(t, {"key": "value"})
    assert isinstance(result, dict)
    assert result["key"] == "value"
    assert "key" in t.string_pool
    assert "value" in t.string_pool


def test_pool_parameter_value_scalar_passthrough() -> None:
    """_pool_parameter_value returns non-string, non-container scalars unchanged."""
    t = _make_transformer()
    assert _pool_parameter_value(t, 42) == 42
    assert _pool_parameter_value(t, 3.14) == 3.14
    assert _pool_parameter_value(t, None) is None


# ---------------------------------------------------------------------------
# visit_string_literal — false branch (value is not a str)
# ---------------------------------------------------------------------------


def test_visit_string_literal_non_str_value_passes_through() -> None:
    """When StringLiteral.value is not a str the value is left unchanged."""
    t = _make_transformer()
    node = StringLiteral(value="hello")
    cast(Any, node).value = 99
    result = visit_string_literal(t, node)
    assert cast(Any, result).value == 99


# ---------------------------------------------------------------------------
# visit_string_offset / visit_string_length — index-not-None branches
# ---------------------------------------------------------------------------


def test_string_offset_with_index_visits_index_expression() -> None:
    """@a[1] form produces a StringOffset with a non-None index which the
    transformer must visit recursively."""
    src = r"""rule offset_indexed {
    strings:
        $a = "hello"
    condition:
        @a[1] > 0
}"""
    ast = parse_yara_source(src)
    before = ast.rules[0].condition

    opt = MemoryOptimizer()
    result = opt.optimize(parse_yara_source(src))
    after = result.rules[0].condition
    assert str(after) == str(before)


def test_string_length_with_index_visits_index_expression() -> None:
    """!a[2] form produces a StringLength with a non-None index."""
    src = r"""rule length_indexed {
    strings:
        $b = "hello"
    condition:
        !b[2] > 0
}"""
    ast = parse_yara_source(src)
    before = ast.rules[0].condition

    opt = MemoryOptimizer()
    result = opt.optimize(parse_yara_source(src))
    after = result.rules[0].condition
    assert str(after) == str(before)


# ---------------------------------------------------------------------------
# visit_identifier — false branch (name is not a str)
# ---------------------------------------------------------------------------


def test_visit_identifier_non_str_name_passes_through() -> None:
    """When Identifier.name is not a str the name is left unchanged."""
    from yaraast.ast.expressions import Identifier

    t = _make_transformer()
    node = Identifier(name="foo")
    cast(Any, node).name = 0
    result = visit_identifier(t, node)
    assert cast(Any, result).name == 0


# ---------------------------------------------------------------------------
# visit_rule — false branches for each optional field
# ---------------------------------------------------------------------------


def test_visit_rule_empty_name_skips_pooling() -> None:
    """A Rule with an empty name does not pool the name."""
    t = _make_transformer()
    rule = Rule(name="")
    result = visit_rule(t, rule)
    assert result.name == ""
    assert "" not in t.string_pool


def test_visit_rule_no_condition_skips_condition_visit() -> None:
    """A Rule with condition=None does not attempt to visit the condition."""
    t = _make_transformer()
    rule = Rule(name="cond_none")
    result = visit_rule(t, rule)
    assert result.condition is None


def test_visit_rule_no_strings_skips_string_visit() -> None:
    """A Rule with no strings list leaves strings empty."""
    t = _make_transformer()
    rule = Rule(name="no_strings")
    result = visit_rule(t, rule)
    assert result.strings == []


def test_visit_rule_with_in_rule_pragma_visits_pragma() -> None:
    """A Rule with InRulePragma entries exercises the pragmas branch (line 222)."""
    t = _make_transformer()
    pragma = Pragma(
        pragma_type=PragmaType.PRAGMA,
        name="mypragma",
        arguments=["arg"],
        scope=PragmaScope.RULE,
    )
    irp = InRulePragma(pragma=pragma, position="before_strings")
    rule = Rule(name="pragma_rule", pragmas=[irp])
    result = visit_rule(t, rule)
    assert len(result.pragmas) == 1
    assert result.pragmas[0].position == "before_strings"
    assert "mypragma" in t.string_pool


def test_visit_rule_aggressive_clears_location() -> None:
    """With aggressive=True the transformer sets location to None."""
    t = _make_transformer(aggressive=True)
    rule = Rule(name="loc_rule")
    cast(Any, rule).location = (1, 0)
    result = visit_rule(t, rule)
    assert cast(Any, result).location is None


# ---------------------------------------------------------------------------
# visit_plain_string — bytes-value branch (value is not str)
# ---------------------------------------------------------------------------


def test_visit_plain_string_bytes_value_not_pooled() -> None:
    """When PlainString.value is bytes the value is shallow-copied but not pooled."""
    t = _make_transformer()
    from yaraast.ast.strings import PlainString

    node = PlainString(identifier="$bin", value=b"binary\x90data", modifiers=[])
    result = visit_plain_string(t, node)
    assert isinstance(result.value, bytes)
    assert result.value == b"binary\x90data"
    assert "binary\x90data" not in t.string_pool


# ---------------------------------------------------------------------------
# visit_meta — false branch (key or value is non-str)
# ---------------------------------------------------------------------------


def test_visit_meta_integer_value_not_pooled() -> None:
    """Meta with an integer value does not attempt to pool the value."""
    t = _make_transformer()
    node = Meta(key="score", value=5)
    result = visit_meta(t, node)
    assert result.value == 5
    assert "score" in t.string_pool  # key IS a str and gets pooled


def test_visit_meta_bool_value_not_pooled() -> None:
    """Meta with a boolean value does not attempt to pool the value."""
    t = _make_transformer()
    node = Meta(key="active", value=True)
    result = visit_meta(t, node)
    assert result.value is True


def test_visit_meta_non_str_key_not_pooled() -> None:
    """Meta with a non-str key leaves the key unchanged."""
    t = _make_transformer()
    node = Meta(key="k", value="v")
    cast(Any, node).key = 42
    result = visit_meta(t, node)
    assert cast(Any, result).key == 42
    assert "v" in t.string_pool  # value IS str and gets pooled


# ---------------------------------------------------------------------------
# visit_yara_file — extern_rules, extern_imports, pragmas, namespaces branches
# ---------------------------------------------------------------------------


def test_visit_yara_file_extern_rules_branch() -> None:
    """YaraFile with extern_rules visits each ExternRule."""
    t = _make_transformer()
    extern_rule = ExternRule(name="RemoteRule", modifiers=[], namespace=None)
    yf = YaraFile(extern_rules=[extern_rule])
    result = t.visit(yf)
    assert len(result.extern_rules) == 1
    assert "RemoteRule" in t.string_pool


def test_visit_yara_file_extern_imports_branch() -> None:
    """YaraFile with extern_imports visits each ExternImport."""
    t = _make_transformer()
    ei = ExternImport(module_path="my_module", alias="mod", rules=["RuleA"])
    yf = YaraFile(extern_imports=[ei])
    result = t.visit(yf)
    assert len(result.extern_imports) == 1
    assert "my_module" in t.string_pool


def test_visit_yara_file_namespaces_branch() -> None:
    """YaraFile with namespaces visits each ExternNamespace."""
    t = _make_transformer()
    er = ExternRule(name="NsRule", modifiers=[], namespace=None)
    ns = ExternNamespace(name="myns", extern_rules=[er])
    yf = YaraFile(namespaces=[ns])
    result = t.visit(yf)
    assert len(result.namespaces) == 1
    assert "myns" in t.string_pool


def test_visit_yara_file_pragmas_branch() -> None:
    """YaraFile with file-level Pragma nodes visits each Pragma."""
    t = _make_transformer()
    pragma = Pragma(
        pragma_type=PragmaType.PRAGMA,
        name="filepragma",
        arguments=["x"],
        scope=PragmaScope.FILE,
    )
    yf = YaraFile(pragmas=[pragma])
    result = t.visit(yf)
    assert len(result.pragmas) == 1
    assert "filepragma" in t.string_pool


def test_visit_yara_file_includes_branch() -> None:
    """YaraFile with includes visits each Include."""
    t = _make_transformer()
    inc = Include(path="other.yar")
    yf = YaraFile(includes=[inc])
    result = t.visit(yf)
    assert len(result.includes) == 1
    assert "other.yar" in t.string_pool


# ---------------------------------------------------------------------------
# visit_string_identifier — false branch (name not a str)
# ---------------------------------------------------------------------------


def test_visit_string_identifier_non_str_name_passes_through() -> None:
    """StringIdentifier with a non-str name leaves name unchanged."""
    t = _make_transformer()
    node = StringIdentifier(name="$sid")
    cast(Any, node).name = 0
    result = visit_string_identifier(t, node)
    assert cast(Any, result).name == 0


# ---------------------------------------------------------------------------
# visit_string_wildcard — false branch (pattern not a str)
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_non_str_pattern_passes_through() -> None:
    """StringWildcard with a non-str pattern leaves pattern unchanged."""
    t = _make_transformer()
    node = StringWildcard(pattern="$a*")
    cast(Any, node).pattern = 0
    result = visit_string_wildcard(t, node)
    assert cast(Any, result).pattern == 0


# ---------------------------------------------------------------------------
# visit_string_operator_expression — covers lines 385-389
# ---------------------------------------------------------------------------


def test_visit_string_operator_expression_pools_operator_and_visits_children() -> None:
    """StringOperatorExpression visits left and right and pools the operator."""
    t = _make_transformer()
    left = StringLiteral(value="haystack")
    right = StringLiteral(value="needle")
    expr = StringOperatorExpression(left=left, operator="icontains", right=right)
    result = visit_string_operator_expression(t, expr)
    assert result.operator == "icontains"
    assert "icontains" in t.string_pool
    assert cast(StringLiteral, result.left).value == "haystack"
    assert cast(StringLiteral, result.right).value == "needle"


# ---------------------------------------------------------------------------
# visit_hex_string — false branch (identifier not a str)
# ---------------------------------------------------------------------------


def test_visit_hex_string_non_str_identifier_passes_through() -> None:
    """HexString with a non-str identifier leaves identifier unchanged."""
    src = r"""rule hextest {
    strings:
        $h = { 4D 5A ?? }
    condition:
        $h
}"""
    ast = parse_yara_source(src)
    hex_node = ast.rules[0].strings[0]
    assert isinstance(hex_node, HexString)

    t = _make_transformer()
    cast(Any, hex_node).identifier = 99
    result = visit_hex_string(t, hex_node)
    assert cast(Any, result).identifier == 99


# ---------------------------------------------------------------------------
# visit_regex_string — false branches (identifier not str, regex not str)
# ---------------------------------------------------------------------------


def test_visit_regex_string_non_str_identifier_passes_through() -> None:
    """RegexString with a non-str identifier leaves identifier unchanged."""
    src = r"""rule retest {
    strings:
        $c = /abc+/ nocase
    condition:
        $c
}"""
    ast = parse_yara_source(src)
    regex_node = ast.rules[0].strings[0]
    assert isinstance(regex_node, RegexString)

    t = _make_transformer()
    cast(Any, regex_node).identifier = 99
    result = visit_regex_string(t, regex_node)
    assert cast(Any, result).identifier == 99


def test_visit_regex_string_non_str_regex_passes_through() -> None:
    """RegexString with a non-str regex leaves regex unchanged."""
    src = r"""rule retest2 {
    strings:
        $d = /def+/
    condition:
        $d
}"""
    ast = parse_yara_source(src)
    regex_node = ast.rules[0].strings[0]
    assert isinstance(regex_node, RegexString)

    t = _make_transformer()
    cast(Any, regex_node).regex = 42
    result = visit_regex_string(t, regex_node)
    assert cast(Any, result).regex == 42


# ---------------------------------------------------------------------------
# visit_extern_rule_reference — covers lines 423-426
# ---------------------------------------------------------------------------


def test_visit_extern_rule_reference_pools_name_and_namespace() -> None:
    """ExternRuleReference has its rule_name and namespace pooled."""
    from yaraast.performance.memory_transformer_visitors import visit_extern_rule_reference

    t = _make_transformer()
    node = ExternRuleReference(rule_name="TargetRule", namespace="ext_ns")
    result = visit_extern_rule_reference(t, node)
    assert result.rule_name == "TargetRule"
    assert result.namespace == "ext_ns"
    assert "TargetRule" in t.string_pool
    assert "ext_ns" in t.string_pool


def test_visit_extern_rule_reference_none_namespace() -> None:
    """ExternRuleReference with namespace=None does not raise."""
    from yaraast.performance.memory_transformer_visitors import visit_extern_rule_reference

    t = _make_transformer()
    node = ExternRuleReference(rule_name="RuleX", namespace=None)
    result = visit_extern_rule_reference(t, node)
    assert result.namespace is None


# ---------------------------------------------------------------------------
# visit_extern_namespace — covers lines 437-441
# ---------------------------------------------------------------------------


def test_visit_extern_namespace_visits_contained_extern_rules() -> None:
    """ExternNamespace visits each contained ExternRule."""
    t = _make_transformer()
    er1 = ExternRule(name="Alpha", modifiers=[], namespace=None)
    er2 = ExternRule(name="Beta", modifiers=[], namespace=None)
    ns = ExternNamespace(name="pkg", extern_rules=[er1, er2])
    result = visit_extern_namespace(t, ns)
    assert result.name == "pkg"
    assert len(result.extern_rules) == 2
    assert "pkg" in t.string_pool
    assert "Alpha" in t.string_pool
    assert "Beta" in t.string_pool


# ---------------------------------------------------------------------------
# visit_pragma — optional dynamic attributes and parameters dict
# ---------------------------------------------------------------------------


def test_visit_pragma_with_macro_name_str_pools_it() -> None:
    """Pragma with a str macro_name attribute has it pooled."""
    t = _make_transformer()
    p = Pragma(
        pragma_type=PragmaType.PRAGMA, name="def_macro", arguments=[], scope=PragmaScope.FILE
    )
    cast(Any, p).macro_name = "MY_MACRO"
    result = visit_pragma(t, p)
    assert cast(Any, result).macro_name == "MY_MACRO"
    assert "MY_MACRO" in t.string_pool


def test_visit_pragma_with_macro_name_non_str_passes_through() -> None:
    """Pragma with a non-str macro_name leaves the attribute unchanged."""
    t = _make_transformer()
    p = Pragma(pragma_type=PragmaType.PRAGMA, name="opt", arguments=[], scope=PragmaScope.FILE)
    cast(Any, p).macro_name = 42
    result = visit_pragma(t, p)
    assert cast(Any, result).macro_name == 42


def test_visit_pragma_with_macro_value_str_pools_it() -> None:
    """Pragma with a str macro_value attribute has it pooled."""
    t = _make_transformer()
    p = Pragma(pragma_type=PragmaType.PRAGMA, name="opt", arguments=[], scope=PragmaScope.FILE)
    cast(Any, p).macro_value = "expanded_value"
    result = visit_pragma(t, p)
    assert cast(Any, result).macro_value == "expanded_value"
    assert "expanded_value" in t.string_pool


def test_visit_pragma_with_macro_value_non_str_passes_through() -> None:
    """Pragma with a non-str macro_value leaves the attribute unchanged."""
    t = _make_transformer()
    p = Pragma(pragma_type=PragmaType.PRAGMA, name="opt", arguments=[], scope=PragmaScope.FILE)
    cast(Any, p).macro_value = 0
    result = visit_pragma(t, p)
    assert cast(Any, result).macro_value == 0


def test_visit_pragma_with_condition_str_pools_it() -> None:
    """Pragma with a str condition attribute has it pooled."""
    t = _make_transformer()
    p = Pragma(pragma_type=PragmaType.PRAGMA, name="opt", arguments=[], scope=PragmaScope.FILE)
    cast(Any, p).condition = "DEFINED_FLAG"
    result = visit_pragma(t, p)
    assert cast(Any, result).condition == "DEFINED_FLAG"
    assert "DEFINED_FLAG" in t.string_pool


def test_visit_pragma_with_condition_non_str_passes_through() -> None:
    """Pragma with a non-str condition leaves the attribute unchanged."""
    t = _make_transformer()
    p = Pragma(pragma_type=PragmaType.PRAGMA, name="opt", arguments=[], scope=PragmaScope.FILE)
    cast(Any, p).condition = False
    result = visit_pragma(t, p)
    assert cast(Any, result).condition is False


def test_visit_pragma_with_parameters_dict_pools_str_keys_and_values() -> None:
    """Pragma with a dict parameters attribute has each str key/value pooled."""
    t = _make_transformer()
    p = Pragma(pragma_type=PragmaType.PRAGMA, name="opt", arguments=[], scope=PragmaScope.FILE)
    cast(Any, p).parameters = {"opt_key": "opt_val", "other": "thing"}
    result = visit_pragma(t, p)
    params: dict[str, Any] = cast(Any, result).parameters
    assert isinstance(params, dict)
    assert params["opt_key"] == "opt_val"
    assert "opt_key" in t.string_pool
    assert "opt_val" in t.string_pool


# ---------------------------------------------------------------------------
# visit_in_rule_pragma — covers lines 477-480
# ---------------------------------------------------------------------------


def test_visit_in_rule_pragma_visits_nested_pragma_and_pools_position() -> None:
    """InRulePragma visits its nested Pragma and pools its position string."""
    t = _make_transformer()
    inner = Pragma(
        pragma_type=PragmaType.PRAGMA,
        name="inner",
        arguments=["a", "b"],
        scope=PragmaScope.RULE,
    )
    irp = InRulePragma(pragma=inner, position="before_strings")
    result = visit_in_rule_pragma(t, irp)
    assert result.position == "before_strings"
    assert "before_strings" in t.string_pool
    assert "inner" in t.string_pool


# ---------------------------------------------------------------------------
# visit_pragma_block — covers lines 484-486
# ---------------------------------------------------------------------------


def test_visit_pragma_block_visits_all_contained_pragmas() -> None:
    """PragmaBlock visits each Pragma in its list."""
    t = _make_transformer()
    p1 = Pragma(pragma_type=PragmaType.PRAGMA, name="first", arguments=[], scope=PragmaScope.FILE)
    p2 = Pragma(
        pragma_type=PragmaType.PRAGMA, name="second", arguments=["x"], scope=PragmaScope.FILE
    )
    from yaraast.ast.pragmas import PragmaBlock

    block = PragmaBlock(pragmas=[p1, p2], scope=PragmaScope.FILE)
    result = visit_pragma_block(t, block)
    assert len(result.pragmas) == 2
    assert "first" in t.string_pool
    assert "second" in t.string_pool


# ---------------------------------------------------------------------------
# visit_string_modifier — str value branch (line 492)
# ---------------------------------------------------------------------------


def test_visit_string_modifier_str_value_is_pooled() -> None:
    """StringModifier with a str value (e.g. XOR range text) has value pooled."""
    t = _make_transformer()
    mod = StringModifier(modifier_type=StringModifierType.XOR, value="0x10-0x20")
    result = visit_string_modifier(t, mod)
    assert result.value == "0x10-0x20"
    assert "0x10-0x20" in t.string_pool


def test_visit_string_modifier_non_str_value_passes_through() -> None:
    """StringModifier with a tuple (int range) value is left unchanged."""
    t = _make_transformer()
    mod = StringModifier(modifier_type=StringModifierType.XOR, value=(0x10, 0x20))
    result = visit_string_modifier(t, mod)
    assert result.value == (0x10, 0x20)


def test_visit_string_modifier_none_value_passes_through() -> None:
    """StringModifier with value=None (bare modifier like 'nocase') is unchanged."""
    t = _make_transformer()
    mod = StringModifier(modifier_type=StringModifierType.NOCASE, value=None)
    result = visit_string_modifier(t, mod)
    assert result.value is None


# ---------------------------------------------------------------------------
# visit_unary_expression — operand branch via MemoryOptimizerTransformer
# ---------------------------------------------------------------------------


def test_visit_unary_expression_visits_operand() -> None:
    """UnaryExpression visits its operand via the transformer."""
    t = _make_transformer()
    operand = StringLiteral(value="op_value")
    node = UnaryExpression(operator="not", operand=operand)
    result = t.visit(node)
    assert cast(StringLiteral, result.operand).value == "op_value"
    assert "op_value" in t.string_pool
    assert "not" in t.string_pool


# ---------------------------------------------------------------------------
# End-to-end: StringOffset/StringLength with index through MemoryOptimizer
# ---------------------------------------------------------------------------


def test_full_optimize_with_indexed_string_offset_and_length() -> None:
    """Optimizing a rule with @a[n] and !a[n] forms preserves the YARA source."""
    src = r"""rule indexed_ops {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        @a[1] < 100 and !b[2] > 0
}"""
    ast = parse_yara_source(src)
    from yaraast.codegen.generator import CodeGenerator

    before = CodeGenerator().generate(ast)
    opt = MemoryOptimizer()
    optimized = opt.optimize(parse_yara_source(src))
    after = CodeGenerator().generate(optimized)
    assert after == before


# ---------------------------------------------------------------------------
# End-to-end: YaraFile with all optional collection branches populated
# ---------------------------------------------------------------------------


def test_full_optimize_yara_file_all_optional_collections() -> None:
    """Optimizing a YaraFile with extern rules, imports, namespaces and pragmas
    visits all optional branches of visit_yara_file."""

    imp = Import(module="pe")
    inc = Include(path="common.yar")
    ext_rule = ExternRule(name="ExtRule", modifiers=[], namespace=None)
    ext_import = ExternImport(module_path="ext_module", alias="em", rules=["ExtRule"])
    ns_rule = ExternRule(name="NsRule", modifiers=[], namespace=None)
    ns = ExternNamespace(name="pkg", extern_rules=[ns_rule])
    file_pragma = Pragma(
        pragma_type=PragmaType.PRAGMA,
        name="filelevel",
        arguments=[],
        scope=PragmaScope.FILE,
    )
    yf = YaraFile(
        imports=[imp],
        includes=[inc],
        extern_rules=[ext_rule],
        extern_imports=[ext_import],
        namespaces=[ns],
        pragmas=[file_pragma],
        rules=[],
    )
    pool: dict[str, str] = {}
    t = MemoryOptimizerTransformer(pool, aggressive=False)
    result = t.visit(yf)

    assert len(result.imports) == 1
    assert len(result.includes) == 1
    assert len(result.extern_rules) == 1
    assert len(result.extern_imports) == 1
    assert len(result.namespaces) == 1
    assert len(result.pragmas) == 1
    assert "pe" in pool
    assert "common.yar" in pool
    assert "ExtRule" in pool
    assert "ext_module" in pool
    assert "pkg" in pool
    assert "filelevel" in pool


# ---------------------------------------------------------------------------
# visit_string_offset / visit_string_length — index IS None (false branch)
# ---------------------------------------------------------------------------


def test_visit_string_offset_index_none_skips_visit() -> None:
    """StringOffset with index=None does not attempt to visit the index."""
    t = _make_transformer()
    node = StringOffset(string_id="$x", index=None)
    from yaraast.performance.memory_transformer_visitors import visit_string_offset

    result = visit_string_offset(t, node)
    assert result.index is None
    assert "$x" in t.string_pool


def test_visit_string_length_index_none_skips_visit() -> None:
    """StringLength with index=None does not attempt to visit the index."""
    t = _make_transformer()
    from yaraast.ast.expressions import StringLength
    from yaraast.performance.memory_transformer_visitors import visit_string_length

    node = StringLength(string_id="$y", index=None)
    result = visit_string_length(t, node)
    assert result.index is None
    assert "$y" in t.string_pool


# ---------------------------------------------------------------------------
# visit_rule — modifiers not a list branch
# ---------------------------------------------------------------------------


def test_visit_rule_non_list_modifiers_skips_visit_items() -> None:
    """When Rule.modifiers is not a list the _visit_items call is skipped."""
    t = _make_transformer()
    rule = Rule(name="mod_test")
    cast(Any, rule).modifiers = "private"
    result = visit_rule(t, rule)
    assert cast(Any, result).modifiers == "private"


# ---------------------------------------------------------------------------
# visit_plain_string — identifier not a str (false branch at line 235)
# ---------------------------------------------------------------------------


def test_visit_plain_string_non_str_identifier_passes_through() -> None:
    """PlainString with a non-str identifier leaves identifier unchanged."""
    t = _make_transformer()
    from yaraast.ast.strings import PlainString

    node = PlainString(identifier="$ps", value="text", modifiers=[])
    cast(Any, node).identifier = 0
    result = visit_plain_string(t, node)
    assert cast(Any, result).identifier == 0
    assert "text" in t.string_pool


# ---------------------------------------------------------------------------
# visit_tag — name not a str (false branch at line 251)
# ---------------------------------------------------------------------------


def test_visit_tag_non_str_name_passes_through() -> None:
    """Tag with a non-str name leaves name unchanged."""
    t = _make_transformer()
    from yaraast.ast.rules import Tag

    node = Tag(name="mytag")
    cast(Any, node).name = 0
    result = visit_tag(t, node)
    assert cast(Any, result).name == 0


# ---------------------------------------------------------------------------
# visit_import — module not a str (false branch at line 277)
# ---------------------------------------------------------------------------


def test_visit_import_non_str_module_passes_through() -> None:
    """Import with a non-str module leaves module unchanged."""
    t = _make_transformer()
    node = Import(module="pe")
    cast(Any, node).module = 0
    result = visit_import(t, node)
    assert cast(Any, result).module == 0


# ---------------------------------------------------------------------------
# visit_include — path not a str (false branch at line 284)
# ---------------------------------------------------------------------------


def test_visit_include_non_str_path_passes_through() -> None:
    """Include with a non-str path leaves path unchanged."""
    t = _make_transformer()
    node = Include(path="other.yar")
    cast(Any, node).path = 0
    result = visit_include(t, node)
    assert cast(Any, result).path == 0
