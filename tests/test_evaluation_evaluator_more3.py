"""Additional evaluator branch tests without mocks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import PlainString
from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.evaluation.mock_modules import MockModuleRegistry
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)


def test_identifier_and_literal_paths() -> None:
    ev = YaraEvaluator(data=b"abc")
    ev.context.variables["x"] = 7
    ev.context.modules["m"] = {"k": 3}
    ev.context.string_matches = {"$a": []}

    assert ev.visit_identifier(Identifier(name="filesize")) == 3
    assert ev.visit_identifier(Identifier(name="entrypoint")) == 0
    assert ev.visit_identifier(Identifier(name="all")) == "all"
    assert ev.visit_identifier(Identifier(name="any")) == "any"
    assert ev.visit_identifier(Identifier(name="them")) == ["$a"]
    assert ev.visit_identifier(Identifier(name="x")) == 7
    assert ev.visit_identifier(Identifier(name="m")) == {"k": 3}

    # Unknown identifiers return False (could be unresolved rule references)
    assert ev.visit_identifier(Identifier(name="zzz")) is False


def test_evaluator_matches_operator_honors_regex_modifiers() -> None:
    ast = Parser().parse('rule r { condition: "FOO" matches /foo/i }')

    assert YaraEvaluator().evaluate_file(ast) == {"r": True}


def test_evaluator_matches_operator_uses_libyara_search_offsets() -> None:
    ast = Parser().parse("""
        rule end_anchor_only {
            condition:
                "abc" matches /$/
        }

        rule consuming_end_anchor {
            condition:
                "abc" matches /abc$/
        }
    """)

    assert YaraEvaluator().evaluate_file(ast) == {
        "end_anchor_only": False,
        "consuming_end_anchor": True,
    }


def test_builtin_integer_readers_propagate_undefined_offsets() -> None:
    ast = Parser().parse("""
        rule undefined_reader_offsets {
            condition:
                uint8(uint8(100)) == 0 or
                defined uint8(uint8(100)) or
                uint16be(uint8(100)) == 0 or
                defined uint16be(uint8(100))
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"undefined_reader_offsets": False}


def test_hash_module_invalid_regions_evaluate_as_undefined() -> None:
    ast = Parser().parse("""
        import "hash"
        rule invalid_hash_regions {
            condition:
                hash.md5(-1, 1) == "d41d8cd98f00b204e9800998ecf8427e" or
                hash.md5(filesize, 0) == "d41d8cd98f00b204e9800998ecf8427e" or
                hash.md5(uint8(100), 1) == "d41d8cd98f00b204e9800998ecf8427e" or
                defined hash.md5(uint8(100), 1) or
                hash.checksum32(-1, 1) == 0 or
                hash.crc32(-1, 1) != 0 or
                not hash.crc32(-1, 1)
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"invalid_hash_regions": False}


def test_hash_module_valid_region_can_extend_to_file_end() -> None:
    ast = Parser().parse("""
        import "hash"
        rule trailing_hash_region {
            condition:
                hash.md5(1, 100) == "5360af35bde9ebd8f01f492dc059593c"
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"trailing_hash_region": True}


@pytest.mark.parametrize(
    "call",
    [
        "hash.md5()",
        "hash.sha1(0)",
        "hash.sha256()",
        "hash.checksum32(0)",
        "hash.crc32()",
    ],
)
def test_hash_module_requires_explicit_region_arguments(call: str) -> None:
    ast = Parser().parse(f'import "hash" rule invalid_hash_call {{ condition: defined {call} }}')

    with pytest.raises(EvaluationError, match=r"hash\.[a-z0-9]+\(\) expects exactly 2 arguments"):
        YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_math_module_invalid_regions_evaluate_as_undefined() -> None:
    ast = Parser().parse("""
        import "math"
        rule invalid_math_regions {
            condition:
                math.entropy(-1, 1) == 0.0 or
                math.mean(filesize, 0) == 0.0 or
                math.deviation(-1, 1, 0.0) == 0.0 or
                math.deviation(0, filesize, math.mean(0, filesize)) == 0.0 or
                math.entropy(uint8(100), 1) == 0.0 or
                defined math.entropy(uint8(100), 1) or
                math.serial_correlation(0, 1) == 0.0 or
                math.monte_carlo_pi(0, 5) == 0.0 or
                not math.entropy(-1, 1)
        }
        """)

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {"invalid_math_regions": False}


def test_math_serial_correlation_returns_libyara_sentinel_for_degenerate_regions() -> None:
    ast = Parser().parse("""
        import "math"
        rule degenerate_serial_correlation {
            condition:
                defined math.serial_correlation(0, 0) and
                math.serial_correlation(0, 0) == -100000.0 and
                defined math.serial_correlation(0, 1) and
                math.serial_correlation(0, 1) == -100000.0 and
                math.serial_correlation(0, 2) == -100000.0
        }
        """)

    assert YaraEvaluator(data=b"aa").evaluate_file(ast) == {"degenerate_serial_correlation": True}


def test_math_to_number_matches_libyara_boolean_conversion() -> None:
    ast = Parser().parse("""
        import "math"
        rule to_number_booleans {
            condition:
                math.to_number(true) == 1 and
                math.to_number(false) == 0
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"to_number_booleans": True}


def test_math_to_number_rejects_non_boolean_arguments() -> None:
    ast = Parser().parse("""
        import "math"
        rule invalid_to_number {
            condition:
                defined math.to_number("1")
        }
        """)

    with pytest.raises(EvaluationError, match=r"math\.to_number\(\) expects a boolean argument"):
        YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_math_to_string_matches_libyara_supported_bases() -> None:
    ast = Parser().parse("""
        import "math"
        rule to_string_bases {
            condition:
                math.to_string(10) == "10" and
                math.to_string(10, 10) == "10" and
                math.to_string(10, 16) == "a" and
                math.to_string(10, 8) == "12" and
                math.to_string(-10, 16) == "fffffffffffffff6" and
                math.to_string(-10, 8) == "1777777777777777777766" and
                not defined math.to_string(10, 2)
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"to_string_bases": True}


def test_math_to_string_rejects_non_integer_arguments() -> None:
    ast = Parser().parse("""
        import "math"
        rule invalid_to_string {
            condition:
                defined math.to_string(true)
        }
        """)

    with pytest.raises(EvaluationError, match=r"math\.to_string\(\) expects integer arguments"):
        YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_math_integer_helpers_reject_boolean_arguments() -> None:
    ast = Parser().parse("""
        import "math"
        rule invalid_integer_helpers {
            condition:
                defined math.abs(true) or
                defined math.min(true, 2) or
                defined math.max(false, 2)
        }
        """)

    with pytest.raises(EvaluationError, match=r"math\.(abs|min|max)\(\) expects integer arguments"):
        YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_math_region_helpers_reject_boolean_offsets_and_sizes() -> None:
    for expression in (
        "math.entropy(true, 1)",
        "math.entropy(0, true)",
        "math.mean(true, 1)",
        "math.mean(0, true)",
        "math.serial_correlation(true, 1)",
        "math.serial_correlation(0, true)",
        "math.monte_carlo_pi(true, 6)",
        "math.monte_carlo_pi(0, true)",
        "math.deviation(true, 1, 0.0)",
        "math.deviation(0, true, 0.0)",
    ):
        ast = Parser().parse(
            f'import "math" rule invalid_region {{ condition: defined {expression} }}'
        )

        with pytest.raises(EvaluationError, match=r"offset and size must be integers"):
            YaraEvaluator(data=bytes(range(16))).evaluate_file(ast)


def test_math_deviation_rejects_non_float_mean_argument() -> None:
    for expression in ("math.deviation(0, 1, 0)", 'math.deviation(0, 1, "0")'):
        ast = Parser().parse(
            f'import "math" rule invalid_deviation {{ condition: defined {expression} }}'
        )

        with pytest.raises(
            EvaluationError,
            match=r"math\.deviation\(\) expects a floating-point mean argument",
        ):
            YaraEvaluator(data=bytes(range(16))).evaluate_file(ast)


def test_pe_functions_reject_wrong_argument_types() -> None:
    for expression in (
        "pe.section_index(true)",
        "pe.exports(true)",
        "pe.imports(true)",
        'pe.imports("KERNEL32.dll", true)',
        "pe.locale(true)",
        "pe.language(true)",
        "pe.rva_to_offset(true)",
    ):
        ast = Parser().parse(f'import "pe" rule invalid_pe {{ condition: defined {expression} }}')

        with pytest.raises(EvaluationError, match=r"pe\..* expects"):
            YaraEvaluator(data=b"MZ" + b"\x00" * 100).evaluate_file(ast)


@pytest.mark.parametrize("data", [b"", b"MZ"])
def test_pe_invalid_files_leave_pe_fields_undefined(data: bytes) -> None:
    ast = Parser().parse("""
        import "pe"
        rule invalid_pe_fields {
            condition:
                pe.is_pe or
                defined pe.machine or
                pe.machine == 0x14c or
                defined pe.number_of_sections or
                pe.number_of_sections == 0 or
                defined pe.is_32bit() or
                pe.is_32bit() or
                defined pe.is_dll() or
                pe.is_dll() or
                defined pe.section_index(".text") or
                pe.section_index(".text") == -1 or
                defined pe.imports("KERNEL32.dll") or
                defined pe.exports("ExportedFn") or
                defined pe.locale(0x409) or
                defined pe.language(0x09)
        }
        """)

    assert YaraEvaluator(data=data).evaluate_file(ast) == {"invalid_pe_fields": False}


def test_console_log_matches_libyara_scalar_arguments() -> None:
    ast = Parser().parse("""
        import "console"
        rule console_log_scalars {
            condition:
                console.log("x") and
                console.log(1, 1.5, filesize)
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"console_log_scalars": True}


def test_console_log_rejects_boolean_arguments() -> None:
    ast = Parser().parse("""
        import "console"
        rule invalid_console_log {
            condition:
                defined console.log(true)
        }
        """)

    with pytest.raises(EvaluationError, match=r"console\.log\(\) expects scalar arguments"):
        YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_string_to_int_matches_libyara_optional_base_and_undefined() -> None:
    ast = Parser().parse("""
        import "string"
        rule string_to_int_values {
            condition:
                string.to_int("123") == 123 and
                string.to_int("10", 16) == 16 and
                string.to_int("0x10", 0) == 16 and
                not defined string.to_int("x") and
                not defined string.to_int("10", 1)
        }

        rule invalid_string_to_int_comparison {
            condition:
                string.to_int("x") == 0
        }
        """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "string_to_int_values": True,
        "invalid_string_to_int_comparison": False,
    }


def test_string_module_rejects_wrong_argument_types() -> None:
    for expression in (
        "string.to_int(true)",
        "string.to_int(1)",
        'string.to_int("10", true)',
        "string.length(true)",
        "string.length(1)",
    ):
        ast = Parser().parse(
            f'import "string" rule invalid_string {{ condition: defined {expression} }}'
        )

        with pytest.raises(EvaluationError, match=r"string\..*(expects|base must)"):
            YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_cuckoo_nested_module_functions_evaluate_behavior_data() -> None:
    class _CuckooWithData:
        def __init__(self, data: bytes) -> None:
            from yaraast.evaluation.mock_modules import CuckooModule

            delegate = CuckooModule(data)
            delegate.network.http_requests = ["http://evil.example/path"]
            delegate.network.http_get_requests = ["http://evil.example/path"]
            delegate.network.http_post_requests = ["http://post.example/path"]
            delegate.network.http_user_agents = ["BadAgent/1.0"]
            delegate.network.dns_lookups = ["evil.example"]
            delegate.network.hosts = ["192.168.1.1"]
            delegate.network.tcp_connections = [("192.168.1.1", 443)]
            delegate.network.udp_connections = [("8.8.8.8", 53)]
            delegate.registry.key_accesses = [r"\\Software\\Bad"]
            delegate.filesystem.file_accesses = [r"C:\\autoexec.bat"]
            delegate.sync.mutexes = ["EvilMutexName"]
            self.__dict__.update(delegate.__dict__)

    registry = MockModuleRegistry()
    registry.register_module("cuckoo", _CuckooWithData)
    ast = Parser().parse(r"""
        import "cuckoo"
        rule cuckoo_behavior {
            condition:
                cuckoo.network.http_request(/evil\.example/) and
                cuckoo.network.http_get(/evil\.example/) and
                cuckoo.network.http_post(/post\.example/) and
                cuckoo.network.http_user_agent(/BadAgent/) and
                cuckoo.network.dns_lookup(/evil\.example/) and
                cuckoo.network.host(/192\.168\.1\.1/) and
                cuckoo.network.tcp(/192\.168\.1\.1/, 443) and
                cuckoo.network.udp(/8\.8\.8\.8/, 53) and
                cuckoo.registry.key_access(/Bad/) and
                cuckoo.filesystem.file_access(/autoexec\.bat/) and
                cuckoo.sync.mutex(/EvilMutex/)
        }
        """)

    assert YaraEvaluator(data=b"abc", modules=registry).evaluate_file(ast) == {
        "cuckoo_behavior": True
    }


def test_math_rejects_non_libyara_functions() -> None:
    ast = Parser().parse("""
        import "math"
        rule invalid_math_function {
            condition:
                defined math.log(1.0)
        }
        """)

    with pytest.raises(EvaluationError, match=r"Unknown function: math\.log"):
        YaraEvaluator(data=b"abc").evaluate_file(ast)


def test_math_module_valid_regions_can_extend_to_file_end() -> None:
    ast = Parser().parse("""
        import "math"
        rule trailing_math_region {
            condition:
                math.mean(1, 100) == 100.0 and
                math.entropy(0, 0) == 0.0
        }
        """)

    assert YaraEvaluator(data=b"abcdef").evaluate_file(ast) == {"trailing_math_region": True}


def test_defined_expression_evaluates_module_function_results() -> None:
    ast = Parser().parse("""
        import "math"
        rule valid_module_function_result {
            condition:
                defined math.entropy(0, 1)
        }

        rule invalid_module_function_result {
            condition:
                defined math.entropy(-1, 1)
        }
        """)

    assert YaraEvaluator(data=b"abcdef").evaluate_file(ast) == {
        "valid_module_function_result": True,
        "invalid_module_function_result": False,
    }


def test_string_count_offset_length_and_wildcard() -> None:
    ev = YaraEvaluator(data=b"xxabxxab")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    assert ev.evaluate_rule(rule) is True

    assert ev.visit_string_identifier(StringIdentifier(name="$a")) is True
    assert ev.visit_string_identifier(StringIdentifier(name="a")) is True
    assert ev.visit_string_wildcard(StringWildcard(pattern="$*")) is True
    assert ev.visit_string_count(StringCount(string_id="a")) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a")) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=1))) == 2
    assert ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=2))) == 6
    assert ev.visit_string_length(StringLength(string_id="$a", index=IntegerLiteral(value=1))) == 2
    assert (
        ev.visit_string_offset(StringOffset(string_id="$a", index=IntegerLiteral(value=9)))
        is YARA_UNDEFINED
    )
    assert (
        ev.visit_string_length(StringLength(string_id="$a", index=IntegerLiteral(value=9)))
        is YARA_UNDEFINED
    )


def test_direct_evaluate_rule_clears_matcher_state_for_rules_without_strings() -> None:
    ev = YaraEvaluator(data=b"xxabxxab")
    matching_rule = Rule(
        name="matching",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    no_strings_rule = Rule(
        name="no_strings",
        strings=[],
        condition=BinaryExpression(
            left=StringCount("$a"),
            operator="==",
            right=IntegerLiteral(0),
        ),
    )

    assert ev.evaluate_rule(matching_rule) is True
    assert ev.evaluate_rule(no_strings_rule) is True


def test_string_offset_length_indexed_parser_forms() -> None:
    ast = Parser().parse("""
        rule indexed {
            strings:
                $a = "ab"
            condition:
                @a[1] == 2 and @a[2] == 6 and !a[1] == 2
        }
        """)
    assert YaraEvaluator(data=b"xxabxxab").evaluate_file(ast) == {"indexed": True}


def test_for_of_zero_quantifier_matches_libyara_zero_satisfied_strings() -> None:
    ast = Parser().parse("""
        rule zero_current_string_truth {
            strings:
                $a = "x"
            condition:
                for 0 of them : ( $ )
        }

        rule zero_body_true {
            strings:
                $a = "x"
            condition:
                for 0 of them : ( true )
        }

        rule zero_string_count {
            strings:
                $a = "x"
            condition:
                for 0 of them : ( # == 0 )
        }
        """)

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {
        "zero_current_string_truth": True,
        "zero_body_true": False,
        "zero_string_count": False,
    }
    assert YaraEvaluator(data=b"x").evaluate_file(ast) == {
        "zero_current_string_truth": False,
        "zero_body_true": False,
        "zero_string_count": True,
    }


def test_binary_unary_function_member_array_and_errors() -> None:
    ev = YaraEvaluator(data=b"\x01\x02\x03\x04")

    assert (
        ev.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))) == 3
    )
    assert (
        ev.visit_binary_expression(
            BinaryExpression(BooleanLiteral(True), "or", BooleanLiteral(False))
        )
        is True
    )
    assert ev.visit_unary_expression(UnaryExpression("not", BooleanLiteral(False))) is True
    assert (
        ev.visit_unary_expression(
            UnaryExpression("not", FunctionCall("uint8", [IntegerLiteral(4)]))
        )
        is YARA_UNDEFINED
    )
    assert ev.visit_unary_expression(UnaryExpression("-", IntegerLiteral(2))) == -2
    assert ev.visit_unary_expression(UnaryExpression("~", IntegerLiteral(1))) == ~1
    assert ev.visit_parentheses_expression(ParenthesesExpression(BooleanLiteral(True))) is True
    assert ev.visit_set_expression(
        SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    ) == {1, 2}
    r = ev.visit_range_expression(RangeExpression(low=IntegerLiteral(2), high=IntegerLiteral(4)))
    assert list(r) == [2, 3, 4]

    assert (
        ev.visit_function_call(FunctionCall(function="uint16", arguments=[IntegerLiteral(value=0)]))
        == 513
    )
    with pytest.raises(EvaluationError, match=r"uint16\(\) expects exactly 1 argument"):
        ev.visit_function_call(FunctionCall(function="uint16", arguments=[]))
    with pytest.raises(EvaluationError, match=r"uint16\(\) expects exactly 1 argument"):
        ev.visit_function_call(
            FunctionCall(
                function="uint16",
                arguments=[IntegerLiteral(value=0), IntegerLiteral(value=1)],
            )
        )
    with pytest.raises(EvaluationError, match=r"uint16\(\) offset must be an integer"):
        ev.visit_function_call(
            FunctionCall(function="uint16", arguments=[StringLiteral(value="0")])
        )
    with pytest.raises(EvaluationError, match="Unknown function"):
        ev.visit_function_call(FunctionCall(function="nope.fn", arguments=[]))

    obj = SimpleNamespace(v=9)
    assert (
        ev.visit_member_access(MemberAccess(object=StringLiteral(value="x"), member="upper"))
        is not None
    )
    ev.context.variables["obj"] = obj
    assert ev.visit_member_access(MemberAccess(object=Identifier(name="obj"), member="v")) == 9
    assert (
        ev.visit_member_access(MemberAccess(object=Identifier(name="m"), member="k")) == 3
        if "m" in ev.context.modules
        else True
    )

    ev.context.variables["arr"] = [10, 20]
    assert (
        ev.visit_array_access(
            ArrayAccess(array=Identifier(name="arr"), index=IntegerLiteral(value=1))
        )
        == 20
    )
    assert (
        ev.visit_array_access(
            ArrayAccess(array=Identifier(name="arr"), index=StringLiteral(value="x"))
        )
        is None
    )

    with pytest.raises(EvaluationError, match="Unknown operator"):
        ev.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "???", IntegerLiteral(2)))
    with pytest.raises(EvaluationError, match="Unknown unary operator"):
        ev.visit_unary_expression(UnaryExpression("!", IntegerLiteral(1)))


def test_evaluator_does_not_treat_boolean_results_as_integers() -> None:
    ev = YaraEvaluator(data=b"\x01\x02\x03\x04")

    assert ev.visit_unary_expression(UnaryExpression("-", BooleanLiteral(True))) is YARA_UNDEFINED
    assert ev.visit_unary_expression(UnaryExpression("~", BooleanLiteral(False))) is YARA_UNDEFINED
    assert (
        ev.visit_range_expression(RangeExpression(BooleanLiteral(False), IntegerLiteral(2)))
        is YARA_UNDEFINED
    )

    with pytest.raises(EvaluationError, match=r"uint8\(\) offset must be an integer"):
        ev.visit_function_call(FunctionCall("uint8", [BooleanLiteral(True)]))

    string_eval = YaraEvaluator(data=b"xab")
    string_eval.evaluate_rule(
        Rule(
            name="boolean_index",
            strings=[PlainString("$a", value="ab")],
            condition=BooleanLiteral(True),
        )
    )
    assert (
        string_eval.visit_string_offset(StringOffset("$a", BooleanLiteral(True))) is YARA_UNDEFINED
    )
    assert string_eval.visit_at_expression(AtExpression("$a", BooleanLiteral(True))) is False


def test_evaluator_uint8be_and_int8be_match_registered_builtin_functions() -> None:
    ast = Parser().parse("""
        rule byte_endian_aliases {
            condition:
                uint8be(0) == 255 and int8be(0) == -1
        }
    """)

    assert YaraEvaluator(data=b"\xff").evaluate_file(ast) == {"byte_endian_aliases": True}


def test_builtin_integer_readers_return_undefined_outside_file() -> None:
    ast = Parser().parse("""
        rule invalid_integer_reader_comparison {
            condition:
                uint8(filesize) == 0 or uint16(2) == 0
        }

        rule invalid_integer_reader_defined {
            condition:
                defined uint8(filesize) or defined uint16(2)
        }

        rule invalid_integer_reader_not_defined {
            condition:
                not defined uint8(filesize) and not defined uint16(2)
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "invalid_integer_reader_comparison": False,
        "invalid_integer_reader_defined": False,
        "invalid_integer_reader_not_defined": True,
    }


def test_defined_not_undefined_reader_matches_libyara() -> None:
    ast = Parser().parse("""
        rule not_undefined_condition {
            condition:
                not uint8(filesize)
        }

        rule defined_not_undefined {
            condition:
                defined (not uint8(filesize))
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "not_undefined_condition": False,
        "defined_not_undefined": False,
    }


def test_boolean_operators_coerce_undefined_to_defined_false() -> None:
    ast = Parser().parse("""
        rule false_or_undefined {
            condition:
                false or uint8(filesize)
        }

        rule true_and_undefined {
            condition:
                true and uint8(filesize)
        }

        rule defined_false_or_undefined {
            condition:
                defined (false or uint8(filesize))
        }

        rule defined_true_and_undefined {
            condition:
                defined (true and uint8(filesize))
        }

        rule defined_undefined_or_undefined {
            condition:
                defined (uint8(filesize) or uint8(filesize))
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "false_or_undefined": False,
        "true_and_undefined": False,
        "defined_false_or_undefined": True,
        "defined_true_and_undefined": True,
        "defined_undefined_or_undefined": True,
    }


def test_division_operator_parses_and_evaluates() -> None:
    ast = Parser().parse("""
        rule integer_division {
            condition:
                5 / 2 == 2 and filesize / 2 == 2
        }

        rule yara_integer_division {
            condition:
                5 \\ 2 == 2 and filesize \\ 2 == 2
        }
    """)

    assert YaraEvaluator(data=b"abcd").evaluate_file(ast) == {
        "integer_division": True,
        "yara_integer_division": True,
    }


def test_bitwise_operator_precedence_matches_yara() -> None:
    ast = Parser().parse("""
        rule precedence {
            condition:
                1 | 2 & 0 == 1 and
                1 ^ 1 & 0 == 1 and
                1 | 2 ^ 3 == 1 and
                1 & 3 ^ 3 == 2
        }
    """)

    assert YaraEvaluator().evaluate_file(ast) == {"precedence": True}


def test_negative_shift_count_evaluates_as_undefined() -> None:
    ast = Parser().parse("""
        rule negative_shift_comparison {
            condition:
                0 << (0 - filesize) == 0
        }

        rule negative_shift_defined {
            condition:
                defined (0 << (0 - filesize))
        }
    """)

    assert YaraEvaluator(data=b"abcd").evaluate_file(ast) == {
        "negative_shift_comparison": False,
        "negative_shift_defined": False,
    }


def test_integer_runtime_semantics_match_yara_int64_boundaries() -> None:
    ast = Parser().parse(r"""
        rule add_wraps_negative {
            condition:
                9223372036854775807 + filesize < 0
        }

        rule shift_past_width_is_zero {
            condition:
                1 << (filesize + 63) == 0
        }

        rule shift_into_sign_bit_is_negative {
            condition:
                1 << (filesize + 62) < 0
        }

        rule division_overflow_is_undefined {
            condition:
                defined ((0 - 9223372036854775807 - filesize) \ (0 - filesize))
        }
    """)

    assert YaraEvaluator(data=b"a").evaluate_file(ast) == {
        "add_wraps_negative": True,
        "shift_past_width_is_zero": True,
        "shift_into_sign_bit_is_negative": True,
        "division_overflow_is_undefined": False,
    }


def test_defined_expression_evaluates_general_expressions() -> None:
    ast = Parser().parse(r"""
        rule defined_builtin {
            condition:
                defined filesize
        }

        rule defined_boolean_literal {
            condition:
                defined false
        }

        rule defined_arithmetic {
            condition:
                defined (1 + filesize)
        }

        rule undefined_arithmetic {
            condition:
                defined (1 \ (filesize - filesize))
        }
    """)

    assert YaraEvaluator(data=b"a").evaluate_file(ast) == {
        "defined_builtin": True,
        "defined_boolean_literal": True,
        "defined_arithmetic": True,
        "undefined_arithmetic": False,
    }


def test_missing_string_offset_and_length_evaluate_as_undefined() -> None:
    ast = Parser().parse("""
        rule missing_offset_comparison {
            strings:
                $a = "zz"
            condition:
                @a == -1
        }

        rule missing_offset_defined {
            strings:
                $a = "zz"
            condition:
                defined @a
        }

        rule missing_length_comparison {
            strings:
                $a = "zz"
            condition:
                !a == 0
        }

        rule missing_length_defined {
            strings:
                $a = "zz"
            condition:
                defined !a
        }

        rule missing_index_defined {
            strings:
                $a = "ab"
            condition:
                defined @a[2] or defined !a[2]
        }
    """)

    assert YaraEvaluator(data=b"ab").evaluate_file(ast) == {
        "missing_offset_comparison": False,
        "missing_offset_defined": False,
        "missing_length_comparison": False,
        "missing_length_defined": False,
        "missing_index_defined": False,
    }


def test_zero_divisor_arithmetic_evaluates_as_undefined() -> None:
    ast = Parser().parse("""
        rule zero_modulo_comparison {
            condition:
                filesize % (filesize - 3) == 0
        }

        rule zero_modulo_truthiness {
            condition:
                filesize % (filesize - 3)
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "zero_modulo_comparison": False,
        "zero_modulo_truthiness": False,
    }


def test_float_zero_divisor_arithmetic_matches_libyara_double_opcode() -> None:
    ast = Parser().parse("""
        rule positive_infinity_truthiness {
            condition:
                1.0 \\ 0.0
        }

        rule positive_infinity_comparison {
            condition:
                1.0 \\ 0.0 > 0
        }

        rule negative_infinity_comparison {
            condition:
                -1.0 \\ 0.0 < 0
        }

        rule nan_truthiness {
            condition:
                0.0 \\ 0.0
        }

        rule nan_defined {
            condition:
                defined (0.0 \\ 0.0)
        }

        rule nan_equality {
            condition:
                0.0 \\ 0.0 == 0.0 \\ 0.0
        }

        rule nan_inequality {
            condition:
                0.0 \\ 0.0 != 0.0 \\ 0.0
        }
    """)

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {
        "positive_infinity_truthiness": True,
        "positive_infinity_comparison": True,
        "negative_infinity_comparison": True,
        "nan_truthiness": True,
        "nan_defined": True,
        "nan_equality": False,
        "nan_inequality": False,
    }


def test_negative_zero_double_truthiness_matches_libyara() -> None:
    ast = Parser().parse("""
        rule positive_zero_literal {
            condition:
                0.0
        }

        rule negative_zero_literal {
            condition:
                -0.0
        }

        rule negative_zero_not {
            condition:
                not -0.0
        }

        rule negative_zero_and {
            condition:
                -0.0 and true
        }

        rule negative_zero_or {
            condition:
                -0.0 or false
        }

        rule multiplication_produces_negative_zero {
            condition:
                -1 * 0.0
        }

        rule division_produces_negative_zero {
            condition:
                0.0 \\ -1
        }
    """)

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {
        "positive_zero_literal": False,
        "negative_zero_literal": True,
        "negative_zero_not": False,
        "negative_zero_and": True,
        "negative_zero_or": True,
        "multiplication_produces_negative_zero": True,
        "division_produces_negative_zero": True,
    }


def test_condition_paths_for_at_in_of_for_and_defined() -> None:
    ev = YaraEvaluator(data=b"00abcd00")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    assert (
        ev.visit_at_expression(AtExpression(string_id="$a", offset=IntegerLiteral(value=2))) is True
    )
    assert (
        ev.visit_at_expression(AtExpression(string_id="a", offset=IntegerLiteral(value=2))) is True
    )
    assert (
        ev.visit_in_expression(
            InExpression(subject="$a", range=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)))
        )
        is True
    )
    assert (
        ev.visit_in_expression(
            InExpression(subject="a", range=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)))
        )
        is True
    )
    assert (
        ev.visit_in_expression(InExpression(subject="$a", range=IntegerLiteral(value=5))) is False
    )
    assert (
        ev.visit_in_expression(
            InExpression(
                subject=BooleanLiteral(value=True),
                range=RangeExpression(IntegerLiteral(0), IntegerLiteral(0)),
            )
        )
        is False
    )

    ev.context.string_matches = {"$a": [1], "$b": []}
    ev.string_matcher.matches = ev.context.string_matches
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=Identifier(name="any"),
                string_set=SetExpression([StringLiteral("$a"), StringLiteral("$b")]),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=StringLiteral(value="none"),
                string_set=SetExpression([StringLiteral("$b")]),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=IntegerLiteral(value=1),
                string_set=SetExpression([StringLiteral("$a"), StringLiteral("$b")]),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=IntegerLiteral(value=0),
                string_set=SetExpression([StringLiteral("$b")]),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=IntegerLiteral(value=0),
                string_set=SetExpression([StringLiteral("$a")]),
            )
        )
        is False
    )

    for_any = ForExpression(
        quantifier="any",
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        body=BinaryExpression(Identifier("i"), "==", IntegerLiteral(2)),
    )
    assert ev.visit_for_expression(for_any) is True

    for_all = ForExpression(
        quantifier="all",
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        body=BinaryExpression(Identifier("i"), ">", IntegerLiteral(0)),
    )
    assert ev.visit_for_expression(for_all) is True

    for_none = ForExpression(
        quantifier="none",
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=False),
    )
    assert ev.visit_for_expression(for_none) is True

    for_zero = ForExpression(
        quantifier=0,
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=True),
    )
    assert ev.visit_for_expression(for_zero) is False

    for_zero_no_matches = ForExpression(
        quantifier=0,
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=False),
    )
    assert ev.visit_for_expression(for_zero_no_matches) is True

    bool_for = ForExpression(
        quantifier=BooleanLiteral(True),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(True),
    )
    assert ev.visit_for_expression(bool_for) is False

    bool_of = OfExpression(
        quantifier=BooleanLiteral(True),
        string_set=SetExpression([StringLiteral("$a")]),
    )
    assert ev.visit_of_expression(bool_of) is False

    ev._current_rule = rule
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=StringIdentifier(name="$a")))
        is True
    )
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=Identifier(name="missing")))
        is False
    )

    assert ev.visit_regex_literal(SimpleNamespace(pattern="ab.*")) == "ab.*"
    assert ev.visit_module_reference(SimpleNamespace()) is None


def test_zero_of_matches_libyara_none_semantics() -> None:
    ast = Parser().parse('rule r { strings: $a = "A" condition: 0 of them }')

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {"r": True}
    assert YaraEvaluator(data=b"A").evaluate_file(ast) == {"r": False}


def test_zero_for_quantifier_matches_libyara_none_semantics() -> None:
    ast = Parser().parse("""
        rule none_satisfied {
            condition:
                for 0 i in (1, 2) : (i == 3)
        }

        rule one_satisfied {
            condition:
                for 0 i in (1, 2) : (i == 1)
        }
    """)

    assert YaraEvaluator(data=b"").evaluate_file(ast) == {
        "none_satisfied": True,
        "one_satisfied": False,
    }


def test_for_expression_with_undefined_range_is_false() -> None:
    ast = Parser().parse("""
        rule any_undefined_range {
            condition:
                for any i in (0..uint8(filesize)) : (true)
        }

        rule all_undefined_range {
            condition:
                for all i in (0..uint8(filesize)) : (true)
        }

        rule none_undefined_range {
            condition:
                for none i in (0..uint8(filesize)) : (true)
        }

        rule zero_undefined_range {
            condition:
                for 0 i in (0..uint8(filesize)) : (true)
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "any_undefined_range": False,
        "all_undefined_range": False,
        "none_undefined_range": False,
        "zero_undefined_range": False,
    }


def test_for_expression_with_dynamic_empty_range_is_false() -> None:
    ast = Parser().parse("""
        rule any_empty_range {
            condition:
                for any i in (filesize..0) : (true)
        }

        rule all_empty_range {
            condition:
                for all i in (filesize..0) : (true)
        }

        rule none_empty_range {
            condition:
                for none i in (filesize..0) : (true)
        }

        rule zero_empty_range {
            condition:
                for 0 i in (filesize..0) : (true)
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {
        "any_empty_range": False,
        "all_empty_range": False,
        "none_empty_range": False,
        "zero_empty_range": False,
    }


def test_for_of_and_module_reference_paths() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    node_any = ForOfExpression(
        quantifier="any",
        string_set=Identifier(name="them"),
        condition=BooleanLiteral(value=True),
    )
    assert ev.visit_for_of_expression(node_any) is True

    node_pct = ForOfExpression(
        quantifier="any",
        string_set=Identifier(name="them"),
        condition=None,
    )
    assert ev.visit_for_of_expression(node_pct) is True

    assert ev.visit_of_expression(OfExpression(quantifier="any", string_set="them")) is True
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier="any", string_set=["$a", "$missing"], condition=None)
        )
        is True
    )
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier=0, string_set=Identifier(name="them"), condition=None)
        )
        is False
    )
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier="all", string_set="$a*", condition=BooleanLiteral(True))
        )
        is True
    )
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(quantifier="all", string_set="a*", condition=BooleanLiteral(True))
        )
        is True
    )

    parsed = Parser().parse('rule r { strings: $a = "ab" condition: for any of them : ($) }')
    assert YaraEvaluator(data=b"xxabyy").evaluate_file(parsed) == {"r": True}

    parsed_single_of = Parser().parse('rule r { strings: $a = "ab" condition: any of ($a) }')
    assert YaraEvaluator(data=b"xxabyy").evaluate_file(parsed_single_of) == {"r": True}

    parsed_single_for_of = Parser().parse(
        'rule r { strings: $a = "ab" condition: for any of ($a) : ($) }'
    )
    assert YaraEvaluator(data=b"xxabyy").evaluate_file(parsed_single_for_of) == {"r": True}

    implicit_ops = Parser().parse("""
        rule r {
            strings:
                $a = "ab"
            condition:
                for any of them : (# == 1 and @ == 2 and ! == 2)
        }
        """)
    assert YaraEvaluator(data=b"xxabyy").evaluate_file(implicit_ops) == {"r": True}

    ev.context.modules["pe"] = {"machine": 0x14C}
    assert ev.visit_module_reference(ModuleReference(module="pe")) == {"machine": 0x14C}
    with pytest.raises(EvaluationError, match="Unknown module"):
        ev.visit_module_reference(ModuleReference(module="missing"))

    # Member access on non-object types returns None gracefully
    assert ev.visit_member_access(MemberAccess(object=IntegerLiteral(value=1), member="x")) is None

    # Expression dispatch should still work for concrete types.
    assert ev.visit_expression(BooleanLiteral(value=True)) is True


def test_of_and_for_of_resolve_nested_string_set_expression_results() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    rule = Rule(
        name="r",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BooleanLiteral(value=True),
    )
    assert ev.evaluate_rule(rule) is True

    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier="any",
                string_set=[Identifier("them")],
            )
        )
        is True
    )
    assert (
        ev.visit_for_of_expression(
            ForOfExpression(
                quantifier="all",
                string_set=[Identifier("them")],
                condition=BooleanLiteral(value=True),
            )
        )
        is True
    )


def test_string_wildcard_condition_respects_pattern() -> None:
    evaluator = YaraEvaluator(data=b"abc")
    rule = Rule(
        name="wildcard",
        strings=[
            PlainString(identifier="$a_one", value="ab"),
            PlainString(identifier="$b_one", value="zz"),
        ],
        condition=BooleanLiteral(value=True),
    )
    evaluator.evaluate_rule(rule)

    assert evaluator.visit_string_wildcard(StringWildcard("$a*")) is True
    assert evaluator.visit_string_wildcard(StringWildcard("$b*")) is False


def test_named_wildcard_string_sets_ignore_anonymous_internal_ids() -> None:
    ast = Parser().parse("""
        rule named_wildcard {
            strings:
                $a = "hit"
                $ = "miss"
            condition:
                all of ($a*)
        }

        rule global_wildcard {
            strings:
                $a = "hit"
                $ = "miss"
            condition:
                any of ($*)
        }
    """)

    assert YaraEvaluator(data=b"hit").evaluate_file(ast) == {
        "named_wildcard": True,
        "global_wildcard": True,
    }
    assert YaraEvaluator(data=b"miss").evaluate_file(ast) == {
        "named_wildcard": False,
        "global_wildcard": True,
    }


def test_empty_wildcard_string_sets_evaluate_false() -> None:
    ast = Parser().parse("""
        rule all_missing {
            strings:
                $a = "a"
            condition:
                all of ($missing*)
        }

        rule none_missing {
            strings:
                $a = "a"
            condition:
                none of ($missing*)
        }

        rule zero_missing {
            strings:
                $a = "a"
            condition:
                0 of ($missing*)
        }

        rule for_all_missing {
            strings:
                $a = "a"
            condition:
                for all of ($missing*) : (true)
        }
    """)

    assert YaraEvaluator(data=b"a").evaluate_file(ast) == {
        "all_missing": False,
        "none_missing": False,
        "zero_missing": False,
        "for_all_missing": False,
    }


def test_of_expression_in_range_uses_match_offsets() -> None:
    def evaluate(condition: str) -> bool:
        ast = Parser().parse(f"""
            rule r {{
                strings:
                    $a = "ab"
                    $b = "cd"
                condition:
                    {condition}
            }}
            """)
        return YaraEvaluator(data=b"xxabyycd").evaluate_file(ast)["r"]

    assert evaluate("any of them in (0..1)") is False
    assert evaluate("any of them in (0..3)") is True
    assert evaluate("2 of them in (0..3)") is False
    assert evaluate("2 of them in (0..7)") is True
    assert evaluate("all of them in (0..3)") is False


def test_percentage_of_expression_uses_ratio_threshold() -> None:
    def evaluate(condition: str, data: bytes) -> bool:
        ast = Parser().parse(f"""
            rule r {{
                strings:
                    $a = "a"
                    $b = "b"
                    $c = "c"
                condition:
                    {condition}
            }}
            """)
        return YaraEvaluator(data=data).evaluate_file(ast)["r"]

    assert evaluate("50% of them", b"a") is False
    assert evaluate("50% of them", b"ab") is True

    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$a", value="a"),
            PlainString(identifier="$b", value="b"),
            PlainString(identifier="$c", value="c"),
        ],
        condition=BooleanLiteral(value=True),
    )
    evaluator = YaraEvaluator(data=b"a")
    evaluator.evaluate_rule(rule)
    assert (
        evaluator.visit_for_of_expression(
            ForOfExpression(
                quantifier=DoubleLiteral(value=0.5),
                string_set=Identifier(name="them"),
                condition=None,
            )
        )
        is False
    )


def test_evaluate_file_with_alias_import_and_string_operator_expression() -> None:
    ev = YaraEvaluator(data=b"abc")
    file_ast = __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
        imports=[Import(module="math", alias="m")],
        rules=[
            Rule(
                name="ok",
                condition=BinaryExpression(
                    left=FunctionCall(function="m.abs", arguments=[IntegerLiteral(value=-1)]),
                    operator="==",
                    right=IntegerLiteral(value=1),
                ),
            )
        ],
    )
    out = ev.evaluate_file(file_ast)
    assert out["ok"] is True


def test_evaluate_file_with_aliased_import_keeps_original_module_name() -> None:
    ev = YaraEvaluator(data=b"abc")
    file_ast = __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
        imports=[Import(module="math", alias="m")],
        rules=[
            Rule(
                name="ok",
                condition=BinaryExpression(
                    left=FunctionCall(function="math.abs", arguments=[IntegerLiteral(value=-1)]),
                    operator="==",
                    right=IntegerLiteral(value=1),
                ),
            )
        ],
    )
    out = ev.evaluate_file(file_ast)
    assert out["ok"] is True


def test_evaluate_file_defined_module_reference_after_import() -> None:
    ast = Parser().parse("""
        import "math"
        rule imported_module {
            condition:
                defined math
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"imported_module": True}


def test_evaluate_file_resolves_forward_rule_references() -> None:
    ast = Parser().parse("""
        rule first {
            strings:
                $a = "missing"
            condition:
                second and #a == 0
        }

        rule second {
            strings:
                $b = "abc"
            condition:
                $b
        }
    """)

    assert YaraEvaluator(data=b"abc").evaluate_file(ast) == {"first": True, "second": True}


def test_evaluate_file_resets_imported_modules_between_files() -> None:
    evaluator = YaraEvaluator(data=b"abc")
    with_import = Parser().parse("""
        import "math"
        rule imported_module {
            condition:
                defined math
        }
    """)
    without_import = Parser().parse("""
        rule no_import {
            condition:
                defined math
        }
    """)

    assert evaluator.evaluate_file(with_import) == {"imported_module": True}
    assert evaluator.evaluate_file(without_import) == {"no_import": False}


def test_evaluate_file_skips_unknown_imports_and_continues() -> None:
    ev = YaraEvaluator(data=b"abc")
    file_ast = __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
        imports=[Import(module="missing"), Import(module="math")],
        rules=[Rule(name="ok", condition=BooleanLiteral(value=True))],
    )

    out = ev.evaluate_file(file_ast)

    assert out["ok"] is True
    assert "missing" not in ev.context.modules
    assert "math" in ev.context.modules


def test_evaluator_or_module_member_of_and_defined_paths() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    ev.context.variables["obj"] = {"k": 7}
    ev.context.variables["present_var"] = 11

    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$a", value="ab"),
            PlainString(identifier="$b", value="yy"),
        ],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    assert (
        ev.visit_binary_expression(
            BinaryExpression(BooleanLiteral(False), "or", BooleanLiteral(True))
        )
        is True
    )
    assert ev.visit_member_access(MemberAccess(object=Identifier(name="obj"), member="k")) == 7

    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=StringLiteral(value="all"),
                string_set=StringLiteral(value="them"),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=DoubleLiteral(value=0.5),
                string_set=StringLiteral(value="them"),
            )
        )
        is True
    )
    assert (
        ev.visit_of_expression(
            OfExpression(
                quantifier=StringLiteral(value="weird"),
                string_set=StringLiteral(value="them"),
            )
        )
        is False
    )

    ev.context.modules["pe"] = {"machine": 0x14C}
    assert ev.visit_defined_expression(DefinedExpression(expression=Identifier(name="pe"))) is True
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=Identifier(name="present_var")))
        is True
    )
    ev._current_rule = rule
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=StringIdentifier(name="$missing")))
        is False
    )
    ev._current_rule = Rule(name="empty", condition=BooleanLiteral(value=True))
    assert (
        ev.visit_defined_expression(DefinedExpression(expression=StringIdentifier(name="$a")))
        is False
    )

    assert (
        ev.visit_string_operator_expression(
            StringOperatorExpression(
                left=StringLiteral(value="Hello"),
                operator="istartswith",
                right=StringLiteral(value="he"),
            )
        )
        is True
    )


def test_evaluator_module_function_for_and_for_of_remaining_paths() -> None:
    ev = YaraEvaluator(data=b"xxabyy")
    ev.context.modules["math"] = ev.module_registry.create_module("math", ev.data)
    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$a", value="ab"),
            PlainString(identifier="$b", value="yy"),
        ],
        condition=BooleanLiteral(value=True),
    )
    ev.evaluate_rule(rule)

    with pytest.raises(EvaluationError, match=r"Unknown function: missing\.abs"):
        ev.visit_function_call(FunctionCall(function="missing.abs", arguments=[]))

    with pytest.raises(EvaluationError, match=r"Unknown function: math\.missing"):
        ev.visit_function_call(FunctionCall(function="math.missing", arguments=[]))
    with pytest.raises(EvaluationError, match="Unknown function: missing"):
        ev.visit_function_call(FunctionCall(function="missing", arguments=[]))

    ev.context.variables["i"] = 99
    for_two = ForExpression(
        quantifier=IntegerLiteral(value=2),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]),
        body=BinaryExpression(Identifier("i"), ">", IntegerLiteral(1)),
    )
    assert ev.visit_for_expression(for_two) is True
    assert ev.context.variables["i"] == 99

    for_unknown = ForExpression(
        quantifier=DoubleLiteral(value=0.25),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=True),
    )
    assert ev.visit_for_expression(for_unknown) is False

    for_weird = ForExpression(
        quantifier=StringLiteral(value="weird"),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=BooleanLiteral(value=True),
    )
    assert ev.visit_for_expression(for_weird) is False

    parsed = Parser().parse("rule r { condition: for all k, v in ((1, 2), (3, 4)) : (k < v) }")
    parsed_condition = parsed.rules[0].condition
    assert parsed_condition is not None
    assert YaraEvaluator().visit(parsed_condition) is True

    from yaraast.ast.conditions import ForOfExpression as ForOf

    node_all = ForOf(
        quantifier="all", string_set=Identifier(name="them"), condition=BooleanLiteral(value=True)
    )
    assert ev.visit_for_of_expression(node_all) is True

    node_none = ForOf(
        quantifier="none", string_set=Identifier(name="them"), condition=BooleanLiteral(value=False)
    )
    assert ev.visit_for_of_expression(node_none) is True

    node_int = ForOf(
        quantifier=IntegerLiteral(value=1), string_set=Identifier(name="them"), condition=None
    )
    assert ev.visit_for_of_expression(node_int) is True

    node_unknown = ForOf(
        quantifier="weird", string_set=Identifier(name="them"), condition=BooleanLiteral(value=True)
    )
    assert ev.visit_for_of_expression(node_unknown) is False

    node_other = ForOf(
        quantifier=SetExpression([]),
        string_set=Identifier(name="them"),
        condition=BooleanLiteral(value=True),
    )
    assert ev.visit_for_of_expression(node_other) is False


def test_parser_numeric_for_quantifier_evaluates_as_integer() -> None:
    ast = Parser().parse("rule r { condition: for 2 i in (1,2,3) : (i > 1) }")

    assert YaraEvaluator().evaluate_file(ast) == {"r": True}


def test_evaluator_evaluates_yarax_collection_literals_and_indexing() -> None:
    ev = YaraEvaluator()
    ev.context.variables["tail"] = [2, 3]
    ev.context.variables["rest"] = {"b": 2}

    assert ev.visit(ListExpression([IntegerLiteral(1), SpreadOperator(Identifier("tail"))])) == [
        1,
        2,
        3,
    ]
    assert ev.visit(TupleExpression([IntegerLiteral(1), IntegerLiteral(2)])) == (1, 2)
    assert ev.visit(
        DictExpression(
            [
                DictItem(StringLiteral("a"), IntegerLiteral(1)),
                DictItem(
                    StringLiteral("__spread__"),
                    SpreadOperator(Identifier("rest"), is_dict=True),
                ),
            ]
        )
    ) == {"a": 1, "b": 2}
    assert (
        ev.visit(
            TupleIndexing(
                TupleExpression([StringLiteral("a"), StringLiteral("b")]),
                IntegerLiteral(1),
            )
        )
        == "b"
    )
    assert ev.visit(
        SliceExpression(
            target=ListExpression([IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]),
            start=IntegerLiteral(1),
        )
    ) == [2, 3]


def test_evaluator_evaluates_yarax_comprehensions() -> None:
    ev = YaraEvaluator()
    ev.context.variables["items"] = [1, 2, 3]
    ev.context.variables["pairs"] = {"a": 1, "b": 2}

    assert ev.visit(
        ArrayComprehension(
            expression=BinaryExpression(Identifier("x"), "*", IntegerLiteral(2)),
            variable="x",
            iterable=Identifier("items"),
            condition=BinaryExpression(Identifier("x"), ">", IntegerLiteral(1)),
        )
    ) == [4, 6]
    assert "x" not in ev.context.variables

    assert ev.visit(
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=BinaryExpression(Identifier("v"), "+", IntegerLiteral(1)),
            key_variable="k",
            value_variable="v",
            iterable=Identifier("pairs"),
            condition=BinaryExpression(Identifier("v"), ">", IntegerLiteral(1)),
        )
    ) == {"b": 3}
    assert "k" not in ev.context.variables
    assert "v" not in ev.context.variables


def test_evaluator_evaluates_yarax_with_statement_and_pattern_match() -> None:
    ev = YaraEvaluator()

    condition = WithStatement(
        declarations=[WithDeclaration("$x", IntegerLiteral(2))],
        body=BinaryExpression(
            PatternMatch(
                value=Identifier("x"),
                cases=[MatchCase(pattern=IntegerLiteral(2), result=BooleanLiteral(True))],
                default=BooleanLiteral(False),
            ),
            "and",
            BinaryExpression(
                TupleIndexing(
                    TupleExpression([IntegerLiteral(1), Identifier("x")]),
                    IntegerLiteral(1),
                ),
                "==",
                IntegerLiteral(2),
            ),
        ),
    )

    assert ev.visit(condition) is True
    assert "$x" not in ev.context.variables
    assert "x" not in ev.context.variables


def test_evaluator_restores_yarax_with_declarations_when_later_declaration_fails() -> None:
    ev = YaraEvaluator()

    condition = WithStatement(
        declarations=[
            WithDeclaration("$x", IntegerLiteral(2)),
            WithDeclaration("$bad", FunctionCall("missing_function", [])),
        ],
        body=BooleanLiteral(True),
    )

    with pytest.raises(EvaluationError):
        ev.visit(condition)

    assert "$x" not in ev.context.variables
    assert "x" not in ev.context.variables


def test_evaluator_evaluates_dictionary_access_and_defined_dictionary_access() -> None:
    ev = YaraEvaluator()
    ev.context.variables["d"] = {"name": "alpha", 1: "one"}
    ev.context.variables["key"] = "name"
    ev.context.modules["pe"] = SimpleNamespace(version_info={"CompanyName": "Microsoft"})

    assert ev.visit(DictionaryAccess(Identifier("d"), "name")) == "alpha"
    assert ev.visit(DictionaryAccess(Identifier("d"), IntegerLiteral(1))) == "one"
    assert ev.visit(DictionaryAccess(Identifier("d"), Identifier("key"))) == "alpha"
    assert (
        ev.visit(
            DictionaryAccess(
                MemberAccess(Identifier("pe"), "version_info"),
                StringLiteral("CompanyName"),
            )
        )
        == "Microsoft"
    )
    assert ev.visit(DefinedExpression(DictionaryAccess(Identifier("d"), "name"))) is True
    assert ev.visit(DefinedExpression(DictionaryAccess(Identifier("d"), "missing"))) is False
