"""Coverage-targeted regression tests for yaraast.types.semantic_validator_strings.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Each test exercises a specific uncovered branch or statement identified by
measuring coverage against the existing test suite. All tests use real AST
nodes, real validator instances, and real execution paths. No mocks, stubs,
or inline suppressions are used.

Missing-line groups targeted (as reported by coverage before this file):
  StringModifierApplicabilityValidator
    147         -- visit_hex_string: modifier collection invalid -> early return
    149         -- visit_hex_string: modifier items invalid -> early return
    172         -- visit_regex_string: modifier collection invalid -> early return
    293-295     -- _check_xor_value: str value with '-' -> text range path
    303-308     -- _check_xor_range: parse returns None -> error + return
    337         -- _parse_xor_key: non-bool/non-int/non-str input -> None
    343->351    -- _check_base64_value: UnicodeEncodeError -> encoded_value = b""
    346-347     -- inner try/except branch setting encoded_value = b""
    349         -- _check_base64_value: valid 64-char ascii alphabet -> return

  UndefinedStringDetector
    409         -- check_rule: string def identifier without '$' prefix -> normalize
    425         -- _normalize_ref: ref text without '$' prefix -> prepend '$'
    475         -- _add_local_string_declaration: non-str identifier -> return
    481         -- _add_local_string_declaration: no scopes or non-'$' identifier -> return
    496         -- _add_local_string_declaration: non-str identifier path (error + return)
    498         -- _add_local_string_declaration: identifier not '$'-prefixed -> skip
    548-553     -- _with_declarations: non-sequence declarations -> error + return []
    560         -- _with_declarations: declaration missing identifier/value -> error
    597-601     -- _collect_string_refs: StringWildcard with non-str pattern -> return
    605         -- _collect_string_refs: StringCount/Offset/Length non-str id -> return
    614-616     -- _collect_string_refs: AtExpression non-str string_id -> recurse
    625->627    -- _collect_string_refs: ForOfExpression ASTNode quantifier + condition
    638->exit   -- _collect_string_refs: ASTNode children fallback recursion
    655-656     -- _collect_string_set_refs: str set that is a local variable -> recurse
    682->exit   -- _collect_string_set_refs: StringWildcard without '$' -> skip
    695         -- _collect_string_set_refs: Identifier '$'-name with local value -> recurse
    698->exit   -- _collect_string_set_refs: Identifier '$'-name without local value -> add
    707         -- _check_invalid_string_sets: parenthesized 'them' in ForOfExpression
    717->exit   -- _check_invalid_string_sets: ASTNode children recursion
    762-766     -- _collect_used_string_defs: StringWildcard non-str pattern / local pattern
    770         -- _collect_used_string_defs: StringCount/Offset/Length non-str id -> return
    778-780     -- _collect_used_string_defs: AtExpression mark-used / non-str recurse
    795->797    -- _collect_used_string_defs: ForOfExpression with non-None condition
    813->exit   -- _collect_used_string_defs: ASTNode children fallback recursion
    834, 836    -- _mark_used_string_set: str with local value / str == 'them'
    861->exit   -- _mark_used_string_set: StringWildcard without '$' -> skip
    874         -- _mark_used_string_set: Identifier 'them' -> used.update(defined)
    877->exit   -- _mark_used_string_set: Identifier '$'-name with local value -> recurse
    886         -- _mark_used_string_ref: ref == '$*' -> used.update(defined)

Genuinely structurally unreachable lines (documented here, not tested):
  161  -- visit_hex_string inner loop: modifier name None after items-check already
         returned False. Every modifier with a None name causes _check_modifier_items
         to return False before the explicit modifier loop is reached.
  179  -- visit_regex_string: same structural reason.
  204  -- _check_unsupported_modifiers: same reason (called after items check passes).
  229  -- _check_duplicate_modifiers: same reason.
  243  -- _check_non_regex_string: same reason.
  277  -- _check_text_string_modifier_values: same reason.
  371->369 -- _modifier_names: same reason.
  438  -- _is_local_string_ref: normalized None branch; all callers pre-validate to str.
  487  -- _local_string_value: normalized None branch; all callers pre-validate to str.
"""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import AtExpression, ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_strings import (
    StringModifierApplicabilityValidator,
    UndefinedStringDetector,
)
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement

# ---------------------------------------------------------------------------
# StringModifierApplicabilityValidator -- modifier-collection guard branches
# ---------------------------------------------------------------------------


def test_visit_hex_string_returns_early_when_modifier_collection_is_invalid() -> None:
    """visit_hex_string returns without further checks when modifiers is not a list/tuple.

    Covers line 147: the early-return after _check_modifier_collection returns False.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    hex_node = HexString(identifier="$h", tokens=[HexByte(value=0x41)])
    hex_node.modifiers = cast(Any, False)
    rule = Rule(name="hex_bad_collection", strings=[hex_node])

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "must be a list or tuple" in error.message and "$h" in error.message
        for error in result.errors
    )


def test_visit_hex_string_returns_early_when_modifier_items_are_invalid() -> None:
    """visit_hex_string returns without further checks when a modifier item has no valid name.

    Covers line 149: the early-return after _check_modifier_items returns False.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    class BadModifier:
        name = False

    hex_node = HexString(identifier="$h", tokens=[HexByte(value=0x41)])
    hex_node.modifiers = [cast(Any, BadModifier())]
    rule = Rule(name="hex_bad_items", strings=[hex_node])

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "must contain strings or StringModifier nodes" in error.message and "$h" in error.message
        for error in result.errors
    )


def test_visit_regex_string_returns_early_when_modifier_collection_is_invalid() -> None:
    """visit_regex_string returns without further checks when modifiers is not a list/tuple.

    Covers line 172: early-return in visit_regex_string.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    regex_node = RegexString(identifier="$r", regex="abc")
    regex_node.modifiers = cast(Any, False)
    rule = Rule(name="regex_bad_collection", strings=[regex_node])

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "must be a list or tuple" in error.message and "$r" in error.message
        for error in result.errors
    )


# ---------------------------------------------------------------------------
# StringModifierApplicabilityValidator -- xor text-range paths
# ---------------------------------------------------------------------------


def test_xor_modifier_accepts_valid_ascending_text_range() -> None:
    """_check_xor_value processes a text value containing '-' as a range (lines 293-295)
    and produces no errors when the range is valid and ascending.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="xor_text_range",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("xor", "0x01-0xff")],
            )
        ],
    )

    validator.visit_rule(rule)

    assert result.is_valid
    assert result.errors == []


def test_xor_modifier_rejects_text_range_with_descending_bounds() -> None:
    """_check_xor_range reports an error when the text range has high < low (line 312-317).

    The text '0xff-0x01' is split on '-', both halves parse successfully, but low > high.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="xor_descending_text",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("xor", "0xff-0x01")],
            )
        ],
    )

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "lower bound no greater than the upper bound" in error.message for error in result.errors
    )


def test_xor_modifier_rejects_text_range_with_unparseable_bounds() -> None:
    """_check_xor_range reports an error when text range bounds cannot be parsed (lines 303-308).

    'abc-def' is split on '-'; both halves fail parse_xor_key_text, yielding None bounds.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="xor_bad_text_bounds",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("xor", "abc-def")],
            )
        ],
    )

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any("must contain integer bounds" in error.message for error in result.errors)


def test_xor_modifier_rejects_non_scalar_value() -> None:
    """_parse_xor_key returns None for a non-bool, non-int, non-str value (line 337).

    An empty list is not bool/int/str, so it falls through all isinstance guards to
    return None, and _check_xor_key then records an out-of-range error.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="xor_non_scalar",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("xor", [])],
            )
        ],
    )

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "xor key for string '$a' must be between 0 and 255" in error.message
        for error in result.errors
    )


# ---------------------------------------------------------------------------
# StringModifierApplicabilityValidator -- base64 alphabet paths
# ---------------------------------------------------------------------------


def test_base64_modifier_accepts_valid_64_char_ascii_alphabet() -> None:
    """_check_base64_value returns without error when alphabet encodes to exactly 64 bytes (line 349).

    The standard Base64 alphabet is 64 printable ASCII characters.
    """
    standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert len(standard_alphabet) == 64

    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="b64_valid_alphabet",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("base64", standard_alphabet)],
            )
        ],
    )

    validator.visit_rule(rule)

    assert result.is_valid
    assert result.errors == []


def test_base64_modifier_rejects_alphabet_containing_non_ascii_characters() -> None:
    """_check_base64_value catches UnicodeEncodeError and reports an error (lines 346-347).

    A 64-character string that includes a non-ASCII character triggers UnicodeEncodeError
    during encode('ascii'), setting encoded_value to b"" (length 0 != 64).
    """
    non_ascii_alphabet = "A" * 63 + "ü"
    assert len(non_ascii_alphabet) == 64

    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="b64_non_ascii_alphabet",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("base64", non_ascii_alphabet)],
            )
        ],
    )

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "base64 alphabet for string '$a' must be 64 bytes" in error.message
        for error in result.errors
    )


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- check_rule identifier normalization
# ---------------------------------------------------------------------------


def test_check_rule_returns_early_when_condition_is_none() -> None:
    """check_rule exits immediately when rule.condition is None (line 409).

    A rule with a condition of None has nothing to validate; the method returns
    without collecting refs, checking string sets, or reporting unreferenced strings.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="no_condition",
        strings=[PlainString(identifier="$a", value="abc")],
        condition=None,
    )

    detector.check_rule(rule)

    assert result.is_valid
    assert result.errors == []


def test_check_rule_normalizes_string_identifiers_without_dollar_prefix() -> None:
    """check_rule prepends '$' when a string definition identifier lacks the prefix (line 424->426).

    Identifiers entered without a leading '$' are normalized so that they match
    condition references that do carry the prefix.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    plain = PlainString(identifier="a", value="abc")
    rule = Rule(
        name="unprefixed_id",
        strings=[plain],
        condition=StringIdentifier("$a"),
    )

    detector.check_rule(rule)

    assert result.is_valid
    assert result.errors == []


def test_normalize_ref_prepends_dollar_when_ref_lacks_prefix() -> None:
    """_normalize_ref returns a '$'-prefixed version of a bare identifier (line 425)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    normalized = detector._normalize_ref("abc")

    assert normalized == "$abc"


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _add_local_string_declaration guard branches
# ---------------------------------------------------------------------------


def test_normalize_ref_returns_none_for_non_string_ref() -> None:
    """_normalize_ref returns None when ref is not a string (line 475).

    _string_ref_or_none returns None for a non-str input; _normalize_ref then returns
    None at line 475 rather than producing a '$'-prefixed string.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    normalized = detector._normalize_ref(cast(Any, False))

    assert normalized is None
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_is_local_string_ref_returns_false_for_non_string_ref() -> None:
    """_is_local_string_ref returns False when ref is not a string (line 481).

    _normalize_ref returns None for non-str input; the None-check at line 480 is True
    and line 481 (return False) is executed.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$a": None})

    is_local = detector._is_local_string_ref(cast(Any, False))

    assert is_local is False
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_local_string_value_returns_missing_sentinel_for_non_string_ref() -> None:
    """_local_string_value returns _MISSING_LOCAL_STRING when ref is not a string (line 487).

    _normalize_ref returns None for non-str input; the None-check at line 486 is True
    and line 487 returns the sentinel object.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$a": "value"})

    sentinel = detector._local_string_value(cast(Any, False))

    assert sentinel is UndefinedStringDetector._MISSING_LOCAL_STRING
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_add_local_string_declaration_silently_ignores_non_string_identifier() -> None:
    """_add_local_string_declaration returns without side effects when identifier is not str (lines 495-496).

    The method calls _string_ref_or_none, which adds an error and returns None for non-str
    identifiers; _add_local_string_declaration then returns immediately leaving the scope
    unchanged.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({})

    detector._add_local_string_declaration(cast(Any, False), BooleanLiteral(True))

    assert detector._local_string_scopes == [{}]
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_add_local_string_declaration_skips_identifier_without_dollar_prefix() -> None:
    """_add_local_string_declaration returns without adding to scope when identifier has no '$' (line 481).

    A non-'$' identifier (e.g. 'my_var') is not treated as a local string binding.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({})

    detector._add_local_string_declaration("my_var", BooleanLiteral(True))

    assert detector._local_string_scopes == [{}]
    assert result.errors == []


def test_add_local_string_declaration_skips_when_no_active_scope() -> None:
    """_add_local_string_declaration returns without error when no scope is active (line 481).

    If _local_string_scopes is empty the guard at line 481 returns early.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    # No scopes pushed

    detector._add_local_string_declaration("$x", BooleanLiteral(True))

    assert result.errors == []
    assert detector._local_string_scopes == []


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _with_declarations validation paths
# ---------------------------------------------------------------------------


def test_with_declarations_rejects_non_sequence_declarations() -> None:
    """_with_declarations adds an error and returns [] when declarations is not a list/tuple (lines 548-553)."""

    class FakeWithNode:
        declarations: Any = False
        location = None

    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    returned = detector._with_declarations(FakeWithNode())

    assert returned == []
    assert any(
        "With-statement declarations must be a sequence" in error.message for error in result.errors
    )


def test_with_declarations_rejects_item_missing_identifier_or_value() -> None:
    """_with_declarations adds an error for each item lacking identifier or value (line 560)."""

    class ItemMissingValue:
        identifier = "$x"

    class FakeWithNode:
        declarations: Any = [ItemMissingValue()]
        location = None

    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    returned = detector._with_declarations(FakeWithNode())

    assert returned == []
    assert any(
        "With-statement declarations item must be WithDeclaration" in error.message
        for error in result.errors
    )


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _collect_string_refs branches
# ---------------------------------------------------------------------------


def test_collect_string_refs_skips_string_wildcard_with_non_str_pattern() -> None:
    """_collect_string_refs returns early when StringWildcard.pattern is not a string (lines 597-601).

    _string_ref_or_none records an error and returns None; the function then returns
    without adding anything to the refs set.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    wildcard = StringWildcard(pattern=cast(Any, False))
    detector._collect_string_refs(wildcard, refs)

    assert refs == set()
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_collect_string_refs_skips_string_count_with_non_str_id() -> None:
    """_collect_string_refs returns early when StringCount.string_id is not a string (line 605)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    count = StringCount(string_id=cast(Any, 42))
    detector._collect_string_refs(count, refs)

    assert refs == set()
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_collect_string_refs_recurses_into_at_expression_with_node_string_id() -> None:
    """_collect_string_refs recurses when AtExpression.string_id is an AST node (lines 614-616).

    When string_id is not a str instance the else branch calls _collect_string_refs on it,
    allowing the nested StringIdentifier to contribute its ref.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    at_expr = AtExpression(
        string_id=cast(Any, StringIdentifier("$missing")),
        offset=IntegerLiteral(0),
    )
    detector._collect_string_refs(at_expr, refs)

    assert "$missing" in refs


def test_collect_string_refs_recurses_into_for_of_quantifier_and_condition() -> None:
    """_collect_string_refs recurses into quantifier (when it has accept) and condition (lines 625->627).

    StringCount is an ASTNode and has an 'accept' method; its string_id '$a' is thus collected
    as a ref through the quantifier recursion.  The non-None condition is also recursed into.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    for_of = ForOfExpression(
        quantifier=StringCount("$a"),
        string_set="them",
        condition=BooleanLiteral(True),
    )
    detector._collect_string_refs(for_of, refs)

    assert "$a" in refs


def test_collect_string_refs_adds_string_wildcard_with_valid_dollar_pattern() -> None:
    """_collect_string_refs adds a StringWildcard with a valid '$'-prefixed pattern (lines 600-601).

    When pattern is a str and is not in any local scope the ref is added (line 601 executed).
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    wildcard = StringWildcard(pattern="$a*")
    detector._collect_string_refs(wildcard, refs)

    assert "$a*" in refs
    assert result.errors == []


def test_collect_string_refs_skips_string_wildcard_pattern_that_is_in_local_scope() -> None:
    """_collect_string_refs skips adding ref when StringWildcard pattern is in local scope (branch 600->638).

    When _is_local_string_ref returns True for the pattern, the condition at line 600 is False
    (not True = False) and line 601 is skipped. Execution falls through to the ASTNode check.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$a*": None})

    refs: set[str] = set()
    wildcard = StringWildcard(pattern="$a*")
    detector._collect_string_refs(wildcard, refs)

    assert "$a*" not in refs
    assert result.errors == []


def test_collect_string_refs_exits_cleanly_for_non_ast_non_specific_node() -> None:
    """_collect_string_refs exits without error when node is not an ASTNode (branch 638->exit).

    When node is not an ASTNode and not any of the specific expression types, the function
    falls through the isinstance check at line 638 and returns without doing anything.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    detector._collect_string_refs(42, refs)

    assert refs == set()
    assert result.errors == []


def test_collect_string_refs_recurses_into_ast_node_children() -> None:
    """_collect_string_refs falls back to children() recursion for generic ASTNode (line 638).

    BinaryExpression is an ASTNode that is not handled by any specific isinstance branch;
    its children are iterated, and the nested StringIdentifier contributes its ref.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    binary = BinaryExpression(BooleanLiteral(True), "and", StringIdentifier("$a"))
    detector._collect_string_refs(binary, refs)

    assert "$a" in refs


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _collect_string_set_refs branches
# ---------------------------------------------------------------------------


def test_collect_string_set_refs_resolves_local_variable_string_set() -> None:
    """_collect_string_set_refs recurses when a str set is a local variable (lines 655-656).

    When a string set value is itself in the local scope the method recursively resolves it,
    eventually adding the underlying ref to the refs set.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$x": "$a"})

    refs: set[str] = set()
    detector._collect_string_set_refs("$x", refs)

    assert "$a" in refs


def test_collect_string_set_refs_skips_string_wildcard_without_dollar_prefix() -> None:
    """_collect_string_set_refs does nothing when StringWildcard.pattern lacks '$' (line 682->exit).

    A wildcard pattern that does not start with '$' is not a string reference and is silently
    ignored.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    wildcard = StringWildcard(pattern="a*")
    detector._collect_string_set_refs(wildcard, refs)

    assert refs == set()
    assert result.errors == []


def test_collect_string_set_refs_resolves_identifier_with_dollar_name_in_local_scope() -> None:
    """_collect_string_set_refs recurses when an Identifier '$'-name is in local scope (line 695).

    The local value is recursed into; its underlying StringLiteral value is then added.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$x": StringLiteral("$a")})

    refs: set[str] = set()
    detector._collect_string_set_refs(Identifier(name="$x"), refs)

    assert "$a" in refs


def test_collect_string_set_refs_adds_identifier_with_dollar_name_not_in_local_scope() -> None:
    """_collect_string_set_refs adds an Identifier '$'-name that is not in local scope (line 698->exit)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    detector._collect_string_set_refs(Identifier(name="$y"), refs)

    assert "$y" in refs


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _check_invalid_string_sets branches
# ---------------------------------------------------------------------------


def test_check_invalid_string_sets_rejects_parenthesized_them_in_for_of() -> None:
    """_check_invalid_string_sets adds an error for parenthesized 'them' in ForOfExpression (line 707).

    '(them)' is not a valid string set; only bare 'of them' is accepted.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="paren_them_for_of",
        strings=[PlainString(identifier="$a", value="abc")],
        condition=ForOfExpression(
            quantifier="any",
            string_set=ParenthesesExpression(Identifier("them")),
            condition=None,
        ),
    )

    detector.check_rule(rule)

    assert not result.is_valid
    assert any(
        "Invalid parenthesized 'them' string set" in error.message for error in result.errors
    )


def test_check_invalid_string_sets_recurses_into_ast_node_children() -> None:
    """_check_invalid_string_sets recurses into ASTNode children (line 717->exit).

    A BinaryExpression wrapping a ForOfExpression with parenthesized 'them' causes
    the recursion to reach the inner node through the children() fallback.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    nested = ForOfExpression(
        quantifier="any",
        string_set=ParenthesesExpression(Identifier("them")),
        condition=None,
    )
    # BinaryExpression is an ASTNode; its children include the ForOfExpression
    binary = BinaryExpression(nested, "and", BooleanLiteral(True))

    detector._check_invalid_string_sets(binary, defined, "nested_rule")

    assert any(
        "Invalid parenthesized 'them' string set" in error.message for error in result.errors
    )


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _collect_used_string_defs branches
# ---------------------------------------------------------------------------


def test_collect_used_string_defs_skips_string_wildcard_with_non_str_pattern() -> None:
    """_collect_used_string_defs returns early when StringWildcard.pattern is not a string (lines 762-764)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    used: set[str] = set()
    wildcard = StringWildcard(pattern=cast(Any, False))
    detector._collect_used_string_defs(wildcard, {"$a"}, set(), used)

    assert used == set()
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_collect_used_string_defs_skips_string_wildcard_matching_local_scope() -> None:
    """_collect_used_string_defs skips marking when StringWildcard pattern is in local scope (line 765).

    A wildcard pattern that resolves to a local scope variable is not treated as a
    reference to a defined string.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$a*": None})

    used: set[str] = set()
    wildcard = StringWildcard(pattern="$a*")
    detector._collect_used_string_defs(wildcard, {"$a"}, set(), used)

    assert used == set()
    assert result.errors == []


def test_collect_used_string_defs_skips_string_count_with_non_str_id() -> None:
    """_collect_used_string_defs returns early when StringCount.string_id is not a string (line 770)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    used: set[str] = set()
    count = StringCount(string_id=cast(Any, False))
    detector._collect_used_string_defs(count, {"$a"}, set(), used)

    assert used == set()
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_collect_used_string_defs_marks_at_expression_with_str_string_id() -> None:
    """_collect_used_string_defs marks an AtExpression str string_id as used (line 778).

    AtExpression("$a", offset) with a str string_id reaches the mark-used branch.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    used: set[str] = set()
    at_expr = AtExpression(string_id="$a", offset=IntegerLiteral(0))
    detector._collect_used_string_defs(at_expr, defined, set(), used)

    assert "$a" in used


def test_collect_used_string_defs_recurses_into_at_expression_with_node_string_id() -> None:
    """_collect_used_string_defs recurses when AtExpression.string_id is an AST node (lines 779-780).

    When string_id is not a str the else branch recurses, allowing the nested
    StringIdentifier to mark the underlying string as used.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    used: set[str] = set()
    at_expr = AtExpression(
        string_id=cast(Any, StringIdentifier("$a")),
        offset=IntegerLiteral(0),
    )
    detector._collect_used_string_defs(at_expr, defined, set(), used)

    assert "$a" in used


def test_collect_used_string_defs_recurses_into_for_of_condition() -> None:
    """_collect_used_string_defs processes non-None ForOfExpression.condition (lines 795->797).

    With a non-None condition the method recurses into it, allowing references within the
    condition body to mark strings as used.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    used: set[str] = set()
    for_of = ForOfExpression(
        quantifier="any",
        string_set="them",
        condition=StringIdentifier("$a"),
    )
    detector._collect_used_string_defs(for_of, defined, set(), used)

    assert "$a" in used


def test_collect_used_string_defs_recurses_into_ast_node_children() -> None:
    """_collect_used_string_defs falls back to children() recursion for generic ASTNode (line 813->exit).

    BinaryExpression is not handled by any specific branch; its StringIdentifier child is
    visited through the children() fallback and marks '$a' as used.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    used: set[str] = set()
    binary = BinaryExpression(StringIdentifier("$a"), "and", BooleanLiteral(True))
    detector._collect_used_string_defs(binary, defined, set(), used)

    assert "$a" in used


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _mark_used_string_set branches
# ---------------------------------------------------------------------------


def test_mark_used_string_set_resolves_str_local_variable_to_its_value() -> None:
    """_mark_used_string_set recurses when a str set is a local variable (line 834).

    The local variable '$x' maps to '$a' so '$a' ends up in used.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$x": "$a"})
    defined = {"$a"}

    used: set[str] = set()
    detector._mark_used_string_set("$x", defined, set(), used)

    assert "$a" in used


def test_mark_used_string_set_marks_all_defined_strings_for_them() -> None:
    """_mark_used_string_set updates used with all defined strings for str 'them' (line 836)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a", "$b"}

    used: set[str] = set()
    detector._mark_used_string_set("them", defined, set(), used)

    assert used == {"$a", "$b"}


def test_mark_used_string_set_skips_string_wildcard_without_dollar_prefix() -> None:
    """_mark_used_string_set does nothing when StringWildcard.pattern has no '$' prefix (line 861->exit)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a", "$ab"}

    used: set[str] = set()
    wildcard = StringWildcard(pattern="a*")
    detector._mark_used_string_set(wildcard, defined, set(), used)

    assert used == set()
    assert result.errors == []


def test_mark_used_string_set_updates_used_for_identifier_them() -> None:
    """_mark_used_string_set updates used with all defined strings for Identifier('them') (line 874)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a", "$b"}

    used: set[str] = set()
    detector._mark_used_string_set(Identifier("them"), defined, set(), used)

    assert used == {"$a", "$b"}


def test_mark_used_string_set_resolves_identifier_with_dollar_name_in_local_scope() -> None:
    """_mark_used_string_set recurses when Identifier '$'-name has a local scope value (line 877->exit).

    The local '$x' maps to '$a' so '$a' ends up in used rather than '$x'.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    detector._local_string_scopes.append({"$x": "$a"})
    defined = {"$a"}

    used: set[str] = set()
    detector._mark_used_string_set(Identifier("$x"), defined, set(), used)

    assert "$a" in used
    assert "$x" not in used


# ---------------------------------------------------------------------------
# UndefinedStringDetector -- _mark_used_string_ref '$*' path
# ---------------------------------------------------------------------------


def test_mark_used_string_ref_updates_used_for_global_wildcard() -> None:
    """_mark_used_string_ref updates used with all defined strings when ref is '$*' (line 886)."""
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a", "$b"}

    used: set[str] = set()
    detector._mark_used_string_ref("$*", defined, set(), used)

    assert used == {"$a", "$b"}


# ---------------------------------------------------------------------------
# Integration: end-to-end scenarios exercising multiple uncovered paths
# ---------------------------------------------------------------------------


def test_check_rule_via_for_of_expression_with_ast_node_quantifier() -> None:
    """ForOfExpression with an ASTNode quantifier is fully processed through check_rule.

    StringCount is an ASTNode with an 'accept' method, exercising the quantifier-recursion
    branches in both _collect_string_refs and _collect_used_string_defs.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="for_of_ast_quantifier",
        strings=[
            PlainString(identifier="$a", value="abc"),
            PlainString(identifier="$b", value="def"),
        ],
        condition=ForOfExpression(
            quantifier=StringCount("$a"),
            string_set="them",
            condition=BooleanLiteral(True),
        ),
    )

    detector.check_rule(rule)

    assert result.is_valid
    assert result.errors == []


def test_check_rule_accepts_rule_using_at_expression_with_str_string_id() -> None:
    """AtExpression with a plain string string_id marks the referenced string as used.

    Exercises the mark-used branch in _collect_used_string_defs (line 778).
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="at_str_id",
        strings=[PlainString(identifier="$a", value="abc")],
        condition=AtExpression(string_id="$a", offset=IntegerLiteral(0)),
    )

    detector.check_rule(rule)

    assert result.is_valid
    assert result.errors == []


def test_check_rule_reports_undefined_string_via_at_expression_node_string_id() -> None:
    """AtExpression with a node string_id recurses; undefined refs are reported correctly.

    Exercises the else-branch recursion in both _collect_string_refs (line 614-616)
    and _collect_used_string_defs (lines 779-780).
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="at_node_undefined",
        strings=[],
        condition=AtExpression(
            string_id=cast(Any, StringIdentifier("$missing")),
            offset=IntegerLiteral(0),
        ),
    )

    detector.check_rule(rule)

    assert not result.is_valid
    assert any("Undefined string '$missing'" in error.message for error in result.errors)


def test_full_rule_with_identifier_string_set_in_local_scope_resolves_correctly() -> None:
    """WithStatement with an Identifier '$'-name in local scope resolves and marks used.

    Exercises _collect_string_set_refs line 695 and _mark_used_string_set line 877->exit.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="local_ident_set",
        strings=[
            PlainString(identifier="$a", value="abc"),
            PlainString(identifier="$b", value="def"),
        ],
        condition=WithStatement(
            declarations=[WithDeclaration("$x", StringLiteral("$a"))],
            body=OfExpression("any", SetExpression([Identifier("$x")])),
        ),
    )

    detector.check_rule(rule)

    messages = [error.message for error in result.errors]
    assert not any("Undefined string '$a'" in m for m in messages)
    assert any("Unreferenced string '$b'" in m for m in messages)


# ---------------------------------------------------------------------------
# Additional branch coverage for remaining missed lines
# ---------------------------------------------------------------------------


def test_base64_modifier_rejects_non_str_non_none_value() -> None:
    """_check_base64_value goes directly to error when value is neither None nor str (branch 343->351).

    An integer value for the base64 alphabet fails the isinstance(value, str) check at line 343
    and falls directly to the add_error call at line 351 without entering the try block.
    """
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="b64_int_value",
        strings=[
            PlainString(
                identifier="$a",
                value="abc",
                modifiers=[StringModifier.from_name_value("base64", 42)],
            )
        ],
    )

    validator.visit_rule(rule)

    assert not result.is_valid
    assert any(
        "base64 alphabet for string '$a' must be 64 bytes" in error.message
        for error in result.errors
    )


def test_collect_used_string_defs_marks_string_wildcard_with_valid_non_local_pattern() -> None:
    """_collect_used_string_defs marks wildcard-matching strings as used when pattern is not local (line 766).

    StringWildcard with a '$'-prefixed pattern that is not in local scope triggers
    _mark_used_string_ref, which expands the wildcard against the defined strings set.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a", "$ab", "$c"}

    used: set[str] = set()
    wildcard = StringWildcard(pattern="$a*")
    detector._collect_used_string_defs(wildcard, defined, set(), used)

    assert "$a" in used
    assert "$ab" in used
    assert "$c" not in used


def test_collect_used_string_defs_exits_cleanly_for_non_ast_non_specific_node() -> None:
    """_collect_used_string_defs exits without error when node is not an ASTNode (branch 813->exit).

    When node is a plain Python object (not an ASTNode and not a specific expression type)
    the function falls through the isinstance check at line 813 and returns without acting.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    used: set[str] = set()
    detector._collect_used_string_defs("not_a_node", {"$a"}, set(), used)

    assert used == set()
    assert result.errors == []


def test_check_invalid_string_sets_exits_cleanly_for_non_ast_node() -> None:
    """_check_invalid_string_sets exits without error when node is not an ASTNode (branch 717->exit).

    A plain Python string is neither ForOfExpression/OfExpression nor an ASTNode;
    the function exits without recording any errors.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    detector._check_invalid_string_sets("not_a_node", {"$a"}, "test_rule")

    assert result.errors == []


def test_collect_string_set_refs_exits_cleanly_for_unrecognized_type() -> None:
    """_collect_string_set_refs exits without error when string_set is none of the known types (branch 698->exit).

    An integer is not a str, list/tuple/set/frozenset, ParenthesesExpression, StringIdentifier,
    StringWildcard, StringLiteral, Identifier, or SetExpression.  The elif chain at line 698
    evaluates to False and the function exits without doing anything.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    refs: set[str] = set()
    detector._collect_string_set_refs(42, refs)

    assert refs == set()
    assert result.errors == []


def test_mark_used_string_set_exits_cleanly_for_unrecognized_type() -> None:
    """_mark_used_string_set exits without error when string_set is none of the known types (branch 877->exit).

    An integer is not a str, list/tuple/set/frozenset, ParenthesesExpression, StringIdentifier,
    StringWildcard, StringLiteral, Identifier, or SetExpression.  The elif chain at line 877
    evaluates to False and the function exits without doing anything.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    used: set[str] = set()
    detector._mark_used_string_set(42, defined, set(), used)

    assert used == set()
    assert result.errors == []


def test_mark_used_string_ref_returns_early_for_non_string_ref() -> None:
    """_mark_used_string_ref returns without acting when ref is not a string (line 886).

    _normalize_ref returns None for non-str input; the None-check at line 885 is True
    and line 886 (return) is executed, leaving 'used' unchanged.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$a"}

    used: set[str] = set()
    detector._mark_used_string_ref(cast(Any, False), defined, set(), used)

    assert used == set()
    assert any(error.message == "String reference must be a string" for error in result.errors)


def test_mark_used_string_ref_updates_used_for_global_wildcard_expanded() -> None:
    """_mark_used_string_ref correctly expands '$*' to all defined strings (line 887-889).

    All strings in 'defined' are added to 'used' and the function returns at line 889.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)
    defined = {"$x", "$y", "$z"}

    used: set[str] = set()
    detector._mark_used_string_ref("$*", defined, set(), used)

    assert used == {"$x", "$y", "$z"}


def test_check_rule_with_string_wildcard_condition_marks_matching_strings_used() -> None:
    """check_rule via StringWildcard in condition exercises _collect_used_string_defs line 766.

    The rule's condition uses a StringWildcard; the matching defined strings are marked used
    and no unreferenced-string error is produced for them.
    """
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    rule = Rule(
        name="wildcard_condition",
        strings=[
            PlainString(identifier="$api_call", value="CreateFile"),
            PlainString(identifier="$api_open", value="OpenFile"),
            PlainString(identifier="$unrelated", value="something"),
        ],
        condition=BinaryExpression(
            OfExpression("any", StringWildcard(pattern="$api*")),
            "and",
            StringIdentifier("$unrelated"),
        ),
    )

    detector.check_rule(rule)

    messages = [error.message for error in result.errors]
    assert not any("Unreferenced string '$api_call'" in m for m in messages)
    assert not any("Unreferenced string '$api_open'" in m for m in messages)
    assert not any("Unreferenced string '$unrelated'" in m for m in messages)
