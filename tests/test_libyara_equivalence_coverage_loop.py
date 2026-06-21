# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage regression tests for yaraast.libyara.equivalence.

Targets the lines not reached by prior test files:
  177-184  re-parse failure branch in test_round_trip
  189      early return when _generate_regenerated_code returns None
  296      _compare_ast modifier-differ branch
  309      _compare_ast string-identifier-differ branch
  313      _compare_ast string-type-differ branch
  321      _compare_ast tag-differ branch

All tests use real ASTs produced by the production Parser, real CodeGenerator
output, and real EquivalenceTester internals.  No mocking frameworks are used.
Lines 177-184 and 189 are defensive handlers against hypothetical future
codegen/parser divergence; they are reached here via real Python subclasses
that delegate to the production implementations but inject a controlled failure
at a specific call count.
"""

from __future__ import annotations

from yaraast.codegen.generator import CodeGenerator
from yaraast.libyara.equivalence import EquivalenceResult, EquivalenceTester
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source

# ---------------------------------------------------------------------------
# Real call-counting subclasses (no mocks, real delegation to production code)
# ---------------------------------------------------------------------------


class _ReparseFailingParser(Parser):
    """Real Parser subclass that raises on its first parse() call.

    This exercises the re-parse error handler at lines 177-184.
    EquivalenceTester.test_round_trip() calls self.parser.parse(original_code)
    exactly once (step 2).  By raising on the first call to this instance,
    we reach the except branch without modifying the production source.
    All other Parser behaviour remains fully real.
    """

    def __init__(self) -> None:
        super().__init__()
        self._parse_calls: int = 0

    def parse(self, text: str | None = None) -> object:  # type: ignore[override]
        self._parse_calls += 1
        raise ValueError(f"Controlled re-parse failure (call {self._parse_calls})")


class _RegenFailingCodeGenerator(CodeGenerator):
    """Real CodeGenerator subclass that succeeds on the first generate() call
    and raises on the second.

    This exercises the early-return path at line 189.
    EquivalenceTester.test_round_trip() calls self.codegen.generate() twice:
      - Call 1 (step 1): generate code from the original AST  → must succeed
      - Call 2 (step 3): generate code from the re-parsed AST → must fail
    All other CodeGenerator behaviour remains fully real.
    """

    def __init__(self) -> None:
        super().__init__()
        self._generate_calls: int = 0

    def generate(self, node: object) -> str:
        self._generate_calls += 1
        if self._generate_calls >= 2:
            raise ValueError(f"Controlled re-generation failure (call {self._generate_calls})")
        return super().generate(node)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Helper: build a tester without the libyara backend
# ---------------------------------------------------------------------------


def _tester(
    *,
    parser: Parser | None = None,
    codegen: CodeGenerator | None = None,
) -> EquivalenceTester:
    """Return an EquivalenceTester with real parser and codegen.

    Skips LibyaraCompiler and LibyaraScanner construction so the tests run
    on machines where yara-python is not installed.
    """
    tester: EquivalenceTester = object.__new__(EquivalenceTester)
    tester.parser = parser if parser is not None else Parser()
    tester.codegen = codegen if codegen is not None else CodeGenerator()
    return tester


# ---------------------------------------------------------------------------
# Lines 177-184: re-parse failure branch in test_round_trip
# ---------------------------------------------------------------------------


def test_round_trip_reparse_failure_sets_all_failure_flags() -> None:
    """Lines 177-184: re-parsing the generated code raises → all flags go False.

    Arrange: use a real _ReparseFailingParser that raises on its first call.
    The original AST is produced by the production parse_yara_source helper
    (a different parser instance, not the injected one).
    Act: call test_round_trip; step 2 raises.
    Assert: result.equivalent is False, code_equivalent is False,
    original_compiles is False, regenerated_compiles is False, and the
    ast_differences list records the failure message.
    """
    original_ast = parse_yara_source("rule r { condition: true }")
    tester = _tester(parser=_ReparseFailingParser())

    result = tester.test_round_trip(original_ast)

    assert result.equivalent is False
    assert result.ast_equivalent is False
    assert result.code_equivalent is False
    assert result.original_compiles is False
    assert result.regenerated_compiles is False
    assert len(result.ast_differences) == 1
    assert "Re-parsing failed" in result.ast_differences[0]
    assert "Controlled re-parse failure" in result.ast_differences[0]


def test_round_trip_reparse_failure_does_not_set_original_code_to_none() -> None:
    """Lines 177-184: step 1 (codegen) succeeds before step 2 fails.

    The result.original_code field must be set because step 1 completed
    before the re-parse failure occurred.
    """
    original_ast = parse_yara_source("rule r { condition: true }")
    tester = _tester(parser=_ReparseFailingParser())

    result = tester.test_round_trip(original_ast)

    # Step 1 produced a code string; it must be stored even though step 2 failed.
    assert result.original_code is not None
    assert "rule r" in result.original_code
    # Step 3 was never reached so regenerated_code stays None.
    assert result.regenerated_code is None


# ---------------------------------------------------------------------------
# Line 189: early return when _generate_regenerated_code returns None
# ---------------------------------------------------------------------------


def test_round_trip_regen_failure_returns_early_at_line_189() -> None:
    """Line 189: _generate_regenerated_code returns None → test_round_trip returns early.

    The _RegenFailingCodeGenerator succeeds on call 1 (step 1, generate original
    code) and raises on call 2 (step 3, generate from re-parsed AST).
    Steps 4-7 must NOT be reached, so compilation_errors stays empty and
    scan_equivalent remains True (the default).
    """
    original_ast = parse_yara_source("rule r { condition: true }")
    tester = _tester(codegen=_RegenFailingCodeGenerator())

    result = tester.test_round_trip(original_ast)

    assert result.equivalent is False
    assert result.code_equivalent is False
    assert result.original_compiles is False
    assert result.regenerated_compiles is False
    # regenerated_code was never stored because generate() raised
    assert result.regenerated_code is None
    # Compilation was never attempted (early return)
    assert result.compilation_errors == []
    assert result.scan_equivalent is True  # default; steps 6-7 never ran
    assert any("Re-generation failed" in d for d in result.ast_differences)
    assert any("Controlled re-generation failure" in d for d in result.ast_differences)


def test_round_trip_regen_failure_original_code_was_stored_before_failure() -> None:
    """Line 189 precondition: step 1 must complete before step 3 fails.

    original_code is stored after step 1 succeeds.  Even when step 3 fails,
    the value must remain in the result.
    """
    original_ast = parse_yara_source('rule r { strings: $a = "abc" condition: $a }')
    tester = _tester(codegen=_RegenFailingCodeGenerator())

    result = tester.test_round_trip(original_ast)

    assert result.original_code is not None
    assert "rule r" in result.original_code
    assert "$a" in result.original_code


# ---------------------------------------------------------------------------
# Line 296: _compare_ast modifier-differ branch
# ---------------------------------------------------------------------------


def test_compare_ast_detects_modifier_difference_private_vs_global() -> None:
    """Line 296: modifiers differ between two real parsed ASTs.

    Uses the production Parser to build two one-rule files where the rule
    has different modifiers, then calls _compare_ast directly.
    """
    parser = Parser()
    ast_private = parser.parse("private rule r { condition: true }")
    ast_global = parser.parse("global rule r { condition: true }")
    tester = _tester()

    differences = tester._compare_ast(ast_private, ast_global)

    modifier_diffs = [d for d in differences if "modifiers differ" in d]
    assert modifier_diffs, f"Expected a modifier-differ message; got: {differences}"
    assert "private" in modifier_diffs[0] or "global" in modifier_diffs[0]


def test_compare_ast_no_modifier_difference_for_identical_modifiers() -> None:
    """Line 296 negative: equal modifiers produce no modifier-differ message.

    Validates the branch is guarded by the inequality condition and does not
    fire when both ASTs carry the same modifier.
    """
    parser = Parser()
    ast1 = parser.parse("private rule r { condition: true }")
    ast2 = parser.parse("private rule r { condition: true }")
    tester = _tester()

    differences = tester._compare_ast(ast1, ast2)

    assert not any("modifiers differ" in d for d in differences)


# ---------------------------------------------------------------------------
# Line 309: _compare_ast string-identifier-differ branch
# ---------------------------------------------------------------------------


def test_compare_ast_detects_string_identifier_difference() -> None:
    """Line 309: string identifier differs between matching string positions.

    Both rules have exactly one string but with different identifiers ($a vs $b).
    The count-comparison guard passes, so the per-string loop runs and hits the
    identifier-differ branch.
    """
    parser = Parser()
    ast_a = parser.parse('rule r { strings: $a = "x" condition: $a }')
    ast_b = parser.parse('rule r { strings: $b = "x" condition: $b }')
    tester = _tester()

    differences = tester._compare_ast(ast_a, ast_b)

    id_diffs = [d for d in differences if "identifier differs" in d]
    assert id_diffs, f"Expected an identifier-differ message; got: {differences}"
    assert "$a" in id_diffs[0] and "$b" in id_diffs[0]


def test_compare_ast_no_identifier_difference_for_matching_identifiers() -> None:
    """Line 309 negative: identical identifiers do not trigger the differ branch."""
    parser = Parser()
    ast1 = parser.parse('rule r { strings: $a = "x" condition: $a }')
    ast2 = parser.parse('rule r { strings: $a = "y" condition: $a }')
    tester = _tester()

    differences = tester._compare_ast(ast1, ast2)

    assert not any("identifier differs" in d for d in differences)


# ---------------------------------------------------------------------------
# Line 313: _compare_ast string-type-differ branch
# ---------------------------------------------------------------------------


def test_compare_ast_detects_string_type_difference_plain_vs_regex() -> None:
    """Line 313: string type differs (PlainString vs RegexString), same identifier.

    Both rules use the same identifier $a but assign a plain string in one and
    a regex in the other.  The type-differ branch at line 313 must fire.
    """
    parser = Parser()
    ast_plain = parser.parse('rule r { strings: $a = "x" condition: $a }')
    ast_regex = parser.parse("rule r { strings: $a = /x/ condition: $a }")
    tester = _tester()

    differences = tester._compare_ast(ast_plain, ast_regex)

    type_diffs = [d for d in differences if "type differs" in d]
    assert type_diffs, f"Expected a type-differ message; got: {differences}"
    assert "PlainString" in type_diffs[0] and "RegexString" in type_diffs[0]


def test_compare_ast_detects_string_type_difference_plain_vs_hex() -> None:
    """Line 313 variant: PlainString vs HexString triggers the type-differ branch."""
    parser = Parser()
    ast_plain = parser.parse('rule r { strings: $a = "x" condition: $a }')
    ast_hex = parser.parse("rule r { strings: $a = { 78 } condition: $a }")
    tester = _tester()

    differences = tester._compare_ast(ast_plain, ast_hex)

    type_diffs = [d for d in differences if "type differs" in d]
    assert type_diffs, f"Expected a type-differ message; got: {differences}"
    assert "PlainString" in type_diffs[0]


def test_compare_ast_no_type_difference_for_same_string_type() -> None:
    """Line 313 negative: same string type in both ASTs does not trigger the branch."""
    parser = Parser()
    ast1 = parser.parse('rule r { strings: $a = "x" condition: $a }')
    ast2 = parser.parse('rule r { strings: $a = "y" condition: $a }')
    tester = _tester()

    differences = tester._compare_ast(ast1, ast2)

    assert not any("type differs" in d for d in differences)


# ---------------------------------------------------------------------------
# Line 321: _compare_ast tag-differ branch
# ---------------------------------------------------------------------------


def test_compare_ast_detects_tag_difference() -> None:
    """Line 321: tags differ between the same rule in two real ASTs.

    Produces two rules with the same name but different tag sets and verifies
    that the tag-differ branch records the discrepancy.
    """
    parser = Parser()
    ast_tag1 = parser.parse("rule r : tag1 { condition: true }")
    ast_tag2 = parser.parse("rule r : tag2 { condition: true }")
    tester = _tester()

    differences = tester._compare_ast(ast_tag1, ast_tag2)

    tag_diffs = [d for d in differences if "tags differ" in d]
    assert tag_diffs, f"Expected a tags-differ message; got: {differences}"
    assert "tag1" in tag_diffs[0] and "tag2" in tag_diffs[0]


def test_compare_ast_detects_missing_tag_in_one_ast() -> None:
    """Line 321 variant: one rule has a tag and the other does not."""
    parser = Parser()
    ast_with_tag = parser.parse("rule r : mytag { condition: true }")
    ast_no_tag = parser.parse("rule r { condition: true }")
    tester = _tester()

    differences = tester._compare_ast(ast_with_tag, ast_no_tag)

    tag_diffs = [d for d in differences if "tags differ" in d]
    assert tag_diffs, f"Expected a tags-differ message; got: {differences}"
    assert "mytag" in tag_diffs[0]


def test_compare_ast_no_tag_difference_for_same_tags() -> None:
    """Line 321 negative: identical tags do not trigger the differ branch."""
    parser = Parser()
    ast1 = parser.parse("rule r : tag1 { condition: true }")
    ast2 = parser.parse("rule r : tag1 { condition: true }")
    tester = _tester()

    differences = tester._compare_ast(ast1, ast2)

    assert not any("tags differ" in d for d in differences)


# ---------------------------------------------------------------------------
# Combined _compare_ast scenario: multiple differs in one call
# ---------------------------------------------------------------------------


def test_compare_ast_reports_multiple_difference_categories_together() -> None:
    """Lines 296, 309, 313, 321: all four differ branches fire in a single call.

    One rule is private with tag 'a' and a plain-string $a.
    The other is global with tag 'b' and a regex $b using the same slot.
    All four difference categories must appear.
    """
    parser = Parser()
    ast1 = parser.parse('private rule r : ta { strings: $a = "x" condition: $a }')
    ast2 = parser.parse("global rule r : tb { strings: $b = /x/ condition: $b }")
    tester = _tester()

    differences = tester._compare_ast(ast1, ast2)

    assert any("modifiers differ" in d for d in differences)
    assert any("identifier differs" in d for d in differences)
    assert any("type differs" in d for d in differences)
    assert any("tags differ" in d for d in differences)


# ---------------------------------------------------------------------------
# EquivalenceResult default field sanity (ensures dataclass is exercised)
# ---------------------------------------------------------------------------


def test_equivalence_result_defaults_are_correct() -> None:
    """Smoke test: EquivalenceResult initialises with expected defaults."""
    result = EquivalenceResult(equivalent=True)

    assert result.equivalent is True
    assert result.ast_equivalent is True
    assert result.ast_differences == []
    assert result.code_equivalent is True
    assert result.original_code is None
    assert result.regenerated_code is None
    assert result.original_compiles is True
    assert result.regenerated_compiles is True
    assert result.compilation_errors == []
    assert result.scan_equivalent is True
    assert result.scan_differences == []
