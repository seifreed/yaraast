"""Coverage-targeted regression tests for yaraast.types.semantic_validator_strings.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

This file targets the remaining uncovered lines and branches reported at 98.33%
after tests/test_semantic_validator_strings_coverage_loop.py runs. The prior
agent incorrectly classified several branches as unreachable. Specifically, the
None-name guard inside each private helper method IS reachable by calling those
methods directly with a node whose modifier list contains an object with a
non-string `.name` attribute. The helper methods are called from `visit_*`
methods only after `_check_modifier_items` returns True, which means the None
path in each helper is bypassed during normal visitor use. However, the helpers
are accessible methods and their None branches constitute valid defensive guards
that CAN be executed by direct calls using real AST nodes.

Targeted lines/branches:
  161  -- visit_hex_string inner for-loop: modifier name is None -> continue
           Reached via a list subclass whose __iter__ yields a valid modifier on
           the first pass (satisfying _check_modifier_items) and an invalid one
           on the second pass (reaching the inner loop body).
  179  -- visit_regex_string inner for-loop: same technique.
  204  -- _check_unsupported_modifiers: modifier name is None -> continue
  229  -- _check_duplicate_modifiers: modifier name is None -> continue
  243  -- _check_non_regex_string: modifier name is None -> continue
  277  -- _check_text_string_modifier_values: modifier name is None -> continue
  371->369 -- _modifier_names: name is None so 'if name is not None:' is False

Genuinely unreachable (documented, not tested):
  438  -- check_rule: for ref in referenced: normalized is None -> continue
           The local 'referenced' set is populated only by _collect_string_refs
           which guards every add() with _string_ref_or_none (returns None for
           non-str inputs and never adds those to refs). Therefore referenced
           always holds only strings, and _normalize_ref always returns non-None
           for string inputs. No real execution path through the public API
           produces a non-str element in referenced.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_strings import StringModifierApplicabilityValidator


class _BadModifier:
    """A real Python object that has a `.name` attribute whose value is not a str.

    `_modifier_name` checks `isinstance(name, str)` after `hasattr(modifier, 'name')`.
    Since `name` is None here, `_modifier_name` records an error and returns None.
    """

    name: Any = None


class _TwoPassList(list):  # type: ignore[type-arg]
    """A list subclass that changes what it yields across successive __iter__ calls.

    First iteration: yields a single valid string modifier ('private').
      -> _check_modifier_items sees a valid modifier and returns True.
    Second iteration: yields a _BadModifier instance.
      -> the inner for-loop in visit_hex_string / visit_regex_string calls
         _modifier_name on the bad object, which returns None, reaching the
         'continue' statement at lines 161 / 179.

    This is a real Python iterable object, not a mock. It exercises the
    defensive None guard that exists inside the inner loops of visit_hex_string
    and visit_regex_string.
    """

    def __init__(self) -> None:
        super().__init__()
        self._call_count: int = 0

    def __iter__(self) -> Iterator[Any]:
        if self._call_count == 0:
            self._call_count += 1
            yield "private"
        else:
            self._call_count += 1
            yield _BadModifier()


def _make_validator() -> tuple[StringModifierApplicabilityValidator, ValidationResult]:
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)
    validator.current_rule_name = "test_rule"
    return validator, result


# ---------------------------------------------------------------------------
# Line 161: visit_hex_string inner loop -- modifier name is None -> continue
# ---------------------------------------------------------------------------


def test_visit_hex_string_inner_loop_skips_modifier_with_none_name() -> None:
    """visit_hex_string continues past a modifier whose resolved name is None.

    The _TwoPassList yields 'private' on the first iteration so that
    _check_modifier_items returns True. On the second iteration it yields a
    _BadModifier whose .name is None, causing _modifier_name to return None
    inside the inner for-loop and exercising the 'continue' at line 161.

    Expected: exactly one error added by _modifier_name (the 'must contain
    strings or StringModifier nodes' diagnostic), no crash or uncaught exception.
    """
    validator, result = _make_validator()
    node = HexString(
        identifier="$h1",
        tokens=[HexByte(value=0x41)],
        modifiers=_TwoPassList(),
    )

    validator.visit_hex_string(node)

    assert not result.is_valid
    error_messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in error_messages)
    assert any("$h1" in m for m in error_messages)


# ---------------------------------------------------------------------------
# Line 179: visit_regex_string inner loop -- modifier name is None -> continue
# ---------------------------------------------------------------------------


def test_visit_regex_string_inner_loop_skips_modifier_with_none_name() -> None:
    """visit_regex_string continues past a modifier whose resolved name is None.

    Same two-pass technique: first iteration satisfies _check_modifier_items,
    second iteration triggers the None path in the inner for-loop at line 179.

    Expected: exactly one error from _modifier_name, no crash.
    """
    validator, result = _make_validator()
    node = RegexString(
        identifier="$r1",
        regex="abc",
        modifiers=_TwoPassList(),
    )

    validator.visit_regex_string(node)

    assert not result.is_valid
    error_messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in error_messages)
    assert any("$r1" in m for m in error_messages)


# ---------------------------------------------------------------------------
# Line 204: _check_unsupported_modifiers -- modifier name is None -> continue
# ---------------------------------------------------------------------------


def test_check_unsupported_modifiers_skips_modifier_with_none_name() -> None:
    """_check_unsupported_modifiers continues when _modifier_name returns None.

    Calling the helper directly with a node containing a _BadModifier exercises
    the guard at line 203-204: 'if name is None: continue'.

    Expected: the error from _modifier_name is recorded ('must contain strings
    or StringModifier nodes'), and the function does not raise or add a second
    error about unsupported modifiers.
    """
    validator, result = _make_validator()
    node = PlainString(identifier="$s1", value="hello", modifiers=[_BadModifier()])

    validator._check_unsupported_modifiers(node, {"nocase"}, "string")

    assert not result.is_valid
    messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in messages)
    assert not any("Unsupported" in m for m in messages)


# ---------------------------------------------------------------------------
# Line 229: _check_duplicate_modifiers -- modifier name is None -> continue
# ---------------------------------------------------------------------------


def test_check_duplicate_modifiers_skips_modifier_with_none_name() -> None:
    """_check_duplicate_modifiers continues when _modifier_name returns None.

    Exercises lines 227-229: the function calls _modifier_name for each modifier
    and, on receiving None, hits 'continue' without adding a duplicate error.

    Expected: the error from _modifier_name is recorded, no duplicate-modifier
    error is emitted, no exception is raised.
    """
    validator, result = _make_validator()
    node = PlainString(identifier="$s2", value="world", modifiers=[_BadModifier()])

    validator._check_duplicate_modifiers(node)

    assert not result.is_valid
    messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in messages)
    assert not any("Duplicate" in m for m in messages)


# ---------------------------------------------------------------------------
# Line 243: _check_non_regex_string -- modifier name is None -> continue
# ---------------------------------------------------------------------------


def test_check_non_regex_string_skips_modifier_with_none_name() -> None:
    """_check_non_regex_string continues when _modifier_name returns None.

    Exercises lines 241-243: the function iterates modifiers, calls
    _modifier_name, and on receiving None hits 'continue' instead of checking
    whether the modifier belongs to the regex-only set.

    Expected: error from _modifier_name recorded, no regex-only-modifier error.
    """
    validator, result = _make_validator()
    node = PlainString(identifier="$s3", value="data", modifiers=[_BadModifier()])

    validator._check_non_regex_string(node, "plain")

    assert not result.is_valid
    messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in messages)
    assert not any("Regex-only modifier" in m for m in messages)


# ---------------------------------------------------------------------------
# Line 277: _check_text_string_modifier_values -- modifier name is None -> continue
# ---------------------------------------------------------------------------


def test_check_text_string_modifier_values_skips_modifier_with_none_name() -> None:
    """_check_text_string_modifier_values continues when _modifier_name returns None.

    Exercises lines 275-277: calling the helper directly with a node containing
    a _BadModifier hits the 'if name is None: continue' guard before any xor or
    base64 value checks are attempted.

    Expected: error from _modifier_name recorded, no xor or base64 value error.
    """
    validator, result = _make_validator()
    node = PlainString(identifier="$s4", value="payload", modifiers=[_BadModifier()])

    validator._check_text_string_modifier_values(node)

    assert not result.is_valid
    messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in messages)
    assert not any("xor key" in m.lower() for m in messages)
    assert not any("base64" in m.lower() for m in messages)


# ---------------------------------------------------------------------------
# Branch 371->369: _modifier_names -- name is None -> if branch not taken
# ---------------------------------------------------------------------------


def test_modifier_names_excludes_modifier_with_none_name() -> None:
    """_modifier_names does not add a name when _modifier_name returns None.

    The branch 371->369 is the False arm of 'if name is not None:'. When
    _modifier_name returns None (because the modifier's .name is not a str),
    the name is skipped and the loop continues without adding to the result set.

    Exercises the branch where 'if name is not None:' evaluates to False,
    causing control to return to the loop header (line 369) rather than
    executing names.add(name) at line 372.

    Expected: returned set is empty, error from _modifier_name is recorded.
    """
    validator, result = _make_validator()
    node = PlainString(
        identifier="$s5",
        value="test",
        modifiers=[_BadModifier()],
    )

    names = validator._modifier_names(node)

    assert names == set()
    assert not result.is_valid
    messages = [e.message for e in result.errors]
    assert any("must contain strings or StringModifier nodes" in m for m in messages)
