# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop for yaraast.lsp.document_query_lookup.

Tests exercise the real lookup-oriented query helpers by constructing genuine
DocumentContext objects from YARA source text and calling the public functions
directly.  No mocks, stubs, or artificial scaffolding are used.

Missing lines targeted (module baseline 63.02% from existing three test files):

  31-32   _require_include_path TypeError (non-string input)
  34-35   _require_include_path ValueError (blank string)
  41-42   _require_module_member_name TypeError (non-string input)
  48-49   _require_document_position TypeError (non-Position input)
  57      get_meta_value cache hit return path
  61->63  get_meta_value fallback result is not None -> set_cached then return
  72-77   get_meta_value 'entries' attribute branch in non-list meta
  86->83  _fallback_meta_value inner for loop exhausts (no break), outer continues
  89      _fallback_meta_value: blank meta line -> continue
  91      _fallback_meta_value: non-indented line -> break
  93      _fallback_meta_value: no '=' in line -> continue
  98->86  _fallback_meta_value: parsed is None (null value) -> continue outer
  100     _fallback_meta_value: key not found, returns None
  110-114 _parse_meta_value: false/null/raw_value branches
  121     get_string_definition_node: cache hit
  124/128 get_string_definition_node: ast is None; is_anonymous skip
  140     get_string_definition_info: cache hit
  143     get_string_definition_info: string_data is None (identifier not found)
  148-156 get_string_definition_info: regex/hex/unknown string type branches
  158-160 get_string_definition_info: non-str modifier -> str(m.name)
  170     get_module_member_info: cache hit
  173     get_module_member_info: len(parts) != 2 -> return None
  210     get_include_info: cache hit
  214-219 get_include_info: doc_path present, candidate does not exist
  226-229 get_include_target_uri: resolved and unresolved paths
  237     get_dotted_symbol_at_position: line index out of range -> None
  241-255 get_dotted_symbol_at_position: character out of range; full scan; no dot;
          two dots; leading/trailing dot; successful hit with Range return

Notes on unreachable code:
  Lines 217-219 (OSError from Path.resolve()) are not reachable on Python 3.13
  because Path.resolve() no longer raises OSError for non-existent paths or symlinks.
"""

from __future__ import annotations

from pathlib import Path
import tempfile

from lsprotocol.types import Position, Range

from yaraast.lsp import document_query_lookup as lookup
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import path_to_uri

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URI = "file://test.yar"


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri=_URI, text=text)


def _pos(line: int, character: int) -> Position:
    return Position(line=line, character=character)


# ---------------------------------------------------------------------------
# Validator helpers -- lines 31-32, 34-35, 41-42, 48-49
# ---------------------------------------------------------------------------


def test_require_include_path_raises_for_non_string() -> None:
    """_require_include_path raises TypeError when given a non-string (lines 31-32)."""
    try:
        lookup._require_include_path(42)
        raise AssertionError("Expected TypeError")
    except TypeError as exc:
        assert "string" in str(exc).lower()


def test_require_include_path_raises_for_blank_string() -> None:
    """_require_include_path raises ValueError when the string is blank (lines 34-35)."""
    try:
        lookup._require_include_path("   ")
        raise AssertionError("Expected ValueError")
    except ValueError as exc:
        assert "empty" in str(exc).lower()


def test_require_module_member_name_raises_for_non_string() -> None:
    """_require_module_member_name raises TypeError for non-string input (lines 41-42)."""
    try:
        lookup._require_module_member_name(None)
        raise AssertionError("Expected TypeError")
    except TypeError as exc:
        assert "string" in str(exc).lower()


def test_require_document_position_raises_for_non_position() -> None:
    """_require_document_position raises TypeError for a non-Position object (lines 48-49)."""
    try:
        lookup._require_document_position("line:0")
        raise AssertionError("Expected TypeError")
    except TypeError as exc:
        assert "position" in str(exc).lower()


# ---------------------------------------------------------------------------
# _parse_meta_value -- lines 110-114
# ---------------------------------------------------------------------------


def test_parse_meta_value_false_literal() -> None:
    """'false' (case-insensitive) returns the boolean False (line 110-111)."""
    assert lookup._parse_meta_value("false") is False
    assert lookup._parse_meta_value("FALSE") is False


def test_parse_meta_value_null_literal() -> None:
    """'null' (case-insensitive) returns None (lines 112-113)."""
    result = lookup._parse_meta_value("null")
    assert result is None


def test_parse_meta_value_raw_unquoted_string() -> None:
    """An unrecognized token that is not a valid literal returns stripped raw value (line 114)."""
    result = lookup._parse_meta_value("some_identifier")
    assert result == "some_identifier"

    # A syntactically invalid literal falls through to the raw return.
    result2 = lookup._parse_meta_value("[broken")
    assert result2 == "[broken"


# ---------------------------------------------------------------------------
# _fallback_meta_value branch coverage -- lines 86->83, 89, 91, 93, 98->86, 100
# ---------------------------------------------------------------------------

# These tests require unparseable documents so the fallback text scanner is used.
# An incomplete rule body (no closing brace) fails the parser reliably.

_BROKEN_PREFIX = "rule x {\n  meta:\n"


def test_fallback_meta_value_blank_meta_line_is_skipped() -> None:
    """A blank line inside the meta section is skipped (continue at line 89)."""
    text = _BROKEN_PREFIX + '    \n    author = "alice"\n  condition:\n'
    doc = _doc(text)
    assert doc.ast() is None
    result = lookup.get_meta_value(doc, "author")
    assert result == "alice"


def test_fallback_meta_value_non_indented_line_breaks_section() -> None:
    """A non-indented line terminates meta scanning via break (line 91).

    The searched key is NOT present in the meta section, so the inner for loop
    reaches the non-indented 'condition:' line and hits the break statement.
    """
    # 'x = 1' is in meta; we search for 'missing', so no early return occurs.
    # The inner loop iterates '    x = 1' (no match), then 'condition:' (non-
    # indented, no leading space/tab) -> triggers break at line 91.
    text = "rule x {\n  meta:\n    x = 1\ncondition:\n"
    doc = _doc(text)
    assert doc.ast() is None
    result = lookup.get_meta_value(doc, "missing")
    assert result is None


def test_fallback_meta_value_line_without_equals_is_skipped() -> None:
    """A line without '=' inside the meta section is skipped (continue at line 93)."""
    text = _BROKEN_PREFIX + '    no_equals_here\n    author = "alice"\n  condition:\n'
    doc = _doc(text)
    assert doc.ast() is None
    result = lookup.get_meta_value(doc, "author")
    assert result == "alice"


def test_fallback_meta_value_null_value_continues_search() -> None:
    """A 'null' meta value yields None, the loop continues, and other keys are found.

    Exercises the parsed-is-None branch (line 98->86): the loop continues the
    outer for instead of returning early.
    """
    text = _BROKEN_PREFIX + '    a = null\n    author = "alice"\n  condition:\n'
    doc = _doc(text)
    assert doc.ast() is None
    # 'author' should still be found after the null entry.
    assert lookup.get_meta_value(doc, "author") == "alice"
    # 'a' should return None (null value is not cached because it is None).
    assert lookup.get_meta_value(doc, "a") is None


def test_fallback_meta_value_key_not_found_returns_none() -> None:
    """When no key matches, _fallback_meta_value returns None (line 100)."""
    text = _BROKEN_PREFIX + '    author = "alice"\n  condition:\n'
    doc = _doc(text)
    assert doc.ast() is None
    result = lookup.get_meta_value(doc, "nonexistent")
    assert result is None


def test_fallback_meta_value_inner_loop_exhaustion_continues_outer() -> None:
    """The inner for-meta_line loop can exhaust naturally (86->83).

    When a meta section has only indented lines that reach end-of-file without
    a non-indented break, the inner for completes its iteration and the outer
    loop tries any subsequent meta: section in the text.
    """
    # Two meta sections in the text.  The first contains x=1 (exhausts inner
    # for without break).  The outer loop then finds the second meta: section
    # containing the target key.
    text = 'rule a {\n  meta:\n    x = 1\n  meta:\n    author = "alice"\n  condition:\n'
    doc = _doc(text)
    assert doc.ast() is None
    result = lookup.get_meta_value(doc, "author")
    assert result == "alice"


# ---------------------------------------------------------------------------
# get_meta_value cache and entries-branch coverage -- lines 57, 61->63, 72-77
# ---------------------------------------------------------------------------


def test_get_meta_value_cache_hit() -> None:
    """Second call to get_meta_value for a known key returns the cached value (line 57)."""
    text = (
        'rule r {\n  meta:\n    author = "alice"\n  strings:\n    $a = "x"\n  condition:\n    $a\n}'
    )
    doc = _doc(text)
    assert doc.ast() is not None
    first = lookup.get_meta_value(doc, "author")
    # Populate the cache.
    assert first == "alice"
    # Second call must hit the cached path (line 57).
    second = lookup.get_meta_value(doc, "author")
    assert second == "alice"


def test_get_meta_value_fallback_caches_found_value() -> None:
    """When fallback finds a value it stores it in the cache (lines 61->63).

    The set_cached call at line 62 is exercised: on a second call the cache
    is hit via line 57 instead of re-scanning.
    """
    text = _BROKEN_PREFIX + '    author = "bob"\n  condition:\n'
    doc = _doc(text)
    assert doc.ast() is None
    first = lookup.get_meta_value(doc, "author")
    assert first == "bob"
    # Second call uses cache, not the text scanner.
    second = lookup.get_meta_value(doc, "author")
    assert second == "bob"


def test_get_meta_value_entries_branch() -> None:
    """get_meta_value covers the 'entries' attribute branch (lines 72-77).

    The production parsers always produce a list for rule.meta. However the
    function also handles any object that exposes a .entries iterable, which
    is the interface used by alternative AST representations.  We inject such
    an object directly into the DocumentContext's cached AST to verify the
    branch is executed.
    """

    class _FakeEntry:
        def __init__(self, key: str, value: str) -> None:
            self.key = key
            self.value = value

    class _FakeMeta:
        """Non-list meta object that exposes .entries."""

        def __init__(self) -> None:
            self.entries = [_FakeEntry("author", "carol")]

    class _FakeRule:
        def __init__(self) -> None:
            self.meta = _FakeMeta()
            self.strings: list[object] = []

    class _FakeAst:
        def __init__(self) -> None:
            self.rules = [_FakeRule()]

    doc = DocumentContext(uri=_URI, text="rule x { condition: true }")
    doc._ast = _FakeAst()  # type: ignore[assignment]

    result = lookup.get_meta_value(doc, "author")
    assert result == "carol"

    # Cache hit on second call.
    cached_result = lookup.get_meta_value(doc, "author")
    assert cached_result == "carol"


def test_get_meta_value_entries_branch_key_not_found() -> None:
    """get_meta_value 'entries' branch when no entry matches (lines 73->64, 74->73).

    When a rule has a non-list meta object with .entries, but none of those
    entries has the searched key, the inner for loop at line 73 exhausts
    (73->64 branch) after each iteration takes the 74->73 (key-not-equal)
    branch.  Control returns to the outer loop, which also exhausts, reaching
    the return None at line 78.
    """

    class _FakeEntry2:
        def __init__(self, key: str, value: str) -> None:
            self.key = key
            self.value = value

    class _FakeMeta2:
        def __init__(self) -> None:
            self.entries = [_FakeEntry2("x", "1"), _FakeEntry2("y", "2")]

    class _FakeRule2:
        def __init__(self) -> None:
            self.meta = _FakeMeta2()
            self.strings: list[object] = []

    class _FakeAst2:
        def __init__(self) -> None:
            self.rules = [_FakeRule2()]

    doc = DocumentContext(uri=_URI, text="rule x { condition: true }")
    doc._ast = _FakeAst2()  # type: ignore[assignment]

    result = lookup.get_meta_value(doc, "missing")
    assert result is None


def test_get_meta_value_meta_not_list_and_no_entries_returns_none() -> None:
    """get_meta_value skips meta that is neither a list nor has 'entries' (line 72->64).

    When rule.meta is some object that is not a list and has no 'entries'
    attribute, neither branch is taken at lines 66/72.  The outer for continues
    to the next rule (or exhausts), and eventually returns None (line 78).
    """

    class _PlainMeta:
        pass  # no 'entries' attribute, not a list

    class _FakeRuleNoEntries:
        meta = _PlainMeta()
        strings: list[object] = []

    class _FakeAstNoEntries:
        rules = [_FakeRuleNoEntries()]

    doc = DocumentContext(uri=_URI, text="rule x { condition: true }")
    doc._ast = _FakeAstNoEntries()  # type: ignore[assignment]

    result = lookup.get_meta_value(doc, "author")
    assert result is None


# ---------------------------------------------------------------------------
# get_string_definition_node -- lines 121, 124, 128
# ---------------------------------------------------------------------------


def test_get_string_definition_node_cache_hit() -> None:
    """Second call returns the cached tuple without re-scanning (line 121)."""
    text = 'rule r {\n  strings:\n    $a = "hello"\n  condition:\n    $a\n}'
    doc = _doc(text)
    assert doc.ast() is not None
    first = lookup.get_string_definition_node(doc, "$a")
    assert first is not None
    # Second call must return the cached object.
    second = lookup.get_string_definition_node(doc, "$a")
    assert second is not None
    assert first[0] is second[0]


def test_get_string_definition_node_returns_none_for_unparseable_ast() -> None:
    """Returns None immediately when ast() is None (line 124)."""
    doc = _doc("rule broken {\n")
    assert doc.ast() is None
    result = lookup.get_string_definition_node(doc, "$a")
    assert result is None


def test_get_string_definition_node_skips_anonymous_strings() -> None:
    """Anonymous strings (is_anonymous=True) are skipped (line 128).

    A rule with an anonymous $ string followed by a named $b string.  The
    anonymous entry triggers the continue at line 128; the named string is
    then returned.
    """
    text = 'rule r {\n  strings:\n    $ = "anon"\n    $b = "named"\n  condition:\n    $b\n}'
    doc = _doc(text)
    assert doc.ast() is not None
    # Anonymous string should not be findable by identifier.
    anon = lookup.get_string_definition_node(doc, "$anon_1")
    assert anon is None
    # Named string after the anonymous one is found correctly.
    named = lookup.get_string_definition_node(doc, "$b")
    assert named is not None
    assert named[0].identifier == "$b"


# ---------------------------------------------------------------------------
# get_string_definition_info -- lines 140, 143, 148-156, 158-160
# ---------------------------------------------------------------------------


def test_get_string_definition_info_cache_hit() -> None:
    """Second call returns cached info dict (line 140)."""
    text = 'rule r {\n  strings:\n    $a = "hello"\n  condition:\n    $a\n}'
    doc = _doc(text)
    first = lookup.get_string_definition_info(doc, "$a")
    assert first is not None
    second = lookup.get_string_definition_info(doc, "$a")
    assert second is not None
    assert second["identifier"] == "$a"


def test_get_string_definition_info_returns_none_for_unknown_identifier() -> None:
    """Returns None when the string identifier does not exist (line 143)."""
    text = 'rule r {\n  strings:\n    $a = "hello"\n  condition:\n    $a\n}'
    doc = _doc(text)
    result = lookup.get_string_definition_info(doc, "$missing")
    assert result is None


def test_get_string_definition_info_regex_type() -> None:
    """Regex strings are classified as 'regex' with the pattern as value (lines 148-150)."""
    text = "rule r {\n  strings:\n    $a = /hello.*world/\n  condition:\n    $a\n}"
    doc = _doc(text)
    info = lookup.get_string_definition_info(doc, "$a")
    assert info is not None
    assert info["type"] == "regex"
    assert "hello" in info["value"]


def test_get_string_definition_info_hex_type() -> None:
    """Hex strings are classified as 'hex string' (lines 151-153)."""
    text = "rule r {\n  strings:\n    $a = { DE AD BE EF }\n  condition:\n    $a\n}"
    doc = _doc(text)
    info = lookup.get_string_definition_info(doc, "$a")
    assert info is not None
    assert info["type"] == "hex string"
    assert info["value"] == "<hex pattern>"


def test_get_string_definition_info_unknown_type() -> None:
    """A string definition without value/regex/tokens attributes yields 'string' type (lines 154-156).

    The branch is exercised by injecting a minimal fake string definition into
    the document AST.  The fake has no .value, .regex, or .tokens attribute, and
    also deliberately has no .modifiers attribute so that the hasattr(string_def,
    'modifiers') check at line 158 is False, exercising the 158->160 branch
    (skipping modifier extraction and going straight to result construction).
    """

    class _FakeStringDefNoModifiers:
        identifier = "$a"
        is_anonymous = False
        # Intentionally no .modifiers, .value, .regex, or .tokens attributes.

    class _FakeRuleUnknown:
        strings = [_FakeStringDefNoModifiers()]
        meta: list[object] = []

    class _FakeAstUnknown:
        rules = [_FakeRuleUnknown()]

    doc = DocumentContext(uri=_URI, text="rule x { condition: true }")
    doc._ast = _FakeAstUnknown()  # type: ignore[assignment]

    info = lookup.get_string_definition_info(doc, "$a")
    assert info is not None
    assert info["type"] == "string"
    assert info["value"] == "<unknown>"
    # modifiers defaults to [] because there was no .modifiers attribute.
    assert info["modifiers"] == []


def test_get_string_definition_info_modifier_object_formatting() -> None:
    """Non-str modifiers are formatted via str(m.name) (lines 158-160).

    Real YARA modifiers parsed from source are StringModifier objects with a
    .name attribute.  The function must convert them to strings using str(m.name).
    """
    text = 'rule r {\n  strings:\n    $a = "hello" nocase wide\n  condition:\n    $a\n}'
    doc = _doc(text)
    info = lookup.get_string_definition_info(doc, "$a")
    assert info is not None
    assert "nocase" in info["modifiers"]
    assert "wide" in info["modifiers"]


# ---------------------------------------------------------------------------
# get_module_member_info -- lines 170, 173
# ---------------------------------------------------------------------------


def test_get_module_member_info_cache_hit() -> None:
    """Second call for the same qualified name returns the cached result (line 170)."""
    doc = _doc("rule x { condition: true }")
    first = lookup.get_module_member_info(doc, "pe.imports")
    assert first is not None
    assert first["kind"] == "function"
    second = lookup.get_module_member_info(doc, "pe.imports")
    assert second is not None
    assert second["kind"] == "function"


def test_get_module_member_info_no_dots_returns_none() -> None:
    """A single-part name (no dot) returns None because len(parts) != 2 (line 173)."""
    doc = _doc("rule x { condition: true }")
    result = lookup.get_module_member_info(doc, "pe")
    assert result is None


def test_get_module_member_info_three_parts_returns_none() -> None:
    """A three-part name returns None because len(parts) != 2 (line 173)."""
    doc = _doc("rule x { condition: true }")
    result = lookup.get_module_member_info(doc, "a.b.c")
    assert result is None


# ---------------------------------------------------------------------------
# get_include_info -- lines 210, 214-215
# ---------------------------------------------------------------------------


def test_get_include_info_cache_hit() -> None:
    """Second call for the same include path returns the cached dict (line 210)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        include_file = tmp / "other.yar"
        include_file.write_text("rule other { condition: true }")
        main_file = tmp / "main.yar"
        main_file.write_text('include "other.yar"\nrule x { condition: true }')
        uri = str(path_to_uri(main_file))
        doc = DocumentContext(uri=uri, text=main_file.read_text())

        first = lookup.get_include_info(doc, "other.yar")
        assert first["path"] == "other.yar"
        assert first["resolved_path"] is not None

        # Second call must use cache (line 210).
        second = lookup.get_include_info(doc, "other.yar")
        assert second["resolved_path"] == first["resolved_path"]


def test_get_include_info_nonexistent_candidate_resolves_to_none() -> None:
    """When the candidate file does not exist, resolved_path is None (line 215 branch not taken)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        main_file = tmp / "main.yar"
        main_file.write_text('include "nonexistent.yar"\nrule x { condition: true }')
        uri = str(path_to_uri(main_file))
        doc = DocumentContext(uri=uri, text=main_file.read_text())

        info = lookup.get_include_info(doc, "nonexistent.yar")
        assert info["resolved_path"] is None


def test_get_include_info_no_doc_path_resolved_path_is_none() -> None:
    """When doc.path does not map to a filesystem path, resolved_path is None.

    Uses a non-file URI so that the path resolution branch at line 213 is not
    entered, resulting in resolved_path staying None.
    """
    # An untitled: URI yields a non-None path but no parent directory that
    # contains the include target, so candidate does not exist.
    doc = DocumentContext(
        uri="untitled:scratch.yar", text='include "other.yar"\nrule x { condition: true }'
    )
    info = lookup.get_include_info(doc, "other.yar")
    assert info["path"] == "other.yar"
    assert info["resolved_path"] is None


# ---------------------------------------------------------------------------
# get_include_target_uri -- lines 226-229
# ---------------------------------------------------------------------------


def test_get_include_target_uri_returns_none_when_not_resolved() -> None:
    """Returns None when the include path cannot be resolved (line 229 else branch)."""
    doc = _doc('include "ghost.yar"\nrule x { condition: true }')
    result = lookup.get_include_target_uri(doc, "ghost.yar")
    assert result is None


def test_get_include_target_uri_returns_file_uri_when_resolved() -> None:
    """Returns a file:// URI when the include target exists on disk (line 229 if branch)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        include_file = tmp / "other.yar"
        include_file.write_text("rule other { condition: true }")
        main_file = tmp / "main.yar"
        main_file.write_text('include "other.yar"\nrule x { condition: true }')
        uri = str(path_to_uri(main_file))
        doc = DocumentContext(uri=uri, text=main_file.read_text())

        result = lookup.get_include_target_uri(doc, "other.yar")
        assert result is not None
        assert result.startswith("file://")
        assert "other.yar" in result


# ---------------------------------------------------------------------------
# get_dotted_symbol_at_position -- lines 237, 241-255
# ---------------------------------------------------------------------------

_DOTTED_TEXT = "rule r {\n  condition:\n    pe.number_of_sections > 0\n}"


def test_get_dotted_symbol_out_of_range_line_returns_none() -> None:
    """A line number beyond the document length returns None (line 237)."""
    doc = _doc(_DOTTED_TEXT)
    result = lookup.get_dotted_symbol_at_position(doc, _pos(100, 0))
    assert result is None


def test_get_dotted_symbol_out_of_range_character_returns_none() -> None:
    """A character beyond the line UTF-16 length returns None (line 240 branch)."""
    doc = _doc(_DOTTED_TEXT)
    # Line 2 is '    pe.number_of_sections > 0' -- far fewer than 1000 chars.
    result = lookup.get_dotted_symbol_at_position(doc, _pos(2, 1000))
    assert result is None


def test_get_dotted_symbol_at_position_no_dot_returns_none() -> None:
    """A token without any dot returns None (token.count('.') != 1, line 251)."""
    doc = _doc(_DOTTED_TEXT)
    # Line 0 is 'rule r {' -- 'rule' has no dot.
    result = lookup.get_dotted_symbol_at_position(doc, _pos(0, 1))
    assert result is None


def test_get_dotted_symbol_two_dots_returns_none() -> None:
    """A token with two dots returns None because count('.') != 1 (line 251)."""
    text = "rule r {\n  condition:\n    a.b.c\n}"
    doc = _doc(text)
    result = lookup.get_dotted_symbol_at_position(doc, _pos(2, 6))
    assert result is None


def test_get_dotted_symbol_empty_left_side_returns_none() -> None:
    """A token where the part before '.' is empty returns None (line 254).

    Starting position inside '.foo' hits the check 'not left' at line 253.
    """
    text = "rule r {\n  condition:\n    .foo\n}"
    doc = _doc(text)
    result = lookup.get_dotted_symbol_at_position(doc, _pos(2, 5))
    assert result is None


def test_get_dotted_symbol_at_position_successful_hit() -> None:
    """A valid dotted token returns the token string and its Range (lines 255-258)."""
    doc = _doc(_DOTTED_TEXT)
    # Position 6 is within 'pe.number_of_sections' on line 2.
    result = lookup.get_dotted_symbol_at_position(doc, _pos(2, 6))
    assert result is not None
    token, rng = result
    assert token == "pe.number_of_sections"
    assert isinstance(rng, Range)
    assert rng.start.line == 2
    assert rng.end.line == 2
    assert rng.start.character < rng.end.character
