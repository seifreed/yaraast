"""Property-based tests for YARA parser using Hypothesis."""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from yaraast.codegen import CodeGenerator
from yaraast.lexer.lexer_tables import KEYWORDS as _LEXER_KEYWORDS
from yaraast.parser.parser import Parser

_ALL_KEYWORDS = frozenset(_LEXER_KEYWORDS.keys())


def _valid_identifier() -> st.SearchStrategy[str]:
    """Generate valid YARA identifiers that are not keywords."""
    return st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,20}", fullmatch=True).filter(
        lambda name: name.lower() not in _ALL_KEYWORDS
    )


def _simple_rule() -> st.SearchStrategy[str]:
    """Generate simple syntactically valid YARA rules."""
    return _valid_identifier().map(lambda name: f"rule {name} {{ condition: true }}")


def _rule_with_strings() -> st.SearchStrategy[str]:
    """Generate rules with string definitions."""
    return st.tuples(
        _valid_identifier(),
        st.lists(
            st.tuples(
                _valid_identifier().map(lambda s: f"${s}"),
                st.text(
                    alphabet=st.characters(
                        whitelist_categories=("L", "N", "P", "Z"),
                        blacklist_characters='"\\',
                    ),
                    min_size=1,
                    max_size=30,
                ),
            ),
            min_size=1,
            max_size=5,
        ),
    ).map(lambda t: _build_rule_with_strings(t[0], t[1]))


def _build_rule_with_strings(name: str, strings: list[tuple[str, str]]) -> str:
    """Build a YARA rule string with given name and string definitions."""
    string_defs = "\n        ".join(f'{ident} = "{value}"' for ident, value in strings)
    first_id = strings[0][0]
    return (
        f"rule {name} {{\n"
        f"    strings:\n"
        f"        {string_defs}\n"
        f"    condition:\n"
        f"        {first_id}\n"
        f"}}"
    )


@pytest.mark.hypothesis
class TestParserRoundtrip:
    """Test that parse -> codegen -> parse produces equivalent ASTs."""

    @given(rule_text=_simple_rule())
    @settings(max_examples=50, deadline=5000)
    def test_simple_rule_roundtrip(self, rule_text: str) -> None:
        """Simple rules survive parse -> codegen -> parse roundtrip."""
        ast1 = Parser(rule_text).parse()
        assert len(ast1.rules) == 1

        generated = CodeGenerator().generate(ast1)
        ast2 = Parser(generated).parse()

        assert len(ast2.rules) == len(ast1.rules)
        assert ast2.rules[0].name == ast1.rules[0].name

    @given(rule_text=_rule_with_strings())
    @settings(max_examples=30, deadline=5000)
    def test_rule_with_strings_roundtrip(self, rule_text: str) -> None:
        """Rules with strings survive roundtrip."""
        try:
            ast1 = Parser(rule_text).parse()
        except Exception:
            assume(False)
            return

        assert len(ast1.rules) == 1
        rule1 = ast1.rules[0]

        generated = CodeGenerator().generate(ast1)
        ast2 = Parser(generated).parse()
        rule2 = ast2.rules[0]

        assert rule2.name == rule1.name
        assert len(rule2.strings) == len(rule1.strings)

    @given(name=_valid_identifier())
    @settings(max_examples=50, deadline=5000)
    def test_rule_name_preserved(self, name: str) -> None:
        """Rule names are preserved through roundtrip."""
        assume(name.lower() not in _ALL_KEYWORDS)
        rule_text = f"rule {name} {{ condition: true }}"
        ast1 = Parser(rule_text).parse()
        generated = CodeGenerator().generate(ast1)
        ast2 = Parser(generated).parse()
        assert ast2.rules[0].name == name


@pytest.mark.hypothesis
class TestParserIdempotent:
    """Test that double-codegen produces identical output."""

    @given(rule_text=_simple_rule())
    @settings(max_examples=50, deadline=5000)
    def test_codegen_idempotent(self, rule_text: str) -> None:
        """CodeGenerator output is stable across multiple applications."""
        ast1 = Parser(rule_text).parse()
        gen1 = CodeGenerator().generate(ast1)
        ast2 = Parser(gen1).parse()
        gen2 = CodeGenerator().generate(ast2)
        assert gen1 == gen2
