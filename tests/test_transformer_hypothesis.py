"""Property-based tests for AST transformer."""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from yaraast.codegen import CodeGenerator
from yaraast.lexer.lexer_tables import KEYWORDS as _LEXER_KEYWORDS
from yaraast.parser.parser import Parser
from yaraast.visitor.transformer_impl import ASTTransformer

RESERVED = frozenset(_LEXER_KEYWORDS.keys())


def _valid_identifier() -> st.SearchStrategy[str]:
    return st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,15}", fullmatch=True)


@pytest.mark.hypothesis
class TestIdentityTransformer:
    """Test that identity ASTTransformer preserves AST."""

    @given(name=_valid_identifier())
    @settings(max_examples=50, deadline=5000)
    def test_identity_transform_preserves_structure(self, name: str) -> None:
        """Identity transformer produces equivalent codegen output."""
        assume(name.lower() not in RESERVED)
        text = f"rule {name} {{ condition: true }}"
        ast1 = Parser(text).parse()
        transformer = ASTTransformer()
        ast2 = transformer.visit(ast1)

        gen1 = CodeGenerator().generate(ast1)
        gen2 = CodeGenerator().generate(ast2)
        assert gen1 == gen2

    @given(name=_valid_identifier())
    @settings(max_examples=30, deadline=5000)
    def test_identity_transform_preserves_rule_count(self, name: str) -> None:
        """Identity transformer preserves number of rules."""
        assume(name.lower() not in RESERVED)
        text = f"rule {name} {{ condition: true }}"
        ast1 = Parser(text).parse()
        ast2 = ASTTransformer().visit(ast1)
        assert len(ast2.rules) == len(ast1.rules)

    @given(name=_valid_identifier())
    @settings(max_examples=30, deadline=5000)
    def test_double_transform_idempotent(self, name: str) -> None:
        """Applying identity transform twice produces same result as once."""
        assume(name.lower() not in RESERVED)
        text = f"rule {name} {{ condition: true }}"
        ast = Parser(text).parse()
        t = ASTTransformer()
        once = CodeGenerator().generate(t.visit(ast))
        twice = CodeGenerator().generate(t.visit(t.visit(ast)))
        assert once == twice
