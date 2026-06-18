"""More tests for LSP parsing helpers."""

from __future__ import annotations

import pytest

from yaraast.errors import ParseError
from yaraast.lsp.parsing import parse_for_lsp


def test_parse_for_lsp_wraps_lexer_errors() -> None:
    with pytest.raises(ParseError, match="Lexer error at 1:30"):
        parse_for_lsp('rule broken { strings: $a = "\ud800" condition: $a }')
