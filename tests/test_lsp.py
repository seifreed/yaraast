"""Tests for LSP implementation."""

import pytest


# Test basic LSP provider functionality
def test_diagnostics_provider():
    """Test diagnostics provider."""
    from yaraast.lsp.diagnostics import DiagnosticsProvider

    provider = DiagnosticsProvider()

    # Valid YARA rule
    valid_code = """
    rule test {
        strings:
            $a = "test"
        condition:
            $a
    }
    """
    diagnostics = provider.get_diagnostics(valid_code)
    assert len(diagnostics) == 0, "Valid code should have no diagnostics"

    # Invalid YARA rule (syntax error)
    invalid_code = """
    rule test {
        strings:
            $a = "test
        condition:
            $a
    }
    """
    diagnostics = provider.get_diagnostics(invalid_code)
    assert len(diagnostics) > 0, "Invalid code should have diagnostics"


def test_completion_provider():
    """Test completion provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.completion import CompletionProvider

    provider = CompletionProvider()

    text = """
    rule test {
        condition:
            file
    """

    # Test completion after "file"
    position = Position(line=3, character=16)
    completions = provider.get_completions(text, position)

    assert completions is not None
    assert len(completions.items) > 0, "Should provide completions"

    # Check for filesize keyword
    completion_labels = [item.label for item in completions.items]
    assert "filesize" in completion_labels, "Should suggest 'filesize'"


def test_hover_provider():
    """Test hover provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.hover import HoverProvider

    provider = HoverProvider()

    text = """
    rule test {
        condition:
            filesize < 100KB
    }
    """

    # Test hover over "filesize"
    position = Position(line=3, character=12)
    hover = provider.get_hover(text, position)

    assert hover is not None, "Should provide hover for 'filesize'"
    assert "filesize" in hover.contents.value.lower(), "Hover should mention filesize"


def test_definition_provider():
    """Test definition provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.definition import DefinitionProvider

    provider = DefinitionProvider()

    text = """
    rule test {
        strings:
            $payload = "malware"
        condition:
            $payload
    }
    """

    # Test go-to-definition for $payload reference
    position = Position(line=5, character=12)  # On $payload in condition
    uri = "file:///test.yar"
    location = provider.get_definition(text, position, uri)

    assert location is not None, "Should find definition of $payload"
    assert location.range.start.line >= 0, "Definition should have valid line number"


def test_references_provider():
    """Test references provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.references import ReferencesProvider

    provider = ReferencesProvider()

    text = """
    rule test {
        strings:
            $str = "test"
        condition:
            $str or #str > 2
    }
    """

    # Test find-all-references for $str
    position = Position(line=3, character=12)  # On $str definition
    uri = "file:///test.yar"
    locations = provider.get_references(text, position, uri)

    assert len(locations) >= 2, "Should find at least 2 references to $str"


def test_symbols_provider():
    """Test document symbols provider."""
    from yaraast.lsp.symbols import SymbolsProvider

    provider = SymbolsProvider()

    text = """
    import "pe"

    rule malware_rule {
        meta:
            author = "analyst"
        strings:
            $mz = { 4D 5A }
            $str = "malware"
        condition:
            $mz and $str
    }
    """

    symbols = provider.get_symbols(text)

    assert len(symbols) > 0, "Should find symbols"

    # Check for rule symbol
    rule_symbols = [s for s in symbols if s.name == "malware_rule"]
    assert len(rule_symbols) == 1, "Should find the rule"

    # Check rule has children (meta, strings, condition)
    rule_symbol = rule_symbols[0]
    assert rule_symbol.children and len(rule_symbol.children) > 0, "Rule should have children"


def test_formatting_provider():
    """Test formatting provider."""
    from yaraast.lsp.formatting import FormattingProvider

    provider = FormattingProvider()

    # Unformatted code
    unformatted = """rule test{strings:$a="test" condition:$a}"""

    edits = provider.format_document(unformatted)

    assert len(edits) > 0, "Should provide formatting edits"
    assert edits[0].new_text != unformatted, "Formatted text should be different"


def test_code_actions_provider():
    """Test code actions provider."""
    from lsprotocol.types import Diagnostic, DiagnosticSeverity, Position, Range

    from yaraast.lsp.code_actions import CodeActionsProvider

    provider = CodeActionsProvider()

    text = """
    rule test {
        condition:
            pe.imphash() == "abc"
    }
    """

    # Create a diagnostic for missing import
    diagnostic = Diagnostic(
        range=Range(start=Position(line=3, character=12), end=Position(line=3, character=14)),
        message="Module 'pe' not imported",
        severity=DiagnosticSeverity.Error,
    )

    uri = "file:///test.yar"
    range_ = Range(start=Position(line=3, character=0), end=Position(line=3, character=30))

    actions = provider.get_code_actions(text, range_, [diagnostic], uri)

    assert len(actions) > 0, "Should provide code actions for missing import"

    # Check for import action
    action_titles = [a.title for a in actions]
    assert any("import" in title.lower() for title in action_titles), "Should suggest adding import"


def test_rename_provider():
    """Test rename provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.rename import RenameProvider

    provider = RenameProvider()

    text = """
    rule test {
        strings:
            $old = "value"
        condition:
            $old and #old > 0
    }
    """

    # Test rename $old to $new
    position = Position(line=3, character=12)  # On $old definition
    uri = "file:///test.yar"

    # First, check if rename is allowed
    range_ = provider.prepare_rename(text, position)
    assert range_ is not None, "Should allow renaming string identifiers"

    # Perform rename
    edit = provider.rename(text, position, "$new", uri)
    assert edit is not None, "Should provide rename edits"
    assert uri in edit.changes, "Should have edits for the document"

    edits_list = edit.changes[uri]
    assert len(edits_list) >= 2, "Should rename all occurrences"


def test_semantic_tokens_provider():
    """Test semantic tokens provider."""
    from yaraast.lsp.semantic_tokens import SemanticTokensProvider

    provider = SemanticTokensProvider()

    text = """
    rule test {
        strings:
            $str = "malware"
        condition:
            $str
    }
    """

    tokens = provider.get_semantic_tokens(text)

    assert tokens is not None, "Should provide semantic tokens"
    assert len(tokens.data) > 0, "Should have token data"

    # Tokens are encoded as [deltaLine, deltaChar, length, tokenType, tokenModifiers]
    # Check that we have valid tokens (divisible by 5)
    assert len(tokens.data) % 5 == 0, "Token data should be in groups of 5"


# Skip LSP server tests if pygls is not installed
try:
    import pygls

    PYGLS_AVAILABLE = True
except ImportError:
    PYGLS_AVAILABLE = False


@pytest.mark.skipif(not PYGLS_AVAILABLE, reason="pygls not installed")
def test_language_server_creation():
    """Test that language server can be created."""
    from yaraast.lsp.server import create_server

    server = create_server()
    assert server is not None, "Should create language server"
    assert server.name == "yaraast-lsp", "Server should have correct name"


def test_signature_help_provider():
    """Test signature help provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.signature_help import SignatureHelpProvider

    provider = SignatureHelpProvider()

    text = """
    rule test {
        condition:
            uint32(
    """

    # Test signature help for uint32 function
    position = Position(line=3, character=19)  # After "uint32("
    signature_help = provider.get_signature_help(text, position)

    assert signature_help is not None, "Should provide signature help for uint32"
    assert len(signature_help.signatures) > 0, "Should have at least one signature"
    assert "uint32" in signature_help.signatures[0].label, "Signature should contain uint32"


def test_document_highlight_provider():
    """Test document highlight provider."""
    from lsprotocol.types import Position

    from yaraast.lsp.document_highlight import DocumentHighlightProvider

    provider = DocumentHighlightProvider()

    text = """
    rule test {
        strings:
            $str = "malware"
        condition:
            $str and #str > 1
    }
    """

    # Test highlighting for $str identifier
    position = Position(line=3, character=12)  # On $str in strings
    highlights = provider.get_highlights(text, position)

    assert len(highlights) >= 2, "Should find at least 2 occurrences of $str"


def test_folding_ranges_provider():
    """Test folding ranges provider."""
    from yaraast.lsp.folding_ranges import FoldingRangesProvider

    provider = FoldingRangesProvider()

    text = """
    rule test {
        meta:
            author = "analyst"
        strings:
            $a = "test"
        condition:
            $a
    }
    """

    ranges = provider.get_folding_ranges(text)

    assert len(ranges) > 0, "Should provide folding ranges"
    # Should have ranges for: rule, meta, strings, condition
    assert len(ranges) >= 1, "Should have at least one folding range"


def test_document_links_provider():
    """Test document links provider."""
    from yaraast.lsp.document_links import DocumentLinksProvider

    provider = DocumentLinksProvider()

    text = """
    import "pe"
    import "hash"

    rule test {
        condition:
            pe.imphash() == "abc"
    }
    """

    uri = "file:///test.yar"
    links = provider.get_document_links(text, uri)

    assert len(links) > 0, "Should find import links"
    # Check that pe and hash imports have documentation links
    link_targets = [link.target for link in links]
    assert any("pe" in str(target) for target in link_targets), "Should have link for pe module"


def test_workspace_symbols_provider():
    """Test workspace symbols provider."""
    import os
    import tempfile
    from pathlib import Path

    from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider

    provider = WorkspaceSymbolsProvider()

    # Create a temporary workspace with YARA files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test YARA file
        test_file = Path(tmpdir) / "test.yar"
        test_file.write_text(
            """
            rule malware_detection {
                strings:
                    $payload = "malicious"
                condition:
                    $payload
            }
            """
        )

        # Set workspace root
        provider.set_workspace_root(tmpdir)

        # Search for symbols
        symbols = provider.get_workspace_symbols("malware")

        assert len(symbols) > 0, "Should find symbols matching 'malware'"
        symbol_names = [sym.name for sym in symbols]
        assert "malware_detection" in symbol_names, "Should find malware_detection rule"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
