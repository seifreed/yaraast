"""Document highlight provider for YARAAST LSP."""

from lsprotocol.types import DocumentHighlight, DocumentHighlightKind, Position, Range

from yaraast.lsp.utils import get_word_at_position, offset_to_position
from yaraast.parser.parser import Parser


class DocumentHighlightProvider:
    """Provide document highlighting for symbols."""

    def get_highlights(self, text: str, position: Position) -> list[DocumentHighlight]:
        """Get all highlights for symbol at position."""
        word, word_range = get_word_at_position(text, position)
        if not word:
            return []

        # Check if it's a string identifier
        if word.startswith("$"):
            return self._highlight_string_identifier(text, word)

        # Check if it's a rule name or other identifier
        return self._highlight_identifier(text, word)

    def _highlight_string_identifier(self, text: str, identifier: str) -> list[DocumentHighlight]:
        """Highlight all occurrences of a string identifier."""
        highlights = []

        try:
            parser = Parser(text)
            ast = parser.parse()

            # Find all occurrences of this string identifier
            # Check both definition and usage
            lines = text.split("\n")

            # Base identifier without $ prefix
            base_id = identifier[1:] if identifier.startswith("$") else identifier

            # Look for: $id, #id, @id, !id
            patterns = [f"${base_id}", f"#{base_id}", f"@{base_id}", f"!{base_id}"]

            for line_num, line in enumerate(lines):
                for pattern in patterns:
                    col = 0
                    while True:
                        idx = line.find(pattern, col)
                        if idx == -1:
                            break

                        # Check if it's a word boundary
                        if idx > 0 and (line[idx - 1].isalnum() or line[idx - 1] == "_"):
                            col = idx + 1
                            continue

                        end_idx = idx + len(pattern)
                        if end_idx < len(line) and (
                            line[end_idx].isalnum() or line[end_idx] == "_"
                        ):
                            col = idx + 1
                            continue

                        # Determine highlight kind
                        kind = DocumentHighlightKind.Read
                        if pattern.startswith("$") and "strings:" in text[: text.find(pattern)]:
                            # This is the definition
                            kind = DocumentHighlightKind.Write

                        highlights.append(
                            DocumentHighlight(
                                range=Range(
                                    start=Position(line=line_num, character=idx),
                                    end=Position(line=line_num, character=end_idx),
                                ),
                                kind=kind,
                            )
                        )
                        col = end_idx

        except Exception:
            # Fallback to simple text search
            return self._simple_highlight(text, identifier)

        return highlights

    def _highlight_identifier(self, text: str, identifier: str) -> list[DocumentHighlight]:
        """Highlight all occurrences of a regular identifier."""
        highlights = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines):
            col = 0
            while True:
                idx = line.find(identifier, col)
                if idx == -1:
                    break

                # Check word boundaries
                if idx > 0 and (line[idx - 1].isalnum() or line[idx - 1] == "_"):
                    col = idx + 1
                    continue

                end_idx = idx + len(identifier)
                if end_idx < len(line) and (line[end_idx].isalnum() or line[end_idx] == "_"):
                    col = idx + 1
                    continue

                highlights.append(
                    DocumentHighlight(
                        range=Range(
                            start=Position(line=line_num, character=idx),
                            end=Position(line=line_num, character=end_idx),
                        ),
                        kind=DocumentHighlightKind.Text,
                    )
                )
                col = end_idx

        return highlights

    def _simple_highlight(self, text: str, word: str) -> list[DocumentHighlight]:
        """Simple text-based highlighting fallback."""
        highlights = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines):
            col = 0
            while True:
                idx = line.find(word, col)
                if idx == -1:
                    break

                highlights.append(
                    DocumentHighlight(
                        range=Range(
                            start=Position(line=line_num, character=idx),
                            end=Position(line=line_num, character=idx + len(word)),
                        ),
                        kind=DocumentHighlightKind.Text,
                    )
                )
                col = idx + len(word)

        return highlights
