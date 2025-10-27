"""Code actions provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import (
    CodeAction,
    CodeActionKind,
    Diagnostic,
    Position,
    Range,
    TextEdit,
    WorkspaceEdit,
)

from yaraast.lsp.utils import get_word_at_position
from yaraast.parser.parser import Parser

if TYPE_CHECKING:
    pass


class CodeActionsProvider:
    """Provides code actions (quick fixes)."""

    def get_code_actions(
        self,
        text: str,
        range_: Range,
        diagnostics: list[Diagnostic],
        uri: str,
    ) -> list[CodeAction]:
        """
        Get code actions for the given range and diagnostics.

        Args:
            text: The YARA source code
            range_: The range to get actions for
            diagnostics: Diagnostics in the range
            uri: The document URI

        Returns:
            List of available code actions
        """
        actions = []

        # Add quick fixes for diagnostics
        for diagnostic in diagnostics:
            if "undefined variable" in diagnostic.message.lower():
                # Suggest adding string definition
                actions.extend(self._create_add_string_actions(text, diagnostic, uri))

            if "not imported" in diagnostic.message.lower():
                # Suggest importing module
                actions.extend(self._create_import_module_actions(text, diagnostic, uri))

            if "duplicate string identifier" in diagnostic.message.lower():
                # Suggest renaming duplicate
                actions.extend(self._create_rename_duplicate_actions(text, diagnostic, uri))

        # Add refactoring actions
        actions.extend(self._get_refactoring_actions(text, range_, uri))

        return actions

    def _create_add_string_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to add missing string definition."""
        actions = []

        # Extract variable name from diagnostic message
        # Example: "undefined variable $payload"
        import re

        match = re.search(r"\$\w+", diagnostic.message)
        if not match:
            return actions

        string_id = match.group(0)

        # Find strings section to insert new string
        lines = text.split("\n")
        strings_line = -1

        for i, line in enumerate(lines):
            if "strings:" in line:
                strings_line = i
                break

        if strings_line >= 0:
            # Find last string in section
            last_string_line = strings_line
            for i in range(strings_line + 1, len(lines)):
                if lines[i].strip().startswith("$"):
                    last_string_line = i
                elif lines[i].strip().startswith("condition:"):
                    break

            # Create edit to add string
            new_string = f'        {string_id} = ""\n'
            insert_position = Position(line=last_string_line + 1, character=0)

            edit = TextEdit(
                range=Range(start=insert_position, end=insert_position),
                new_text=new_string,
            )

            actions.append(
                CodeAction(
                    title=f"Add string definition for {string_id}",
                    kind=CodeActionKind.QuickFix,
                    edit=WorkspaceEdit(changes={uri: [edit]}),
                    diagnostics=[diagnostic],
                )
            )

        return actions

    def _create_import_module_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to import missing module."""
        actions = []

        # Extract module name from diagnostic message
        import re

        match = re.search(r"Module '(\w+)' not imported", diagnostic.message)
        if not match:
            return actions

        module_name = match.group(1)

        # Create edit to add import at the top
        import_line = f'import "{module_name}"\n'
        insert_position = Position(line=0, character=0)

        edit = TextEdit(
            range=Range(start=insert_position, end=insert_position),
            new_text=import_line,
        )

        actions.append(
            CodeAction(
                title=f'Add import "{module_name}"',
                kind=CodeActionKind.QuickFix,
                edit=WorkspaceEdit(changes={uri: [edit]}),
                diagnostics=[diagnostic],
            )
        )

        return actions

    def _create_rename_duplicate_actions(
        self,
        text: str,
        diagnostic: Diagnostic,
        uri: str,
    ) -> list[CodeAction]:
        """Create actions to rename duplicate string identifier."""
        actions = []

        # Extract string identifier from diagnostic
        import re

        match = re.search(r"'\$(\w+)'", diagnostic.message)
        if not match:
            return actions

        base_name = match.group(1)

        # Find a unique name
        lines = text.split("\n")
        existing_ids = set()

        for line in lines:
            id_match = re.search(r"\$(\w+)\s*=", line)
            if id_match:
                existing_ids.add(id_match.group(1))

        # Generate unique name
        counter = 2
        while f"{base_name}_{counter}" in existing_ids:
            counter += 1

        new_name = f"${base_name}_{counter}"

        # Get the position of the duplicate
        line_num = diagnostic.range.start.line
        if line_num < len(lines):
            line = lines[line_num]
            col = line.find(f"${base_name}")
            if col >= 0:
                edit = TextEdit(
                    range=Range(
                        start=Position(line=line_num, character=col),
                        end=Position(line=line_num, character=col + len(f"${base_name}")),
                    ),
                    new_text=new_name,
                )

                actions.append(
                    CodeAction(
                        title=f"Rename to {new_name}",
                        kind=CodeActionKind.QuickFix,
                        edit=WorkspaceEdit(changes={uri: [edit]}),
                        diagnostics=[diagnostic],
                    )
                )

        return actions

    def _get_refactoring_actions(
        self,
        text: str,
        range_: Range,
        uri: str,
    ) -> list[CodeAction]:
        """Get refactoring actions for the given range."""
        actions = []

        # Get word at position
        word, word_range = get_word_at_position(text, range_.start)

        # Add "Extract to rule" action if we're in a condition
        if self._is_in_condition(text, range_.start):
            actions.append(
                CodeAction(
                    title="Extract to rule",
                    kind=CodeActionKind.RefactorExtract,
                    # Note: This would need full implementation with UI prompts
                )
            )

        return actions

    def _is_in_condition(self, text: str, position: Position) -> bool:
        """Check if position is inside a condition section."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return False

        # Look backwards for condition:
        for i in range(position.line, -1, -1):
            if "condition:" in lines[i]:
                return True
            if "rule " in lines[i] or "strings:" in lines[i]:
                return False

        return False
