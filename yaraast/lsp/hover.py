"""Hover provider for YARA Language Server."""

from __future__ import annotations

import logging
from typing import Any

from lsprotocol.types import Hover, MarkupContent, MarkupKind, Position, Range

from yaraast.lsp.hover_renderers import include_hover as render_include_hover
from yaraast.lsp.hover_renderers import meta_hover as render_meta_hover
from yaraast.lsp.hover_renderers import module_field_hover as render_module_field_hover
from yaraast.lsp.hover_renderers import module_function_hover as render_module_function_hover
from yaraast.lsp.hover_renderers import module_hover as render_module_hover
from yaraast.lsp.hover_renderers import rule_hover as render_rule_hover
from yaraast.lsp.hover_renderers import string_identifier_hover as render_string_identifier_hover
from yaraast.lsp.hover_renderers import workspace_rule_hover as render_workspace_rule_hover
from yaraast.lsp.lsp_docs import BUILTIN_DOCS, KEYWORD_DOCS, MODULE_DOCS
from yaraast.lsp.runtime import DocumentContext, LspRuntime
from yaraast.lsp.safe_handler import lsp_safe_handler
from yaraast.lsp.utils import get_word_at_position
from yaraast.types.module_loader import ModuleLoader

logger = logging.getLogger(__name__)


class HoverProvider:
    """Provides hover information for YARA symbols."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime
        self.module_loader: ModuleLoader = ModuleLoader()
        self.keyword_docs = KEYWORD_DOCS
        self.builtin_docs = BUILTIN_DOCS
        self.module_docs = MODULE_DOCS

    def get_hover(self, text: str, position: Position, uri: str | None = None) -> Hover | None:
        """
        Get hover information for the symbol at the given position.

        Args:
            text: The YARA source code
            position: The cursor position

        Returns:
            Hover information or None
        """
        doc = (
            self.runtime.ensure_document(uri, text)
            if self.runtime and uri
            else DocumentContext(
                uri or "file://local.yar",
                text,
            )
        )
        resolved = doc.resolve_symbol(position)
        word, word_range = get_word_at_position(text, position)

        # Check modules resolved structurally first.
        result = self._hover_for_module(doc, resolved, word_range)
        if result:
            return result

        # Check module members (e.g., pe.imphash)
        result = self._hover_for_module_member(doc, resolved, word, word_range, position)
        if result:
            return result

        # Check string identifiers and variants
        result = self._hover_for_string(doc, resolved, word, word_range)
        if result:
            return result

        # Check meta
        if resolved and resolved.kind == "meta":
            meta_hover = self._get_meta_hover(doc, resolved.normalized_name, resolved.range)
            if meta_hover:
                return meta_hover

        # Check includes
        if resolved and resolved.kind == "include":
            include_hover = self._get_include_hover(doc, resolved.normalized_name, resolved.range)
            if include_hover:
                return include_hover

        # Check sections
        result = self._hover_for_section(resolved)
        if result:
            return result

        if not word:
            return None

        # Check keywords
        result = self._hover_for_keyword(word, word_range)
        if result:
            return result

        # Check built-in functions
        result = self._hover_for_builtin(word, word_range)
        if result:
            return result

        # Check modules by word
        result = self._hover_for_module_by_word(doc, word, word_range)
        if result:
            return result

        # Check rule names
        result = self._hover_for_rule(doc, resolved, word, word_range, uri)
        if result:
            return result

        return None

    def _hover_for_module(self, doc, resolved, word_range):
        """Get hover for a resolved module symbol."""
        if resolved and resolved.kind == "module":
            module_info = doc.get_module_info(resolved.normalized_name)
            if module_info is not None:
                module_name = str(module_info["name"])
                return Hover(
                    contents=render_module_hover(
                        module_name, str(module_info["description"]), resolved.range
                    ).contents,
                    range=resolved.range,
                )
            if resolved.normalized_name in self.module_docs:
                module_name = resolved.normalized_name
                return Hover(
                    contents=render_module_hover(
                        module_name, self.module_docs[module_name], resolved.range
                    ).contents,
                    range=resolved.range,
                )
        return None

    def _hover_for_module_member(self, doc, resolved, word, word_range, position):
        """Get hover for a module member (e.g., pe.imphash)."""
        if resolved and resolved.kind == "module_member":
            return self._get_module_member_hover(doc, resolved.normalized_name, resolved.range)
        if not resolved:
            dotted = doc.get_dotted_symbol_at_position(position)
            if dotted is not None:
                qualified_name, dotted_range = dotted
                parts = qualified_name.split(".")
                if len(parts) == 2:
                    return self._get_module_member_hover(parts[0], parts[1], dotted_range)
            elif "." in word:
                parts = word.split(".")
                if len(parts) == 2:
                    return self._get_module_member_hover(parts[0], parts[1], word_range)
        return None

    def _hover_for_string(self, doc, resolved, word, word_range):
        """Get hover for a string identifier."""
        if resolved and resolved.kind == "string":
            return self._get_string_identifier_hover(doc, resolved.normalized_name, resolved.range)
        if word.startswith(("$", "#", "@", "!")):
            return self._get_string_identifier_hover(doc, word, word_range)
        return None

    def _hover_for_section(self, resolved):
        """Get hover for a section keyword."""
        if resolved and resolved.kind == "section":
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=(
                        f"**{resolved.normalized_name}** (section)\n\n"
                        "Structured section of the current rule."
                    ),
                ),
                range=resolved.range,
            )
        return None

    def _hover_for_keyword(self, word, word_range):
        """Get hover for a YARA keyword."""
        if word in self.keyword_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (keyword)\n\n{self.keyword_docs[word]}",
                ),
                range=word_range,
            )
        return None

    def _hover_for_builtin(self, word, word_range):
        """Get hover for a built-in function."""
        if word in self.builtin_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (built-in function)\n\n{self.builtin_docs[word]}",
                ),
                range=word_range,
            )
        return None

    def _hover_for_module_by_word(self, doc, word, word_range):
        """Get hover for a module matched by word text."""
        module_info = doc.get_module_info(word)
        if module_info is not None:
            return Hover(
                contents=render_module_hover(
                    str(module_info["name"]), str(module_info["description"]), word_range
                ).contents,
                range=word_range,
            )
        return None

    def _hover_for_rule(self, doc, resolved, word, word_range, uri):
        """Get hover for a rule name, including workspace rules."""
        rule_hover = self._get_rule_hover(
            doc,
            resolved.normalized_name if resolved and resolved.kind == "rule" else word,
            resolved.range if resolved and resolved.kind == "rule" else word_range,
        )
        if rule_hover:
            return rule_hover

        if self.runtime and uri:
            workspace_rule_hover = self._get_workspace_rule_hover(uri, word, word_range)
            if workspace_rule_hover:
                return workspace_rule_hover

        return None

    def _get_module_member_hover(
        self,
        doc_or_module: DocumentContext | str,
        qualified_or_member: str,
        word_range: Range,
    ) -> Hover | None:
        """Get hover for a module member (field or function)."""
        member_info = self._resolve_member_info(doc_or_module, qualified_or_member)
        if not member_info:
            return None
        return self._render_member_hover(member_info, word_range)

    def _resolve_member_info(
        self,
        doc_or_module: DocumentContext | str,
        qualified_or_member: str,
    ) -> dict[str, Any] | None:
        """Resolve module member info from a DocumentContext or raw module name."""
        if isinstance(doc_or_module, DocumentContext):
            return doc_or_module.get_module_member_info(qualified_or_member)

        module_name = str(doc_or_module)
        member_name = qualified_or_member
        module_def = self.module_loader.get_module(module_name)
        if not module_def:
            return None

        if member_name in module_def.functions:
            func_def = module_def.functions[member_name]
            return {
                "module": module_name,
                "member": member_name,
                "kind": "function",
                "parameters": list(getattr(func_def, "parameters", [])),
                "return_type": getattr(func_def, "return_type", "unknown"),
                "description": getattr(func_def, "description", None),
            }

        fields = getattr(module_def, "fields", None) or {}
        if member_name in fields:
            field_def = fields[member_name]
            return {
                "module": module_name,
                "member": member_name,
                "kind": "field",
                "type": getattr(field_def, "type", "unknown"),
                "description": getattr(field_def, "description", None),
            }

        return None

    def _render_member_hover(
        self,
        member_info: dict[str, Any],
        word_range: Range,
    ) -> Hover | None:
        """Render a Hover for a resolved module member."""
        if member_info["kind"] == "function":
            return Hover(
                contents=render_module_function_hover(member_info, word_range).contents,
                range=word_range,
            )

        if member_info["kind"] == "field":
            return Hover(
                contents=render_module_field_hover(member_info, word_range).contents,
                range=word_range,
            )

        return None

    def _get_string_identifier_hover(
        self,
        doc: DocumentContext,
        identifier: str,
        word_range: Range,
    ) -> Hover | None:
        """Get hover for a string identifier."""
        base_identifier = identifier.lstrip("#@!")
        if not base_identifier.startswith("$"):
            base_identifier = f"${base_identifier}"
        try:
            string_info = doc.get_string_definition_info(base_identifier)
            if string_info is not None:
                return render_string_identifier_hover(base_identifier, string_info, word_range)

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)

        return render_string_identifier_hover(base_identifier, None, word_range)

    @lsp_safe_handler
    def _get_meta_hover(
        self,
        doc: DocumentContext,
        key: str,
        word_range: Range,
    ) -> Hover | None:
        meta_value = doc.get_meta_value(key)
        if meta_value is not None:
            return render_meta_hover(key, meta_value, word_range)
        return None

    def _get_include_hover(
        self,
        doc: DocumentContext,
        include_path: str,
        word_range: Range,
    ) -> Hover | None:
        include_info = doc.get_include_info(include_path)
        if include_info is None:
            return None

        return render_include_hover(include_path, include_info["resolved_path"], word_range)

    @lsp_safe_handler
    def _get_rule_hover(
        self,
        doc: DocumentContext,
        rule_name: str,
        word_range: Range,
    ) -> Hover | None:
        """Get hover for a rule name."""
        rule_info = doc.get_rule_info(rule_name)
        if rule_info is not None:
            return render_rule_hover(rule_name, rule_info, word_range)
        return None

    def _get_workspace_rule_hover(
        self,
        current_uri: str,
        rule_name: str,
        word_range: Range,
    ) -> Hover | None:
        if self.runtime is None:
            return None
        definition = self.runtime.find_rule_definition(rule_name, current_uri)
        if definition is None:
            return None
        if definition.uri == current_uri:
            return None

        target_doc = self.runtime.get_document(definition.uri)
        if target_doc is None:
            return None

        rule_info = target_doc.get_rule_info(rule_name)
        if rule_info is None:
            return None

        return render_workspace_rule_hover(rule_name, rule_info, definition.uri, word_range)
