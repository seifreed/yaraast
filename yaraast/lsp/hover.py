"""Hover provider for YARA Language Server."""

from __future__ import annotations

from typing import Any, cast

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
from yaraast.lsp.utils import get_word_at_position
from yaraast.types.module_loader import ModuleLoader


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

        if resolved and resolved.kind == "module" and resolved.normalized_name in self.module_docs:
            module_name = resolved.normalized_name
            return Hover(
                contents=render_module_hover(
                    module_name, self.module_docs[module_name], resolved.range
                ).contents,
                range=resolved.range,
            )

        # Check module members (e.g., pe.imphash)
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

        # Check string identifiers and variants
        if resolved and resolved.kind == "string":
            return self._get_string_identifier_hover(doc, resolved.normalized_name, resolved.range)
        if word.startswith(("$", "#", "@", "!")):
            return self._get_string_identifier_hover(doc, word, word_range)

        if resolved and resolved.kind == "meta":
            meta_hover = self._get_meta_hover(doc, resolved.normalized_name, resolved.range)
            if meta_hover:
                return meta_hover

        if resolved and resolved.kind == "include":
            include_hover = self._get_include_hover(doc, resolved.normalized_name, resolved.range)
            if include_hover:
                return include_hover

        if resolved and resolved.kind == "section":
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{resolved.normalized_name}** (section)\n\nStructured section of the current rule.",
                ),
                range=resolved.range,
            )

        if not word:
            return None

        # Check keywords
        if word in self.keyword_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (keyword)\n\n{self.keyword_docs[word]}",
                ),
                range=word_range,
            )

        # Check built-in functions
        if word in self.builtin_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (built-in function)\n\n{self.builtin_docs[word]}",
                ),
                range=word_range,
            )

        # Check modules
        module_info = doc.get_module_info(word)
        if module_info is not None:
            return Hover(
                contents=render_module_hover(
                    str(module_info["name"]), str(module_info["description"]), word_range
                ).contents,
                range=word_range,
            )

        # Check rule names
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
        if isinstance(doc_or_module, DocumentContext):
            member_info = doc_or_module.get_module_member_info(qualified_or_member)
        else:
            module_name = str(doc_or_module)
            member_name = qualified_or_member
            member_info = None
            module_def = self.module_loader.get_module(module_name)
            if module_def:
                if member_name in module_def.functions:
                    func_def = module_def.functions[member_name]
                    member_info = {
                        "module": module_name,
                        "member": member_name,
                        "kind": "function",
                        "parameters": list(getattr(func_def, "parameters", [])),
                        "return_type": getattr(func_def, "return_type", "unknown"),
                        "description": getattr(func_def, "description", None),
                    }
                else:
                    fields = getattr(module_def, "fields", None) or {}
                    if member_name in fields:
                        field_def = fields[member_name]
                        member_info = {
                            "module": module_name,
                            "member": member_name,
                            "kind": "field",
                            "type": getattr(field_def, "type", "unknown"),
                            "description": getattr(field_def, "description", None),
                        }

        if member_info:
            module_name = str(member_info["module"])
            member_name = str(member_info["member"])
            if member_info["kind"] == "function":
                params = ", ".join(
                    f"{p[0]}: {p[1]}"
                    for p in cast(list[tuple[str, Any]], member_info["parameters"])
                )
                signature = f"{module_name}.{member_name}({params}) -> {member_info['return_type']}"
                value = f"**{member_name}** (function)\n\n```yara\n{signature}\n```"
                if member_info.get("description"):
                    value += f"\n\n{member_info['description']}"

                return Hover(
                    contents=render_module_function_hover(member_info, word_range).contents,
                    range=word_range,
                )

            if member_info["kind"] == "field":
                value = (
                    f"**{member_name}** (field)\n\n```yara\n"
                    f"{module_name}.{member_name}: {member_info['type']}\n```"
                )
                if member_info.get("description"):
                    value += f"\n\n{member_info['description']}"

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
            pass

        return render_string_identifier_hover(base_identifier, None, word_range)

    def _get_meta_hover(
        self,
        doc: DocumentContext,
        key: str,
        word_range: Range,
    ) -> Hover | None:
        try:
            meta_value = doc.get_meta_value(key)
            if meta_value is not None:
                return render_meta_hover(key, meta_value, word_range)
        except Exception:
            return None

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

    def _get_rule_hover(
        self,
        doc: DocumentContext,
        rule_name: str,
        word_range: Range,
    ) -> Hover | None:
        """Get hover for a rule name."""
        try:
            rule_info = doc.get_rule_info(rule_name)
            if rule_info is not None:
                return render_rule_hover(rule_name, rule_info, word_range)

        except Exception:
            pass

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
