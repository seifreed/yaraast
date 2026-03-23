"""Completion provider for YARA Language Server."""

from __future__ import annotations

import logging

from lsprotocol.types import (
    CompletionItem,
    CompletionItemKind,
    CompletionList,
    InsertTextFormat,
    Position,
)

from yaraast.lsp.completion_helpers import (
    BUILTIN_FUNCTIONS,
    KEYWORDS,
    STRING_MODIFIERS,
    analyze_context,
    build_builtin_function_completions,
    build_condition_completions,
    build_keyword_completions,
    build_module_completions,
    build_module_member_completions,
    build_string_modifier_completions,
    get_current_module,
    get_keywords_for_mode,
)
from yaraast.lsp.runtime import LspRuntime
from yaraast.types.module_loader import ModuleLoader

logger = logging.getLogger(__name__)


class CompletionProvider:
    """Provides intelligent autocompletion for YARA files."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime
        self.module_loader: ModuleLoader = ModuleLoader()
        self.keywords = list(KEYWORDS)
        self.builtin_functions = dict(BUILTIN_FUNCTIONS)
        self.string_modifiers = dict(STRING_MODIFIERS)

    def get_completions(
        self,
        text: str,
        position: Position,
        uri: str | None = None,
    ) -> CompletionList:
        """
        Get completion items for the given position.

        Args:
            text: The YARA source code
            position: The cursor position

        Returns:
            CompletionList with available completions
        """
        items = []

        # Analyze context
        context = analyze_context(text, position)

        keywords = self._keywords_for_document(text, uri)

        if context == "import":
            items.extend(self._get_module_completions())
        elif context == "module_member":
            module_name = get_current_module(text, position)
            if module_name:
                items.extend(self._get_module_member_completions(module_name))
        elif context == "string_modifier":
            items.extend(self._get_string_modifier_completions())
        elif context == "condition":
            items.extend(self._get_condition_completions(text, keywords))
            if self.runtime and uri:
                items.extend(self._get_workspace_rule_completions(uri))
        elif context == "meta":
            items.extend(self._get_meta_completions())
        else:
            # General completions
            items.extend(self._get_keyword_completions(keywords))
            items.extend(self._get_builtin_function_completions())

        return CompletionList(is_incomplete=False, items=items)

    def _keywords_for_document(self, text: str, uri: str | None) -> list[str]:
        if self.runtime and uri:
            doc = self.runtime.ensure_document(uri, text)
            mode = doc.language_mode
            detected = doc.dialect()
            if mode.value == "auto":
                from yaraast.lsp.runtime import LanguageMode

                mapping = {
                    "YARA": LanguageMode.YARA,
                    "YARA_X": LanguageMode.YARA_X,
                    "YARA_L": LanguageMode.YARA_L,
                }
                mode = mapping.get(detected.name, LanguageMode.YARA)
            return get_keywords_for_mode(mode)
        return self.keywords

    def _get_keyword_completions(self, keywords: list[str]) -> list[CompletionItem]:
        """Get keyword completions."""
        return build_keyword_completions(keywords)

    def _get_builtin_function_completions(self) -> list[CompletionItem]:
        """Get built-in function completions."""
        return build_builtin_function_completions(self.builtin_functions)

    def _get_module_completions(self) -> list[CompletionItem]:
        """Get available YARA modules."""
        return build_module_completions()

    def _get_module_member_completions(
        self, module_name: str, access_chain: str = ""
    ) -> list[CompletionItem]:
        """Get completions for module members with deep type resolution."""
        # Extract the root module name from chains like pe.sections[0]
        root_module = module_name.split(".")[0] if "." in module_name else module_name
        module_def = self.module_loader.get_module(root_module)
        if not module_def:
            return []
        # Build access chain from everything after the root module
        chain = access_chain
        if "." in module_name:
            chain = module_name[len(root_module) + 1 :]
            if access_chain:
                chain = f"{chain}.{access_chain}"
        return build_module_member_completions(root_module, module_def, access_chain=chain)

    def _get_string_modifier_completions(self) -> list[CompletionItem]:
        """Get string modifier completions."""
        return build_string_modifier_completions(self.string_modifiers)

    def _get_condition_completions(self, text: str, keywords: list[str]) -> list[CompletionItem]:
        """Get completions relevant to condition context."""
        return build_condition_completions(text, keywords)

    def _get_workspace_rule_completions(self, uri: str) -> list[CompletionItem]:
        """Collect rule names from other workspace documents for cross-file completion."""
        items: list[CompletionItem] = []
        if not self.runtime:
            return items
        try:
            for doc in self.runtime.iter_workspace_documents():
                if doc.uri == uri:
                    continue
                # Extract source filename from URI
                source_filename = doc.uri.rsplit("/", 1)[-1] if "/" in doc.uri else doc.uri
                ast = doc.get_cached("ast")
                if ast is None:
                    from yaraast.lsp.language_services import parse_source

                    try:
                        ast = parse_source(doc.text)
                    except Exception:
                        logger.debug("Operation failed in %s", __name__, exc_info=True)
                        continue
                if ast is None:
                    continue
                for rule in getattr(ast, "rules", []):
                    rule_name = getattr(rule, "name", None)
                    if rule_name:
                        items.append(
                            CompletionItem(
                                label=rule_name,
                                detail=f"Rule ({source_filename})",
                                kind=CompletionItemKind.Class,
                                insert_text=rule_name,
                            )
                        )
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
        return items

    def _get_meta_completions(self) -> list[CompletionItem]:
        """Get completions for meta section."""
        common_meta_keys = [
            ("author", "Rule author name"),
            ("description", "Rule description"),
            ("date", "Rule creation date"),
            ("version", "Rule version"),
            ("reference", "External reference or link"),
            ("hash", "Sample hash"),
            ("sample", "Sample filename"),
            ("tlp", "Traffic Light Protocol classification"),
        ]

        items = []
        for key, description in common_meta_keys:
            items.append(
                CompletionItem(
                    label=key,
                    kind=CompletionItemKind.Property,
                    detail="Meta field",
                    documentation=description,
                    insert_text=f'{key} = "$0"',
                    insert_text_format=InsertTextFormat.Snippet,
                )
            )

        return items
