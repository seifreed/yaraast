"""Document links provider for YARAAST LSP."""

from __future__ import annotations

import logging
import re
from typing import Any

from lsprotocol.types import DocumentLink, Position, Range

from yaraast.lsp.runtime import DocumentContext, LspRuntime, SymbolRecord
from yaraast.lsp.utf16 import utf8_col_to_utf16

logger = logging.getLogger(__name__)

IMPORT_DIRECTIVE_RE = re.compile(r'^\s*import\s+"(?P<value>(?:\\.|[^"\\])*)"')
INCLUDE_DIRECTIVE_RE = re.compile(r'^\s*include\s+"(?P<value>(?:\\.|[^"\\])*)"')


def _link_key(link: DocumentLink) -> tuple[int, int, int, int, str | None, str | None]:
    return (
        link.range.start.line,
        link.range.start.character,
        link.range.end.line,
        link.range.end.character,
        link.target,
        link.tooltip,
    )


class DocumentLinksProvider:
    """Provide document links for imports and includes."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        """Initialize document links provider."""
        self.runtime = runtime
        # YARA module documentation URLs
        self.module_docs = {
            "pe": "https://yara.readthedocs.io/en/stable/modules/pe.html",
            "elf": "https://yara.readthedocs.io/en/stable/modules/elf.html",
            "cuckoo": "https://yara.readthedocs.io/en/stable/modules/cuckoo.html",
            "hash": "https://yara.readthedocs.io/en/stable/modules/hash.html",
            "math": "https://yara.readthedocs.io/en/stable/modules/math.html",
            "dotnet": "https://yara.readthedocs.io/en/stable/modules/dotnet.html",
            "time": "https://yara.readthedocs.io/en/stable/modules/time.html",
            "console": "https://yara.readthedocs.io/en/stable/modules/console.html",
        }

    def get_document_links(self, text: str, document_uri: str) -> list[DocumentLink]:
        """Get all document links in the file."""
        if not isinstance(text, str):
            msg = "Document links text must be a string"
            raise TypeError(msg)
        if not isinstance(document_uri, str):
            msg = "Document links URI must be a string"
            raise TypeError(msg)

        links = []

        try:
            if self.runtime and document_uri:
                doc = self.runtime.ensure_document(document_uri, text)
                try:
                    symbol_records = doc.symbols()
                except Exception:
                    logger.debug("Operation failed in %s", __name__, exc_info=True)
                    symbol_records = []
                links.extend(self._create_runtime_symbol_links(doc, symbol_records))
                links.extend(self._create_rule_reference_links(document_uri))
                self._append_fallback_links(links, text, document_uri)
                return links
            doc = DocumentContext(document_uri, text)
            symbol_records = doc.symbols()
            links.extend(self._create_runtime_symbol_links(doc, symbol_records))
            links.extend(self._create_local_rule_reference_links(doc))
            self._append_fallback_links(links, text, document_uri)

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            # Fallback to regex-based link detection
            links.extend(self._fallback_links(text, document_uri))

        return links

    def _create_runtime_symbol_links(
        self,
        doc: Any,
        symbol_records: list[SymbolRecord],
    ) -> list[DocumentLink]:
        links: list[DocumentLink] = []
        for record in symbol_records:
            if record.kind == "import":
                url = self.module_docs.get(record.name)
                if url:
                    links.append(
                        DocumentLink(
                            range=record.range,
                            target=url,
                            tooltip=f"Open documentation for {record.name} module",
                        )
                    )
            elif record.kind == "include":
                target_uri = doc.get_include_target_uri(record.name)
                if target_uri:
                    links.append(
                        DocumentLink(
                            range=record.range,
                            target=target_uri,
                            tooltip=f"Open {record.name}",
                        )
                    )
        return links

    def _create_rule_reference_links(self, document_uri: str) -> list[DocumentLink]:
        if self.runtime is None:
            return []

        links: list[DocumentLink] = []
        for record in self.runtime.get_rule_link_records_for_document(document_uri):
            links.append(
                DocumentLink(
                    range=record.location.range,
                    target=record.target_uri,
                    tooltip=f"Go to rule {record.rule_name}",
                )
            )
        return links

    def _create_local_rule_reference_links(self, doc: DocumentContext) -> list[DocumentLink]:
        links: list[DocumentLink] = []
        for record in doc.get_local_rule_link_records():
            links.append(
                DocumentLink(
                    range=record.location.range,
                    target=record.target_uri,
                    tooltip=f"Go to rule {record.rule_name}",
                )
            )
        return links

    def _append_fallback_links(
        self,
        links: list[DocumentLink],
        text: str,
        document_uri: str,
    ) -> None:
        seen = {_link_key(link) for link in links}
        for link in self._fallback_links(text, document_uri):
            key = _link_key(link)
            if key in seen:
                continue
            links.append(link)
            seen.add(key)

    def _fallback_links(self, text: str, document_uri: str) -> list[DocumentLink]:
        """Fallback regex-based link detection."""
        links = []
        lines = text.split("\n")
        doc = DocumentContext(document_uri, text)

        for line_num, line in enumerate(lines):
            import_match = IMPORT_DIRECTIVE_RE.match(line)
            if import_match:
                module_name = import_match.group("value")
                url = self.module_docs.get(module_name)
                if url:
                    links.append(
                        DocumentLink(
                            range=Range(
                                start=Position(
                                    line=line_num,
                                    character=utf8_col_to_utf16(line, import_match.start("value")),
                                ),
                                end=Position(
                                    line=line_num,
                                    character=utf8_col_to_utf16(line, import_match.end("value")),
                                ),
                            ),
                            target=url,
                            tooltip=f"Open documentation for {module_name} module",
                        )
                    )
                continue

            include_match = INCLUDE_DIRECTIVE_RE.match(line)
            if include_match:
                include_path = include_match.group("value")
                target_uri = doc.get_include_target_uri(include_path)
                if target_uri:
                    links.append(
                        DocumentLink(
                            range=Range(
                                start=Position(
                                    line=line_num,
                                    character=utf8_col_to_utf16(line, include_match.start("value")),
                                ),
                                end=Position(
                                    line=line_num,
                                    character=utf8_col_to_utf16(line, include_match.end("value")),
                                ),
                            ),
                            target=target_uri,
                            tooltip=f"Open {include_path}",
                        )
                    )

        return links
