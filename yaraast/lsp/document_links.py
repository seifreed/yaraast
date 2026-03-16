"""Document links provider for YARAAST LSP."""

from __future__ import annotations

from typing import Any

from lsprotocol.types import DocumentLink, Position, Range

from yaraast.lsp.runtime import DocumentContext, LspRuntime, SymbolRecord


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
            "magic": "https://yara.readthedocs.io/en/stable/modules/magic.html",
            "hash": "https://yara.readthedocs.io/en/stable/modules/hash.html",
            "math": "https://yara.readthedocs.io/en/stable/modules/math.html",
            "dotnet": "https://yara.readthedocs.io/en/stable/modules/dotnet.html",
            "time": "https://yara.readthedocs.io/en/stable/modules/time.html",
            "console": "https://yara.readthedocs.io/en/stable/modules/console.html",
        }

    def get_document_links(self, text: str, document_uri: str) -> list[DocumentLink]:
        """Get all document links in the file."""
        links = []

        try:
            if self.runtime and document_uri:
                doc = self.runtime.ensure_document(document_uri, text)
                symbol_records = doc.symbols()
                links.extend(self._create_runtime_symbol_links(doc, symbol_records))
                links.extend(self._create_rule_reference_links(document_uri))
                return links
            doc = DocumentContext(document_uri, text)
            symbol_records = doc.symbols()
            if not symbol_records and doc.parse_error() is not None:
                return self._fallback_links(text, document_uri)
            links.extend(self._create_runtime_symbol_links(doc, symbol_records))
            links.extend(self._create_local_rule_reference_links(doc))

        except Exception:
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

    def _fallback_links(self, text: str, document_uri: str) -> list[DocumentLink]:
        """Fallback regex-based link detection."""
        links = []
        lines = text.split("\n")
        doc = DocumentContext(document_uri, text)

        for line_num, line in enumerate(lines):
            # Look for import statements
            if "import" in line and '"' in line:
                start = line.find('"')
                end = line.find('"', start + 1)
                if start != -1 and end != -1:
                    module_name = line[start + 1 : end]
                    url = self.module_docs.get(module_name)
                    if url:
                        links.append(
                            DocumentLink(
                                range=Range(
                                    start=Position(line=line_num, character=start + 1),
                                    end=Position(line=line_num, character=end),
                                ),
                                target=url,
                                tooltip=f"Open documentation for {module_name} module",
                            )
                        )

            # Look for include statements
            elif "include" in line and '"' in line:
                start = line.find('"')
                end = line.find('"', start + 1)
                if start != -1 and end != -1:
                    include_path = line[start + 1 : end]
                    target_uri = doc.get_include_target_uri(include_path)
                    if target_uri:
                        links.append(
                            DocumentLink(
                                range=Range(
                                    start=Position(line=line_num, character=start + 1),
                                    end=Position(line=line_num, character=end),
                                ),
                                target=target_uri,
                                tooltip=f"Open {include_path}",
                            )
                        )

        return links
