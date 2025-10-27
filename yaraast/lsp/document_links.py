"""Document links provider for YARAAST LSP."""

from pathlib import Path

from lsprotocol.types import DocumentLink, Position, Range

from yaraast.parser.parser import Parser


class DocumentLinksProvider:
    """Provide document links for imports and includes."""

    def __init__(self):
        """Initialize document links provider."""
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
            parser = Parser(text)
            ast = parser.parse()

            # Add links for imports
            for import_node in ast.imports:
                link = self._create_import_link(text, import_node)
                if link:
                    links.append(link)

            # Add links for includes
            for include_node in ast.includes:
                link = self._create_include_link(text, include_node, document_uri)
                if link:
                    links.append(link)

        except Exception:
            # Fallback to regex-based link detection
            links.extend(self._fallback_links(text, document_uri))

        return links

    def _create_import_link(self, text: str, import_node) -> DocumentLink | None:
        """Create a link for an import statement."""
        module_name = import_node.module

        # Get documentation URL for this module
        url = self.module_docs.get(module_name)
        if not url:
            return None

        # Find the import statement in the text
        lines = text.split("\n")
        for line_num, line in enumerate(lines):
            if f'import "{module_name}"' in line:
                # Find the position of the module name
                start_col = line.find(f'"{module_name}"') + 1  # Skip opening quote
                end_col = start_col + len(module_name)

                return DocumentLink(
                    range=Range(
                        start=Position(line=line_num, character=start_col),
                        end=Position(line=line_num, character=end_col),
                    ),
                    target=url,
                    tooltip=f"Open documentation for {module_name} module",
                )

        return None

    def _create_include_link(
        self, text: str, include_node, document_uri: str
    ) -> DocumentLink | None:
        """Create a link for an include statement."""
        include_path = include_node.path

        # Find the include statement in the text
        lines = text.split("\n")
        for line_num, line in enumerate(lines):
            if f'include "{include_path}"' in line:
                # Find the position of the path
                start_col = line.find(f'"{include_path}"') + 1  # Skip opening quote
                end_col = start_col + len(include_path)

                # Resolve the include path relative to current document
                target_uri = self._resolve_include_path(include_path, document_uri)
                if not target_uri:
                    return None

                return DocumentLink(
                    range=Range(
                        start=Position(line=line_num, character=start_col),
                        end=Position(line=line_num, character=end_col),
                    ),
                    target=target_uri,
                    tooltip=f"Open {include_path}",
                )

        return None

    def _resolve_include_path(self, include_path: str, document_uri: str) -> str | None:
        """Resolve an include path to an absolute file URI."""
        try:
            # Convert document URI to file path
            if document_uri.startswith("file://"):
                doc_path = Path(document_uri[7:])
            else:
                doc_path = Path(document_uri)

            # Resolve include path relative to document directory
            include_file = doc_path.parent / include_path

            if include_file.exists():
                return f"file://{include_file.resolve()}"

        except Exception:
            pass

        return None

    def _fallback_links(self, text: str, document_uri: str) -> list[DocumentLink]:
        """Fallback regex-based link detection."""
        links = []
        lines = text.split("\n")

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
                    target_uri = self._resolve_include_path(include_path, document_uri)
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
