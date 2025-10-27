"""Workspace symbols provider for YARAAST LSP."""

from pathlib import Path

from lsprotocol.types import Location, Position, Range, SymbolInformation, SymbolKind

from yaraast.parser.parser import Parser


class WorkspaceSymbolsProvider:
    """Provide workspace-wide symbol search."""

    def __init__(self):
        """Initialize workspace symbols provider."""
        self.symbol_cache = {}
        self.workspace_root = None

    def set_workspace_root(self, root_path: str):
        """Set the workspace root directory."""
        self.workspace_root = Path(root_path)

    def get_workspace_symbols(self, query: str) -> list[SymbolInformation]:
        """Search for symbols across the entire workspace."""
        if not self.workspace_root or not self.workspace_root.exists():
            return []

        symbols = []

        # Find all YARA files in workspace
        yara_files = list(self.workspace_root.rglob("*.yar")) + list(
            self.workspace_root.rglob("*.yara")
        )

        for yara_file in yara_files:
            try:
                # Get symbols from this file
                file_symbols = self._get_symbols_from_file(yara_file)

                # Filter by query (case-insensitive substring match)
                if query:
                    query_lower = query.lower()
                    file_symbols = [sym for sym in file_symbols if query_lower in sym.name.lower()]

                symbols.extend(file_symbols)

            except Exception:
                # Skip files that fail to parse
                continue

        return symbols

    def _get_symbols_from_file(self, file_path: Path) -> list[SymbolInformation]:
        """Extract all symbols from a YARA file."""
        # Check cache first
        cache_key = str(file_path)
        mtime = file_path.stat().st_mtime

        if cache_key in self.symbol_cache:
            cached_mtime, cached_symbols = self.symbol_cache[cache_key]
            if cached_mtime == mtime:
                return cached_symbols

        # Parse file and extract symbols
        symbols = []

        try:
            with open(file_path) as f:
                content = f.read()

            parser = Parser(content)
            ast = parser.parse()

            file_uri = f"file://{file_path.resolve()}"

            # Extract rule symbols
            for rule in ast.rules:
                rule_line = self._find_rule_line(content, rule.name)
                if rule_line is not None:
                    symbols.append(
                        SymbolInformation(
                            name=rule.name,
                            kind=SymbolKind.Class,  # Rules are like classes
                            location=Location(
                                uri=file_uri,
                                range=Range(
                                    start=Position(line=rule_line, character=0),
                                    end=Position(line=rule_line, character=len(rule.name) + 5),
                                ),
                            ),
                            container_name=file_path.name,
                        )
                    )

                    # Extract string symbols from rule
                    for string_def in rule.strings:
                        string_line = self._find_string_line(content, string_def.identifier)
                        if string_line is not None:
                            symbols.append(
                                SymbolInformation(
                                    name=string_def.identifier,
                                    kind=SymbolKind.Variable,
                                    location=Location(
                                        uri=file_uri,
                                        range=Range(
                                            start=Position(line=string_line, character=0),
                                            end=Position(
                                                line=string_line,
                                                character=len(string_def.identifier),
                                            ),
                                        ),
                                    ),
                                    container_name=f"{file_path.name} :: {rule.name}",
                                )
                            )

            # Cache results
            self.symbol_cache[cache_key] = (mtime, symbols)

        except Exception:
            # Return empty list if parsing fails
            pass

        return symbols

    def _find_rule_line(self, text: str, rule_name: str) -> int | None:
        """Find the line number where a rule is defined."""
        lines = text.split("\n")
        for line_num, line in enumerate(lines):
            if f"rule {rule_name}" in line or f"rule {rule_name}:" in line:
                return line_num
        return None

    def _find_string_line(self, text: str, string_id: str) -> int | None:
        """Find the line number where a string is defined."""
        lines = text.split("\n")
        for line_num, line in enumerate(lines):
            # Look for string definition like: $str = "value"
            if f"{string_id} =" in line or f"{string_id}=" in line:
                return line_num
        return None

    def clear_cache(self):
        """Clear the symbol cache."""
        self.symbol_cache.clear()

    def invalidate_file(self, file_path: str):
        """Invalidate cache for a specific file."""
        if file_path in self.symbol_cache:
            del self.symbol_cache[file_path]
