"""Additional coverage for base AST nodes."""

from __future__ import annotations

from yaraast.ast.base import YaraFile


class _Visitor:
    def visit_yara_file(self, node: YaraFile) -> tuple[str, int, int]:
        return ("yara_file", len(node.rules), len(node.pragmas))


def test_yarafile_accept_and_pragma_lookup_paths() -> None:
    file_node = YaraFile()
    visitor = _Visitor()
    assert file_node.accept(visitor) == ("yara_file", 0, 0)
