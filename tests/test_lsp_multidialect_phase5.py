from __future__ import annotations

from lsprotocol.types import Position

from yaraast.dialects import YaraDialect
from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.symbols import SymbolsProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_runtime_auto_detects_yaral_dialect() -> None:
    text = """
rule basic_detection {
    meta:
        author = "Security Team"
    events:
        $e.metadata.event_type = "USER_LOGIN"
    condition:
        #e > 5
}
""".lstrip()
    runtime = LspRuntime()
    uri = "file:///basic.yar"

    doc = runtime.open_document(uri, text)
    ast = doc.ast()

    assert ast is not None
    assert doc.dialect() == YaraDialect.YARA_L
    assert getattr(ast.rules[0], "events", None) is not None


def test_runtime_respects_forced_dialect_mode_from_config() -> None:
    text = "rule sample { condition: true }\n"
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yarax"}})
    uri = "file:///sample.yar"

    doc = runtime.open_document(uri, text)

    assert doc.language_mode.value == "yarax"
    assert doc.dialect() == YaraDialect.YARA_X
    assert doc.ast() is not None


def test_completion_provider_uses_yaral_keywords_from_runtime() -> None:
    text = """
rule basic_detection {
    events:
        $e.metadata.event_type = "USER_LOGIN"
    condition:
        #e > 5
}
""".lstrip()
    runtime = LspRuntime()
    uri = "file:///basic.yar"
    runtime.open_document(uri, text)
    provider = CompletionProvider(runtime)

    completions = provider.get_completions(text, _pos(0, 0), uri)
    labels = {item.label for item in completions.items}

    assert "events" in labels
    assert "outcome" in labels
    assert "match" in labels


def test_completion_provider_uses_yarax_keywords_when_forced() -> None:
    text = "rule sample { condition: true }\n"
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yarax"}})
    uri = "file:///sample.yar"
    runtime.open_document(uri, text)
    provider = CompletionProvider(runtime)

    completions = provider.get_completions(text, _pos(0, 0), uri)
    labels = {item.label for item in completions.items}

    assert "with" in labels
    assert "lambda" in labels
    assert "match" in labels


def test_symbols_provider_exposes_yaral_sections() -> None:
    text = """
rule basic_detection {
    meta:
        author = "Security Team"
    events:
        $e.metadata.event_type = "USER_LOGIN"
    match:
        $e over 5m
    condition:
        #e > 5
    outcome:
        $risk_score = 80
    options:
        severity = "high"
}
""".lstrip()
    runtime = LspRuntime()
    uri = "file:///basic.yar"
    runtime.open_document(uri, text)
    provider = SymbolsProvider(runtime)

    symbols = provider.get_symbols(text, uri)
    assert len(symbols) == 1
    rule = symbols[0]
    child_names = {child.name for child in rule.children or []}
    assert {"meta", "events", "match", "condition", "outcome", "options"} <= child_names
