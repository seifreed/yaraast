from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_hover_provider_supports_yaral_rule_metadata_and_sections() -> None:
    text = """
rule detect_login {
    meta:
        author = "sec"
        severity = "high"
    events:
        $e.metadata.event_type = "USER_LOGIN"
    match:
        $e over 5m
    condition:
        #e > 5
    outcome:
        $risk_score = 80
}

rule wrapper {
    condition:
        detect_login
}
""".lstrip()
    runtime = LspRuntime()
    uri = "file:///yaral_rule.yar"
    runtime.open_document(uri, text)
    provider = HoverProvider(runtime)

    hover = provider.get_hover(text, _pos(16, 10), uri)
    assert hover is not None
    value = hover.contents.value
    assert "**detect_login**" in value
    assert "Metadata" in value
    assert "**YARA-L:** events section present" in value
    assert "**YARA-L:** match section present" in value
    assert "**YARA-L:** outcome section present" in value


def test_definition_references_and_rename_work_for_yaral_rules_cross_file(tmp_path: Path) -> None:
    common = tmp_path / "common.yar"
    user = tmp_path / "user.yar"
    common.write_text(
        """
rule detect_login {
    events:
        $e.metadata.event_type = "USER_LOGIN"
    condition:
        #e > 5
}
""".lstrip(),
        encoding="utf-8",
    )
    user.write_text(
        """
rule wrapper {
    condition:
        detect_login
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yaral"}})
    runtime.set_workspace_folders([str(tmp_path)])

    uri = path_to_uri(user)
    text = user.read_text(encoding="utf-8")

    definition = DefinitionProvider(runtime).get_definition(text, _pos(2, 10), uri)
    assert definition is not None
    assert definition.uri == path_to_uri(common)

    records = ReferencesProvider(runtime).get_reference_records(text, _pos(2, 10), uri)
    assert {record.role for record in records} == {"declaration", "use"}
    assert {record.location.uri for record in records} == {path_to_uri(common), uri}

    edit = RenameProvider(runtime).rename(text, _pos(2, 10), "detect_login_new", uri)
    assert edit is not None and edit.changes is not None
    assert set(edit.changes) == {path_to_uri(common), uri}


def test_definition_and_hover_work_for_yarax_rule() -> None:
    text = """
rule helper { condition: true }
rule sample {
  condition:
    with $x = 1:
      helper
}
""".lstrip()
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yarax"}})
    uri = "file:///yarax_rule.yar"
    runtime.open_document(uri, text)

    definition = DefinitionProvider(runtime).get_definition(text, _pos(4, 8), uri)
    assert definition is not None
    assert definition.range.start.line == 0

    hover = HoverProvider(runtime).get_hover(text, _pos(4, 8), uri)
    assert hover is not None
    assert "**helper**" in hover.contents.value
