"""Additional real tests for LSP code actions."""

from __future__ import annotations

from lsprotocol.types import CodeActionKind, Diagnostic, Position, Range, TextEdit, WorkspaceEdit

from yaraast.lsp.code_actions import CodeActionsProvider
from yaraast.lsp.diagnostics import DiagnosticData, DiagnosticPatch
from yaraast.lsp.utf16 import utf8_col_to_utf16


def _range(line: int, start: int, end: int) -> Range:
    return Range(start=Position(line=line, character=start), end=Position(line=line, character=end))


def _change_set(edit: WorkspaceEdit, uri: str) -> list[TextEdit]:
    changes = edit.changes
    assert changes is not None
    return list(changes[uri])


def test_code_action_helpers_handle_unmatched_messages_and_missing_sections() -> None:
    provider = CodeActionsProvider()
    uri = "file://test.yar"

    no_match_diag = Diagnostic(range=_range(0, 0, 1), message="undefined variable payload")
    assert (
        provider._create_add_string_actions("rule a { condition: true }", no_match_diag, uri) == []
    )

    no_strings_diag = Diagnostic(range=_range(0, 0, 1), message="undefined variable $payload")
    assert (
        provider._create_add_string_actions("rule a { condition: $payload }", no_strings_diag, uri)
        == []
    )

    bad_import_diag = Diagnostic(range=_range(0, 0, 1), message="missing module pe")
    assert (
        provider._create_import_module_actions("rule a { condition: true }", bad_import_diag, uri)
        == []
    )

    bad_rename_diag = Diagnostic(range=_range(0, 0, 1), message="Duplicate string identifier a")
    assert (
        provider._create_rename_duplicate_actions(
            "rule a { condition: true }", bad_rename_diag, uri
        )
        == []
    )


def test_code_action_rename_duplicate_skips_existing_suffixes_and_bad_positions() -> None:
    provider = CodeActionsProvider()
    uri = "file://test.yar"

    text = """
rule a {
  strings:
    $a = "x"
    $a_2 = "y"
    $a = "z"
  condition:
    $a
}
""".lstrip()
    diag = Diagnostic(range=_range(4, 4, 6), message="Duplicate string identifier '$a'")
    actions = provider._create_rename_duplicate_actions(text, diag, uri)
    assert actions
    assert actions[0].title == "Rename to $a_3"

    off_range_diag = Diagnostic(range=_range(99, 0, 1), message="Duplicate string identifier '$a'")
    assert provider._create_rename_duplicate_actions(text, off_range_diag, uri) == []

    wrong_line_diag = Diagnostic(range=_range(0, 0, 1), message="Duplicate string identifier '$a'")
    assert (
        provider._create_rename_duplicate_actions(
            "rule a { condition: true }", wrong_line_diag, uri
        )
        == []
    )


def test_code_action_rename_duplicate_targets_diagnostic_occurrence_on_same_line() -> None:
    provider = CodeActionsProvider()
    uri = "file://test.yar"
    text = 'rule a { strings: $a = "x" $a_2 = "y" $a = "z" condition: true }'
    duplicate_start = text.rindex("$a")
    diag = Diagnostic(
        range=_range(0, duplicate_start, duplicate_start + len("$a")),
        message="Duplicate string identifier '$a'",
    )

    actions = provider._create_rename_duplicate_actions(text, diag, uri)

    assert actions
    assert actions[0].title == "Rename to $a_3"
    assert actions[0].edit is not None
    change = _change_set(actions[0].edit, uri)[0]
    assert change.range.start.character == duplicate_start
    assert change.new_text == "$a_3"


def test_code_action_refactoring_bounds_checks() -> None:
    provider = CodeActionsProvider()

    assert (
        provider._is_in_condition("rule a { condition: true }", Position(line=99, character=0))
        is False
    )
    assert (
        provider._is_in_condition(
            'rule a {\n  strings:\n    $a = "x"\n}\n', Position(line=2, character=4)
        )
        is False
    )
    assert provider._is_in_condition("free text only", Position(line=0, character=0)) is False


def test_code_action_structured_patches() -> None:
    provider = CodeActionsProvider()
    diag = Diagnostic(
        range=_range(0, 0, 1),
        message="Module 'pe' not imported",
        data=DiagnosticData(
            code="semantic.module_not_imported",
            severity="error",
            error_type="semantic",
            patches=[DiagnosticPatch(_range(0, 0, 0), 'import "pe"\n')],
        ).to_dict(),
    )

    actions = provider._create_structured_actions(diag, "file://test.yar")
    assert actions
    assert actions[0].edit is not None
    assert _change_set(actions[0].edit, "file://test.yar")[0].new_text == 'import "pe"\n'


def test_code_action_structured_patches_accept_serialized_ranges_and_skip_heuristics() -> None:
    provider = CodeActionsProvider()
    diag = Diagnostic(
        range=_range(0, 0, 1),
        message="Module 'pe' not imported",
        data={
            "code": "semantic.module_not_imported",
            "severity": "error",
            "error_type": "semantic",
            "patches": [
                {
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 0},
                    },
                    "replacement": 'import "pe"\n',
                }
            ],
        },
    )

    actions = provider.get_code_actions(
        'rule a { condition: pe.imphash() == "x" }',
        _range(0, 0, 1),
        [diag],
        "file://test.yar",
    )
    quickfixes = [action for action in actions if action.kind == CodeActionKind.QuickFix]
    assert len(quickfixes) == 1
    assert quickfixes[0].edit is not None
    assert _change_set(quickfixes[0].edit, "file://test.yar")[0].new_text == 'import "pe"\n'


def test_code_action_structured_patches_reject_negative_serialized_ranges() -> None:
    provider = CodeActionsProvider()
    diag = Diagnostic(
        range=_range(0, 0, 1),
        message="Module 'pe' not imported",
        data={
            "patches": [
                {
                    "range": {
                        "start": {"line": -1, "character": 0},
                        "end": {"line": 0, "character": 0},
                    },
                    "replacement": 'import "pe"\n',
                }
            ],
        },
    )

    assert provider._create_structured_actions(diag, "file://test.yar") == []


def test_code_action_structured_patches_reject_boolean_serialized_ranges() -> None:
    provider = CodeActionsProvider()
    diag = Diagnostic(
        range=_range(0, 0, 1),
        message="Module 'pe' not imported",
        data={
            "patches": [
                {
                    "range": {
                        "start": {"line": True, "character": 0},
                        "end": {"line": True, "character": 0},
                    },
                    "replacement": 'import "pe"\n',
                }
            ],
        },
    )

    assert provider._create_structured_actions(diag, "file://test.yar") == []


def test_code_action_uses_structured_metadata_for_import_without_message_regex() -> None:
    provider = CodeActionsProvider()
    diag = Diagnostic(
        range=_range(0, 0, 1),
        message="module missing",
        data={
            "code": "semantic.module_not_imported",
            "severity": "error",
            "error_type": "semantic",
            "metadata": {"module": "pe"},
        },
    )

    actions = provider.get_code_actions(
        'rule a { condition: pe.imphash() == "x" }',
        _range(0, 0, 1),
        [diag],
        "file://test.yar",
    )
    assert actions
    assert actions[0].title == 'Add import "pe"'


def test_code_action_uses_structured_metadata_for_duplicate_identifier_without_message_regex() -> (
    None
):
    provider = CodeActionsProvider()
    text = """
rule a {
  strings:
    $a = "x"
    $a = "y"
  condition:
    $a
}
""".lstrip()
    diag = Diagnostic(
        range=_range(3, 4, 6),
        message="duplicate",
        data={
            "code": "semantic.duplicate_string_identifier",
            "severity": "error",
            "error_type": "semantic",
            "metadata": {"identifier": "$a"},
        },
    )

    actions = provider.get_code_actions(text, _range(3, 4, 6), [diag], "file://test.yar")
    assert actions
    assert actions[0].title == "Rename to $a_2"


def test_code_action_uses_structured_metadata_for_missing_string_without_message_regex() -> None:
    provider = CodeActionsProvider()
    text = """
rule a {
  condition:
    $payload
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 4, 12),
        message="missing string",
        data={
            "code": "semantic.undefined_string_identifier",
            "severity": "error",
            "error_type": "semantic",
            "metadata": {"identifier": "$payload"},
        },
    )

    actions = provider.get_code_actions(text, _range(2, 4, 12), [diag], "file://test.yar")
    assert actions
    assert actions[0].title.startswith("Add string definition for $payload")


def test_authoring_actions_include_structured_preview_data() -> None:
    provider = CodeActionsProvider()
    text = """
rule demo {
    strings:
        $a = "abc"
        $b = "abc"
    condition:
        $a or $b
}
""".lstrip()

    actions = provider.get_code_actions(text, _range(4, 8, 17), [], "file://test.yar")
    action = next(
        action for action in actions if action.title.startswith("Deduplicate identical strings")
    )
    assert action.data is not None
    assert action.data["provider"] == "authoring"
    assert "Merged duplicates:" in action.data["preview"]


def test_code_action_uses_structured_metadata_for_unknown_function_without_message_regex() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint33(0)
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 14),
        message="Unknown function uint33",
        data=DiagnosticData(
            code="semantic.unknown_function",
            severity="error",
            error_type="semantic",
            metadata={"function": "uint33", "suggested_functions": ["uint32", "uint16"]},
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 14), [diag], "file://test.yar")
    titles = {action.title for action in actions}
    assert "Replace with uint32()" in titles


def test_code_action_ignores_empty_unknown_function_metadata() -> None:
    provider = CodeActionsProvider()
    diag = Diagnostic(
        range=_range(0, 0, 1),
        message="Unknown function",
        data=DiagnosticData(
            code="semantic.unknown_function",
            severity="error",
            error_type="semantic",
            metadata={"function": "", "suggested_functions": ["uint32"]},
        ).to_dict(),
    )

    assert provider._create_semantic_actions("uint8(0)", diag, "file://test.yar") == []


def test_code_action_replace_builtin_targets_diagnostic_occurrence() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint33(0) and uint33(1)
}
""".lstrip()
    call_line = text.splitlines()[2]
    call_start = call_line.rindex("uint33")
    diag = Diagnostic(
        range=_range(2, call_start, call_start + len("uint33")),
        message="Unknown function uint33",
        data=DiagnosticData(
            code="semantic.unknown_function",
            severity="error",
            error_type="semantic",
            metadata={"function": "uint33", "suggested_functions": ["uint32"]},
        ).to_dict(),
    )

    actions = provider.get_code_actions(
        text, _range(2, call_start, call_start + len("uint33")), [diag], "file://test.yar"
    )
    action = next(action for action in actions if action.title == "Replace with uint32()")
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.range.start.character == call_start
    assert change.new_text == "uint32"


def test_code_action_replace_builtin_ranges_use_utf16_columns() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        /* 😀😀 */ uint33(0)
}
""".lstrip()
    call_line = text.splitlines()[2]
    call_start = call_line.index("uint33")
    diag_range = _range(
        2,
        utf8_col_to_utf16(call_line, call_start),
        utf8_col_to_utf16(call_line, call_start + len("uint33")),
    )
    diag = Diagnostic(
        range=diag_range,
        message="Unknown function uint33",
        data=DiagnosticData(
            code="semantic.unknown_function",
            severity="error",
            error_type="semantic",
            metadata={"function": "uint33", "suggested_functions": ["uint32"]},
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, diag_range, [diag], "file://test.yar")

    action = next(action for action in actions if action.title == "Replace with uint32()")
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.range.start.character == utf8_col_to_utf16(call_line, call_start)
    assert change.range.end.character == utf8_col_to_utf16(
        call_line,
        call_start + len("uint33"),
    )
    assert change.new_text == "uint32"


def test_code_action_replace_module_function_targets_diagnostic_occurrence() -> None:
    provider = CodeActionsProvider()
    text = """
import "pe"
rule sample {
    condition:
        pe.unknown(0) and pe.unknown(1)
}
""".lstrip()
    call_line = text.splitlines()[3]
    call_start = call_line.rindex("pe.unknown")
    diag = Diagnostic(
        range=_range(3, call_start, call_start + len("pe.unknown")),
        message="Unknown module function pe.unknown",
        data=DiagnosticData(
            code="semantic.module_function_not_found",
            severity="error",
            error_type="semantic",
            metadata={
                "module": "pe",
                "function": "unknown",
                "available_functions": ["is_pe"],
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(
        text, _range(3, call_start, call_start + len("pe.unknown")), [diag], "file://test.yar"
    )
    action = next(action for action in actions if action.title == "Replace with pe.is_pe")
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.range.start.character == call_start
    assert change.new_text == "pe.is_pe"


def test_code_action_uses_structured_metadata_for_exact_arity_without_message_regex() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint8()
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 13),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "uint8",
                "arity_kind": "exact",
                "actual_args": 0,
                "expected_args": 1,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 13), [diag], "file://test.yar")
    titles = {action.title for action in actions}
    assert "Add 1 missing argument(s) to uint8()" in titles


def test_code_action_ignores_boolean_arity_metadata() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint8()
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 13),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "uint8",
                "arity_kind": "exact",
                "actual_args": False,
                "expected_args": True,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 13), [diag], "file://test.yar")

    assert all("uint8()" not in action.title for action in actions)


def test_code_action_add_missing_argument_uses_outer_call_close() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        custom(inner(1, 2))
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 28),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "custom",
                "arity_kind": "exact",
                "actual_args": 1,
                "expected_args": 2,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 28), [diag], "file://test.yar")
    action = next(
        action for action in actions if action.title == "Add 1 missing argument(s) to custom()"
    )
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.new_text == ", 0"
    assert change.range.start.character == text.splitlines()[2].rfind(")")


def test_code_action_add_missing_argument_targets_diagnostic_call() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        custom(1) and custom(2)
}
""".lstrip()
    call_line = text.splitlines()[2]
    call_start = call_line.rindex("custom(")
    call_end = call_line.index(")", call_start) + 1
    diag = Diagnostic(
        range=_range(2, call_start, call_end),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "custom",
                "arity_kind": "exact",
                "actual_args": 1,
                "expected_args": 2,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(
        text, _range(2, call_start, call_end), [diag], "file://test.yar"
    )
    action = next(
        action for action in actions if action.title == "Add 1 missing argument(s) to custom()"
    )
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.range.start.character == call_end - 1
    assert change.new_text == ", 0"


def test_code_action_add_placeholder_targets_diagnostic_call() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint8() and uint8()
}
""".lstrip()
    call_line = text.splitlines()[2]
    call_start = call_line.rindex("uint8(")
    call_end = call_line.index(")", call_start) + 1
    diag = Diagnostic(
        range=_range(2, call_start, call_end),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "uint8",
                "arity_kind": "min",
                "actual_args": 0,
                "expected_min": 1,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(
        text, _range(2, call_start, call_end), [diag], "file://test.yar"
    )
    action = next(
        action for action in actions if action.title == "Add placeholder argument to uint8()"
    )
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.range.start.character == call_end - 1
    assert change.new_text == "0"


def test_code_action_uses_structured_metadata_to_trim_extra_arguments() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint8(1, 2)
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 19),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "uint8",
                "arity_kind": "max",
                "actual_args": 2,
                "expected_max": 1,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 19), [diag], "file://test.yar")
    action = next(
        action for action in actions if action.title == "Remove extra argument(s) from uint8()"
    )
    assert action.edit is not None
    assert _change_set(action.edit, "file://test.yar")[0].new_text == "1"


def test_code_action_trim_arguments_targets_diagnostic_call() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        uint8(1, 2) and uint8(3, 4)
}
""".lstrip()
    call_line = text.splitlines()[2]
    call_start = call_line.rindex("uint8(")
    call_end = call_line.index(")", call_start) + 1
    diag = Diagnostic(
        range=_range(2, call_start, call_end),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "uint8",
                "arity_kind": "max",
                "actual_args": 2,
                "expected_max": 1,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(
        text, _range(2, call_start, call_end), [diag], "file://test.yar"
    )
    action = next(
        action for action in actions if action.title == "Remove extra argument(s) from uint8()"
    )
    assert action.edit is not None
    change = _change_set(action.edit, "file://test.yar")[0]
    assert change.range.start.character == call_start + len("uint8(")
    assert change.new_text == "3"


def test_code_action_trim_arguments_preserves_commas_inside_strings() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        custom("a,b", 1)
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 24),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "custom",
                "arity_kind": "max",
                "actual_args": 2,
                "expected_max": 1,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 24), [diag], "file://test.yar")
    action = next(
        action for action in actions if action.title == "Remove extra argument(s) from custom()"
    )
    assert action.edit is not None
    assert _change_set(action.edit, "file://test.yar")[0].new_text == '"a,b"'


def test_code_action_trim_arguments_preserves_commas_inside_matches_regex() -> None:
    provider = CodeActionsProvider()
    text = """
rule sample {
    condition:
        custom("abc" matches /a,b/, 1)
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 8, 37),
        message="arity",
        data=DiagnosticData(
            code="semantic.invalid_arity",
            severity="error",
            error_type="semantic",
            metadata={
                "function": "custom",
                "arity_kind": "max",
                "actual_args": 2,
                "expected_max": 1,
            },
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 8, 37), [diag], "file://test.yar")
    action = next(
        action for action in actions if action.title == "Remove extra argument(s) from custom()"
    )
    assert action.edit is not None
    assert _change_set(action.edit, "file://test.yar")[0].new_text == '"abc" matches /a,b/'


def test_code_action_uses_compiler_undefined_identifier_metadata_for_missing_string() -> None:
    provider = CodeActionsProvider()
    text = """
rule a {
  condition:
    $payload
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 4, 12),
        message='Compilation error: undefined identifier "$payload"',
        data=DiagnosticData(
            code="compiler.undefined_identifier",
            severity="error",
            error_type="compiler",
            metadata={"identifier": "$payload"},
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 4, 12), [diag], "file://test.yar")
    assert any(action.title.startswith("Add string definition for $payload") for action in actions)


def test_code_action_uses_compiler_undefined_identifier_metadata_for_missing_module_import() -> (
    None
):
    provider = CodeActionsProvider()
    text = """
rule a {
  condition:
    pe.is_pe
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 4, 6),
        message='Compilation error: undefined identifier "pe"',
        data=DiagnosticData(
            code="compiler.module_not_imported",
            severity="error",
            error_type="compiler",
            metadata={"identifier": "pe", "module": "pe"},
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 4, 6), [diag], "file://test.yar")
    assert any(action.title == 'Add import "pe"' for action in actions)


def test_code_action_uses_compiler_dotted_identifier_metadata_for_missing_module_import() -> None:
    provider = CodeActionsProvider()
    text = """
rule a {
  condition:
    pe.is_pe
}
""".lstrip()
    diag = Diagnostic(
        range=_range(2, 4, 12),
        message='Compilation error: undefined identifier "pe.is_pe"',
        data=DiagnosticData(
            code="compiler.module_not_imported",
            severity="error",
            error_type="compiler",
            metadata={"identifier": "pe.is_pe", "module": "pe", "member": "is_pe"},
        ).to_dict(),
    )

    actions = provider.get_code_actions(text, _range(2, 4, 12), [diag], "file://test.yar")
    assert any(action.title == 'Add import "pe"' for action in actions)
