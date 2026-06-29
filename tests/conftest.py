from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)


WINDOWS_POSIX_ONLY_TESTS = {
    "test_ast_benchmarker_reports_inaccessible_file_paths",
    "test_ast_differ_reports_inaccessible_file_path",
    "test_ast_formatter_rejects_inaccessible_paths",
    "test_build_diff_output_path_rejects_inaccessible_output_path",
    "test_cli_utils_rejects_inaccessible_paths",
    "test_definition_include_target_ignores_inaccessible_paths",
    "test_display_export_import_reject_inaccessible_output_path",
    "test_export_graph_files_ioerror_during_write_fails_job",
    "test_file_io_helpers_reject_inaccessible_paths",
    "test_find_rule_reference_records_in_document_get_document_returns_none_for_unreadable",
    "test_find_rule_reference_records_in_document_unreadable_file_returns_empty",
    "test_fmt_cmd_rejects_inaccessible_output",
    "test_format_command_rejects_inaccessible_output_file",
    "test_get_document_returns_none_when_read_fails",
    "test_get_include_target_uri_resolves_existing_file",
    "test_graph_dot_all_types_unwritable_output_reraises",
    "test_graph_dot_format_unwritable_output_does_not_produce_graphviz_text",
    "test_graph_dot_format_unwritable_output_propagates_permission_error",
    "test_handle_watched_files_read_failure_clears_document",
    "test_hover_provider_uses_structured_include_resolution_from_runtime",
    "test_include_resolver_rejects_absolute_includes",
    "test_include_resolver_rejects_inaccessible_paths",
    "test_iter_workspace_documents_skips_unreadable_index_file",
    "test_lsp_path_helpers_reject_empty_workspace_paths",
    "test_lsp_root_path_file_uri_is_normalized",
    "test_module_loader_rejects_inaccessible_env_spec_paths",
    "test_optimize_command_rejects_inaccessible_output_path",
    "test_os_error_raised_as_value_error",
    "test_os_error_returns_false",
    "test_path_access_error_returns_module_spec_error",
    "test_path_exists_oserror_raises_module_spec_error",
    "test_path_is_dir_oserror_branch_via_private_helper",
    "test_path_is_dir_oserror_converted_to_value_error",
    "test_path_is_dir_oserror_raises_module_spec_error",
    "test_path_is_dir_raises_value_error_on_os_error_from_name_too_long",
    "test_path_is_dir_raises_value_error_on_permission_denied",
    "test_path_is_file_oserror_converted_to_value_error",
    "test_patterns_dot_all_types_unwritable_output_reraises",
    "test_patterns_dot_format_unwritable_output_no_text_analysis_fallback",
    "test_patterns_dot_format_unwritable_output_propagates_permission_error",
    "test_performance_services_reject_inaccessible_paths",
    "test_read_test_data_raises_validation_error_on_unreadable_file",
    "test_read_utf8_permission_denied_raises_value_error",
    "test_register_server_features_and_initialize_handlers",
    "test_related_info_returns_list_when_location_file_is_present",
    "test_resolve_include_target_uri_keeps_symlinked_ancestor_path",
    "test_resolve_output_path_raises_for_inaccessible_path",
    "test_roundtrip_display_helpers_reject_inaccessible_output_path",
    "test_unreadable_directory_causes_oserror_wrapped_as_value_error",
    "test_validate_output_dir_path_raises_for_inaccessible_path",
    "test_value_error_wraps_original_os_error",
    "test_workspace_index_treats_inaccessible_workspace_folders_as_empty",
    "test_workspace_normalizes_file_uri_root_path",
    "test_workspace_rejects_inaccessible_root_path",
    "test_workspace_symbols_empty_and_exception_paths",
    "test_workspace_symbols_normalize_file_uri_workspace_root",
    "test_workspace_symbols_rejects_inaccessible_workspace_root",
}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if sys.platform != "win32":
        return

    marker = pytest.mark.skip(reason="POSIX-only path permission semantics")
    for item in items:
        name = item.originalname or item.name
        if name in WINDOWS_POSIX_ONLY_TESTS:
            item.add_marker(marker)
