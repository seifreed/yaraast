from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.pragmas import CustomPragma
from yaraast.ast.rules import Rule
from yaraast.parser import Parser
from yaraast.performance.batch_processor import BatchOperation, BatchProcessor, BatchResult
from yaraast.performance.batch_processor_ops import _large_file_asts, parse_item


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


def test_batch_result_properties_cover_zero_and_nonzero_branches() -> None:
    empty = BatchResult(operation=BatchOperation.PARSE, input_count=0)
    assert empty.success_rate == 0.0
    assert empty.avg_processing_time == 0.0

    done = BatchResult(
        operation=BatchOperation.PARSE,
        input_count=4,
        successful_count=3,
        total_time=0.9,
    )
    assert done.success_rate == 75.0
    assert done.avg_processing_time == 0.3


def test_batch_processor_rejects_invalid_batch_sizes() -> None:
    with pytest.raises(ValueError, match="batch_size must be at least 1"):
        BatchProcessor(batch_size=0)

    processor = BatchProcessor(batch_size=1)
    with pytest.raises(ValueError, match="batch_size must be at least 1"):
        processor.process_batch([1], None, batch_size=0)


def test_batch_processor_rejects_invalid_worker_count() -> None:
    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        BatchProcessor(max_workers=0)


def test_batch_processor_rejects_invalid_memory_limit() -> None:
    with pytest.raises(ValueError, match="max_memory_mb must be at least 1"):
        BatchProcessor(max_memory_mb=0)


def test_batch_processor_rejects_boolean_numeric_settings() -> None:
    with pytest.raises(TypeError, match="max_workers must be an integer"):
        BatchProcessor(max_workers=cast(Any, True))

    with pytest.raises(TypeError, match="max_memory_mb must be an integer"):
        BatchProcessor(max_memory_mb=cast(Any, True))

    with pytest.raises(TypeError, match="batch_size must be an integer"):
        BatchProcessor(batch_size=cast(Any, True))

    processor = BatchProcessor()
    with pytest.raises(TypeError, match="batch_size must be an integer"):
        processor.process_batch([1], None, batch_size=cast(Any, True))


def test_batch_processor_rejects_single_string_file_paths(tmp_path: Path) -> None:
    path = tmp_path / "single.yar"
    path.write_text("rule single { condition: true }", encoding="utf-8")

    with pytest.raises(TypeError, match="file_paths must be a sequence of paths"):
        BatchProcessor().process_files(cast(Any, str(path)), BatchOperation.PARSE)


def test_process_batch_parse_handles_invalid_item_without_exceptions() -> None:
    processor = BatchProcessor(batch_size=1)

    results = processor.process_batch([123, "rule ok { condition: true }"], BatchOperation.PARSE)

    assert results[0] is None
    assert results[1] is not None

    stats = processor.get_statistics()
    assert stats["items_processed"] == 2
    assert stats["failures"] == 0
    assert stats["batches_processed"] == 2


def test_parse_item_returns_none_for_invalid_rule_syntax() -> None:
    assert parse_item("rule bad { condition: }") is None


def test_large_file_split_preserves_top_level_extensions() -> None:
    parsed = YaraFile(
        rules=[
            Rule(name="first", condition=BooleanLiteral(value=True)),
            Rule(name="second", condition=BooleanLiteral(value=True)),
        ],
        extern_rules=[ExternRule("ExternalRule")],
        extern_imports=[ExternImport("external_rules")],
        pragmas=[CustomPragma("vendor")],
        namespaces=[ExternNamespace("corp")],
    )

    split_asts = _large_file_asts(Path("rules.yar"), parsed, split_rules=True)

    assert len(split_asts) == 2
    for index, (_stem, ast) in enumerate(split_asts):
        assert ast is not parsed
        assert ast.rules == [parsed.rules[index]]
        assert ast.rules is not parsed.rules
        assert ast.extern_rules == parsed.extern_rules
        assert ast.extern_imports == parsed.extern_imports
        assert ast.pragmas == parsed.pragmas
        assert ast.namespaces == parsed.namespaces


def test_batch_processor_accepts_yarax_sources_and_files(tmp_path: Path) -> None:
    source = _yarax_rule()
    processor = BatchProcessor(batch_size=1)

    parsed = processor.process_batch([source], BatchOperation.PARSE)[0]

    assert parsed is not None
    assert parsed.rules[0].name == "x"

    path = tmp_path / "x.yar"
    path.write_text(source, encoding="utf-8")
    result = BatchProcessor().process_files([path], BatchOperation.PARSE)

    assert result.successful_count == 1
    assert result.failed_count == 0

    large = BatchProcessor().process_large_file(
        path,
        operations=[BatchOperation.PARSE, BatchOperation.VALIDATE],
        output_dir=tmp_path / "out",
    )

    assert large[BatchOperation.PARSE].successful_count == 1
    assert large[BatchOperation.VALIDATE].successful_count == 1


def test_process_batch_custom_callable_exception_tracks_failure() -> None:
    progress_calls: list[tuple[str, int, int]] = []

    def progress(stage: str, done: int, total: int) -> None:
        progress_calls.append((stage, done, total))

    processor = BatchProcessor(batch_size=2, progress_callback=progress)

    items = [{"ok": 10}, 42]
    results = processor.process_batch(items, lambda x: cast(Any, x)["ok"])

    assert results == [10, None]
    stats = processor.get_statistics()
    assert stats["items_processed"] == 1
    assert stats["failures"] == 1
    assert progress_calls[-1] == ("Processing", 2, 2)


def test_process_files_uses_real_invalid_path_and_collects_error(tmp_path: Path) -> None:
    valid_file = tmp_path / "good.yar"
    valid_file.write_text("rule ok { condition: true }", encoding="utf-8")

    invalid_path = tmp_path / "not_a_file"
    invalid_path.mkdir()

    processor = BatchProcessor()
    result = processor.process_files(
        [valid_file, invalid_path],
        BatchOperation.SERIALIZE,
        output_dir=tmp_path / "out",
    )

    assert result.successful_count == 1
    assert result.failed_count == 1
    assert len(result.output_files) == 1
    assert any("Error processing" in err for err in result.errors)


def test_output_file_operations_require_output_directory(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text("rule ok { condition: true }", encoding="utf-8")

    processor = BatchProcessor()

    for operation in (
        BatchOperation.SERIALIZE,
        BatchOperation.HTML_TREE,
        BatchOperation.DEPENDENCY_GRAPH,
    ):
        result = processor.process_files([rule_file], operation)

        assert result.successful_count == 0
        assert result.failed_count == 1
        assert result.output_files == []
        assert result.errors == [f"{operation.value} requires output_dir"]


def test_process_large_file_missing_file_fails_all_operations(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yar"
    processor = BatchProcessor()

    results = processor.process_large_file(
        missing,
        operations=[BatchOperation.PARSE, BatchOperation.COMPLEXITY],
        output_dir=tmp_path,
    )

    for op in [BatchOperation.PARSE, BatchOperation.COMPLEXITY]:
        assert results[op].failed_count == 1
        assert results[op].successful_count == 0
        assert any("Error processing" in err for err in results[op].errors)


def test_process_batch_operation_none_and_validation_branches() -> None:
    processor = BatchProcessor(batch_size=2)
    parsed = Parser().parse("rule valid { condition: true }")
    rule = parsed.rules[0]

    passthrough = processor.process_batch([1, 2], None)
    assert passthrough == [1, 2]

    validated = processor.process_batch([rule], BatchOperation.VALIDATE)
    assert validated == [True]

    analyzed = processor.process_batch([rule], BatchOperation.COMPLEXITY)
    assert isinstance(analyzed[0], dict)

    serialized = processor.process_batch([parsed], BatchOperation.SERIALIZE)
    assert isinstance(serialized[0], str)
    assert '"rules"' in serialized[0]


def test_process_files_parse_failures_and_recursive_directory(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yar"
    bad.write_text("not yara syntax", encoding="utf-8")

    nested = tmp_path / "nested"
    nested.mkdir()
    good = nested / "ok.yar"
    alt = nested / "ok_alt.yara"
    native = nested / "native.yarax"
    good.write_text("rule ok { condition: true }", encoding="utf-8")
    alt.write_text("rule ok_alt { condition: true }", encoding="utf-8")
    native.write_text("rule native { condition: true }", encoding="utf-8")

    processor = BatchProcessor()
    failed = processor.process_files([bad], BatchOperation.PARSE, output_dir=tmp_path / "out")
    assert failed.failed_count == 1
    assert any("Error processing" in err or "Failed to parse" in err for err in failed.errors)

    rec = processor.process_directory(
        tmp_path,
        BatchOperation.PARSE,
        output_dir=tmp_path / "out2",
        recursive=True,
    )
    assert rec.input_count >= 3
    assert rec.successful_count >= 2


def test_process_files_validate_records_summary(tmp_path: Path) -> None:
    rule_file = tmp_path / "valid.yar"
    rule_file.write_text("rule ok { condition: true }", encoding="utf-8")
    invalid_rule_file = tmp_path / "invalid.yar"
    invalid_rule_file.write_text("rule missing_condition { }", encoding="utf-8")

    progress_calls: list[tuple[str, int, int]] = []

    def progress(stage: str, done: int, total: int) -> None:
        progress_calls.append((stage, done, total))

    processor = BatchProcessor(progress_callback=progress)
    result = processor.process_files(
        [rule_file, invalid_rule_file],
        BatchOperation.VALIDATE,
    )

    assert result.successful_count == 1
    assert result.failed_count == 1
    assert result.summary["valid.yar"] == {"valid": True, "rule_count": 1}
    assert "invalid.yar" not in result.summary
    assert any("Failed to parse" in error and "invalid.yar" in error for error in result.errors)
    assert progress_calls == [
        ("Processing validate", 1, 2),
        ("Processing validate", 2, 2),
    ]


def test_process_large_file_non_split_and_invalid_content(tmp_path: Path) -> None:
    valid = tmp_path / "big.yar"
    valid.write_text("rule a { condition: true }\nrule b { condition: true }\n", encoding="utf-8")
    invalid = tmp_path / "invalid_big.yar"
    invalid.write_text("this is not yara", encoding="utf-8")

    processor = BatchProcessor()

    non_split = processor.process_large_file(
        valid,
        operations=[BatchOperation.PARSE, BatchOperation.COMPLEXITY],
        output_dir=tmp_path,
        split_rules=False,
    )
    assert non_split[BatchOperation.PARSE].successful_count == 1
    assert non_split[BatchOperation.COMPLEXITY].successful_count == 1
    assert "a" in non_split[BatchOperation.COMPLEXITY].summary
    assert "b" in non_split[BatchOperation.COMPLEXITY].summary

    invalid_res = processor.process_large_file(
        invalid,
        operations=[BatchOperation.PARSE, BatchOperation.COMPLEXITY],
        output_dir=tmp_path,
        split_rules=False,
    )
    assert invalid_res[BatchOperation.PARSE].failed_count == 1
    assert invalid_res[BatchOperation.COMPLEXITY].failed_count == 1


def test_process_rules_analyze_rules_optimize_rules_and_progress_callback() -> None:
    parsed = Parser().parse("rule x { condition: true }")
    rule = parsed.rules[0]

    progress_calls: list[tuple[str, int, int]] = []

    def progress(stage: str, done: int, total: int) -> None:
        progress_calls.append((stage, done, total))

    processor = BatchProcessor(progress_callback=progress, batch_size=1)

    processed = processor.process_rules([rule], lambda r: r.name.upper())
    assert processed == ["X"]

    complexity = processor.analyze_rules([rule])
    assert isinstance(complexity[0], dict)

    optimized = processor.optimize_rules([rule])
    assert len(optimized) == 1
    assert optimized[0].name == "x"

    _ = processor.process_files([], BatchOperation.PARSE)
    # Callback called by batched paths with non-empty inputs.
    assert any(call[0].startswith("Processing") for call in progress_calls)


def test_process_large_file_serializes_valid_input(tmp_path: Path) -> None:
    path = tmp_path / "rules.yar"
    path.write_text("rule r { condition: true }", encoding="utf-8")

    processor = BatchProcessor()
    results = processor.process_large_file(
        path,
        operations=[BatchOperation.SERIALIZE],
        output_dir=tmp_path,
        split_rules=False,
    )

    assert BatchOperation.SERIALIZE in results
    assert results[BatchOperation.SERIALIZE].successful_count == 1
    assert results[BatchOperation.SERIALIZE].failed_count == 0
    assert len(results[BatchOperation.SERIALIZE].output_files) == 1
    output = Path(results[BatchOperation.SERIALIZE].output_files[0])
    assert output.exists()
    assert '"rules"' in output.read_text(encoding="utf-8")
