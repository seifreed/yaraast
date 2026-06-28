"""Operational helpers for BatchProcessor."""

from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
from os import PathLike, fspath
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any

from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.errors import YaraASTError
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.parser.source import parse_yara_source
from yaraast.performance.validation import path_exists_and_not_dir
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule
    from yaraast.performance.batch_processor import BatchOperation, BatchProcessor, BatchResult

_EXPECTED_BATCH_ERRORS = (
    OSError,
    UnicodeDecodeError,
    ValueError,
    TypeError,
    YaraASTError,
)
OUTPUT_DIR_TYPE_ERROR = "output_dir must be a directory path"


def _read_yara_text_file(file_path: Path) -> str:
    try:
        if path_is_symlink(file_path) or path_has_symlink_ancestor(file_path):
            raise ValueError("YARA file must not traverse a symlink")
        with open(file_path, encoding="utf-8") as handle:
            return handle.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def parse_item(item: object) -> YaraFile | None:
    if not isinstance(item, (str, Path)):
        return None
    try:
        content = _read_yara_text_file(item) if isinstance(item, Path) else item
        return parse_yara_source(content)
    except _EXPECTED_BATCH_ERRORS:
        return None


def _require_parsed_item(parsed: YaraFile | None, file_path: Path) -> YaraFile:
    if parsed is None:
        msg = f"Failed to parse {file_path}"
        raise ValueError(msg)
    return parsed


def analyze_complexity(item: Rule) -> dict[str, Any]:
    from yaraast.ast.base import YaraFile

    analyzer = RuleAnalyzer()
    yara_file = YaraFile(imports=[], includes=[], rules=[item])
    return analyzer.analyze(yara_file)


def _rule_summary_key(rule_name: str, occurrence: int, counts: Counter[str]) -> str:
    if counts[rule_name] == 1:
        return rule_name
    return f"{rule_name}#{occurrence}"


def _add_complexity_summaries(summary: dict[str, Any], rules: list[Rule]) -> None:
    rule_counts = Counter(rule.name for rule in rules)
    seen_rules: defaultdict[str, int] = defaultdict(int)
    for rule in rules:
        seen_rules[rule.name] += 1
        summary_key = _rule_summary_key(rule.name, seen_rules[rule.name], rule_counts)
        summary[summary_key] = analyze_complexity(rule)


def serialize_item(item: Any) -> str:
    return JsonSerializer().serialize(item)


def validate_item(item: Rule) -> bool:
    return bool(item.name) and item.condition is not None


def _safe_output_stem(base_name: str, index: int, rule_name: str) -> str:
    safe_rule_name = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in rule_name
    ).strip("._-")
    return f"{base_name}_{index:04d}_{safe_rule_name or 'rule'}"


def _single_rule_ast(parsed: YaraFile, rule: Rule) -> YaraFile:
    split_ast = copy.copy(parsed)
    split_ast.rules = [rule]
    return split_ast


def _large_file_asts(
    file_path: Path,
    parsed: YaraFile,
    split_rules: bool,
) -> list[tuple[str, YaraFile]]:
    if not split_rules:
        return [(file_path.stem, parsed)]
    return [
        (
            _safe_output_stem(file_path.stem, index, rule.name),
            _single_rule_ast(parsed, rule),
        )
        for index, rule in enumerate(parsed.rules, 1)
    ]


def _process_large_serialize(
    file_path: Path,
    parsed: YaraFile,
    output_dir: Path,
    split_rules: bool,
    result: BatchResult,
) -> None:
    for stem, ast in _large_file_asts(file_path, parsed, split_rules):
        output_file = output_dir / f"{stem}.json"
        output_file.write_text(serialize_item(ast), encoding="utf-8")
        result.output_files.append(str(output_file))
        result.successful_count += 1


def _process_large_html_tree(
    file_path: Path,
    parsed: YaraFile,
    output_dir: Path,
    split_rules: bool,
    result: BatchResult,
) -> None:
    for stem, ast in _large_file_asts(file_path, parsed, split_rules):
        output_file = output_dir / f"{stem}.html"
        html_content = HtmlTreeGenerator().generate_html(ast, None)
        output_file.write_text(html_content, encoding="utf-8")
        result.output_files.append(str(output_file))
        result.successful_count += 1


def _process_large_validate(parsed: YaraFile, split_rules: bool, result: BatchResult) -> None:
    if not split_rules:
        is_valid = all(validate_item(rule) for rule in parsed.rules)
        result.summary["valid"] = is_valid
        result.summary["rule_count"] = len(parsed.rules)
        if is_valid:
            result.successful_count = 1
        else:
            result.failed_count = 1
            result.errors.append("Validation failed")
        return

    for index, rule in enumerate(parsed.rules, 1):
        key = rule.name or f"rule_{index}"
        is_valid = validate_item(rule)
        result.summary[key] = is_valid
        if is_valid:
            result.successful_count += 1
        else:
            result.failed_count += 1
            result.errors.append(f"Validation failed for rule {key}")


def _process_dependency_graph(
    file_path: Path,
    parsed: YaraFile,
    output_dir: Path,
    result: BatchResult,
) -> None:
    from yaraast.metrics.dependency_graph_utils import (
        analyze_dependencies,
        build_dependency_graph,
        export_dependency_graph,
    )

    graph = build_dependency_graph(parsed)
    json_output = output_dir / f"{file_path.stem}_dependencies.json"
    dot_output = output_dir / f"{file_path.stem}_dependencies.dot"
    export_dependency_graph(graph, json_output, "json")
    export_dependency_graph(graph, dot_output, "dot")
    result.output_files.extend([str(json_output), str(dot_output)])
    result.summary[file_path.name] = analyze_dependencies(parsed)["stats"]


def _ensure_output_directory(output_dir: Path | None, operation: BatchOperation) -> Path:
    if output_dir is None:
        msg = f"{operation.value} requires output_dir"
        raise RuntimeError(msg)
    return output_dir


def _requires_output_dir(operation: BatchOperation) -> bool:
    from yaraast.performance.batch_processor import BatchOperation

    return operation in {
        BatchOperation.DEPENDENCY_GRAPH,
        BatchOperation.HTML_TREE,
        BatchOperation.SERIALIZE,
    }


def _ast_dependent_operations() -> set[BatchOperation]:
    from yaraast.performance.batch_processor import BatchOperation

    return {
        BatchOperation.COMPLEXITY,
        BatchOperation.DEPENDENCY_GRAPH,
        BatchOperation.HTML_TREE,
        BatchOperation.VALIDATE,
        BatchOperation.SERIALIZE,
    }


def _process_file_operations(
    file_path: Path,
    operations: list[BatchOperation],
    output_dir: Path | None = None,
) -> dict[BatchOperation, BatchResult]:
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    local_results: dict[BatchOperation, BatchResult] = {
        operation: BatchResult(operation=operation, input_count=1) for operation in operations
    }
    parsed: YaraFile | None = None
    parse_error: Exception | None = None
    parsed_once = False

    def _ensure_parsed() -> None:
        nonlocal parsed, parse_error, parsed_once
        if parsed_once:
            return

        try:
            parsed = _require_parsed_item(parse_item(file_path), file_path)
        except _EXPECTED_BATCH_ERRORS as exc:
            parse_error = exc
        finally:
            parsed_once = True

    for operation in operations:
        op_start = time.perf_counter()
        result = local_results[operation]

        if _requires_output_dir(operation) and output_dir is None:
            result.failed_count += 1
            result.errors.append(f"{operation.value} requires output_dir")
        else:
            if operation == BatchOperation.PARSE:
                _ensure_parsed()
                if parsed is not None:
                    result.successful_count += 1
                else:
                    result.failed_count += 1
                    result.errors.append(f"Error processing {file_path}: {parse_error}")
            elif operation in _ast_dependent_operations():
                try:
                    _ensure_parsed()
                    if parsed is None:
                        result.failed_count += 1
                        result.errors.append(f"Error processing {file_path}: {parse_error}")
                    elif operation == BatchOperation.COMPLEXITY:
                        _add_complexity_summaries(result.summary, parsed.rules)
                        result.successful_count += 1
                    elif operation == BatchOperation.SERIALIZE:
                        if output_dir is None:
                            msg = "output directory is required for serialize"
                            raise RuntimeError(msg)
                        output_file = output_dir / f"{file_path.stem}.json"
                        output_file.write_text(serialize_item(parsed), encoding="utf-8")
                        result.output_files.append(str(output_file))
                        result.successful_count += 1
                    elif operation == BatchOperation.VALIDATE:
                        result.summary[file_path.name] = {
                            "valid": True,
                            "rule_count": len(parsed.rules),
                        }
                        result.successful_count += 1
                    elif operation == BatchOperation.DEPENDENCY_GRAPH:
                        if output_dir is None:
                            msg = "output directory is required for dependency graph"
                            raise RuntimeError(msg)
                        _process_dependency_graph(file_path, parsed, output_dir, result)
                        result.successful_count += 1
                    elif operation == BatchOperation.HTML_TREE:
                        if output_dir is None:
                            msg = "output directory is required for html tree"
                            raise RuntimeError(msg)
                        output_file = output_dir / f"{file_path.stem}.html"
                        html_content = HtmlTreeGenerator().generate_html(parsed, None)
                        output_file.write_text(html_content, encoding="utf-8")
                        result.output_files.append(str(output_file))
                        result.successful_count += 1
                except Exception as exc:
                    result.failed_count += 1
                    result.errors.append(f"Error processing {file_path}: {exc!s}")
            else:
                result.errors.append(f"Unsupported batch operation: {operation.value}")
                result.failed_count += 1

        result.total_time += time.perf_counter() - op_start

    return local_results


def process_files_multi(
    processor: BatchProcessor,
    file_paths: list[Path],
    operations: list[BatchOperation],
    output_dir: str | PathLike[str] | None = None,
) -> dict[BatchOperation, BatchResult]:
    """Process multiple files and multiple operations in one pass.

    This keeps parsing work shared across operations for the same file, which
    avoids reparsing every file for each requested operation.
    """
    from yaraast.performance.batch_processor import BatchResult

    output_dir = require_output_dir_path(output_dir)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
    results: dict[BatchOperation, BatchResult] = {
        operation: BatchResult(operation=operation, input_count=len(file_paths))
        for operation in operations
    }

    worker_count = processor.max_workers or 1
    if worker_count < 2:
        file_results: list[tuple[int, dict[BatchOperation, BatchResult]]] = []
        for file_index, file_path in enumerate(file_paths):
            file_results.append(
                (file_index, _process_file_operations(file_path, operations, output_dir))
            )
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    _process_file_operations, file_path, operations, output_dir
                ): file_index
                for file_index, file_path in enumerate(file_paths)
            }
            file_results = []
            for future in as_completed(futures):
                file_index = futures[future]
                file_results.append((file_index, future.result()))

    for file_index, file_local_results in sorted(file_results, key=lambda item: item[0]):
        for operation in operations:
            if processor.progress_callback:
                processor.progress_callback(
                    f"Processing {operation.value}",
                    file_index + 1,
                    len(file_paths),
                )
            aggregate = file_local_results[operation]
            aggregate_result = results[operation]
            aggregate_result.successful_count += aggregate.successful_count
            aggregate_result.failed_count += aggregate.failed_count
            aggregate_result.total_time += aggregate.total_time
            aggregate_result.output_files.extend(aggregate.output_files)
            aggregate_result.errors.extend(aggregate.errors)
            aggregate_result.summary.update(aggregate.summary)

    return results


def require_output_dir_path(output_dir: object) -> Path | None:
    """Normalize an optional batch output directory path."""
    if output_dir is None:
        return None
    if isinstance(output_dir, bool | bytes) or not isinstance(output_dir, str | PathLike):
        raise TypeError(OUTPUT_DIR_TYPE_ERROR)
    raw_path = fspath(output_dir)
    if not isinstance(raw_path, str):
        raise TypeError(OUTPUT_DIR_TYPE_ERROR)
    if not raw_path.strip():
        msg = "output_dir must not be empty"
        raise ValueError(msg)
    if "\x00" in raw_path:
        msg = "output_dir must not contain null bytes"
        raise ValueError(msg)
    path = Path(raw_path)
    if path_exists_and_not_dir(path):
        msg = "output_dir must not be a file"
        raise ValueError(msg)
    if path_is_symlink(path) or path_has_symlink_ancestor(path):
        msg = "output_dir must not traverse a symlink"
        raise ValueError(msg)
    return path


def process_files_single(
    processor: BatchProcessor,
    file_paths: list[Path],
    operation: BatchOperation,
    output_dir: str | PathLike[str] | None = None,
) -> BatchResult:
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    start_time = time.time()
    result = BatchResult(operation=operation, input_count=len(file_paths))
    output_dir = require_output_dir_path(output_dir)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
    elif file_paths and _requires_output_dir(operation):
        result.failed_count = len(file_paths)
        result.errors.append(f"{operation.value} requires output_dir")
        result.total_time = time.time() - start_time
        return result

    for index, file_path in enumerate(file_paths):
        try:
            content = _read_yara_text_file(file_path)
            parsed = _require_parsed_item(parse_item(content), file_path)
            if operation == BatchOperation.COMPLEXITY:
                _add_complexity_summaries(result.summary, parsed.rules)
            elif operation == BatchOperation.HTML_TREE and output_dir is not None:
                output_file = output_dir / f"{file_path.stem}.html"
                html_content = HtmlTreeGenerator().generate_html(parsed, None)
                output_file.write_text(html_content, encoding="utf-8")
                result.output_files.append(str(output_file))
            elif operation == BatchOperation.SERIALIZE and output_dir is not None:
                output_file = output_dir / f"{file_path.stem}.json"
                output_file.write_text(serialize_item(parsed), encoding="utf-8")
                result.output_files.append(str(output_file))
            elif operation == BatchOperation.DEPENDENCY_GRAPH and output_dir is not None:
                _process_dependency_graph(file_path, parsed, output_dir, result)
            elif operation == BatchOperation.VALIDATE:
                result.summary[file_path.name] = {
                    "valid": True,
                    "rule_count": len(parsed.rules),
                }
            result.successful_count += 1
        except _EXPECTED_BATCH_ERRORS as exc:
            result.failed_count += 1
            result.errors.append(f"Error processing {file_path}: {exc!s}")
        finally:
            if processor.progress_callback:
                processor.progress_callback(
                    f"Processing {operation.value}", index + 1, len(file_paths)
                )

    result.total_time = time.time() - start_time
    return result


def process_large_file(
    processor: BatchProcessor,
    file_path: Path,
    operations: list[BatchOperation],
    output_dir: str | PathLike[str],
    split_rules: bool = False,
) -> dict[BatchOperation, BatchResult]:
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    output_path = require_output_dir_path(output_dir)
    if output_path is None:
        raise TypeError(OUTPUT_DIR_TYPE_ERROR)

    results: dict[BatchOperation, BatchResult] = {}
    output_path.mkdir(parents=True, exist_ok=True)

    try:
        content = _read_yara_text_file(file_path)
        parsed = _require_parsed_item(parse_item(content), file_path)
        input_count = len(parsed.rules) if split_rules else 1
    except _EXPECTED_BATCH_ERRORS as exc:
        for operation in operations:
            result = BatchResult(operation=operation, input_count=1)
            result.failed_count = 1
            result.errors.append(f"Error processing {file_path}: {exc!s}")
            results[operation] = result
        return results

    for index, operation in enumerate(operations, 1):
        op_start = time.perf_counter()
        result = BatchResult(operation=operation, input_count=input_count)
        try:
            if operation == BatchOperation.PARSE:
                result.successful_count = input_count
            elif operation == BatchOperation.COMPLEXITY:
                _add_complexity_summaries(result.summary, parsed.rules)
                result.successful_count = input_count
            elif operation == BatchOperation.SERIALIZE:
                _process_large_serialize(file_path, parsed, output_path, split_rules, result)
            elif operation == BatchOperation.HTML_TREE:
                _process_large_html_tree(file_path, parsed, output_path, split_rules, result)
            elif operation == BatchOperation.VALIDATE:
                _process_large_validate(parsed, split_rules, result)
            elif operation == BatchOperation.DEPENDENCY_GRAPH:
                _process_dependency_graph(file_path, parsed, output_path, result)
                result.successful_count = 1
        except _EXPECTED_BATCH_ERRORS as exc:
            result.failed_count = input_count
            result.errors.append(f"Error processing {file_path}: {exc!s}")
        finally:
            result.total_time = time.perf_counter() - op_start
            results[operation] = result
            if processor.progress_callback:
                processor.progress_callback(
                    f"Processing {operation.value}",
                    index,
                    len(operations),
                )

    return results
