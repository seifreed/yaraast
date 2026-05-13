"""Operational helpers for BatchProcessor."""

from __future__ import annotations

from pathlib import Path
import time
from typing import TYPE_CHECKING, Any

from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.parser.source import parse_yara_source
from yaraast.serialization.json_serializer import JsonSerializer

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule
    from yaraast.performance.batch_processor import BatchOperation, BatchProcessor, BatchResult


def parse_item(item: str | Path) -> YaraFile | None:
    try:
        if isinstance(item, Path):
            with open(item, encoding="utf-8") as handle:
                content = handle.read()
        else:
            content = item
        return parse_yara_source(content)
    except (ValueError, TypeError, AttributeError):
        return None


def analyze_complexity(item: Rule) -> dict[str, Any]:
    from yaraast.ast.base import YaraFile

    analyzer = RuleAnalyzer()
    yara_file = YaraFile(imports=[], includes=[], rules=[item])
    return analyzer.analyze(yara_file)


def serialize_item(item: Any) -> str:
    return JsonSerializer().serialize(item)


def validate_item(item: Rule) -> bool:
    return bool(item.name and item.condition)


def _safe_output_stem(base_name: str, index: int, rule_name: str) -> str:
    safe_rule_name = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in rule_name
    ).strip("._-")
    return f"{base_name}_{index:04d}_{safe_rule_name or 'rule'}"


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
            YaraFile(imports=parsed.imports, includes=parsed.includes, rules=[rule]),
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


def process_files_single(
    processor: BatchProcessor,
    file_paths: list[Path],
    operation: BatchOperation,
    output_dir: Path | None = None,
) -> BatchResult:
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    start_time = time.time()
    result = BatchResult(operation=operation, input_count=len(file_paths))
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    for index, file_path in enumerate(file_paths):
        try:
            with open(file_path, encoding="utf-8") as handle:
                content = handle.read()
            parsed = parse_item(content)
            if operation == BatchOperation.COMPLEXITY:
                for rule in parsed.rules:
                    result.summary[rule.name] = analyze_complexity(rule)
            elif operation == BatchOperation.HTML_TREE and output_dir:
                output_file = output_dir / f"{file_path.stem}.html"
                html_content = HtmlTreeGenerator().generate_html(parsed, None)
                output_file.write_text(html_content, encoding="utf-8")
                result.output_files.append(str(output_file))
            elif operation == BatchOperation.SERIALIZE and output_dir:
                output_file = output_dir / f"{file_path.stem}.json"
                output_file.write_text(serialize_item(parsed), encoding="utf-8")
                result.output_files.append(str(output_file))
            elif operation == BatchOperation.DEPENDENCY_GRAPH and output_dir:
                _process_dependency_graph(file_path, parsed, output_dir, result)
            elif operation == BatchOperation.VALIDATE:
                is_valid = all(validate_item(rule) for rule in parsed.rules)
                result.summary[file_path.name] = {
                    "valid": is_valid,
                    "rule_count": len(parsed.rules),
                }
                if not is_valid:
                    result.failed_count += 1
                    result.errors.append(f"Validation failed for {file_path}")
                    continue
            result.successful_count += 1
        except Exception as exc:
            result.failed_count += 1
            result.errors.append(f"Error processing {file_path}: {exc!s}")

        if processor.progress_callback:
            processor.progress_callback(f"Processing {operation.value}", index + 1, len(file_paths))

    result.total_time = time.time() - start_time
    return result


def process_large_file(
    processor: BatchProcessor,
    file_path: Path,
    operations: list[BatchOperation],
    output_dir: Path,
    split_rules: bool = False,
) -> dict[BatchOperation, BatchResult]:
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    results: dict[BatchOperation, BatchResult] = {}
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(file_path, encoding="utf-8") as handle:
            content = handle.read()
        parsed = parse_item(content)
        input_count = len(parsed.rules) if (parsed and split_rules) else 1
        for index, operation in enumerate(operations, 1):
            result = BatchResult(operation=operation, input_count=input_count)
            if operation == BatchOperation.PARSE:
                result.successful_count = len(parsed.rules) if split_rules else 1
            elif operation == BatchOperation.COMPLEXITY:
                for rule in parsed.rules:
                    result.summary[rule.name] = analyze_complexity(rule)
                    if split_rules:
                        result.successful_count += 1
                if not split_rules:
                    result.successful_count = 1
            elif operation == BatchOperation.SERIALIZE:
                _process_large_serialize(file_path, parsed, output_dir, split_rules, result)
            elif operation == BatchOperation.HTML_TREE:
                _process_large_html_tree(file_path, parsed, output_dir, split_rules, result)
            elif operation == BatchOperation.VALIDATE:
                _process_large_validate(parsed, split_rules, result)
            elif operation == BatchOperation.DEPENDENCY_GRAPH:
                _process_dependency_graph(file_path, parsed, output_dir, result)
                result.successful_count = 1
            results[operation] = result
            if processor.progress_callback:
                processor.progress_callback(
                    f"Processing {operation.value}",
                    index,
                    len(operations),
                )
    except Exception as exc:
        for operation in operations:
            result = BatchResult(operation=operation, input_count=1)
            result.failed_count += 1
            result.errors.append(f"Error processing {file_path}: {exc!s}")
            results[operation] = result
    return results
