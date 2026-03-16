"""Operational helpers for BatchProcessor."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.parser.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule
    from yaraast.performance.batch_processor import BatchOperation, BatchProcessor


def parse_item(item: str | Path) -> YaraFile | None:
    try:
        parser = Parser()
        if isinstance(item, Path):
            with open(item) as handle:
                content = handle.read()
        else:
            content = item
        return parser.parse(content)
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


def process_files_single(
    processor: BatchProcessor,
    file_paths: list[Path],
    operation: BatchOperation,
    output_dir: Path | None = None,
):
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    start_time = time.time()
    result = BatchResult(operation=operation, input_count=len(file_paths))
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    for index, file_path in enumerate(file_paths):
        try:
            with open(file_path) as handle:
                content = handle.read()
            parsed = parse_item(content)
            if operation == BatchOperation.COMPLEXITY:
                for rule in parsed.rules:
                    result.summary[rule.name] = analyze_complexity(rule)
            elif operation == BatchOperation.HTML_TREE and output_dir:
                output_file = output_dir / f"{file_path.stem}.html"
                html_content = HtmlTreeGenerator().generate_html(parsed, None)
                output_file.write_text(html_content)
                result.output_files.append(str(output_file))
            elif operation == BatchOperation.SERIALIZE and output_dir:
                output_file = output_dir / f"{file_path.stem}.json"
                output_file.write_text(serialize_item(parsed))
                result.output_files.append(str(output_file))
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
    operations: list,
    output_dir: Path,
    split_rules: bool = False,
):
    from yaraast.performance.batch_processor import BatchOperation, BatchResult

    results = {}
    try:
        with open(file_path) as handle:
            content = handle.read()
        parsed = parse_item(content)
        input_count = len(parsed.rules) if (parsed and split_rules) else 1
        for operation in operations:
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
            results[operation] = result
    except Exception as exc:
        for operation in operations:
            result = BatchResult(operation=operation, input_count=1)
            result.failed_count += 1
            result.errors.append(f"Error processing {file_path}: {exc!s}")
            results[operation] = result
    return results
