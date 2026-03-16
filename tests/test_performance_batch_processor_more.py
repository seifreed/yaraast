"""Tests for batch processor utilities (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.performance.batch_processor import BatchOperation, BatchProcessor


def _write_rules(tmp_path: Path) -> list[Path]:
    code1 = """
    rule batch_one {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    code2 = """
    rule batch_two {
        condition:
            true
    }
    """
    p1 = tmp_path / "r1.yar"
    p2 = tmp_path / "r2.yar"
    p1.write_text(dedent(code1), encoding="utf-8")
    p2.write_text(dedent(code2), encoding="utf-8")
    return [p1, p2]


def test_batch_processor_process_files_and_directory(tmp_path: Path) -> None:
    paths = _write_rules(tmp_path)
    processor = BatchProcessor(batch_size=1)

    result = processor.process_files(paths, BatchOperation.HTML_TREE, output_dir=tmp_path / "out")
    assert result.successful_count == 2
    assert result.output_files

    result2 = processor.process_directory(
        tmp_path, BatchOperation.SERIALIZE, output_dir=tmp_path / "jsons"
    )
    assert result2.successful_count == 2
    assert result2.output_files


def test_batch_processor_process_batch_and_stats(tmp_path: Path) -> None:
    paths = _write_rules(tmp_path)
    processor = BatchProcessor(batch_size=1)

    results = processor.process_batch(paths, BatchOperation.PARSE)
    assert len(results) == 2

    stats = processor.get_statistics()
    assert stats["items_processed"] >= 2

    processor.reset_statistics()
    stats_after = processor.get_statistics()
    assert stats_after["items_processed"] == 0


def test_batch_processor_large_file_split(tmp_path: Path) -> None:
    code = """
    rule r1 { condition: true }
    rule r2 { condition: true }
    """
    path = tmp_path / "many.yar"
    path.write_text(dedent(code), encoding="utf-8")

    processor = BatchProcessor()
    results = processor.process_large_file(
        path,
        operations=[BatchOperation.PARSE, BatchOperation.COMPLEXITY],
        output_dir=tmp_path,
        split_rules=True,
    )

    assert results[BatchOperation.PARSE].successful_count == 2
    assert results[BatchOperation.COMPLEXITY].summary
