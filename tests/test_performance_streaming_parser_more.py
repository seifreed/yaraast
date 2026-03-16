"""Tests for streaming parser (no mocks)."""

from __future__ import annotations

import io
from pathlib import Path
from textwrap import dedent

from yaraast.performance.streaming_parser import StreamingParser


def _rules_text() -> str:
    return """
    rule s1 {
        condition:
            true
    }

    rule s2 {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """


def test_streaming_parse_stream_and_chunk(tmp_path: Path) -> None:
    parser = StreamingParser(buffer_size=16)
    stream = io.StringIO(dedent(_rules_text()))
    rules = list(parser.parse_stream(stream))
    assert len(rules) == 2

    path = tmp_path / "rules.yar"
    path.write_text(dedent(_rules_text()), encoding="utf-8")

    chunks = list(parser.parse_file_chunked(path, chunk_size=1))
    assert len(chunks) == 2
    assert len(chunks[0]) == 1


def test_streaming_parse_files_and_directory(tmp_path: Path) -> None:
    parser = StreamingParser()
    path1 = tmp_path / "r1.yar"
    path2 = tmp_path / "r2.yar"
    path1.write_text("rule r1 { condition: true }", encoding="utf-8")
    path2.write_text("rule r2 { condition: true }", encoding="utf-8")

    results = list(parser.parse_files([path1, path2]))
    assert len(results) == 2
    assert all(r.status.name in {"SUCCESS", "ERROR"} for r in results)

    dir_results = list(parser.parse_directory(tmp_path, recursive=False))
    assert len(dir_results) >= 2


def test_streaming_parse_with_progress_and_stats(tmp_path: Path) -> None:
    parser = StreamingParser(buffer_size=8)
    path = tmp_path / "rules.yar"
    path.write_text(dedent(_rules_text()), encoding="utf-8")

    progress = []

    def cb(processed: int, total: int) -> None:
        progress.append((processed, total))

    rules = parser.parse_with_progress(path, cb)
    assert len(rules) == 2
    assert progress

    stats = parser.get_statistics()
    assert stats["rules_parsed"] >= 2

    estimate = parser.estimate_memory_usage(path)
    assert estimate["file_size_mb"] >= 0
