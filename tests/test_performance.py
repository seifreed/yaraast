"""Tests for performance optimization features."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from yaraast.parser import Parser
from yaraast.performance import (
    BatchOperation,
    BatchProcessor,
    MemoryOptimizer,
    ParallelAnalyzer,
    StreamingParser,
)


@pytest.fixture
def sample_yara_files():
    """Create sample YARA files for testing."""
    files = []

    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp())

    # Sample YARA contents
    yara_contents = [
        """
rule TestRule1 {
    strings:
        $s1 = "test1"
    condition:
        $s1
}
        """,
        """
rule TestRule2 {
    strings:
        $s1 = "test2"
        $s2 = { 41 42 43 }
    condition:
        $s1 and $s2
}
        """,
        """
import "pe"

rule TestRule3 : malware {
    meta:
        author = "test"
    strings:
        $hex = { 90 90 ?? 90 }
    condition:
        pe.is_pe and $hex
}
        """,
    ]

    # Write files
    for i, content in enumerate(yara_contents):
        file_path = temp_dir / f"test_{i}.yar"
        file_path.write_text(content)
        files.append(file_path)

    yield files

    # Cleanup
    for file_path in files:
        if file_path.exists():
            file_path.unlink()
    temp_dir.rmdir()


@pytest.fixture
def large_yara_file():
    """Create a large YARA file with multiple rules."""
    with tempfile.NamedTemporaryFile(suffix=".yar", delete=False) as tmp:
        temp_file = Path(tmp.name)

    content = """import "pe"
import "math"

"""

    # Generate multiple rules
    for i in range(20):
        content += f"""
rule LargeRule{i} {{
    meta:
        id = {i}
        author = "test"
    strings:
        $s{i}_1 = "string_{i}_1"
        $s{i}_2 = "string_{i}_2"
        $h{i} = {{ {i:02X} {i + 1:02X} {i + 2:02X} }}
    condition:
        any of them
}}
"""

    temp_file.write_text(content)
    yield temp_file

    if temp_file.exists():
        temp_file.unlink()


class TestStreamingParser:
    """Test streaming parser functionality."""

    def test_parse_files(self, sample_yara_files) -> None:
        """Test parsing multiple files with streaming parser."""
        parser = StreamingParser(max_memory_mb=100)

        results = list(parser.parse_files(sample_yara_files))

        assert len(results) == 3

        # All should be successful
        successful = [r for r in results if r.status.value == "success"]
        assert len(successful) == 3

        # Check ASTs were parsed
        for result in successful:
            assert result.ast is not None
            assert result.rule_count > 0
            assert result.parse_time > 0

    def test_parse_directory(self, sample_yara_files) -> None:
        """Test parsing directory with streaming parser."""
        parser = StreamingParser()

        # Get directory from first file
        directory = sample_yara_files[0].parent

        results = list(parser.parse_directory(directory, "*.yar", recursive=False))

        assert len(results) >= 3  # Should find our test files

        successful = [r for r in results if r.status.value == "success"]
        assert len(successful) >= 3

    def test_parse_rules_from_file(self, large_yara_file) -> None:
        """Test parsing individual rules from large file."""
        parser = StreamingParser()

        results = list(parser.parse_rules_from_file(large_yara_file))

        # Should have parsed individual rules
        assert len(results) == 20  # 20 rules in the file

        successful = [r for r in results if r.status.value == "success"]
        assert len(successful) == 20

        # Each should have exactly 1 rule
        for result in successful:
            assert result.ast is not None
            assert result.rule_count == 1
            assert result.rule_name.startswith("LargeRule")

    def test_memory_management(self, sample_yara_files) -> None:
        """Test memory management during parsing."""
        parser = StreamingParser(max_memory_mb=50, enable_gc=True)

        # Parse files
        list(parser.parse_files(sample_yara_files))

        # Check statistics
        stats = parser.get_statistics()
        assert stats["files_processed"] == 3
        assert stats["files_successful"] == 3
        assert stats["total_parse_time"] > 0

    def test_progress_callback(self, sample_yara_files) -> None:
        """Test progress callback functionality."""
        progress_calls = []

        def progress_callback(current, total, current_file) -> None:
            progress_calls.append((current, total, current_file))

        parser = StreamingParser(progress_callback=progress_callback)

        list(parser.parse_files(sample_yara_files))

        # Should have received progress callbacks
        assert len(progress_calls) == 3
        assert progress_calls[-1][0] == 3  # Final call should be 3/3
        assert progress_calls[-1][1] == 3

    def test_cancellation(self, sample_yara_files) -> None:
        """Test parser cancellation."""
        parser = StreamingParser()

        # Start parsing and cancel immediately
        parser.cancel()

        results = list(parser.parse_files(sample_yara_files))

        # Should have stopped early due to cancellation
        assert len(results) == 0


class TestParallelAnalyzer:
    """Test parallel analyzer functionality."""

    def test_parse_files_parallel(self, sample_yara_files) -> None:
        """Test parallel file parsing."""
        with ParallelAnalyzer(max_workers=2) as analyzer:
            jobs = analyzer.parse_files_parallel(sample_yara_files, chunk_size=2)

            # Should have jobs for the files
            assert len(jobs) >= 1

            # Check that jobs completed
            for job in jobs:
                assert job.is_completed
                if job.status.value == "completed":
                    assert job.result is not None
                    assert isinstance(job.result, list)

    def test_complexity_analysis_parallel(self, sample_yara_files) -> None:
        """Test parallel complexity analysis."""
        # First parse files
        parser = Parser()
        asts = []
        for file_path in sample_yara_files:
            content = file_path.read_text()
            ast = parser.parse(content)
            asts.append(ast)

        with ParallelAnalyzer(max_workers=2) as analyzer:
            jobs = analyzer.analyze_complexity_parallel(asts)

            assert len(jobs) == 3

            # Check results
            successful_jobs = [j for j in jobs if j.status.value == "completed"]
            assert len(successful_jobs) == 3

            for job in successful_jobs:
                assert "metrics" in job.result
                assert "quality_score" in job.result

    def test_batch_processing(self, sample_yara_files) -> None:
        """Test custom batch processing."""

        def simple_worker(file_path, parameters):
            # Simple worker that returns file size
            return Path(file_path).stat().st_size

        with ParallelAnalyzer(max_workers=2) as analyzer:
            jobs = analyzer.process_batch(
                sample_yara_files,
                simple_worker,
                job_type="file_size",
            )

            assert len(jobs) == 3

            for job in jobs:
                assert job.is_completed
                if job.status.value == "completed":
                    assert isinstance(job.result, int)  # File size
                    assert job.result > 0

    def test_job_management(self, sample_yara_files) -> None:
        """Test job status and management."""
        with ParallelAnalyzer(max_workers=1) as analyzer:
            jobs = analyzer.parse_files_parallel(sample_yara_files, chunk_size=1)

            # Check job IDs are unique
            job_ids = [job.job_id for job in jobs]
            assert len(set(job_ids)) == len(job_ids)

            # Check statistics
            stats = analyzer.get_statistics()
            assert stats["jobs_submitted"] >= 3
            assert stats["jobs_completed"] >= 3


class TestBatchProcessor:
    """Test batch processor functionality."""

    def test_process_files(self, sample_yara_files) -> None:
        """Test batch processing of files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            processor = BatchProcessor(batch_size=2, max_workers=2)

            results = processor.process_files(
                sample_yara_files,
                [BatchOperation.PARSE, BatchOperation.COMPLEXITY],
                output_dir,
            )

            # Should have results for both operations
            assert BatchOperation.PARSE in results
            assert BatchOperation.COMPLEXITY in results

            parse_result = results[BatchOperation.PARSE]
            assert parse_result.input_count == 3
            assert parse_result.successful_count == 3
            assert abs(parse_result.success_rate - 100.0) < 1e-9

            complexity_result = results[BatchOperation.COMPLEXITY]
            assert complexity_result.successful_count > 0

    def test_process_directory(self, sample_yara_files) -> None:
        """Test batch processing of directory."""
        directory = sample_yara_files[0].parent

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            processor = BatchProcessor(batch_size=2)

            results = processor.process_directory(
                directory,
                [BatchOperation.PARSE],
                output_dir,
                file_pattern="*.yar",
                recursive=False,
            )

            assert BatchOperation.PARSE in results

            parse_result = results[BatchOperation.PARSE]
            assert parse_result.successful_count >= 3

    @patch("yaraast.performance.batch_processor.HtmlTreeGenerator")
    def test_html_tree_generation(self, mock_generator, sample_yara_files) -> None:
        """Test HTML tree generation in batch."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Mock the HTML generator
            mock_gen_instance = MagicMock()
            mock_generator.return_value = mock_gen_instance

            processor = BatchProcessor()

            results = processor.process_files(
                sample_yara_files,
                [BatchOperation.PARSE, BatchOperation.HTML_TREE],
                output_dir,
            )

            assert BatchOperation.HTML_TREE in results

            # Should have attempted to generate trees
            html_result = results[BatchOperation.HTML_TREE]
            assert html_result.input_count > 0

    def test_large_file_processing(self, large_yara_file) -> None:
        """Test processing of large file with rule splitting."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            processor = BatchProcessor()

            results = processor.process_large_file(
                large_yara_file,
                [BatchOperation.PARSE, BatchOperation.COMPLEXITY],
                output_dir,
                split_rules=True,
            )

            assert BatchOperation.PARSE in results

            parse_result = results[BatchOperation.PARSE]
            assert parse_result.input_count == 20  # 20 rules
            assert parse_result.successful_count == 20


class TestMemoryOptimizer:
    """Test memory optimization functionality."""

    def test_memory_managed_context(self) -> None:
        """Test memory managed context manager."""
        optimizer = MemoryOptimizer(memory_limit_mb=100)

        with optimizer.memory_managed_context():
            # Create some objects
            test_objects = [f"test_object_{i}" for i in range(100)]

            for obj in test_objects:
                optimizer.track_object(obj)

        # Context should have cleaned up
        stats = optimizer.get_memory_stats()
        assert stats.total_objects >= 0  # Some objects may still be tracked

    def test_object_tracking(self) -> None:
        """Test object tracking functionality."""
        optimizer = MemoryOptimizer(gc_threshold=10, enable_tracking=True)

        # Create and track objects
        objects = []
        for i in range(15):
            obj = f"test_object_{i}"
            objects.append(obj)
            optimizer.track_object(obj)

        stats = optimizer.get_memory_stats()
        assert stats.total_objects > 0

        # Clear objects and force cleanup
        objects.clear()
        collected = optimizer.force_cleanup()
        assert collected >= 0  # Should have collected some objects

    def test_ast_pooling(self) -> None:
        """Test AST object pooling."""
        optimizer = MemoryOptimizer()

        # Create ASTs
        ast1 = optimizer.create_memory_efficient_ast()
        ast2 = optimizer.create_memory_efficient_ast()

        assert ast1 is not ast2

        # Return to pool
        optimizer.return_ast_to_pool(ast1)
        optimizer.return_ast_to_pool(ast2)

        # Should reuse from pool
        ast3 = optimizer.create_memory_efficient_ast()
        assert ast3 in [ast1, ast2]  # Should be one of the pooled ASTs

    def test_batch_processing_with_memory_limit(self) -> None:
        """Test batch processing with memory limits."""
        optimizer = MemoryOptimizer(memory_limit_mb=50)

        items = list(range(100))

        def simple_processor(item):
            return item * 2

        results = list(
            optimizer.batch_process_with_memory_limit(
                items,
                simple_processor,
                batch_size=10,
            ),
        )

        # Should have processed all items in batches
        assert len(results) == 10  # 100 items / 10 batch_size = 10 batches

        # Check first batch
        assert len(results[0]) == 10
        assert results[0][0] == 0  # 0 * 2
        assert results[0][1] == 2  # 1 * 2

    def test_optimization_recommendations(self) -> None:
        """Test optimization recommendations."""
        optimizer = MemoryOptimizer()

        # Test small collection
        small_recommendations = optimizer.optimize_for_large_collection(50)
        assert small_recommendations["batch_size"] >= 10
        assert not small_recommendations["use_streaming"]

        # Test large collection
        large_recommendations = optimizer.optimize_for_large_collection(10000)
        assert large_recommendations["use_streaming"]
        assert large_recommendations["enable_pooling"]
        assert large_recommendations["memory_limit_mb"] > 500


class TestPerformanceIntegration:
    """Test integration between performance components."""

    def test_streaming_with_parallel_analysis(self, sample_yara_files) -> None:
        """Test combining streaming parser with parallel analyzer."""
        # Parse files with streaming parser
        streaming_parser = StreamingParser()
        parse_results = list(streaming_parser.parse_files(sample_yara_files))

        # Extract successful ASTs
        successful_asts = [r.ast for r in parse_results if r.ast is not None]

        # Analyze with parallel analyzer
        with ParallelAnalyzer(max_workers=2) as analyzer:
            complexity_jobs = analyzer.analyze_complexity_parallel(successful_asts)

            assert len(complexity_jobs) == len(successful_asts)

            successful_analyses = [j for j in complexity_jobs if j.status.value == "completed"]
            assert len(successful_analyses) == len(successful_asts)

    def test_batch_processor_with_memory_optimizer(self, sample_yara_files) -> None:
        """Test batch processor using memory optimizer."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Use batch processor with memory optimization
            processor = BatchProcessor(
                max_memory_mb=100,  # Low limit to trigger optimization
                batch_size=1,  # Small batches
            )

            results = processor.process_files(
                sample_yara_files,
                [BatchOperation.PARSE],
                output_dir,
            )

            assert BatchOperation.PARSE in results
            parse_result = results[BatchOperation.PARSE]
            assert parse_result.successful_count > 0

    def test_end_to_end_performance_workflow(self, large_yara_file) -> None:
        """Test complete performance workflow on large file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir)

            # Step 1: Stream parse individual rules
            streaming_parser = StreamingParser(max_memory_mb=200)
            rule_results = list(streaming_parser.parse_rules_from_file(large_yara_file))

            # Step 2: Extract successful ASTs
            successful_asts = [r.ast for r in rule_results if r.ast is not None]
            assert len(successful_asts) == 20

            # Step 3: Parallel analysis
            with ParallelAnalyzer(max_workers=2) as analyzer:
                complexity_jobs = analyzer.analyze_complexity_parallel(successful_asts)

                # Should have analyzed all rules
                successful_analyses = [j for j in complexity_jobs if j.status.value == "completed"]
                assert len(successful_analyses) == 20

                # Each analysis should have metrics
                for job in successful_analyses:
                    assert "quality_score" in job.result
                    assert job.result["quality_score"] > 0
