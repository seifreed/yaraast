"""Performance optimizations for large YARA rule sets.

This module provides AST-focused performance optimizations including:
- Incremental/streaming parsing for huge collections
- Thread pooling for parallel AST analysis
- Memory-efficient batch processing
- Progress tracking for long-running operations
"""

from yaraast.performance.batch_processor import BatchOperation, BatchProcessor, BatchResult
from yaraast.performance.memory_optimizer import MemoryOptimizer, MemoryStats
from yaraast.performance.parallel_analyzer import AnalysisJob, JobStatus, ParallelAnalyzer
from yaraast.performance.streaming_parser import ParseResult, ParseStatus, StreamingParser

__all__ = [
    "AnalysisJob",
    "BatchOperation",
    "BatchProcessor",
    "BatchResult",
    "JobStatus",
    "MemoryOptimizer",
    "MemoryStats",
    "ParallelAnalyzer",
    "ParseResult",
    "ParseStatus",
    "StreamingParser",
]
