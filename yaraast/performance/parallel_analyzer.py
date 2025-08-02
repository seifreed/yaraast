"""Parallel AST analysis using thread pooling for performance optimization."""

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

from yaraast.ast.base import YaraFile
from yaraast.metrics import ComplexityAnalyzer, DependencyGraphGenerator
from yaraast.parser import Parser

T = TypeVar("T")


class JobStatus(Enum):
    """Analysis job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AnalysisJob[T]:
    """Represents an analysis job for parallel processing."""

    job_id: str
    input_data: Any  # File path, AST, or other input
    job_type: str  # 'parse', 'complexity', 'dependency', etc.
    parameters: dict[str, Any] = field(default_factory=dict)

    # Status tracking
    status: JobStatus = JobStatus.PENDING
    result: T | None = None
    error: str | None = None
    start_time: float | None = None
    end_time: float | None = None
    worker_id: str | None = None

    @property
    def duration(self) -> float | None:
        """Get job duration in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    @property
    def is_completed(self) -> bool:
        """Check if job is completed (success or failure)."""
        return self.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)


class ParallelAnalyzer:
    """Parallel AST analysis engine with thread pooling.

    This analyzer provides thread-pooled execution for AST operations:
    - Parallel parsing of multiple YARA files
    - Concurrent complexity analysis
    - Parallel dependency graph generation
    - Batch processing with progress tracking
    """

    def __init__(
        self,
        max_workers: int | None = None,
        queue_size: int = 1000,
        timeout: float = 300.0,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ):
        """Initialize parallel analyzer.

        Args:
            max_workers: Maximum number of worker threads (default: CPU count)
            queue_size: Maximum job queue size
            timeout: Job timeout in seconds
            progress_callback: Called with (job_type, completed, total)
        """
        self.max_workers = max_workers
        self.queue_size = queue_size
        self.timeout = timeout
        self.progress_callback = progress_callback

        self._executor: ThreadPoolExecutor | None = None
        self._jobs: dict[str, AnalysisJob] = {}
        self._job_counter = 0
        self._lock = threading.Lock()

        # Statistics
        self.stats = {
            "jobs_submitted": 0,
            "jobs_completed": 0,
            "jobs_failed": 0,
            "total_processing_time": 0.0,
            "avg_job_time": 0.0,
            "peak_concurrent_jobs": 0,
            "workers_created": 0,
        }

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()

    def start(self) -> None:
        """Start the thread pool executor."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.max_workers, thread_name_prefix="yaraast-worker"
            )
            self.stats["workers_created"] = self._executor._max_workers

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the thread pool executor."""
        if self._executor:
            self._executor.shutdown(wait=wait)
            self._executor = None

    def parse_files_parallel(
        self, file_paths: list[str | Path], chunk_size: int = 10
    ) -> list[AnalysisJob[YaraFile]]:
        """Parse multiple YARA files in parallel.

        Args:
            file_paths: List of file paths to parse
            chunk_size: Number of files to process per job

        Returns:
            List of analysis jobs with parsed ASTs
        """
        if not self._executor:
            self.start()

        jobs = []

        # Create jobs for file chunks
        for i in range(0, len(file_paths), chunk_size):
            chunk = file_paths[i : i + chunk_size]
            job = self._submit_job(
                job_type="parse_files", input_data=chunk, worker_func=self._parse_files_worker
            )
            jobs.append(job)

        # Wait for completion and collect results
        return self._wait_for_jobs(jobs, "Parsing files")

    def analyze_complexity_parallel(
        self, asts: list[YaraFile], file_names: list[str] | None = None
    ) -> list[AnalysisJob]:
        """Analyze complexity of multiple ASTs in parallel.

        Args:
            asts: List of parsed YARA ASTs
            file_names: Optional list of file names for identification

        Returns:
            List of analysis jobs with complexity metrics
        """
        if not self._executor:
            self.start()

        jobs = []

        for i, ast in enumerate(asts):
            file_name = file_names[i] if file_names and i < len(file_names) else f"ast_{i}"

            job = self._submit_job(
                job_type="complexity",
                input_data=ast,
                parameters={"file_name": file_name},
                worker_func=self._complexity_worker,
            )
            jobs.append(job)

        return self._wait_for_jobs(jobs, "Analyzing complexity")

    def generate_graphs_parallel(
        self,
        asts: list[YaraFile],
        output_dir: Path | None = None,
        graph_types: list[str] | None = None,
    ) -> list[AnalysisJob]:
        """Generate dependency graphs for multiple ASTs in parallel.

        Args:
            asts: List of parsed YARA ASTs
            output_dir: Directory to save graphs
            graph_types: Types of graphs to generate ['full', 'rules', 'modules']

        Returns:
            List of analysis jobs with generated graphs
        """
        if not self._executor:
            self.start()

        if graph_types is None:
            graph_types = ["full", "rules", "modules"]

        jobs = []

        for i, ast in enumerate(asts):
            for graph_type in graph_types:
                job = self._submit_job(
                    job_type=f"graph_{graph_type}",
                    input_data=ast,
                    parameters={"ast_index": i, "graph_type": graph_type, "output_dir": output_dir},
                    worker_func=self._graph_worker,
                )
                jobs.append(job)

        return self._wait_for_jobs(jobs, "Generating graphs")

    def process_batch(
        self,
        items: list[Any],
        worker_func: Callable[[Any, dict[str, Any]], Any],
        job_type: str = "batch",
        parameters: dict[str, Any] | None = None,
        max_concurrent: int | None = None,
    ) -> list[AnalysisJob]:
        """Process a batch of items in parallel with custom worker function.

        Args:
            items: List of items to process
            worker_func: Function to process each item
            job_type: Type identifier for jobs
            parameters: Additional parameters for worker
            max_concurrent: Maximum concurrent jobs (None = no limit)

        Returns:
            List of completed analysis jobs
        """
        if not self._executor:
            self.start()

        if parameters is None:
            parameters = {}

        jobs = []

        # Submit jobs with concurrency control
        for i, item in enumerate(items):
            # Wait if we have too many concurrent jobs
            if max_concurrent and len([j for j in jobs if not j.is_completed]) >= max_concurrent:
                # Wait for some jobs to complete
                self._wait_for_some_completion(jobs, max_concurrent // 2)

            job = self._submit_job(
                job_type=f"{job_type}_{i}",
                input_data=item,
                parameters=parameters.copy(),
                worker_func=worker_func,
            )
            jobs.append(job)

        return self._wait_for_jobs(jobs, f"Processing {job_type}")

    def get_job_status(self, job_id: str) -> AnalysisJob | None:
        """Get status of a specific job."""
        return self._jobs.get(job_id)

    def get_active_jobs(self) -> list[AnalysisJob]:
        """Get list of currently active (non-completed) jobs."""
        return [job for job in self._jobs.values() if not job.is_completed]

    def get_statistics(self) -> dict[str, Any]:
        """Get processing statistics."""
        completed_jobs = [j for j in self._jobs.values() if j.is_completed]

        if completed_jobs:
            total_time = sum(j.duration or 0 for j in completed_jobs)
            self.stats["avg_job_time"] = total_time / len(completed_jobs)

        return self.stats.copy()

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a specific job."""
        job = self._jobs.get(job_id)
        if job and job.status == JobStatus.PENDING:
            job.status = JobStatus.CANCELLED
            return True
        return False

    def cancel_all_jobs(self) -> int:
        """Cancel all pending jobs."""
        cancelled = 0
        for job in self._jobs.values():
            if job.status == JobStatus.PENDING:
                job.status = JobStatus.CANCELLED
                cancelled += 1
        return cancelled

    def _submit_job(
        self,
        job_type: str,
        input_data: Any,
        worker_func: Callable,
        parameters: dict[str, Any] | None = None,
    ) -> AnalysisJob:
        """Submit a job to the thread pool."""
        with self._lock:
            self._job_counter += 1
            job_id = f"{job_type}_{self._job_counter}"

        job = AnalysisJob(
            job_id=job_id, input_data=input_data, job_type=job_type, parameters=parameters or {}
        )

        self._jobs[job_id] = job

        # Submit to executor
        future = self._executor.submit(self._job_wrapper, job, worker_func)
        job.future = future

        self.stats["jobs_submitted"] += 1

        return job

    def _job_wrapper(self, job: AnalysisJob, worker_func: Callable) -> Any:
        """Wrapper for job execution with error handling and timing."""
        job.start_time = time.time()
        job.status = JobStatus.RUNNING
        job.worker_id = threading.current_thread().name

        try:
            result = worker_func(job.input_data, job.parameters)
            job.result = result
            job.status = JobStatus.COMPLETED
            self.stats["jobs_completed"] += 1
            return result

        except Exception as e:
            job.error = str(e)
            job.status = JobStatus.FAILED
            self.stats["jobs_failed"] += 1
            raise

        finally:
            job.end_time = time.time()
            if job.duration:
                self.stats["total_processing_time"] += job.duration

    def _wait_for_jobs(self, jobs: list[AnalysisJob], operation_name: str) -> list[AnalysisJob]:
        """Wait for jobs to complete with progress tracking."""
        total_jobs = len(jobs)

        while True:
            completed = sum(1 for job in jobs if job.is_completed)

            if self.progress_callback:
                self.progress_callback(operation_name, completed, total_jobs)

            if completed == total_jobs:
                break

            time.sleep(0.1)

        return jobs

    def _wait_for_some_completion(self, jobs: list[AnalysisJob], target_completed: int) -> None:
        """Wait until at least target_completed jobs are finished."""
        while True:
            completed = sum(1 for job in jobs if job.is_completed)
            if completed >= target_completed:
                break
            time.sleep(0.1)

    # Worker functions for different analysis types

    def _parse_files_worker(
        self, file_paths: list[Path], parameters: dict[str, Any]
    ) -> list[YaraFile]:
        """Worker function for parsing files."""
        parser = Parser()
        results = []

        for file_path in file_paths:
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                ast = parser.parse(content)
                results.append(ast)
            except Exception as e:
                # Create empty AST with error info
                ast = YaraFile(imports=[], includes=[], rules=[])
                ast._parse_error = str(e)
                results.append(ast)

        return results

    def _complexity_worker(self, ast: YaraFile, parameters: dict[str, Any]) -> dict[str, Any]:
        """Worker function for complexity analysis."""
        analyzer = ComplexityAnalyzer()
        metrics = analyzer.analyze(ast)

        return {
            "file_name": parameters.get("file_name", "unknown"),
            "metrics": metrics.to_dict(),
            "quality_score": metrics.get_quality_score(),
            "quality_grade": metrics.get_complexity_grade(),
        }

    def _graph_worker(self, ast: YaraFile, parameters: dict[str, Any]) -> dict[str, Any]:
        """Worker function for graph generation."""
        generator = DependencyGraphGenerator()
        graph_type = parameters["graph_type"]
        ast_index = parameters["ast_index"]
        output_dir = parameters.get("output_dir")

        # Generate appropriate graph
        if graph_type == "full":
            graph_source = generator.generate_graph(ast)
        elif graph_type == "rules":
            graph_source = generator.generate_rule_graph(ast)
        elif graph_type == "modules":
            graph_source = generator.generate_module_graph(ast)
        else:
            raise ValueError(f"Unknown graph type: {graph_type}")

        result = {"ast_index": ast_index, "graph_type": graph_type, "graph_source": graph_source}

        # Save to file if output directory provided
        if output_dir:
            output_file = Path(output_dir) / f"ast_{ast_index}_{graph_type}.dot"
            output_file.write_text(graph_source)
            result["output_file"] = str(output_file)

        return result


class ProgressTracker:
    """Helper class for tracking progress of parallel operations."""

    def __init__(self, total_operations: int, update_interval: float = 1.0):
        """Initialize progress tracker.

        Args:
            total_operations: Total number of operations to track
            update_interval: Minimum seconds between progress updates
        """
        self.total_operations = total_operations
        self.update_interval = update_interval
        self.completed_operations = 0
        self.start_time = time.time()
        self.last_update = 0
        self._lock = threading.Lock()

    def update(self, increment: int = 1) -> dict[str, Any] | None:
        """Update progress and return stats if update interval reached.

        Args:
            increment: Number of operations completed

        Returns:
            Progress stats dict if update should be displayed, None otherwise
        """
        with self._lock:
            self.completed_operations += increment
            current_time = time.time()

            if current_time - self.last_update >= self.update_interval:
                self.last_update = current_time

                elapsed = current_time - self.start_time
                percentage = (self.completed_operations / self.total_operations) * 100

                # Estimate remaining time
                if self.completed_operations > 0:
                    avg_time_per_op = elapsed / self.completed_operations
                    remaining_ops = self.total_operations - self.completed_operations
                    eta = remaining_ops * avg_time_per_op
                else:
                    eta = None

                return {
                    "completed": self.completed_operations,
                    "total": self.total_operations,
                    "percentage": percentage,
                    "elapsed": elapsed,
                    "eta": eta,
                }

        return None
