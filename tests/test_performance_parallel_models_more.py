"""Additional real coverage for parallel_models."""

from __future__ import annotations

import time

from yaraast.performance.parallel_models import Job, JobStatus


def test_parallel_job_completion_and_duration_paths() -> None:
    running = Job(job_id="1", job_type="scan", status=JobStatus.RUNNING)
    assert running.status is not JobStatus.COMPLETED
    assert running.status is not JobStatus.FAILED
    assert running.duration >= 0

    completed = Job(
        job_id="2",
        job_type="scan",
        status=JobStatus.COMPLETED,
        start_time=time.time() - 2,
        end_time=time.time() - 1,
    )
    assert completed.status is JobStatus.COMPLETED
    assert 0.9 <= completed.duration <= 1.1

    failed = Job(job_id="3", job_type="scan", status=JobStatus.FAILED)
    assert failed.status is JobStatus.FAILED
