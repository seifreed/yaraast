"""Additional real coverage for parallel_models."""

from __future__ import annotations

from yaraast.performance.parallel_models import Job, JobStatus


def test_parallel_job_completion_and_time_fields() -> None:
    running = Job(job_id="1", job_type="scan", status=JobStatus.RUNNING)
    assert running.status is not JobStatus.COMPLETED
    assert running.status is not JobStatus.FAILED

    completed = Job(
        job_id="2",
        job_type="scan",
        status=JobStatus.COMPLETED,
        start_time=1.0,
        end_time=2.0,
    )
    assert completed.status is JobStatus.COMPLETED
    assert completed.start_time == 1.0
    assert completed.end_time == 2.0

    failed = Job(job_id="3", job_type="scan", status=JobStatus.FAILED)
    assert failed.status is JobStatus.FAILED
