"""Models for parallel analysis."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JobStatus(Enum):
    """Job status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Job:
    """Represents a parallel analysis job."""

    job_id: str
    job_type: str
    status: JobStatus = JobStatus.PENDING
    result: Any = None
    error: str | None = None
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None

    @property
    def is_completed(self) -> bool:
        """Check if job is completed."""
        return self.status in (JobStatus.COMPLETED, JobStatus.FAILED)

    @property
    def duration(self) -> float:
        """Get job duration in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
