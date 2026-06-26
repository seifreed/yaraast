"""Models for parallel analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
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


@dataclass(frozen=True)
class ParseErrorMarker:
    """Placeholder for a file that failed while parsing a mixed chunk."""

    file_path: str
    error: str
    _parse_error: bool = True
