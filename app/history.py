from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: Literal["github", "api"]
    repository: str
    reference: str | None = None
    exchange: str
    status: Literal["pass", "review", "block", "error"]
    findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AuditHistory:
    """Thread-safe, bounded metadata history.

    Repository content and finding messages are deliberately excluded. The
    in-memory implementation is an MVP and can be replaced by durable storage
    without changing the dashboard API.
    """

    def __init__(self, limit: int = 100) -> None:
        self._records: deque[AuditRecord] = deque(maxlen=limit)
        self._lock = Lock()

    def add(self, record: AuditRecord) -> AuditRecord:
        with self._lock:
            self._records.appendleft(record)
        return record

    def list(self, limit: int = 25) -> list[AuditRecord]:
        safe_limit = max(1, min(limit, 100))
        with self._lock:
            return list(self._records)[:safe_limit]

    def summary(self) -> dict[str, int]:
        with self._lock:
            records = list(self._records)
        return {
            "total": len(records),
            "passed": sum(record.status == "pass" for record in records),
            "needs_attention": sum(
                record.status in {"review", "block"} for record in records
            ),
            "failed": sum(record.status == "error" for record in records),
            "findings": sum(record.findings for record in records),
        }


audit_history = AuditHistory()
