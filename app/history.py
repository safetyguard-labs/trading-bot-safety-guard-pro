import logging
import os
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, Field


logger = logging.getLogger("safety_guard.history")


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


class AuditHistoryStore(Protocol):
    storage: str

    def add(self, record: AuditRecord) -> AuditRecord: ...
    def list(self, limit: int = 25) -> list[AuditRecord]: ...
    def summary(self) -> dict[str, int]: ...


def _summary(records: list[AuditRecord]) -> dict[str, int]:
    return {
        "total": len(records),
        "passed": sum(record.status == "pass" for record in records),
        "needs_attention": sum(
            record.status in {"review", "block"} for record in records
        ),
        "failed": sum(record.status == "error" for record in records),
        "findings": sum(record.findings for record in records),
    }


class MemoryAuditHistory:
    """Thread-safe bounded fallback for development and unconfigured deploys."""

    storage = "temporary"

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
        return _summary(records)


class PostgresAuditHistory:
    """Durable audit metadata storage backed by PostgreSQL."""

    storage = "postgres"

    def __init__(self, database_url: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._database_url = database_url
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS safety_guard_audits (
                    id VARCHAR(12) PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL,
                    source VARCHAR(16) NOT NULL,
                    repository TEXT NOT NULL,
                    reference TEXT,
                    exchange VARCHAR(32) NOT NULL,
                    status VARCHAR(16) NOT NULL,
                    findings INTEGER NOT NULL,
                    critical INTEGER NOT NULL,
                    high INTEGER NOT NULL,
                    medium INTEGER NOT NULL,
                    low INTEGER NOT NULL
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS safety_guard_audits_created_at_idx
                ON safety_guard_audits (created_at DESC)
            """)

    def _connect(self):
        return self._psycopg.connect(self._database_url, connect_timeout=5)

    def add(self, record: AuditRecord) -> AuditRecord:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO safety_guard_audits
                (id, created_at, source, repository, reference, exchange, status,
                 findings, critical, high, medium, low)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING""",
                (
                    record.id, record.created_at, record.source, record.repository,
                    record.reference, record.exchange, record.status, record.findings,
                    record.critical, record.high, record.medium, record.low,
                ),
            )
        return record

    def list(self, limit: int = 25) -> list[AuditRecord]:
        safe_limit = max(1, min(limit, 100))
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, created_at, source, repository, reference, exchange,
                status, findings, critical, high, medium, low
                FROM safety_guard_audits ORDER BY created_at DESC LIMIT %s""",
                (safe_limit,),
            ).fetchall()
        return [
            AuditRecord(
                id=row[0], created_at=row[1], source=row[2], repository=row[3],
                reference=row[4], exchange=row[5], status=row[6], findings=row[7],
                critical=row[8], high=row[9], medium=row[10], low=row[11],
            )
            for row in rows
        ]

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute("""
                SELECT COUNT(*),
                       COUNT(*) FILTER (WHERE status = 'pass'),
                       COUNT(*) FILTER (WHERE status IN ('review', 'block')),
                       COUNT(*) FILTER (WHERE status = 'error'),
                       COALESCE(SUM(findings), 0)
                FROM safety_guard_audits
            """).fetchone()
        return {
            "total": row[0], "passed": row[1], "needs_attention": row[2],
            "failed": row[3], "findings": row[4],
        }


def build_audit_history() -> AuditHistoryStore:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        return MemoryAuditHistory()
    try:
        return PostgresAuditHistory(database_url)
    except Exception:
        logger.exception("PostgreSQL audit history unavailable; using temporary storage")
        return MemoryAuditHistory()


audit_history = build_audit_history()
