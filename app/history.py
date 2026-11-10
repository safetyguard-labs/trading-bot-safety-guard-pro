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
    installation_id: int | None = None
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
    def list(
        self, limit: int = 25, installation_ids: set[int] | None = None
    ) -> list[AuditRecord]: ...
    def summary(self, installation_ids: set[int] | None = None) -> dict[str, int]: ...


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

    def list(
        self, limit: int = 25, installation_ids: set[int] | None = None
    ) -> list[AuditRecord]:
        safe_limit = max(1, min(limit, 100))
        with self._lock:
            records = list(self._records)
        if installation_ids is not None:
            records = [
                record for record in records
                if record.installation_id in installation_ids
            ]
        return records[:safe_limit]

    def summary(self, installation_ids: set[int] | None = None) -> dict[str, int]:
        return _summary(self.list(100, installation_ids))


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
                    installation_id BIGINT,
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
            connection.execute("""
                ALTER TABLE safety_guard_audits
                ADD COLUMN IF NOT EXISTS installation_id BIGINT
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS safety_guard_audits_installation_idx
                ON safety_guard_audits (installation_id, created_at DESC)
            """)

    def _connect(self):
        return self._psycopg.connect(self._database_url, connect_timeout=5)

    def add(self, record: AuditRecord) -> AuditRecord:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO safety_guard_audits
                (id, created_at, source, installation_id, repository, reference, exchange, status,
                 findings, critical, high, medium, low)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING""",
                (
                    record.id, record.created_at, record.source, record.installation_id,
                    record.repository,
                    record.reference, record.exchange, record.status, record.findings,
                    record.critical, record.high, record.medium, record.low,
                ),
            )
        return record

    def list(
        self, limit: int = 25, installation_ids: set[int] | None = None
    ) -> list[AuditRecord]:
        safe_limit = max(1, min(limit, 100))
        where = ""
        params: tuple[object, ...]
        if installation_ids is None:
            params = (safe_limit,)
        elif not installation_ids:
            return []
        else:
            where = "WHERE installation_id = ANY(%s)"
            params = (list(installation_ids), safe_limit)
        with self._connect() as connection:
            rows = connection.execute(
                f"""SELECT id, created_at, source, installation_id, repository, reference, exchange,
                status, findings, critical, high, medium, low
                FROM safety_guard_audits {where} ORDER BY created_at DESC LIMIT %s""",
                params,
            ).fetchall()
        return [
            AuditRecord(
                id=row[0], created_at=row[1], source=row[2], installation_id=row[3],
                repository=row[4], reference=row[5], exchange=row[6], status=row[7],
                findings=row[8], critical=row[9], high=row[10], medium=row[11], low=row[12],
            )
            for row in rows
        ]

    def summary(self, installation_ids: set[int] | None = None) -> dict[str, int]:
        return _summary(self.list(100, installation_ids))


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
