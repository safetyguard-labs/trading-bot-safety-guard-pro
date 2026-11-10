import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from urllib.parse import urlencode

import httpx
SESSION_COOKIE = "safetyguard_session"
STATE_COOKIE = "safetyguard_oauth_state"
SESSION_SECONDS = 7 * 24 * 60 * 60
STATE_SECONDS = 10 * 60


@dataclass
class UserSession:
    session_id: str
    github_user_id: int
    login: str
    avatar_url: str
    installation_ids: set[int]
    expires_at: datetime


class MemorySessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, UserSession] = {}
        self._lock = Lock()

    def save(self, session: UserSession) -> None:
        with self._lock:
            self._sessions[_session_hash(session.session_id)] = session

    def get(self, session_id: str) -> UserSession | None:
        with self._lock:
            session = self._sessions.get(_session_hash(session_id))
        if not session or session.expires_at <= datetime.now(timezone.utc):
            return None
        return session

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(_session_hash(session_id), None)


class PostgresSessionStore:
    def __init__(self, database_url: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._database_url = database_url
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS safety_guard_sessions (
                    session_hash CHAR(64) PRIMARY KEY,
                    github_user_id BIGINT NOT NULL,
                    login TEXT NOT NULL,
                    avatar_url TEXT NOT NULL,
                    installation_ids BIGINT[] NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS safety_guard_sessions_expiry_idx
                ON safety_guard_sessions (expires_at)
            """)

    def _connect(self):
        return self._psycopg.connect(self._database_url, connect_timeout=5)

    def save(self, session: UserSession) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO safety_guard_sessions
                (session_hash, github_user_id, login, avatar_url, installation_ids, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (session_hash) DO UPDATE SET
                    installation_ids = EXCLUDED.installation_ids,
                    expires_at = EXCLUDED.expires_at""",
                (
                    _session_hash(session.session_id), session.github_user_id,
                    session.login, session.avatar_url,
                    list(session.installation_ids), session.expires_at,
                ),
            )

    def get(self, session_id: str) -> UserSession | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT github_user_id, login, avatar_url, installation_ids, expires_at
                FROM safety_guard_sessions
                WHERE session_hash = %s AND expires_at > NOW()""",
                (_session_hash(session_id),),
            ).fetchone()
        if not row:
            return None
        return UserSession(
            session_id=session_id, github_user_id=row[0], login=row[1],
            avatar_url=row[2], installation_ids=set(row[3]), expires_at=row[4],
        )

    def delete(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM safety_guard_sessions WHERE session_hash = %s",
                (_session_hash(session_id),),
            )


def _session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


def auth_configured() -> bool:
    return bool(
        os.getenv("GITHUB_CLIENT_ID")
        and os.getenv("GITHUB_CLIENT_SECRET")
        and os.getenv("SESSION_SECRET")
        and os.getenv("DATABASE_URL")
    )


def _state_signature(payload: str) -> str:
    secret = os.environ["SESSION_SECRET"].encode()
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def create_oauth_state() -> str:
    payload = f"{secrets.token_urlsafe(24)}.{int(time.time())}"
    signed = f"{payload}.{_state_signature(payload)}"
    return base64.urlsafe_b64encode(signed.encode()).decode().rstrip("=")


def verify_oauth_state(state: str) -> bool:
    try:
        padding = "=" * (-len(state) % 4)
        decoded = base64.urlsafe_b64decode(state + padding).decode()
        nonce, timestamp, supplied = decoded.rsplit(".", 2)
        payload = f"{nonce}.{timestamp}"
        fresh = 0 <= int(time.time()) - int(timestamp) <= STATE_SECONDS
        return fresh and hmac.compare_digest(supplied, _state_signature(payload))
    except (ValueError, UnicodeDecodeError):
        return False


def github_authorize_url(state: str) -> str:
    query = urlencode({
        "client_id": os.environ["GITHUB_CLIENT_ID"],
        "redirect_uri": "https://trading-bot-safety-guard-pro.vercel.app/auth/callback",
        "state": state,
    })
    return f"https://github.com/login/oauth/authorize?{query}"


def complete_github_login(code: str) -> UserSession:
    with httpx.Client(timeout=10.0) as client:
        token_response = client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": os.environ["GITHUB_CLIENT_ID"],
                "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
                "code": code,
            },
        )
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")
        if not access_token:
            raise ValueError("GitHub did not return an access token")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        user_response = client.get("https://api.github.com/user", headers=headers)
        user_response.raise_for_status()
        installations_response = client.get(
            "https://api.github.com/user/installations", headers=headers
        )
        installations_response.raise_for_status()
        user = user_response.json()
        installation_ids = {
            int(item["id"])
            for item in installations_response.json().get("installations", [])
        }

    session = UserSession(
        session_id=secrets.token_urlsafe(32),
        github_user_id=int(user["id"]),
        login=user["login"],
        avatar_url=user.get("avatar_url", ""),
        installation_ids=installation_ids,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=SESSION_SECONDS),
    )
    session_store.save(session)
    return session


def current_session(session_id: str | None) -> UserSession | None:
    if not session_id or not auth_configured():
        return None
    return session_store.get(session_id)


def _build_session_store():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        try:
            return PostgresSessionStore(database_url)
        except Exception:
            pass
    return MemorySessionStore()


session_store = _build_session_store()
