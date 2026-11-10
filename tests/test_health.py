import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import app
from app.auth import create_oauth_state, verify_oauth_state
from app.history import AuditRecord, MemoryAuditHistory, audit_history, build_audit_history


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_landing_page() -> None:
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "Ship bots with" in response.text
    assert response.headers["x-frame-options"] == "DENY"


def test_dashboard_and_empty_history() -> None:
    audit_history._records.clear()
    client = TestClient(app)
    dashboard = client.get("/dashboard")
    history = client.get("/api/audits")
    assert dashboard.status_code == 200
    assert "Repository safety overview" in dashboard.text
    assert history.status_code == 401


def test_api_analysis_adds_history_without_storing_content() -> None:
    audit_history._records.clear()
    secret = 'API_SECRET="this-is-a-real-looking-secret"'
    client = TestClient(app)
    response = client.post("/api/analyze", json={"exchange": "binance", "content": secret})
    assert response.status_code == 200
    records = audit_history.list()
    assert len(records) == 1
    assert records[0].status == "block"
    assert records[0].critical == 1
    assert secret not in str(records)


def test_ready_reports_missing_secret(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    response = TestClient(app).get("/ready")
    assert response.json() == {
        "status": "ready", "webhook": "missing", "automation": "disabled",
        "history": "temporary", "auth": "disabled",
    }


def test_history_uses_memory_without_database_url(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    history = build_audit_history()
    assert isinstance(history, MemoryAuditHistory)
    assert history.storage == "temporary"


def test_memory_history_filters_by_installation() -> None:
    history = MemoryAuditHistory()
    history.add(AuditRecord(
        source="github", installation_id=10, repository="private/one",
        exchange="binance", status="pass",
    ))
    history.add(AuditRecord(
        source="github", installation_id=20, repository="private/two",
        exchange="bybit", status="review", findings=1,
    ))
    assert [record.installation_id for record in history.list(25, {20})] == [20]
    assert history.summary({10})["total"] == 1


def test_oauth_state_is_signed_and_expires_safely(monkeypatch) -> None:
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret")
    state = create_oauth_state()
    assert verify_oauth_state(state)
    assert not verify_oauth_state(state + "tampered")


def test_webhook_requires_configuration(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    response = TestClient(app).post("/webhooks/github", content=b"{}")
    assert response.status_code == 503


def test_webhook_accepts_valid_signature(monkeypatch) -> None:
    secret = "test-secret"
    body = b'{"action":"created"}'
    signature = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)
    response = TestClient(app).post(
        "/webhooks/github",
        content=body,
        headers={
            "x-hub-signature-256": signature,
            "x-github-event": "installation",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "accepted", "event": "installation", "automation": "disabled"
    }


def test_analyzer_blocks_exposed_secret() -> None:
    response = TestClient(app).post(
        "/api/analyze",
        json={
            "exchange": "binance",
            "content": 'API_SECRET="this-is-a-real-looking-secret"\ntestnet=true\nmax_daily_loss=2',
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "block"
    assert response.json()["findings"][0]["rule"] == "credentials.exposed"


def test_analyzer_flags_live_bybit_and_leverage() -> None:
    response = TestClient(app).post(
        "/api/analyze",
        json={
            "exchange": "bybit",
            "content": "testnet=false\nleverage=25\nkill_switch=true",
        },
    )
    rules = {finding["rule"] for finding in response.json()["findings"]}
    assert "bybit.live-mode-confirmation" in rules
    assert "risk.excessive-leverage" in rules


def test_analyzer_ignores_non_trading_configuration() -> None:
    response = TestClient(app).post(
        "/api/analyze",
        json={
            "exchange": "generic",
            "content": "name: Test\non:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest",
        },
    )
    assert response.json()["status"] == "pass"
    assert response.json()["findings"] == []


def test_analyzer_does_not_treat_marketing_copy_as_runtime_config() -> None:
    response = TestClient(app).post(
        "/api/analyze",
        json={
            "exchange": "generic",
            "content": (
                "Trading Bot Safety Guard reviews Binance and Bybit projects "
                "before code reaches production. It checks missing loss controls."
            ),
        },
    )
    assert response.json()["status"] == "pass"
