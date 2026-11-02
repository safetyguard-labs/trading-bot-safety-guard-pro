import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import app


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_landing_page() -> None:
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "Ship bots with" in response.text
    assert response.headers["x-frame-options"] == "DENY"


def test_ready_reports_missing_secret(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    response = TestClient(app).get("/ready")
    assert response.json() == {"status": "ready", "webhook": "missing"}


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
    assert response.json() == {"status": "accepted", "event": "installation"}


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
