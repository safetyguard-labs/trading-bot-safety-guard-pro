import hashlib
import hmac

from fastapi.testclient import TestClient

from app.main import app


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


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
