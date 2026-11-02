import hashlib
import hmac
import os

from fastapi import FastAPI, HTTPException, Request


app = FastAPI(
    title="Trading Bot Safety Guard Pro",
    version="0.1.0",
    description="Defensive repository auditing for trading bots.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "trading-bot-safety-guard-pro"}


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "Trading Bot Safety Guard Pro",
        "status": "development-preview",
        "docs": "/docs",
    }


@app.post("/webhooks/github")
async def github_webhook(request: Request) -> dict[str, str]:
    """Accept only events signed with the configured GitHub webhook secret."""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="Webhook is not configured")

    body = await request.body()
    supplied = request.headers.get("x-hub-signature-256", "")
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event = request.headers.get("x-github-event", "unknown")
    return {"status": "accepted", "event": event}
