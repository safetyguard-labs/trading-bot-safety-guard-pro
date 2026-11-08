import hashlib
import hmac
import logging
import os
import uuid
from collections import Counter

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.analyzer import AnalysisRequest, AnalysisResult, analyze_trading_config
from app.github_app import credentials_configured, event_from_payload, process_github_event


app = FastAPI(
    title="Trading Bot Safety Guard Pro",
    version="1.0.0",
    description="Defensive repository auditing for trading bots.",
)

logger = logging.getLogger("safety_guard")
metrics: Counter[str] = Counter()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    logger.info("request completed", extra={"request_id": request_id})
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "trading-bot-safety-guard-pro"}


@app.get("/ready")
def ready() -> dict[str, str]:
    webhook = "configured" if os.getenv("GITHUB_WEBHOOK_SECRET") else "missing"
    automation = "configured" if credentials_configured() else "disabled"
    return {"status": "ready", "webhook": webhook, "automation": automation}


@app.get("/metrics")
def service_metrics() -> dict[str, int]:
    return {
        "webhooks_accepted": metrics["webhooks_accepted"],
        "checks_completed": metrics["checks_completed"],
        "checks_failed": metrics["checks_failed"],
        "analyses_requested": metrics["analyses_requested"],
    }


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return LANDING_PAGE


@app.post("/api/analyze", response_model=AnalysisResult)
def analyze(payload: AnalysisRequest) -> AnalysisResult:
    metrics["analyses_requested"] += 1
    return analyze_trading_config(payload)


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
    metrics["webhooks_accepted"] += 1
    payload = await request.json()
    github_event = event_from_payload(event, payload)
    if github_event and credentials_configured():
        try:
            result = process_github_event(github_event)
            metrics["checks_completed"] += 1
            return {"status": "processed", "event": event, "result": result["status"]}
        except Exception:
            metrics["checks_failed"] += 1
            logger.exception("github check processing failed")
            raise HTTPException(status_code=502, detail="GitHub check processing failed")
    return {
        "status": "accepted",
        "event": event,
        "automation": "enabled" if credentials_configured() else "disabled",
    }


LANDING_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="Defensive repository checks for Binance and Bybit trading systems.">
  <title>Trading Bot Safety Guard Pro</title>
  <style>
    :root{--bg:#07111f;--panel:#0d1d31;--line:#1e3853;--text:#eef7ff;--muted:#9bb2c8;--cyan:#42d9dc;--lime:#98f5a9;--danger:#ff8c8c}
    *{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 85% 0,#153a51 0,transparent 35%),var(--bg);color:var(--text);font:16px/1.6 Inter,system-ui,sans-serif}
    a{color:inherit}.wrap{width:min(1120px,92%);margin:auto}.nav{display:flex;justify-content:space-between;align-items:center;padding:24px 0}.brand{font-weight:800;letter-spacing:.04em}.badge{border:1px solid var(--line);border-radius:999px;padding:6px 12px;color:var(--lime);font-size:.85rem}
    .hero{padding:70px 0 48px;display:grid;grid-template-columns:1.15fr .85fr;gap:52px;align-items:center}h1{font-size:clamp(2.6rem,7vw,5.6rem);line-height:.95;margin:18px 0}h1 span{color:var(--cyan)}.lead{font-size:1.2rem;color:var(--muted);max-width:700px}.actions{display:flex;gap:14px;flex-wrap:wrap;margin-top:28px}.btn{display:inline-block;text-decoration:none;border-radius:10px;padding:12px 18px;font-weight:750;background:var(--cyan);color:#031119}.btn.alt{background:transparent;color:var(--text);border:1px solid var(--line)}
    .terminal,.card{background:linear-gradient(145deg,#10243a,#091626);border:1px solid var(--line);border-radius:18px;box-shadow:0 22px 70px #0008}.terminal{padding:22px;font-family:ui-monospace,monospace}.ok{color:var(--lime)}.warn{color:#ffd37b}.bad{color:var(--danger)}
    .section{padding:52px 0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.card{padding:24px}.card h3{margin-top:0}.card p,.small{color:var(--muted)}.plans .card:nth-child(2){border-color:var(--cyan)}.trust{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0 0}.trust span{border:1px solid var(--line);border-radius:999px;padding:7px 11px;color:var(--muted);font-size:.84rem}footer{border-top:1px solid var(--line);padding:28px 0 50px;color:var(--muted)}
    @media(max-width:800px){.hero,.grid{grid-template-columns:1fr}.hero{padding-top:30px}.terminal{order:-1}}
  </style>
</head>
<body>
<div class="wrap">
  <nav class="nav"><div class="brand">SAFETYGUARD LABS</div><div class="badge">GitHub App · Free plan</div></nav>
  <main>
    <section class="hero">
      <div><div class="badge">AUTOMATED GITHUB CHECKS · LIVE NOW</div><h1>Ship bots with <span>guardrails.</span></h1><p class="lead">Catch exposed credentials, unsafe live-exchange settings, excessive leverage and missing loss controls before trading code reaches production.</p><div class="actions"><a class="btn" href="https://github.com/apps/trading-bot-safety-guard-pro">Install free on GitHub</a><a class="btn alt" href="https://github.com/safetyguard-labs/trading-bot-safety-guard-pro">View source</a><a class="btn alt" href="/docs">API docs</a></div><div class="trust"><span>No exchange keys</span><span>No trade execution</span><span>Short-lived GitHub tokens</span></div></div>
      <div class="terminal"><div>$ safety-guard audit ./bot</div><br><div class="ok">✓ Webhook signature verified</div><div class="ok">✓ No exchange secrets detected</div><div class="warn">! Leverage limit set above 10x</div><div class="bad">✕ Production mode without explicit confirmation</div><br><div>Result: <span class="warn">2 controls require attention</span></div></div>
    </section>
    <section class="section"><h2>From commit to decision</h2><div class="grid"><article class="card"><h3>1. Install</h3><p>Choose the trading repositories you want to protect. The free plan is available now.</p></article><article class="card"><h3>2. Push</h3><p>Every push and pull-request update triggers a bounded review of changed runtime files.</p></article><article class="card"><h3>3. Review</h3><p>See a pass or actionable findings directly in the GitHub Checks interface.</p></article></div></section>
    <section class="section"><h2>Trading-specific controls</h2><div class="grid"><article class="card"><h3>Secret exposure</h3><p>Flags likely API keys, secrets and credentials before they reach production history.</p></article><article class="card"><h3>Exchange controls</h3><p>Understands common Binance and Bybit testnet, live-mode and leverage settings.</p></article><article class="card"><h3>Risk guardrails</h3><p>Checks for maximum-loss, drawdown and emergency shutdown controls.</p></article></div></section>
    <section class="section plans"><h2>Simple plans</h2><div class="grid"><article class="card"><h3>Free</h3><p class="small">Community</p><h2>$0</h2><p>Basic audits, signed webhooks and GitHub Issues support.</p></article><article class="card"><h3>Pro</h3><p class="small">Planned after approval</p><h2>$15/mo</h2><p>Continuous audits, history and alerts.</p></article><article class="card"><h3>Team</h3><p class="small">Planned after approval</p><h2>$49/mo</h2><p>Organization policies and team reporting.</p></article></div></section>
  </main>
  <footer>Trading Bot Safety Guard Pro is a defensive software-analysis tool. It does not execute trades or provide financial advice. · <a href="https://github.com/safetyguard-labs/trading-bot-safety-guard-pro/blob/main/docs/PRIVACY.md">Privacy</a> · <a href="https://github.com/safetyguard-labs/trading-bot-safety-guard-pro/blob/main/docs/TERMS.md">Terms</a> · <a href="https://github.com/safetyguard-labs/trading-bot-safety-guard-pro/blob/main/docs/SUPPORT.md">Support</a></footer>
</div>
</body></html>"""
