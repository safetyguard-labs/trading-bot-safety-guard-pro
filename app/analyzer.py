import re
from typing import Literal

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    exchange: Literal["binance", "bybit", "generic"] = "generic"
    content: str = Field(max_length=100_000)


class Finding(BaseModel):
    rule: str
    severity: Literal["low", "medium", "high", "critical"]
    message: str
    remediation: str


class AnalysisResult(BaseModel):
    status: Literal["pass", "review", "block"]
    exchange: str
    findings: list[Finding]
    disclaimer: str = "Defensive static analysis only; this is not financial advice."


SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}"),
    re.compile(r"(?i)(binance|bybit)[_-]?(key|secret)\s*[:=]\s*[^\s#]{8,}"),
)


def analyze_trading_config(payload: AnalysisRequest) -> AnalysisResult:
    text = payload.content
    lower = text.lower()
    findings: list[Finding] = []

    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        findings.append(Finding(
            rule="credentials.exposed",
            severity="critical",
            message="A likely exchange credential is embedded in repository content.",
            remediation="Revoke the credential, remove it from Git history, and use encrypted environment secrets.",
        ))

    live_enabled = bool(re.search(r"(?i)(testnet|sandbox|paper)\s*[:=]\s*(false|0|no)", text))
    explicit_live = bool(re.search(r"(?i)(live|production|mainnet)\s*[:=]\s*(true|1|yes)", text))
    confirmation = "confirm_live_trading" in lower or "live_trading_ack" in lower
    if (live_enabled or explicit_live) and not confirmation:
        findings.append(Finding(
            rule=f"{payload.exchange}.live-mode-confirmation",
            severity="high",
            message="Live trading appears enabled without an explicit production acknowledgement.",
            remediation="Default to testnet and require a separate CONFIRM_LIVE_TRADING control for production.",
        ))

    leverage_values = [int(value) for value in re.findall(r"(?i)leverage\s*[:=]\s*(\d+)", text)]
    if leverage_values and max(leverage_values) > 10:
        findings.append(Finding(
            rule="risk.excessive-leverage",
            severity="high",
            message=f"Configured leverage reaches {max(leverage_values)}x.",
            remediation="Set a documented leverage ceiling of 10x or lower and enforce it in code.",
        ))

    if not re.search(r"(?i)(max[_-]?(daily[_-]?)?loss|drawdown[_-]?limit|kill[_-]?switch)", text):
        findings.append(Finding(
            rule="risk.missing-loss-limit",
            severity="medium",
            message="No maximum-loss, drawdown, or kill-switch control was detected.",
            remediation="Add an enforced loss limit and a tested emergency shutdown path.",
        ))

    if any(f.severity == "critical" for f in findings):
        status = "block"
    elif findings:
        status = "review"
    else:
        status = "pass"
    return AnalysisResult(status=status, exchange=payload.exchange, findings=findings)
