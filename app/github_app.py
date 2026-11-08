import base64
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from app.analyzer import AnalysisRequest, AnalysisResult, analyze_trading_config


API_ROOT = "https://api.github.com"
MAX_FILES = 20
MAX_COMBINED_CONTENT = 100_000
TEXT_EXTENSIONS = {
    ".env", ".ini", ".json", ".py", ".toml", ".txt", ".yaml", ".yml"
}
IGNORED_PATH_PREFIXES = (".github/", "docs/", "tests/")


@dataclass
class GitHubEvent:
    installation_id: int
    repository: str
    sha: str
    before: str | None = None
    pull_number: int | None = None


def credentials_configured() -> bool:
    return bool(os.getenv("GITHUB_APP_ID") and os.getenv("GITHUB_APP_PRIVATE_KEY"))


def is_analyzable_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    if normalized.startswith(IGNORED_PATH_PREFIXES):
        return False
    filename = normalized.rsplit("/", 1)[-1]
    return any(filename.endswith(extension) for extension in TEXT_EXTENSIONS)


def event_from_payload(event: str, payload: dict[str, Any]) -> GitHubEvent | None:
    installation_id = payload.get("installation", {}).get("id")
    repository = payload.get("repository", {}).get("full_name")
    if not installation_id or not repository:
        return None

    if event == "push":
        sha = payload.get("after")
        if not sha or sha == "0" * 40:
            return None
        return GitHubEvent(
            installation_id=int(installation_id),
            repository=repository,
            sha=sha,
            before=payload.get("before"),
        )

    if event == "pull_request" and payload.get("action") in {
        "opened", "reopened", "synchronize", "ready_for_review"
    }:
        pull = payload.get("pull_request", {})
        sha = pull.get("head", {}).get("sha")
        if sha:
            return GitHubEvent(
                installation_id=int(installation_id),
                repository=repository,
                sha=sha,
                pull_number=int(payload["number"]),
            )
    return None


def _app_jwt() -> str:
    now = int(time.time())
    private_key = os.environ["GITHUB_APP_PRIVATE_KEY"].replace("\\n", "\n")
    return jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": os.environ["GITHUB_APP_ID"]},
        private_key,
        algorithm="RS256",
    )


def _headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "trading-bot-safety-guard-pro",
    }


def _installation_token(client: httpx.Client, installation_id: int) -> str:
    response = client.post(
        f"{API_ROOT}/app/installations/{installation_id}/access_tokens",
        headers=_headers(_app_jwt()),
    )
    response.raise_for_status()
    return response.json()["token"]


def _changed_files(client: httpx.Client, token: str, event: GitHubEvent) -> list[dict[str, Any]]:
    if event.pull_number:
        url = f"{API_ROOT}/repos/{event.repository}/pulls/{event.pull_number}/files"
    elif event.before and event.before != "0" * 40:
        url = f"{API_ROOT}/repos/{event.repository}/compare/{event.before}...{event.sha}"
    else:
        return []
    response = client.get(url, headers=_headers(token), params={"per_page": MAX_FILES})
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, list) else data.get("files", [])


def _file_content(client: httpx.Client, token: str, repository: str, path: str, sha: str) -> str:
    response = client.get(
        f"{API_ROOT}/repos/{repository}/contents/{path}",
        headers=_headers(token),
        params={"ref": sha},
    )
    if response.status_code == 404:
        return ""
    response.raise_for_status()
    data = response.json()
    if data.get("encoding") != "base64" or not data.get("content"):
        return ""
    raw = base64.b64decode(data["content"], validate=False)
    if b"\x00" in raw:
        return ""
    return raw.decode("utf-8", errors="replace")


def _analyze_files(client: httpx.Client, token: str, event: GitHubEvent) -> AnalysisResult:
    sections: list[str] = []
    size = 0
    for item in _changed_files(client, token, event)[:MAX_FILES]:
        if item.get("status") == "removed":
            continue
        path = item.get("filename", "")
        if not is_analyzable_path(path):
            continue
        content = _file_content(client, token, event.repository, path, event.sha)
        if not content:
            continue
        section = f"\n# FILE: {path}\n{content}"
        remaining = MAX_COMBINED_CONTENT - size
        if remaining <= 0:
            break
        sections.append(section[:remaining])
        size += len(sections[-1])

    combined = "".join(sections)
    if not combined:
        return AnalysisResult(status="pass", exchange="generic", findings=[])
    exchange = "generic"
    lower = combined.lower()
    if "binance" in lower:
        exchange = "binance"
    elif "bybit" in lower:
        exchange = "bybit"
    return analyze_trading_config(AnalysisRequest(exchange=exchange, content=combined))


def _summary(result: AnalysisResult) -> str:
    if not result.findings:
        return "No supported trading-bot safety risks were detected in the changed text files."
    return "\n".join(
        f"- **{finding.severity.upper()}** `{finding.rule}`: {finding.message}"
        for finding in result.findings[:20]
    )


def process_github_event(event: GitHubEvent) -> dict[str, Any]:
    with httpx.Client(timeout=8.0) as client:
        token = _installation_token(client, event.installation_id)
        check = client.post(
            f"{API_ROOT}/repos/{event.repository}/check-runs",
            headers=_headers(token),
            json={
                "name": "Trading Bot Safety Guard Pro",
                "head_sha": event.sha,
                "status": "in_progress",
            },
        )
        check.raise_for_status()
        check_id = check.json()["id"]
        try:
            result = _analyze_files(client, token, event)
            conclusion = "success" if result.status == "pass" else "failure"
            title = "Safety review passed" if result.status == "pass" else "Safety review needs attention"
            client.patch(
                f"{API_ROOT}/repos/{event.repository}/check-runs/{check_id}",
                headers=_headers(token),
                json={
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": {
                        "title": title,
                        "summary": _summary(result),
                        "text": result.disclaimer,
                    },
                },
            ).raise_for_status()
            return {"status": result.status, "findings": len(result.findings), "check_id": check_id}
        except Exception:
            client.patch(
                f"{API_ROOT}/repos/{event.repository}/check-runs/{check_id}",
                headers=_headers(token),
                json={
                    "status": "completed",
                    "conclusion": "neutral",
                    "output": {
                        "title": "Safety review could not complete",
                        "summary": "The defensive review encountered a temporary processing error.",
                    },
                },
            )
            raise
