# Operations

## Health checks

- `GET /health` confirms that the application is running.
- `GET /ready` confirms runtime readiness and reports whether webhook validation is configured.

## Webhook verification

GitHub webhook requests are accepted only when `X-Hub-Signature-256` matches the raw request body using `GITHUB_WEBHOOK_SECRET`. Rotate the value in GitHub and Vercel together, then redeploy.

## Incident response

1. Disable the webhook or uninstall the GitHub App if unexpected events appear.
2. Rotate the webhook secret in GitHub and the hosting environment.
3. Review Vercel runtime logs using `X-Request-ID` for correlation.
4. Revoke any exchange credential detected in repository history.

## Availability

Use an external uptime monitor against `/health`. Alert only after repeated failures to avoid transient noise.
