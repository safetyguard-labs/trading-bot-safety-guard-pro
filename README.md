# Trading Bot Safety Guard Pro

Automated defensive reviews for algorithmic-trading repositories. **Trading Bot Safety Guard Pro** publishes a GitHub Check on pushes and pull requests to help teams catch exposed credentials, unsafe live-exchange configuration, excessive leverage, and missing risk controls before deployment.

[Live app](https://trading-bot-safety-guard-pro.vercel.app/) · [Install GitHub App](https://github.com/apps/trading-bot-safety-guard-pro) · [Quickstart](docs/QUICKSTART.md) · [Operations](docs/OPERATIONS.md)

> Live now on GitHub. The analyzer performs defensive static analysis only: it never places trades, connects to an exchange, or requests exchange credentials.

## Why install it

- **Review every change automatically.** Results appear directly on commits and pull requests.
- **Catch trading-specific risk.** Rules cover Binance, Bybit, live-mode acknowledgement, leverage, secrets, and loss controls.
- **Keep credentials private.** The App uses short-lived GitHub installation tokens and never needs brokerage keys.
- **Reduce noise.** Tests, documentation, and workflow files are excluded from operational trading analysis.

## How it works

1. Install the GitHub App on the repositories you choose.
2. Push a commit or update a pull request.
3. Review the **Trading Bot Safety Guard Pro** Check before merging or deploying.

The current engine analyzes up to 20 changed text files and 100 KB per event. Findings include a rule identifier, severity, plain-language explanation, and remediation guidance.

## Product roadmap

- Automatic repository audits after pushes and pull requests (**available now**)
- Central dashboard and audit history
- Binance and Bybit safety policies
- Team policy templates and alerts
- GitHub Marketplace plan synchronization

## Plans

| Plan | Price | Included |
| --- | ---: | --- |
| Free — available now | USD 0 | Automatic repository audits and GitHub Checks |
| Pro | USD 15/month | Continuous audits, history, alerts |
| Team | USD 49/month | Organization policies and team reporting |

Paid plans are a public roadmap and will be activated only after GitHub publisher verification, financial onboarding, and the required Marketplace eligibility threshold. No paid subscription is currently offered.

## Current capabilities

- Signed GitHub and Marketplace webhook verification
- Defensive Binance and Bybit configuration analysis
- Detection for likely embedded secrets, unsafe live mode, excessive leverage, and missing loss limits
- Health/readiness endpoints and security headers
- Responsive public landing page and interactive API documentation
- Automatic changed-file analysis for push and pull-request events
- GitHub Check Run results with severity summaries
- Bounded processing: 20 files and 100 KB of combined text per delivery
- In-process operational counters at `/metrics`
- Privacy-preserving audit dashboard at `/dashboard`
- Bounded recent-audit metadata at `/api/audits` (temporary MVP storage)
- Optional durable PostgreSQL audit history through `DATABASE_URL`

## GitHub Check status

The production installation is active and `/ready` reports `automation: configured`. For self-hosted deployments, activate Check Runs by following these steps:

1. Grant the GitHub App **Checks: Read and write**.
2. Generate a GitHub App private key.
3. Store `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` in the deployment environment.
4. Redeploy and verify `/ready` reports `automation: configured`.

Never commit the private key. The service exchanges its short-lived App JWT for an installation token and reads only the changed files needed for the review.

## Local development

```bash
python -m venv .venv
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000/health`.

Run tests with:

```bash
python -m pytest
```

To persist audit metadata, provide a PostgreSQL `DATABASE_URL`. The service
creates its audit table and index automatically. If the variable is absent or
the database is unavailable during startup, it safely falls back to bounded
temporary storage and reports the active mode through `/ready`.

## Free preview deployment

The repository is structured for zero-configuration FastAPI deployment on
Vercel. Production webhook events require a `GITHUB_WEBHOOK_SECRET` environment
variable and are rejected when the secret is missing or the HMAC signature is
invalid.

## Legal and support

- [Privacy policy](docs/PRIVACY.md)
- [Terms of service](docs/TERMS.md)
- [Support](docs/SUPPORT.md)
- [Security policy](SECURITY.md)

## Disclaimer

This product is a defensive software-analysis tool. It does not execute trades, provide investment advice, or guarantee that a trading system is safe or profitable.

## License

Apache-2.0
