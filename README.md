# Trading Bot Safety Guard Pro

GitHub App and SaaS companion for **Trading Bot Safety Guard**. It helps trading-bot maintainers detect exposed credentials, unsafe live-exchange configuration, excessive leverage, and missing testnet safeguards.

[Live app](https://trading-bot-safety-guard-pro.vercel.app/) · [Install GitHub App](https://github.com/apps/trading-bot-safety-guard-pro) · [Quickstart](docs/QUICKSTART.md) · [Operations](docs/OPERATIONS.md)

> The analyzer is defensive static analysis. It never places trades and does not require exchange credentials.

## Product roadmap

- Automatic repository audits after pushes and pull requests (implemented; activation requires GitHub App credentials and Checks write permission)
- Central dashboard and audit history
- Binance and Bybit safety policies
- Team policy templates and alerts
- GitHub Marketplace plan synchronization

## Planned plans

| Plan | Price | Included |
| --- | ---: | --- |
| Free | USD 0 | Basic repository audit |
| Pro | USD 15/month | Continuous audits, history, alerts |
| Team | USD 49/month | Organization policies and team reporting |

Paid plans will only be activated after GitHub publisher verification, financial onboarding, and the required Marketplace eligibility threshold.

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

## GitHub Check activation

The automation fails closed when credentials are absent. To activate Check Runs:

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
