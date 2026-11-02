# Trading Bot Safety Guard Pro

GitHub App and SaaS companion for **Trading Bot Safety Guard**. It helps trading-bot maintainers detect exposed credentials, unsafe live-exchange configuration, excessive leverage, and missing testnet safeguards.

## Product roadmap

- Automatic repository audits after pushes and pull requests
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

## Development status

This repository contains the initial free and open development scaffold. No exchange keys or customer credentials are stored.

## Local development

```bash
python -m venv .venv
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000/health`.

## Legal and support

- [Privacy policy](docs/PRIVACY.md)
- [Terms of service](docs/TERMS.md)
- [Support](docs/SUPPORT.md)
- [Security policy](SECURITY.md)

## Disclaimer

This product is a defensive software-analysis tool. It does not execute trades, provide investment advice, or guarantee that a trading system is safe or profitable.

## License

Apache-2.0
