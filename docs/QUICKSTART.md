# Quickstart

## Install the GitHub App

1. Open the [Trading Bot Safety Guard Pro GitHub App](https://github.com/apps/trading-bot-safety-guard-pro).
2. Select only the repositories that contain trading-system code.
3. Keep exchange credentials in your deployment platform, never in the repository.
4. Use testnet by default and review every high or critical finding before deployment.

## Run the service locally

```bash
python -m venv .venv
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` or use the API at `http://127.0.0.1:8000/docs`.

## Analyze a configuration

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "content-type: application/json" \
  -d '{"exchange":"bybit","content":"testnet=true\nleverage=3\nmax_daily_loss=2"}'
```

The analyzer never connects to an exchange and does not require API keys.
