# ARGUS Backend Intelligence System

ARGUS is an autonomous cyber intelligence backend for the Bright Data Web Data UNLOCKED Hackathon, Track 3: Security & Compliance. It exposes a FastAPI API and WebSocket stream that scan a company domain for actionable risk intelligence.

## Current Repository Structure

```text
ARGUS/
  backend/
    app/
      clients/        Bright Data, Ollama clients
      collectors/     Leak scanner, domain monitor, attack simulator
      core/           Environment-backed settings
      services/       LangGraph reasoning, memory, alerts, agent orchestration
      utils/          Domain validation and typosquatting helpers
      main.py         FastAPI application and WebSocket endpoint
  frontend/
    index.html        Existing ARGUS demo UI, connects to ws://localhost:8000/ws/{domain}
  .env.example        Backend configuration template
  requirements.txt    Python dependencies
  setup.sh            Local setup helper
  LICENSE             MIT License
```

## Implementation Plan

1. FastAPI backend with `/health`, `/scan`, and `/ws/{company_domain}`.
2. Bright Data intelligence layer using Bright Data MCP with Web Unlocker enabled by appending `unlock=1`, plus capped SERP API collectors.
3. LangGraph orchestration around an Ollama reasoning node using `chevalblanc/gpt-4o-mini`.
4. Persistent threat memory through Cognee, with local JSONL fallback for demos without Cognee credentials.
5. TriggerWare.ai webhook alerts for `CRITICAL` and `HIGH` findings.
6. MIT-licensed, environment-configured structure suitable for production hardening.

## Hackathon Compliance

- Bright Data MCP: `backend/app/clients/bright_data.py` calls the configured MCP endpoint.
- Web Unlocker: `Settings.bright_data_mcp_unlocker_url` appends `unlock=1`.
- SERP API: collectors call `BrightDataClient.serp_search`.
- Track 3 Security & Compliance: collectors produce actionable leak, typosquatting, subdomain, cloud bucket, and exposed admin-surface findings.
- Ollama: `backend/app/clients/ollama_client.py` uses `model="chevalblanc/gpt-4o-mini"`.
- LangGraph: `backend/app/services/reasoning.py` builds a `StateGraph` for risk classification.
- Cognee: `backend/app/services/memory.py` stores structured findings after every scan when available.
- TriggerWare.ai: `backend/app/services/alerts.py` sends webhook alerts for high-impact threats.
- License: MIT License is included in `LICENSE`.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example backend/.env
```

Install and start Ollama, then pull the requested model:

```bash
ollama pull chevalblanc/gpt-4o-mini
```

Edit `backend/.env` with Bright Data, Cognee, and TriggerWare.ai values.

## Run

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

Open `frontend/index.html` in a browser and start a scan. The frontend connects to:

```text
ws://localhost:8000/ws/{company_domain}
```

## API

### Health

```bash
curl http://localhost:8000/health
```

### REST Scan

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"company_domain":"example.com","focus":"full"}'
```

### WebSocket Scan

Connect to `/ws/{company_domain}`. The server streams:

```json
{"type":"finding","data":{"severity":"HIGH","risk_score":80}}
{"type":"complete","data":{"score":80,"finding_count":5}}
```

## Environment

Key variables are documented in `.env.example`.

- `BRIGHT_DATA_API_TOKEN`
- `BRIGHT_DATA_SERP_ZONE`
- `BRIGHT_DATA_MCP_URL`
- `OLLAMA_HOST`
- `COGNEE_ENABLED`
- `TRIGGERWARE_WEBHOOK_URL`

When Bright Data credentials are not configured, ARGUS returns deterministic demo findings so the API and frontend remain testable.
