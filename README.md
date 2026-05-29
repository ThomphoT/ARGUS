# ARGUS Backend Intelligence System

ARGUS is an autonomous cyber intelligence backend for the Bright Data Web Data UNLOCKED Hackathon, Track 3: Security & Compliance. It exposes a FastAPI API and WebSocket stream that scan a company domain for actionable risk intelligence.

## Current Repository Structure

```text
ARGUS/
  backend/
    app/
      clients/        Bright Data, Ollama, optional OpenAI clients
      collectors/     Leak scanner, domain monitor, threat intel, attack simulator
      shared/         Rate limiting and TTL cache helpers
      core/           Environment-backed settings
      services/       LangGraph reasoning, memory, alerts, agent orchestration
      utils/          Domain validation and typosquatting helpers
      main.py         FastAPI application and WebSocket endpoint
    test_collectors.py  CLI collector smoke test
  frontend/
    index.html        Existing ARGUS demo UI, connects to ws://localhost:8000/ws/{domain}
  .env.example        Backend configuration template
  requirements.txt    Python dependencies
  setup.sh            Local setup helper
  LICENSE             MIT License
```

## Implementation Plan

1. FastAPI backend with `/health`, `/scan`, and `/ws/{company_domain}`.
2. Bright Data intelligence layer using Bright Data MCP with Web Unlocker enabled by appending the configured `unlocker` zone, plus capped SERP API collectors.
3. LangGraph orchestration around an Ollama reasoning node using `chevalblanc/gpt-4o-mini`.
4. Persistent threat memory through Cognee, with local JSONL fallback for demos without Cognee credentials.
5. TriggerWare.ai webhook alerts for `CRITICAL` and `HIGH` findings.
6. MIT-licensed, environment-configured structure suitable for production hardening.

## Hackathon Compliance

- Bright Data MCP: `backend/app/clients/bright_data.py` calls the configured MCP endpoint.
- Web Unlocker: `Settings.bright_data_mcp_unlocker_url` appends `unlocker=mcp_unlocker` by default, or the value from `BRIGHT_DATA_WEB_UNLOCKER_ZONE`.
- SERP API: collectors call `BrightDataClient.web_search`, which attempts Bright Data MCP first and falls back to SERP API.
- Track 3 Security & Compliance: collectors produce actionable leak, typosquatting, subdomain, cloud bucket, and exposed admin-surface findings.
- Ollama: `backend/app/clients/ollama_client.py` uses `model="chevalblanc/gpt-4o-mini"`.
- OpenAI: optional `LLM_PROVIDER=openai` uses `OPENAI_MODEL=gpt-4o-mini` and has a circuit breaker so rate limits do not stall every finding.
- LangGraph: `backend/app/services/reasoning.py` builds a `StateGraph` for risk classification.
- Cognee: `backend/app/services/memory.py` stores structured findings after every scan when available.
- TriggerWare.ai: `backend/app/services/alerts.py` sends webhook alerts for high-impact threats.
- Defense webhook: `backend/app/services/remediation.py` sends halt-exfiltration containment payloads to a configured SOAR, firewall, or EDR playbook.
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

Edit `backend/.env` with Bright Data, Cognee, TriggerWare.ai, and optional OpenAI values.

For Bright Data MCP, install the CLI and log in locally:

```bash
npm install -g @brightdata/cli
bdata login
```

Then set a real SERP zone in `backend/.env`:

```env
BRIGHT_DATA_API_TOKEN=your_bright_data_token
BRIGHT_DATA_SERP_ZONE=your_serp_zone
```

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
  -d '{"company_domain":"example.com","focus":"full","attack_mode":true}'
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
- `BRIGHT_DATA_MCP_SEARCH_TOOL`
- `LLM_PROVIDER`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OLLAMA_HOST`
- `COGNEE_ENABLED`
- `TRIGGERWARE_WEBHOOK_URL`
- `DEFENSE_WEBHOOK_URL`
- `DEFENSE_WEBHOOK_SECRET`

When Bright Data credentials are not configured, ARGUS returns deterministic demo findings so the API and frontend remain testable.
When `DEFENSE_WEBHOOK_URL` is configured, pressing `HALT EXFILTRATION` sends a signed containment request if `DEFENSE_WEBHOOK_SECRET` is also set. Without it, ARGUS still cancels the active scan and generates the recovered-data report for manual response.

## Collector Test Runner

Run collectors without the frontend:

```bash
python -m backend.test_collectors example.com --attack-mode
```

Use this after configuring `BRIGHT_DATA_SERP_ZONE` to confirm collectors are using live Bright Data instead of mock data.

## Demo Readiness Checklist

- `backend/.env` exists locally and is not committed.
- `BRIGHT_DATA_API_TOKEN` is set.
- `BRIGHT_DATA_SERP_ZONE` is set to a valid Bright Data SERP zone.
- `bdata login` has completed successfully for MCP session access.
- `LLM_PROVIDER=ollama` with local Ollama running, or `LLM_PROVIDER=openai` with a non-rate-limited key.
- `COGNEE_ENABLED=true` if using Cognee persistent memory.
- `TRIGGERWARE_WEBHOOK_URL` is set if showing automated alerts.
- `DEFENSE_WEBHOOK_URL` points to the containment playbook if showing real attack blocking.
