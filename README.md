# ARGUS

ARGUS is an autonomous open-web defense system for Security & Compliance teams. It turns Bright Data-powered reconnaissance into actionable threat intelligence, risk scoring, automated alerting, and halt-exfiltration remediation workflows.

The enterprise security market is racing past $200B because internal tools cannot see the public internet the way adversaries do. ARGUS closes that gap: it continuously monitors search signals, exposed infrastructure, leaked configuration files, cloud storage, and attacker-style reconnaissance paths at open-web scale.

## What ARGUS Does

- Finds public exposure signals with Bright Data MCP, Web Unlocker, and SERP API.
- Classifies every finding with LangGraph-backed reasoning and concrete recommendations.
- Compares current findings against stored investigations to produce diff intelligence and a threat timeline.
- Fires TriggerWare.ai `threat_detected` workflows when risk reaches `HIGH` or `CRITICAL`.
- Generates halt-exfiltration payloads for SOAR, firewall, or EDR playbooks.
- Streams the agent's internal flow in real time: understands, decides, acts.

## Track 3 Alignment

- **Security & Compliance:** Finds leaked secrets, exposed admin surfaces, public cloud storage, suspicious subdomains, and brand-adjacent infrastructure.
- **Bright Data Best Practices:** Uses Bright Data MCP with `unlock=1`, Web Unlocker zone configuration, and SERP API fallback for reliable search intelligence.
- **Automated Workflows:** TriggerWare receives `threat_detected` events with simulated Slack, firewall block, and SOAR case actions.
- **Active Remediation:** The remediation agent builds `halt_exfiltration` containment payloads for downstream playbooks.
- **Differentiator:** Attack Simulation Mode mimics red-team reconnaissance before attackers exploit the surface.

## Architecture

```text
ARGUS/
  backend/
    app/
      clients/        Bright Data, Ollama, optional OpenAI
      collectors/     Leak scanner, domain monitor, threat intel, attack simulator
      core/           Environment-backed settings
      services/       Agent orchestration, reasoning, memory, alerts, remediation
      main.py         FastAPI API, WebSocket stream, frontend serving
  frontend/
    index.html        Neural Interface dashboard
    ARGUS.png         Logo asset
  tests/              Backend, collector, alert, and reasoning tests
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example backend/.env
```

Install and start Ollama, then pull the default local model:

```bash
ollama pull chevalblanc/gpt-4o-mini
```

Configure Bright Data:

```bash
npm install -g @brightdata/cli
bdata login
```

Set at least these values in `backend/.env` for live collection:

```env
BRIGHT_DATA_API_TOKEN=your_bright_data_token
BRIGHT_DATA_SERP_ZONE=your_serp_zone
```

## TriggerWare Manual Webhook

For hackathon demos, create a manual TriggerWare trigger:

1. Choose trigger type `Webhook`.
2. Set the event name to `threat_detected`.
3. Paste the generated URL into `backend/.env`.

```env
TRIGGERWARE_WEBHOOK_URL=https://your-triggerware-webhook-url
```

ARGUS sends this event automatically for findings with `risk_score >= 70`.

## Optional Defense Webhook

To connect the halt-exfiltration button to a real playbook:

```env
DEFENSE_WEBHOOK_URL=https://your-soar-or-firewall-playbook
DEFENSE_WEBHOOK_SECRET=shared_signing_secret
```

Without this URL, ARGUS still stops the scan and generates a containment report for manual action.

## Run

Backend:

```bash
source .venv/bin/activate
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
open frontend/index.html
```

Or serve the frontend locally:

```bash
python -m http.server 5500 --directory frontend
```

Open:

```text
http://localhost:5500
```

## API

Health:

```bash
curl http://localhost:8000/health
```

REST scan:

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"company_domain":"example.com","focus":"full","attack_mode":true}'
```

WebSocket scan:

```text
ws://localhost:8000/ws/{company_domain}
```

The stream includes:

```json
{"type":"agent_step","data":{"stage":"understands","message":"ARGUS collected signal..."}}
{"type":"agent_step","data":{"stage":"decides","message":"Risk scored 80/100..."}}
{"type":"finding","data":{"severity":"HIGH","risk_score":80}}
{"type":"complete","data":{"score":80,"finding_count":5}}
```

## Demo Checklist

- `backend/.env` exists locally and is not committed.
- `BRIGHT_DATA_API_TOKEN` and `BRIGHT_DATA_SERP_ZONE` are configured.
- `bdata login` completed for MCP access.
- `LLM_PROVIDER=ollama` with Ollama running, or `LLM_PROVIDER=openai` with a working key.
- `TRIGGERWARE_WEBHOOK_URL` is configured for automated alerts.
- Attack Mode is enabled for the red-team reconnaissance demo.

## Test

```bash
.venv/bin/python -m pytest
```

License: MIT.
