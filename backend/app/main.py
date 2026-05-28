"""FastAPI entry point for the ARGUS backend intelligence system."""

import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import get_settings
from backend.app.models import ScanRequest
from backend.app.services.agent import ArgusAgent
from backend.app.utils.domain import normalize_domain

logger = logging.getLogger("argus")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

settings = get_settings()

app = FastAPI(
    title="ARGUS Backend Intelligence System",
    description="Autonomous cyber intelligence backend using Bright Data MCP, Web Unlocker, SERP API, LangGraph, Ollama, Cognee, and TriggerWare.ai.",
    version="1.0.0",
    license_info={"name": "MIT", "url": "https://opensource.org/license/mit"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "bright_data_mcp_web_unlocker_url": settings.bright_data_mcp_unlocker_url,
        "llm_provider": "openai" if settings.openai_api_key else "ollama",
        "ollama_model": settings.ollama_model,
        "cognee_enabled": settings.cognee_enabled,
        "triggerware_configured": bool(settings.triggerware_webhook_url),
    }


@app.post("/scan")
async def scan(request: ScanRequest) -> dict:
    domain = normalize_domain(request.company_domain)
    agent = ArgusAgent(settings)
    events = []
    async for event in agent.stream_scan(domain):
        events.append(event)
    return {"events": events}


@app.websocket("/ws/{company_domain}")
async def websocket_scan(websocket: WebSocket, company_domain: str) -> None:
    await websocket.accept()
    try:
        domain = normalize_domain(company_domain)
        logger.info("Starting scan for domain=%s", domain)
        agent = ArgusAgent(settings)
        event_count = 0
        async for event in agent.stream_scan(domain):
            await websocket.send_json(event)
            event_count += 1
        logger.info("Scan complete for domain=%s, events=%d", domain, event_count)
    except WebSocketDisconnect:
        logger.warning("Client disconnected during scan for domain=%s", company_domain)
        return
    except Exception as exc:
        logger.error("Scan error for domain=%s: %s: %s", company_domain, type(exc).__name__, exc)
        try:
            await websocket.send_json({"type": "error", "data": {"message": str(exc)}})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
