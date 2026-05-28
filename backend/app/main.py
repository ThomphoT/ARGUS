"""FastAPI entry point for the ARGUS backend intelligence system."""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import get_settings
from backend.app.models import ScanRequest
from backend.app.services.agent import ArgusAgent
from backend.app.utils.domain import normalize_domain

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
        try:
            await websocket.receive_json()
        except Exception:
            pass

        agent = ArgusAgent(settings)
        async for event in agent.stream_scan(domain):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": {"message": str(exc)}})
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
