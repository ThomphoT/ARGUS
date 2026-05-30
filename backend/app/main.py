"""FastAPI entry point for the ARGUS backend intelligence system."""

import asyncio
import contextlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.app.clients.bright_data import BrightDataClient
from backend.app.core.config import get_settings
from backend.app.models import RemediationRequest, ScanRequest
from backend.app.services.agent import ArgusAgent
from backend.app.services.remediation import RemediationAgent
from backend.app.utils.domain import normalize_domain

logger = logging.getLogger("argus")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logging.getLogger("httpx").setLevel(logging.WARNING)

settings = get_settings()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

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


def _active_llm_provider() -> str:
    if settings.llm_provider == "auto":
        return "openai" if settings.openai_api_key else "ollama"
    return settings.llm_provider


@app.get("/health")
async def health() -> dict:
    bright_data = BrightDataClient(settings)
    return {
        "status": "ok",
        "bright_data_mcp_web_unlocker_url": settings.bright_data_mcp_unlocker_url,
        "llm_provider": _active_llm_provider(),
        "openai_model": settings.openai_model,
        "ollama_model": settings.ollama_model,
        "bright_data": bright_data.status(),
        "cognee_enabled": settings.cognee_enabled,
        "triggerware_configured": bool(settings.triggerware_webhook_url),
    }


@app.get("/", include_in_schema=False)
async def frontend_index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html", headers=NO_STORE_HEADERS)


@app.get("/ARGUS.png", include_in_schema=False)
async def frontend_logo() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "ARGUS.png")


@app.post("/scan")
async def scan(request: ScanRequest) -> dict:
    domain = normalize_domain(request.company_domain)
    agent = ArgusAgent(settings)
    events = []
    async for event in agent.stream_scan(domain, request.focus, request.attack_mode):
        events.append(event)
    return {"events": events}


@app.post("/api/remediate")
async def remediate(request: RemediationRequest) -> dict:
    if request.command.lower() != "halt":
        raise HTTPException(status_code=400, detail="Unsupported remediation command.")
    domain = normalize_domain(request.target_id)
    threat = request.threat_data or {}
    findings = [threat] if threat else []
    report = await RemediationAgent(settings).halt_exfiltration(domain, findings)
    return report


@app.websocket("/ws/{company_domain}")
async def websocket_scan(websocket: WebSocket, company_domain: str) -> None:
    await websocket.accept()
    scan_completed = False
    try:
        domain = normalize_domain(company_domain)
        focus = "full"
        attack_mode = False
        try:
            payload = await asyncio.wait_for(websocket.receive_json(), timeout=2.0)
            focus = payload.get("focus", focus)
            attack_mode = bool(payload.get("attack_mode", attack_mode))
        except asyncio.TimeoutError:
            logger.info(
                "No WebSocket scan options received for domain=%s; using defaults",
                domain,
            )
        except WebSocketDisconnect:
            logger.info(
                "Client disconnected before scan options were received for domain=%s",
                domain,
            )
            return
        except Exception:
            pass

        logger.info(
            "Starting scan for domain=%s focus=%s attack_mode=%s",
            domain,
            focus,
            attack_mode,
        )
        agent = ArgusAgent(settings)
        remediation_agent = RemediationAgent(settings)
        event_count = 0
        findings = []
        queue: asyncio.Queue[dict] = asyncio.Queue()
        scan_task = asyncio.create_task(
            _stream_scan_events(agent, domain, focus, attack_mode, queue)
        )
        queue_task = asyncio.create_task(queue.get())
        receive_task = asyncio.create_task(websocket.receive_json())

        try:
            while True:
                done, pending = await asyncio.wait(
                    {queue_task, receive_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if receive_task in done:
                    payload = receive_task.result()
                    if payload.get("type") == "stop":
                        logger.info("Stop requested for domain=%s", domain)
                        if not scan_task.done():
                            scan_task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await scan_task
                        await websocket.send_json(
                            {
                                "type": "stopped",
                                "data": {
                                    "company_domain": domain,
                                    "stopped_at": datetime.now(timezone.utc).isoformat(),
                                    "message": "Scan stopped by user.",
                                },
                            }
                        )
                        scan_completed = True
                        break
                    if payload.get("type") == "halt":
                        logger.info("Halt requested for domain=%s", domain)
                        if not scan_task.done():
                            scan_task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await scan_task
                        threat_data = payload.get("threat_data") or {}
                        scoped_findings = [threat_data] if threat_data else findings
                        report = await remediation_agent.halt_exfiltration(
                            domain, scoped_findings
                        )
                        await websocket.send_json(
                            {"type": "remediation_report", "data": report}
                        )
                        scan_completed = True
                        break
                    receive_task = asyncio.create_task(websocket.receive_json())

                if queue_task in done:
                    event = queue_task.result()
                    if event.get("type") == "_scan_finished":
                        break
                    await websocket.send_json(event)
                    event_count += 1
                    if event.get("type") == "finding":
                        findings.append(event.get("data") or {})
                    if event.get("type") == "complete":
                        scan_completed = True
                        break
                    queue_task = asyncio.create_task(queue.get())

                for task in pending:
                    if task.done():
                        task.result()
        finally:
            for task in (queue_task, receive_task, scan_task):
                if not task.done():
                    task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scan_task
        logger.info("Scan complete for domain=%s, events=%d", domain, event_count)
    except WebSocketDisconnect:
        if scan_completed:
            logger.info(
                "Client closed WebSocket after scan completed for domain=%s",
                company_domain,
            )
        else:
            logger.warning(
                "Client disconnected during scan for domain=%s", company_domain
            )
        return
    except Exception as exc:
        logger.error(
            "Scan error for domain=%s: %s: %s",
            company_domain,
            type(exc).__name__,
            exc,
        )
        try:
            await websocket.send_json({"type": "error", "data": {"message": str(exc)}})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


async def _stream_scan_events(
    agent: ArgusAgent,
    domain: str,
    focus: str,
    attack_mode: bool,
    queue: asyncio.Queue[dict],
) -> None:
    try:
        async for event in agent.stream_scan(domain, focus, attack_mode):
            await queue.put(event)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("Scan producer failed for domain=%s: %s", domain, exc)
        await queue.put({"type": "error", "data": {"message": str(exc)}})
    finally:
        await queue.put({"type": "_scan_finished"})
