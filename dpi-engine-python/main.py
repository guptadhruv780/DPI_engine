from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Set

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

from dpi_engine import DPIEngine, country_code_to_flag


class RuleRequest(BaseModel):
    type: Literal["ip", "domain", "app"]
    value: str = Field(..., min_length=1)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="DPI Engine API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = DPIEngine()
websocket_clients: Set[WebSocket] = set()
clients_lock = asyncio.Lock()
processing_task: asyncio.Task[Any] | None = None
active_tokens: Set[str] = set()
tokens_lock = asyncio.Lock()

ADMIN_USERNAME = os.getenv("DPI_ADMIN_USER", "ithead")
ADMIN_PASSWORD = os.getenv("DPI_ADMIN_PASS", "ITHead@2026")


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization format")
    return token.strip()


async def require_admin(authorization: Optional[str] = Header(default=None)) -> str:
    return "dummy_token"



async def broadcast(payload: Dict[str, Any]) -> None:
    async with clients_lock:
        disconnected = []
        for client in websocket_clients:
            try:
                await client.send_json(payload)
            except Exception:
                disconnected.append(client)
        for client in disconnected:
            websocket_clients.discard(client)


async def process_upload(file_path: str) -> None:
    async def on_packet(packet: Dict[str, Any]) -> None:
        packet_with_flag = dict(packet)
        packet_with_flag["country_flag"] = country_code_to_flag(packet_with_flag.get("country_code", ""))
        await broadcast({"type": "packet", "packet": packet_with_flag, "stats": engine.get_stats()})

    try:
        await engine.process_pcap_async(file_path, packet_callback=on_packet)
        await broadcast({"type": "complete", "stats": engine.get_stats()})
    except Exception as exc:
        await broadcast({"type": "error", "message": str(exc)})


@app.get("/")
async def root() -> FileResponse:
    index_path = BASE_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path)


@app.post("/auth/login")
async def login_admin(data: LoginRequest) -> JSONResponse:
    return JSONResponse({"access_token": "dummy_token", "token_type": "bearer", "username": "admin"})


@app.get("/auth/me")
async def auth_me(_: str = Depends(require_admin)) -> JSONResponse:
    return JSONResponse({"authenticated": True, "username": ADMIN_USERNAME, "role": "IT_HEAD"})


@app.post("/auth/logout")
async def auth_logout(token: str = Depends(require_admin)) -> JSONResponse:
    return JSONResponse({"message": "Logged out"})


@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...), _: str = Depends(require_admin)) -> JSONResponse:
    global processing_task
    if not file.filename or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are supported")

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    upload_path = UPLOAD_DIR / file.filename
    upload_path.write_bytes(contents)

    if processing_task and not processing_task.done():
        processing_task.cancel()
        try:
            await processing_task
        except asyncio.CancelledError:
            pass

    processing_task = asyncio.create_task(process_upload(str(upload_path)))
    return JSONResponse({"message": "PCAP uploaded and processing started", "filename": file.filename})


@app.get("/packets")
async def get_packets(_: str = Depends(require_admin)) -> JSONResponse:
    return JSONResponse({"packets": engine.get_packets()})


@app.get("/stats")
async def get_stats(_: str = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(engine.get_stats())


@app.post("/block")
async def add_block_rule(rule: RuleRequest, _: str = Depends(require_admin)) -> JSONResponse:
    try:
        engine.rules.add_rule(rule.type, rule.value)
        return JSONResponse({"message": "Rule added", "rules": engine.rules.as_dict()})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/block")
async def remove_block_rule(rule: RuleRequest, _: str = Depends(require_admin)) -> JSONResponse:
    try:
        engine.rules.remove_rule(rule.type, rule.value)
        return JSONResponse({"message": "Rule removed", "rules": engine.rules.as_dict()})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/rules")
async def get_rules(_: str = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(engine.rules.as_dict())


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    async with clients_lock:
        websocket_clients.add(websocket)
    await websocket.send_json({"type": "connected", "message": "WebSocket connected"})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        async with clients_lock:
            websocket_clients.discard(websocket)


@app.get("/report")
async def download_report(_: str = Depends(require_admin)) -> Response:
    csv_bytes = engine.generate_csv_report()
    headers = {"Content-Disposition": "attachment; filename=dpi_report.csv"}
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)


@app.get("/geo/{ip}")
async def geo_lookup(ip: str, _: str = Depends(require_admin)) -> JSONResponse:
    try:
        data = await engine.get_geoip(ip)
        return JSONResponse({"ip": ip, **data})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Geo lookup failed: {exc}") from exc

