#!/usr/bin/env python3
import hmac
import os
import logging
from typing import Dict

import core
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("awg-agent")

TOKEN = os.environ.get("AWG_AGENT_TOKEN", "")
app = FastAPI(title="AWG Agent", docs_url=None, redoc_url=None)


def secure_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


@app.middleware("http")
async def bearer_auth(request: Request, call_next):
    if TOKEN:
        header = request.headers.get("X-Api-Key", "")
        if not header or not secure_eq(header, TOKEN):
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized"},
                headers={"WWW-Authenticate": "Bearer"},
            )
    return await call_next(request)


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=15)


class ClientToggle(BaseModel):
    enabled: bool


@app.get("/api/health")
def health():
    params_ok = (core.CONFIG_DIR / "params").exists()
    config_ok = core.config_path().exists()
    return {"ok": params_ok and config_ok, "config": config_ok, "params": params_ok,
            "interface": core.iface()}


@app.get("/api/clients")
def list_clients():
    return core.client_full_list(core.load_state(), core.get_status())


@app.get("/api/clients/{name}/config", response_class=Response)
def get_client_config(name: str):
    try:
        fname, conf = core.op_client_config(name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return Response(
        content=conf,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/clients/{name}/qr")
def get_client_qr(name: str):
    try:
        return {"qr": core.op_client_qr(name)}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/clients", status_code=201)
def create_client(body: ClientCreate):
    name = body.name.strip()
    try:
        return core.op_create_client(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/api/clients/{name}")
def toggle_client(name: str, body: ClientToggle):
    try:
        return core.op_toggle_client(name, body.enabled)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/clients/{name}")
def delete_client(name: str):
    try:
        return core.op_delete_client(name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))