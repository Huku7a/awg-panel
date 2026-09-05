#!/usr/bin/env python3
import base64
import hmac
import logging
import os
import uuid
from typing import Dict, List, Optional

import core
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("awg-panel")

AUTH_USER = os.environ.get("AWG_PANEL_USER", "admin")
AUTH_PASSWORD = os.environ.get("AWG_PANEL_PASSWORD", "")

app = FastAPI(title="AWG Panel", docs_url=None, redoc_url=None)


def secure_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if AUTH_PASSWORD:
        auth = request.headers.get("Authorization", "")
        ok = auth.startswith("Basic ")
        if ok:
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                user, _, password = decoded.partition(":")
                ok = secure_eq(user, AUTH_USER) and secure_eq(password, AUTH_PASSWORD)
            except Exception:
                ok = False
        if not ok:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized"},
                headers={"WWW-Authenticate": 'Basic realm="AWG Panel"'},
            )
    return await call_next(request)


# ----------------------------------------------------------------------
# Node helpers
# ----------------------------------------------------------------------

def public_servers() -> List[Dict]:
    out = [{"id": "local", "name": "Локальный сервер", "url": "", "is_local": True}]
    for s in core.load_servers():
        out.append({
            "id": s["id"],
            "name": s["name"],
            "url": s["url"],
            "is_local": False,
        })
    return out


def find_server(server_id: str) -> Optional[Dict]:
    if server_id == "local":
        return {"id": "local", "url": "", "token": ""}
    for s in core.load_servers():
        if s["id"] == server_id:
            return s
    return None


async def agent_request(method: str, server: Dict, path: str, body=None, timeout=15.0):
    url = server["url"].rstrip("/") + path
    headers = {"X-Api-Key": server.get("token", "")}
    kwargs = {"headers": headers, "timeout": timeout}
    if body is not None:
        kwargs["json"] = body
    try:
        resp = await httpx.AsyncClient().request(method, url, **kwargs)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Agent unreachable: {e}")
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code >= 400:
        detail = data.get("detail") or data if data else f"HTTP {resp.status_code}"
        raise HTTPException(status_code=resp.status_code, detail=str(detail))
    return data


# ----------------------------------------------------------------------
# Panel endpoints
# ----------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse((core.PANEL_DIR / "templates" / "index.html").read_text())


@app.get("/api/config-check")
def config_check():
    return {
        "config_exists": core.config_path().exists(),
        "params_exists": (core.CONFIG_DIR / "params").exists(),
        "has_auth": bool(AUTH_PASSWORD),
        "auth_user": AUTH_USER if AUTH_PASSWORD else "",
    }


@app.get("/api/servers")
def list_servers():
    return public_servers()


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    url: str = Field(min_length=1, max_length=200)
    token: str = Field(min_length=8, max_length=200)


@app.post("/api/servers", status_code=201)
async def add_server(body: ServerCreate):
    name = body.name.strip()
    url = body.url.rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    probe = {"id": "probe", "url": url, "token": body.token}
    try:
        health = await agent_request("GET", probe, "/api/health")
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=f"Не удалось подключиться к агенту: {e.detail}")
    if not health.get("ok"):
        raise HTTPException(status_code=400, detail="Агент отвечает, но конфигурация AWG не найдена на узле")
    servers = core.load_servers()
    for s in servers:
        if s["url"].rstrip("/") == url:
            raise HTTPException(status_code=409, detail="Сервер с таким URL уже добавлен")
    new = {"id": uuid.uuid4().hex, "name": name, "url": url, "token": body.token}
    servers.append(new)
    core.save_servers(servers)
    logger.info("Added server %s (%s)", name, url)
    return {"id": new["id"], "name": name, "url": url, "is_local": False}


class ServerProbe(BaseModel):
    url: str = Field(min_length=1, max_length=200)
    token: str = Field(min_length=1, max_length=200)


@app.post("/api/servers/probe/ping")
async def probe_server(body: ServerProbe):
    url = body.url.rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    probe = {"id": "probe", "url": url, "token": body.token}
    health = await agent_request("GET", probe, "/api/health")
    return {"ok": bool(health.get("ok")), "interface": health.get("interface")}


@app.delete("/api/servers/{server_id}")
def delete_server(server_id: str):
    servers = core.load_servers()
    kept = [s for s in servers if s["id"] != server_id]
    if len(kept) == len(servers):
        raise HTTPException(status_code=404, detail="Server not found")
    core.save_servers(kept)
    return {"deleted": True}


@app.post("/api/servers/{server_id}/ping")
async def ping_server(server_id: str):
    server = find_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    if server_id == "local":
        return {"id": server_id, "ok": core.config_path().exists(), "name": "Локальный сервер"}
    data = await agent_request("GET", server, "/api/health")
    return {"id": server_id, "ok": bool(data.get("ok")), "name": server["name"],
            "interface": data.get("interface")}


# ----------------------------------------------------------------------
# Client endpoints (with ?server=id, default "local")
# ----------------------------------------------------------------------

class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=15)


class ClientToggle(BaseModel):
    enabled: bool


@app.get("/api/clients")
async def list_clients(server: str = "local"):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if server == "local":
        return core.client_full_list(core.load_state(), core.get_status())
    return await agent_request("GET", s, "/api/clients")


@app.get("/api/clients/{name}/config", response_class=Response)
async def get_client_config(name: str, server: str = "local"):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if server == "local":
        try:
            fname, conf = core.op_client_config(name)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        return Response(
            content=conf,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
    return await agent_request("GET", s, f"/api/clients/{name}/config")


@app.get("/api/clients/{name}/qr")
async def get_client_qr(name: str, server: str = "local"):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if server == "local":
        try:
            return {"qr": core.op_client_qr(name)}
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
    return await agent_request("GET", s, f"/api/clients/{name}/qr")


@app.post("/api/clients", status_code=201)
async def create_client(body: ClientCreate, server: str = "local"):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    name = body.name.strip()
    if server == "local":
        try:
            return core.op_create_client(name)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
    return await agent_request("POST", s, "/api/clients", {"name": name})


@app.patch("/api/clients/{name}")
async def toggle_client(name: str, body: ClientToggle, server: str = "local"):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if server == "local":
        try:
            return core.op_toggle_client(name, body.enabled)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
    return await agent_request("PATCH", s, f"/api/clients/{name}", {"enabled": body.enabled})


@app.delete("/api/clients/{name}")
async def delete_client(name: str, server: str = "local"):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if server == "local":
        try:
            return core.op_delete_client(name)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
    return await agent_request("DELETE", s, f"/api/clients/{name}")