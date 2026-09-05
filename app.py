#!/usr/bin/env python3
import base64
import ipaddress
import asyncio
import hmac
import logging
import os
import secrets
import socket
import threading
import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import core
import deployer
import httpx
import updater
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("awg-panel")

AUTH_USER = os.environ.get("AWG_PANEL_USER", "admin")
AUTH_PASSWORD = os.environ.get("AWG_PANEL_PASSWORD", "")
# Fail closed: a panel without credentials refuses all requests unless the
# operator explicitly opts into running it without authentication.
ALLOW_NO_AUTH = os.environ.get("AWG_ALLOW_NO_AUTH", "") == "1"
# Extra origins (besides the panel's own Host header) allowed to mutate state.
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get("AWG_ALLOWED_ORIGINS", "").split(",") if o.strip()}
# Allow agent URLs pointing at private/reserved IP ranges (only for isolated LANs).
ALLOW_PRIVATE_AGENTS = os.environ.get("AWG_ALLOW_PRIVATE_AGENTS", "") == "1"

@asynccontextmanager
async def lifespan(app: FastAPI):
    worker = asyncio.create_task(updater.updater_worker())
    try:
        yield
    finally:
        worker.cancel()


app = FastAPI(title="AWG Panel", docs_url=None, redoc_url=None, lifespan=lifespan)


def secure_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _origin_allowed(request: Request) -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True
    netloc = urlsplit(origin).netloc
    if netloc == request.headers.get("Host", ""):
        return True
    return origin in ALLOWED_ORIGINS


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    if request.method in ("POST", "PATCH", "PUT", "DELETE") and not _origin_allowed(request):
        return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected"})
    return await call_next(request)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if not AUTH_PASSWORD and not ALLOW_NO_AUTH:
        return JSONResponse(
            status_code=503,
            content={"detail": "Panel authentication is not configured (set AWG_PANEL_PASSWORD)"},
        )
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
        async with httpx.AsyncClient() as client:
            resp = await client.request(method, url, **kwargs)
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


def agent_request_sync(method: str, server: Dict, path: str, body=None, timeout=900.0):
    url = server["url"].rstrip("/") + path
    headers = {"X-Api-Key": server.get("token", "")}
    kwargs = {"headers": headers, "timeout": timeout}
    if body is not None:
        kwargs["json"] = body
    try:
        with httpx.Client() as client:
            resp = client.request(method, url, **kwargs)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Agent unreachable: {e}")
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code >= 400:
        raise RuntimeError(str(data.get("detail") or data or f"HTTP {resp.status_code}"))
    return data


def _check_agent_url(url: str) -> str:
    """Validate an agent URL to avoid SSRF (private/loopback/link-local/reserved
    targets incl. cloud metadata 169.254.169.254). Opt out with
    AWG_ALLOW_PRIVATE_AGENTS=1 for isolated LANs."""
    if ALLOW_PRIVATE_AGENTS:
        return url
    try:
        host = urlsplit(url).hostname
    except ValueError:
        raise HTTPException(status_code=400, detail="Некорректный URL агента")
    if not host:
        raise HTTPException(status_code=400, detail="URL агента не содержит хоста")
    host = host.rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        raise HTTPException(status_code=400, detail="localhost запрещён как адрес агента")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Не удалось разрешить хост агента: {host}")
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(
                status_code=400,
                detail=f"Недопустимый адрес агента (internal/private IP): {ip}",
            )
    return url


async def _agent_retry(method: str, server: Dict, path: str, body=None, timeout=15.0, attempts=3):
    """agent_request with a few retries: the path to remote VDS occasionally
    drops packets, so a short retry makes AWG operations resilient."""
    last = None
    for i in range(attempts):
        try:
            return await agent_request(method, server, path, body=body, timeout=timeout)
        except HTTPException as e:
            last = e
            if e.status_code not in (502, 504):
                raise
            await asyncio.sleep(1.0 * (i + 1))
    raise HTTPException(status_code=502, detail=f"Agent unreachable after {attempts} attempts")


def _agent_retry_sync(method: str, server: Dict, path: str, body=None, timeout=900.0, attempts=3):
    last = None
    for i in range(attempts):
        try:
            return agent_request_sync(method, server, path, body=body, timeout=timeout)
        except RuntimeError as e:
            last = e
            if "unreachable" not in str(e):
                raise
            time.sleep(1.0 * (i + 1))
    raise last or RuntimeError("Agent unreachable")


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
    _check_agent_url(url)
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
    _check_agent_url(url)
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
# Remote agent deployment
# ----------------------------------------------------------------------

deployments: Dict[str, Dict] = {}
DEPLOY_LOCK = threading.Lock()

_TASK_TTL = 3600  # keep finished tasks in memory for 1 hour
_MAX_TASKS = 100


def _prune_tasks(tasks: Dict[str, Dict]):
    now = time.time()
    for k in list(tasks):
        t = tasks[k]
        if t.get("status") in ("done", "error") and now - t.get("done_at", 0) > _TASK_TTL:
            del tasks[k]
    if len(tasks) > _MAX_TASKS:
        finished = sorted(
            ((t.get("done_at") or 0, k) for k, t in tasks.items() if t.get("status") in ("done", "error")),
            reverse=True,
        )
        for _, k in finished[_MAX_TASKS:]:
            tasks.pop(k, None)


def panel_public_ip() -> str:
    env = os.environ.get("AWG_PANEL_IP")
    if env:
        return env
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        pass
    try:
        r = core.run("hostname -I")
        return r.stdout.split()[0]
    except Exception:
        return ""


def register_server(name: str, url: str, token: str) -> str:
    servers = core.load_servers()
    url = url.rstrip("/")
    for s in servers:
        if s["url"].rstrip("/") == url:
            s["name"] = name
            s["token"] = token
            core.save_servers(servers)
            return s["id"]
    new = {"id": uuid.uuid4().hex, "name": name, "url": url, "token": token}
    servers.append(new)
    core.save_servers(servers)
    logger.info("Registered server %s (%s)", name, url)
    return new["id"]


def _run_deploy(did: str, body: "DeployRequest"):
    d = deployments[did]
    try:
        token = (body.token or "").strip() or secrets.token_hex(16)
        deployer.deploy_agent(
            host=body.host.strip(),
            user=body.user.strip() or "root",
            password=body.password,
            token=token,
            panel_ip=panel_public_ip(),
            port=body.port,
            steps=d["steps"],
        )
        url = f"http://{body.host.strip()}:5183"
        server_id = register_server(body.name.strip(), url, token)
        d["steps"].append({"msg": "Сервер добавлен в панель", "ok": True})
        d.update(status="done", result={"server_id": server_id, "url": url, "token": token}, done_at=time.time())
        logger.info("Deployment %s finished, server %s", did, server_id)
    except Exception as e:
        d["steps"].append({"msg": f"Ошибка: {e}", "ok": False})
        d.update(status="error", error=str(e), done_at=time.time())
        logger.exception("Deployment %s failed", did)


class DeployRequest(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    host: str = Field(min_length=1, max_length=200)
    user: str = Field(default="root", max_length=60)
    password: str = Field(min_length=1, max_length=200)
    port: int = Field(default=22, ge=1, le=65535)
    token: str = Field(default="", max_length=200)


@app.post("/api/deploy", status_code=202)
def start_deploy(body: DeployRequest):
    _prune_tasks(deployments)
    did = uuid.uuid4().hex
    deployments[did] = {"status": "running", "steps": [], "result": None, "error": None, "done_at": 0}
    threading.Thread(target=_run_deploy, args=(did, body), daemon=True).start()
    return {"id": did}


@app.get("/api/deploy/{did}")
def deploy_status(did: str):
    _prune_tasks(deployments)
    d = deployments.get(did)
    if not d:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return d


# ----------------------------------------------------------------------
# Panel self-update (GitHub Releases)
# ----------------------------------------------------------------------

@app.get("/api/update/status")
def update_status():
    return updater.status()


@app.post("/api/update/check")
def update_check():
    try:
        return updater.check_updates()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update check failed: {e}")


@app.post("/api/update/start", status_code=202)
def update_start():
    try:
        tid = updater.start_update()
    except updater.UpdateBusy as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update failed to start: {e}")
    return {"id": tid}


@app.get("/api/update/task/{tid}")
def update_task(tid: str):
    updater.prune_tasks()
    t = updater.task(tid)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    return t


# ----------------------------------------------------------------------
# AmneziaWG package management
# ----------------------------------------------------------------------

awg_tasks: Dict[str, Dict] = {}


@app.get("/api/awg/status")
async def awg_status(server: str = "local", refresh: int = 0):
    s = find_server(server)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    if server == "local":
        try:
            return core.awg_apt_state(update=bool(refresh))
        except Exception as e:
            return {"error": str(e), "installed": core.awg_bin_present()}
    # Remote: the agent maintains apt state itself (apt-get update runs in the
    # background on the agent). refresh only kicks the agent's refresher and the
    # status endpoint returns the cached result, keeping responses small/stable.
    if refresh:
        await _agent_retry("GET", s, "/api/awg/refresh", timeout=15)
    return await _agent_retry("GET", s, "/api/awg/status", timeout=15)


def _awg_update_task(tid: str, server_id: str, action: str):
    d = awg_tasks[tid]
    try:
        if server_id == "local":
            steps: list = []
            if action == "install":
                result = core.awg_install(steps=steps)
            else:
                result = core.awg_upgrade(steps=steps)
            d["steps"] = steps[-8:]
            d["result"] = result
        else:
            s = find_server(server_id)
            if not s:
                raise RuntimeError("Server not found")
            data = _agent_retry_sync("POST", s, f"/api/awg/update?action={action}", timeout=30)
            sub_id = data.get("id")
            if not sub_id:
                raise RuntimeError(data.get("error") or "agent did not start a task")
            deadline = time.monotonic() + 2400
            while time.monotonic() < deadline:
                sub = _agent_retry_sync("GET", s, f"/api/awg/update/{sub_id}", timeout=30)
                if sub.get("steps"):
                    d["steps"] = sub["steps"][-8:]
                if sub.get("status") in ("done", "error"):
                    d["steps"] = (sub.get("steps") or [])[-8:]
                    d["result"] = sub.get("result")
                    if sub.get("status") == "error":
                        raise RuntimeError(sub.get("error") or "агент вернул ошибку")
                    break
                time.sleep(3)
            else:
                raise RuntimeError("превышено время ожидания задачи на агенте")
        d["status"] = "done"
        d["done_at"] = time.time()
    except Exception as e:
        d["steps"].append({"msg": f"Ошибка: {e}", "ok": False})
        d["status"] = "error"
        d["error"] = str(e)
        d["done_at"] = time.time()
        logger.exception("awg task %s failed", tid)


@app.post("/api/awg/update", status_code=202)
def start_awg_update(server: str = "local", action: str = "upgrade"):
    _prune_tasks(awg_tasks)
    if action not in ("upgrade", "install"):
        raise HTTPException(status_code=400, detail="action must be 'upgrade' or 'install'")
    if not find_server(server):
        raise HTTPException(status_code=404, detail="Server not found")
    tid = uuid.uuid4().hex
    awg_tasks[tid] = {"id": tid, "status": "running", "steps": [], "result": None,
                      "error": None, "action": action, "server": server, "done_at": 0}
    threading.Thread(target=_awg_update_task, args=(tid, server, action), daemon=True).start()
    return {"id": tid}


@app.get("/api/awg/update/{tid}")
def awg_update_status(tid: str):
    _prune_tasks(awg_tasks)
    d = awg_tasks.get(tid)
    if not d:
        raise HTTPException(status_code=404, detail="Task not found")
    return d


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
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
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
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
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