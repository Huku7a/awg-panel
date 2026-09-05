#!/usr/bin/env python3
import asyncio
import datetime as _dt
import hmac
import os
import logging
import threading
import uuid
from contextlib import asynccontextmanager
from typing import Dict

import core
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("awg-agent")

TOKEN = os.environ.get("AWG_AGENT_TOKEN", "")

REFRESH_INTERVAL = 6 * 3600  # seconds between automatic apt self-refreshes

# Cached result of awg_apt_state(update=True) maintained by the agent itself.
# {"data": dict|None, "at": ISO str|None, "ok": bool|None, "error": str|None}
_APT_CACHE: Dict = {"data": None, "at": None, "ok": None, "error": None}
_refresh_event = asyncio.Event()


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


async def _apt_worker():
    """Periodically run apt-get update in background and cache the result."""
    while True:
        try:
            await asyncio.wait_for(_refresh_event.wait(), timeout=REFRESH_INTERVAL)
        except asyncio.TimeoutError:
            pass
        _refresh_event.clear()
        try:
            data = await asyncio.to_thread(core.awg_apt_state, True)
            _APT_CACHE["data"] = data
            _APT_CACHE["ok"] = True
            _APT_CACHE["error"] = None
            logger.info("apt refresh ok, upgradable=%s", data.get("upgradable"))
        except Exception as e:
            _APT_CACHE["ok"] = False
            _APT_CACHE["error"] = str(e)
            logger.warning("apt refresh failed: %s", e)
        _APT_CACHE["at"] = _now_iso()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _refresh_event.set()  # do an initial refresh on startup
    task = asyncio.create_task(_apt_worker())
    yield
    task.cancel()


app = FastAPI(title="AWG Agent", docs_url=None, redoc_url=None, lifespan=lifespan)


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


@app.get("/api/awg/status")
def awg_status():
    c = dict(_APT_CACHE)
    data = c.get("data")
    if data is None:
        try:
            data = core.awg_apt_state(update=False)
        except Exception as e:
            return {"error": str(e), "installed": core.awg_bin_present()}
    state = "pending" if c["ok"] is None else ("ok" if c["ok"] else "error")
    return {**data, "update_state": state, "checked_at": c["at"], "error": c["error"]}


@app.get("/api/awg/refresh")
def awg_refresh():
    _refresh_event.set()
    return {"ok": True, "queued": True}


_UPD_TASKS: Dict[str, Dict] = {}


def _run_update_task(tid: str, action: str):
    t = _UPD_TASKS[tid]
    try:
        steps: list = []
        if action == "install":
            result = core.awg_install(steps=steps)
        else:
            result = core.awg_upgrade(steps=steps)
        t["steps"] = steps
        t["result"] = result
        t["status"] = "done"
    except Exception as e:
        t["status"] = "error"
        t["error"] = str(e)
        t["steps"].append({"msg": f"Ошибка: {e}", "ok": False})
        logger.exception("awg update task %s failed", tid)
    finally:
        try:
            _APT_CACHE["data"] = core.awg_apt_state(update=False)
            _APT_CACHE["ok"] = True
            _APT_CACHE["error"] = None
            _APT_CACHE["at"] = _now_iso()
        except Exception:
            pass


@app.post("/api/awg/update", status_code=202)
def awg_update(action: str = "upgrade"):
    if action not in ("upgrade", "install"):
        raise HTTPException(status_code=400, detail="action must be 'upgrade' or 'install'")
    tid = uuid.uuid4().hex
    _UPD_TASKS[tid] = {"id": tid, "status": "running", "steps": [], "result": None,
                       "error": None, "action": action}
    threading.Thread(target=_run_update_task, args=(tid, action), daemon=True).start()
    return {"id": tid}


@app.get("/api/awg/update/{tid}")
def awg_update_status(tid: str):
    t = _UPD_TASKS.get(tid)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    return t


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