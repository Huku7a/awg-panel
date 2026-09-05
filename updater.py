#!/usr/bin/env python3
"""Self-update of the AWG Panel from GitHub Releases.

Deliverable contract for each release tag ``vX.Y.Z``:
  - asset ``awg-panel-X.Y.Z.tar.gz``         (payload bundle, top dir awg-panel-X.Y.Z/)
  - asset ``awg-panel-X.Y.Z.tar.gz.sha256``  (SHA-256 of the bundle)

Both are produced by ``deploy/build-release.sh`` / ``.github/workflows/release.yml``.
The panel verifies the checksum *before* touching anything, swaps code in place
(MANIFEST-driven, no local ``.git`` is used), re-installs requirements, restarts
the systemd service and rolls back on any failure.
"""
import asyncio
import calendar
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("awg-updater")

PANEL_DIR = Path(__file__).resolve().parent
UPDATE_DIR = Path(os.environ.get("AWG_UPDATE_DIR", default=str(PANEL_DIR / ".updates")))
UPDATE_REPO = os.environ.get("AWG_UPDATE_REPO", "Huku7a/awg-panel").strip("/")
GITHUB_TOKEN = os.environ.get("AWG_GITHUB_TOKEN", "")
CHECK_INTERVAL = int(os.environ.get("AWG_UPDATE_CHECK_INTERVAL", "21600"))  # 6h default
SERVICE_NAME = os.environ.get("AWG_SERVICE_NAME", "awg-panel")

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
_ASSET_RE = re.compile(r"^awg-panel-(\d+\.\d+\.\d+)\.tar\.gz$")
_PAYLOAD_REQUIRED = (
    "app.py", "core.py", "updater.py", "deployer.py",
    "requirements.txt", "VERSION", "MANIFEST", "templates/index.html",
)

_CACHE: Dict = {
    "state": "pending", "version": "", "latest": None, "published_at": None,
    "release_notes": "", "html_url": "", "asset_name": None, "asset_url": None,
    "checked_at": None, "error": None, "update_available": False,
}
_lock = threading.Lock()
_event = asyncio.Event()
_UPD_TASKS: Dict[str, Dict] = {}
_update_busy = False
_TASK_TTL = 3600
_MAX_TASKS = 20


class UpdateBusy(Exception):
    pass


# ----------------------------------------------------------------------
# version helpers
# ----------------------------------------------------------------------

def current_version() -> str:
    try:
        v = (PANEL_DIR / "VERSION").read_text().strip()
        if v:
            return v
    except OSError:
        pass
    return "0.0.0-dev"


def semver_key(version: str) -> Optional[tuple]:
    m = _SEMVER_RE.match((version or "").strip())
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def _is_newer(latest: str, current: str) -> bool:
    lk, ck = semver_key(latest), semver_key(current)
    if lk is None or ck is None:
        return bool(latest) and latest != current
    return lk > ck


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ----------------------------------------------------------------------
# GitHub API
# ----------------------------------------------------------------------

def _gh_get(path: str) -> httpx.Response:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"awg-panel/{current_version()}",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return httpx.get(f"https://api.github.com{path}", headers=headers, timeout=20.0)


def _release_asset(rel: dict) -> Optional[dict]:
    tag_ver = (rel.get("tag_name") or "").lstrip("v")
    for a in rel.get("assets") or []:
        name = a.get("name") or ""
        m = _ASSET_RE.match(name)
        if m and m.group(1) == tag_ver:
            return a
    return None


def _check() -> Dict:
    """Fetch the latest release info and build a status snapshot."""
    base = {"state": "error", "latest": None, "published_at": None,
            "release_notes": "", "html_url": "", "asset_name": None,
            "asset_url": None, "error": None, "update_available": False}
    try:
        r = _gh_get(f"/repos/{UPDATE_REPO}/releases/latest")
    except httpx.HTTPError as e:
        base["error"] = f"GitHub недоступен: {e.__class__.__name__}"
        base["state"] = "error"
        return base
    if r.status_code == 404:
        base["state"] = "no-release"
        return base
    if r.status_code in (401, 403):
        base["error"] = ("Лимит GitHub API/авторизация (%s). "
                         "Попробуйте позже или задайте AWG_GITHUB_TOKEN." % r.status_code)
        base["state"] = "error"
        return base
    if r.status_code >= 400:
        base["error"] = f"GitHub API: HTTP {r.status_code}"
        base["state"] = "error"
        return base
    rel = r.json()
    tag_ver = (rel.get("tag_name") or "").lstrip("v")
    asset = _release_asset(rel)
    base.update({
        "state": "no-asset" if not asset else "ok",
        "latest": tag_ver or None,
        "published_at": rel.get("published_at"),
        "release_notes": rel.get("body") or "",
        "html_url": rel.get("html_url") or "",
        "error": None if asset else ("В релизе нет ассета awg-panel-%s.tar.gz" % tag_ver),
    })
    if asset:
        base["asset_name"] = asset["name"]
        base["asset_url"] = asset["browser_download_url"]
    base["update_available"] = (
        bool(asset) and bool(base["latest"]) and _is_newer(base["latest"], current_version())
    )
    if not base["latest"]:
        base["state"] = "no-release"
    return base


def check_updates() -> Dict:
    res = _check()
    res["version"] = current_version()
    res["checked_at"] = _now_iso()
    with _lock:
        _CACHE.update(res)
    logger.info("update check: state=%s latest=%s", res.get("state"), res.get("latest"))
    return dict(_CACHE)


# ----------------------------------------------------------------------
# download / integrity / unpack
# ----------------------------------------------------------------------

def _download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    headers = {"User-Agent": f"awg-panel/{current_version()}"}
    with httpx.stream("GET", url, headers=headers, follow_redirects=True,
                      timeout=120.0) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in resp.iter_bytes(1 << 16):
                f.write(chunk)
    tmp.replace(dest)
    return dest


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def verify_sha256(archive: Path, sha_url: str) -> bool:
    try:
        txt = httpx.get(sha_url, follow_redirects=True, timeout=30.0).text.strip()
    except httpx.HTTPError:
        return False
    m = re.search(r"([0-9a-fA-F]{64})", txt)
    if not m:
        return False
    return hmac.compare_digest(m.group(1).lower(), _sha256_of(archive))


def _safe_extract(archive: Path, dest: Path):
    """Extract a bundle, stripping the top-level directory, with path
    traversal / symlink protection."""
    dest.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            if not members:
                raise ValueError("архив пуст")
            for m in members:
                p = Path(m.name)
                if p.is_absolute() or any(part == ".." for part in p.parts):
                    raise ValueError(f"Недопустимый путь в архиве: {m.name!r}")
                if m.issym() or m.islnk() or m.isdev() or not (m.isdir() or m.isfile()):
                    raise ValueError(f"Недопустимый член архива: {m.name!r}")
            if not members[0].isdir():
                raise ValueError("в архиве отсутствует корневой каталог")
            top = members[0].name.rstrip("/")
            tf.extractall(tmp)
        inner = tmp / top
        if not inner.is_dir():
            raise ValueError("не удалось найти корневой каталог после распаковки")
        for child in inner.iterdir():
            shutil.move(str(child), dest / child.name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _venv_python() -> str:
    p = PANEL_DIR / "venv" / "bin" / "python"
    return str(p) if p.exists() else sys.executable


def validate_payload(payload: Path, tag_ver: str):
    missing = [f for f in _PAYLOAD_REQUIRED if not (payload / f).exists()]
    if missing:
        raise ValueError(f"В бандле отсутствуют обязательные файлы: {', '.join(missing)}")
    v = (payload / "VERSION").read_text().strip()
    if v != tag_ver:
        raise ValueError(f"VERSION в бандле ({v}) не совпадает с тегом релиза ({tag_ver})")
    py = _venv_python()
    files = [str(p) for p in sorted(payload.rglob("*.py"))]
    r = subprocess.run([py, "-m", "py_compile"] + files, capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"Компиляция Python из бандла не прошла: {r.stderr.strip()[-300:]}")
    r = subprocess.run([py, "-c", "import app"],
                       cwd=str(payload), capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise ValueError(f"Импорт app из бандла не прошёл: {r.stderr.strip()[-300:]}")


# ----------------------------------------------------------------------
# update task
# ----------------------------------------------------------------------

def _bak_dir(ver: str) -> Path:
    return UPDATE_DIR / "backup" / ver


def _launch_swap(marker: Path):
    """Launch the swap in a transient systemd scope so it is not killed when
    `systemctl restart <service>` signals the panel's own cgroup."""
    script = PANEL_DIR / "deploy" / "upgrade-panel.sh"
    log = open(UPDATE_DIR / "upgrade.log", "ab")
    if shutil.which("systemd-run"):
        cmd = [
            "systemd-run", "--quiet", "--scope", "--collect",
            "--unit", "awg-panel-upgrade-%d" % int(time.time()),
            str(script), str(marker),
        ]
    else:
        cmd = [str(script), str(marker)]
    proc = subprocess.Popen(
        cmd,
        cwd=str(PANEL_DIR),
        stdout=log, stderr=log,
    )
    logger.info("swap launched pid=%s (systemd-run=%s)", proc.pid,
                shutil.which("systemd-run") is not None)


def _run_update_task(tid: str):
    t = _UPD_TASKS[tid]
    global _update_busy
    try:
        res = check_updates()
        if not res.get("update_available"):
            raise RuntimeError("Уже установлена последняя версия")
        t["steps"].append({"msg": f"Найдено обновление: v{res['latest']}", "ok": True})

        archive = UPDATE_DIR / "assets" / res["asset_name"]
        t["steps"].append({"msg": f"Загрузка {res['asset_name']}", "ok": True})
        _download(res["asset_url"], archive)

        t["steps"].append({"msg": "Проверка контрольной суммы SHA-256", "ok": True})
        if not verify_sha256(archive, res["asset_url"] + ".sha256"):
            raise RuntimeError("Контрольная сумма не совпадает; обновление отменено")

        payload = UPDATE_DIR / "payload" / res["latest"]
        t["steps"].append({"msg": "Распаковка и проверка бандла", "ok": True})
        _safe_extract(archive, payload)
        validate_payload(payload, res["latest"])

        marker = UPDATE_DIR / "swap.json"
        marker.write_text(json.dumps({
            "tid": tid,
            "version": res["latest"],
            "current_version": current_version(),
            "payload": str(payload),
            "app_dir": str(PANEL_DIR),
            "python": _venv_python(),
            "service": SERVICE_NAME,
            "backup": str(_bak_dir(res["latest"])),
            "update_dir": str(UPDATE_DIR),
            "created": _now_iso(),
        }, indent=2))

        t["steps"].append({"msg": "Запуск обновления (замена файлов, перезапуск)", "ok": True})
        _launch_swap(marker)
        t["status"] = "swapping"
        logger.info("update %s launched for version %s", tid, res["latest"])
    except Exception as e:
        t["steps"].append({"msg": f"Ошибка: {e}", "ok": False})
        t["status"] = "error"
        t["error"] = str(e)
        logger.exception("update task %s failed", tid)
    finally:
        _update_busy = False
        t["done_at"] = time.time()


_STALE_SWAP_SEC = 10 * 60


def _result_time(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return None


def _read_last_result() -> Optional[Dict]:
    p = UPDATE_DIR / "last_result.json"
    try:
        if p.exists():
            return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _read_progress() -> Optional[Dict]:
    p = UPDATE_DIR / "progress.json"
    try:
        if p.exists():
            d = json.loads(p.read_text())
            if isinstance(d, dict) and d.get("text"):
                return d
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _fresh_last_result() -> Optional[Dict]:
    last = _read_last_result()
    if not last or last.get("status") != "running":
        return None
    ts = _result_time(last.get("time"))
    if ts is not None and time.time() - ts <= _STALE_SWAP_SEC:
        return last
    return None


def _active_steps() -> List[Dict]:
    with _lock:
        best = None
        for t in _UPD_TASKS.values():
            if t.get("status") == "running" and (
                    best is None or len(t.get("steps", [])) > len(best.get("steps", []))):
                best = t
        return (best or {}).get("steps", [])[-6:]


def start_update() -> str:
    global _update_busy
    prune_tasks()
    if _fresh_last_result():
        raise UpdateBusy("Обновление уже выполняется")
    with _lock:
        if _update_busy:
            raise UpdateBusy("Обновление уже выполняется")
        _update_busy = True
    tid = uuid.uuid4().hex
    _UPD_TASKS[tid] = {"id": tid, "status": "running", "steps": [], "error": None, "done_at": 0}
    threading.Thread(target=_run_update_task, args=(tid,), daemon=True).start()
    return tid


def task(tid: str) -> Optional[Dict]:
    with _lock:
        return _UPD_TASKS.get(tid)


def prune_tasks():
    now = time.time()
    for k in list(_UPD_TASKS):
        t = _UPD_TASKS[k]
        if t.get("status") in ("done", "error", "swapping") and now - t.get("done_at", 0) > _TASK_TTL:
            del _UPD_TASKS[k]
    if len(_UPD_TASKS) > _MAX_TASKS:
        finished = sorted(
            ((t.get("done_at") or 0, k) for k, t in _UPD_TASKS.items()
             if t.get("status") in ("done", "error")),
            reverse=True,
        )
        for _, k in finished[_MAX_TASKS:]:
            _UPD_TASKS.pop(k, None)


def status() -> Dict:
    with _lock:
        cached = dict(_CACHE)
    cached["version"] = current_version()
    last = _read_last_result()
    if last and last.get("status") == "running":
        ts = _result_time(last.get("time"))
        if ts is not None and time.time() - ts > _STALE_SWAP_SEC:
            last = {
                "status": "error",
                "version": last.get("version"),
                "previous": last.get("previous"),
                "time": last.get("time"),
                "detail": "обновление было прервано (не завершилось за 10 минут)",
            }
    cached["last_result"] = last
    cached["busy"] = _update_busy or bool(_fresh_last_result())
    if cached["busy"]:
        cached["progress"] = _read_progress()
        cached["active_steps"] = _active_steps()
    else:
        cached["progress"] = None
        cached["active_steps"] = []
    if cached.get("latest") and not cached.get("update_available"):
        cached["update_available"] = _is_newer(cached["latest"], cached["version"])
    return cached


# ----------------------------------------------------------------------
# background refresh loop
# ----------------------------------------------------------------------

async def updater_worker():
    while True:
        try:
            await asyncio.to_thread(check_updates)
        except Exception:
            logger.exception("update check failed")
        try:
            await asyncio.wait_for(_event.wait(), timeout=CHECK_INTERVAL)
        except asyncio.TimeoutError:
            pass
        _event.clear()