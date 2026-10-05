#!/usr/bin/env python3
"""Deploy the AWG agent to a fresh VDS over SSH (used by the panel)."""
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import List

import paramiko

logger = logging.getLogger("awg-deployer")

PANEL_DIR = Path(__file__).resolve().parent

EXCLUDE_DIRS = {"venv", ".git", "__pycache__", ".updates", ".bak", "dist", ".github"}
EXCLUDE_FILES = {
    "state.json", "servers.json", "stats.db", "stats.db-wal", "stats.db-shm",
    "*.pyc", "*.tar.gz", "*.sha256",
}

# Where SSH host keys are pinned (trust-on-first-use). Overridable via env.
KNOWN_HOSTS_FILE = Path(os.environ.get("AWG_KNOWN_HOSTS_FILE", "/etc/awg-panel/known-hosts.json"))


class DeployError(Exception):
    pass


# ----------------------------------------------------------------------
# SSH host-key pinning (trust-on-first-use)
# ----------------------------------------------------------------------

def _key_fp(key):
    return hashlib.sha256(key.asbytes()).hexdigest()


def _kp_load() -> dict:
    if not KNOWN_HOSTS_FILE.exists():
        return {}
    try:
        data = json.loads(KNOWN_HOSTS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _kp_save(data: dict):
    KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = KNOWN_HOSTS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(KNOWN_HOSTS_FILE)
    try:
        KNOWN_HOSTS_FILE.chmod(0o600)
    except OSError:
        pass


class TrustOnFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """Pin the SSH host key on the first deploy; refuse to connect if the key
    later changes (mirrors SSH known_hosts behaviour)."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def missing_host_key(self, client, hostname, key):
        rec = _kp_load()
        pinned = rec.get(self.host) or {}
        fp = _key_fp(key)
        if pinned.get(key.get_name()) is None:
            rec.setdefault(self.host, {})[key.get_name()] = fp
            _kp_save(rec)
            logger.info("Pinned SSH host key for %s:%s (%s %s...)",
                        self.host, self.port, key.get_name(), fp[:16])
        elif pinned[key.get_name()] != fp:
            raise paramiko.SSHException(
                f"SSH host key for {self.host} has CHANGED (expected {pinned[key.get_name()]}, "
                f"got {fp}). Remove the entry from {KNOWN_HOSTS_FILE} to accept the new key.")


def _run_ssh(client: paramiko.SSHClient, command: str, timeout: int = 600):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def _ensure_dir(sftp: paramiko.SFTPClient, path: str, base: str = "/"):
    current = base
    for part in path.strip("/").split("/"):
        if not part:
            continue
        current = current.rstrip("/") + "/" + part
        try:
            sftp.mkdir(current)
        except OSError:
            pass


def _upload_tree(sftp: paramiko.SFTPClient, local_dir: Path, remote_dir: str):
    _ensure_dir(sftp, remote_dir)
    for child in sorted(local_dir.iterdir()):
        name = child.name
        if child.is_dir():
            if name in EXCLUDE_DIRS:
                continue
            _upload_tree(sftp, child, f"{remote_dir.rstrip('/')}/{name}")
        else:
            if name in EXCLUDE_FILES:
                continue
            sftp.put(str(child), f"{remote_dir.rstrip('/')}/{name}")


def _check_aws(ssh: paramiko.SSHClient) -> bool:
    rc, out, _ = _run_ssh(
        ssh,
        "command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1 && echo OK || echo NO",
        timeout=30,
    )
    return rc == 0 and "OK" in out


def deploy_agent(
    host: str,
    user: str,
    password: str,
    token: str,
    panel_ip: str,
    port: int = 22,
    remote_dir: str = "/root/awg-agent",
    steps: List[str] | None = None,
) -> None:
    """Deploy the agent to `host`, appending human-readable progress to `steps`."""

    def step(msg: str, ok: bool = True):
        if steps is not None:
            steps.append({"msg": msg, "ok": ok})
        logger.info("deploy %s: %s", host, msg)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(TrustOnFirstUsePolicy(host, port))
    try:
        step(f"Подключение к {host}:{port} ({user})")
        ssh.connect(
            host,
            port=port,
            username=user,
            password=password,
            timeout=15,
            banner_timeout=30,
            auth_timeout=30,
            allow_agent=False,
            look_for_keys=False,
        )
        step("SSH-соединение установлено")

        if not _check_aws(ssh):
            raise DeployError(f"AmneziaWG не найден на {host} (нужны awg и awg-quick)")

        step("Копирование файлов агента (SFTP)")
        sftp = ssh.open_sftp()
        try:
            _upload_tree(sftp, PANEL_DIR, remote_dir)
            # Pre-seed the agent token so it never appears on the command
            # line; install-agent.sh reuses the value it finds here.
            _ensure_dir(sftp, "awg-panel", "/etc")
            token_file = "/etc/awg-panel/agent-config"
            with sftp.open(token_file, "w") as f:
                f.write(f"AWG_AGENT_TOKEN={token}\n")
            try:
                sftp.chmod(token_file, 0o600)
            except OSError:
                pass
        finally:
            sftp.close()

        step("Установка агента (venv, systemd, firewall)")
        cmd = f"cd {remote_dir} && bash deploy/install-agent.sh {panel_ip}"
        rc, out, err = _run_ssh(ssh, cmd, timeout=600)
        if rc != 0:
            tail = (err.strip().splitlines() or ["no output"])[:20]
            raise DeployError("install-agent.sh failed (rc=%d): %s" % (rc, "\n".join(tail)))
        step("Агент установлен и запущен")
    finally:
        try:
            ssh.close()
        except Exception:
            pass