#!/usr/bin/env python3
"""Deploy the AWG agent to a fresh VDS over SSH (used by the panel)."""
import logging
from pathlib import Path
from typing import List

import paramiko

logger = logging.getLogger("awg-deployer")

PANEL_DIR = Path(__file__).resolve().parent

EXCLUDE_DIRS = {"venv", ".git", "__pycache__"}
EXCLUDE_FILES = {"state.json", "servers.json", "*.pyc"}


class DeployError(Exception):
    pass


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
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
        finally:
            sftp.close()

        step("Установка агента (venv, systemd, firewall)")
        cmd = f"cd {remote_dir} && bash deploy/install-agent.sh {panel_ip} {token}"
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