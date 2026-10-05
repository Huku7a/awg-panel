#!/usr/bin/env python3
"""Deploy / update the AWG agent on a VDS over SSH (used by the panel).

The very first deploy to a node needs the root password. Right after a
successful password login the panel appends its own public key to the node's
authorized_keys, so every later deploy or update runs passwordless.
"""
import hashlib
import json
import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import paramiko

logger = logging.getLogger("awg-deployer")

PANEL_DIR = Path(__file__).resolve().parent

EXCLUDE_DIRS = {"venv", ".git", "__pycache__", ".updates", ".bak", "dist", ".github"}
EXCLUDE_FILES = {
    "state.json", "servers.json", "stats.db", "stats.db-wal", "stats.db-shm",
    "*.pyc", "*.tar.gz", "*.sha256",
    # never ship SSH material to a node (the panel key lives in /etc/awg-panel,
    # but a stray copy in the repo must not be uploaded either)
    "id_ed25519", "id_ed25519.pub", "*.pem", "*.key",
}

# Where SSH host keys are pinned (trust-on-first-use). Overridable via env.
KNOWN_HOSTS_FILE = Path(os.environ.get("AWG_KNOWN_HOSTS_FILE", "/etc/awg-panel/known-hosts.json"))

# The panel's own SSH keypair. Generated on the first deploy and appended to
# every node's authorized_keys, so updates need no password at all.
DEPLOY_KEY = Path(os.environ.get("AWG_DEPLOY_KEY", "/etc/awg-panel/id_ed25519"))
DEPLOY_KEY_COMMENT = "awg-panel-deploy"

# Where the agent token is pre-seeded on a node (so it never hits `ps`).
AGENT_TOKEN_FILE = os.environ.get("AWG_AGENT_TOKEN_FILE", "/etc/awg-panel/agent-config")


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


# ----------------------------------------------------------------------
# the panel's own SSH key (passwordless re-deploys)
# ----------------------------------------------------------------------

def _generate_deploy_key() -> None:
    """Create the panel keypair if it does not exist yet."""
    DEPLOY_KEY.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(DEPLOY_KEY.parent, 0o700)
    # Generate beside the target and rename: ssh-keygen refuses to overwrite,
    # and a partial file would break every later deploy.
    tmp = DEPLOY_KEY.with_name(f"{DEPLOY_KEY.name}.tmp{os.getpid()}")
    rc, _, err = _run_subprocess([
        "ssh-keygen", "-t", "ed25519", "-N", "", "-C", DEPLOY_KEY_COMMENT, "-f", str(tmp),
    ])
    if rc != 0 or not tmp.exists():
        tmp.unlink(missing_ok=True)
        raise DeployError(f"Не удалось создать SSH-ключ панели: {err.strip() or 'ssh-keygen failed'}")
    os.replace(tmp, DEPLOY_KEY)
    os.replace(str(tmp) + ".pub", DEPLOY_KEY.with_suffix(".pub"))
    for p in (DEPLOY_KEY, DEPLOY_KEY.with_suffix(".pub")):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    logger.info("Generated panel deploy key %s", DEPLOY_KEY)


def _run_subprocess(cmd: List[str]):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)


def deploy_key_pem() -> Optional[str]:
    """Path of the private key to authenticate with, or None if not yet created."""
    return str(DEPLOY_KEY) if DEPLOY_KEY.exists() else None


def deploy_public_key() -> Optional[str]:
    """Single-line public key line to append to a node's authorized_keys."""
    pub = DEPLOY_KEY.with_suffix(".pub")
    if not pub.exists():
        return None
    try:
        line = pub.read_text().strip()
    except OSError:
        return None
    return line or None


def _install_authorized_key(ssh: paramiko.SSHClient, pub: str) -> bool:
    """Append the panel key to authorized_keys (idempotent). True if it was added."""
    q = shlex.quote(pub)
    cmd = (
        "install -d -m 700 \"$HOME/.ssh\" && "
        "touch \"$HOME/.ssh/authorized_keys\" && "
        "chmod 600 \"$HOME/.ssh/authorized_keys\" && "
        f"grep -qxF {q} \"$HOME/.ssh/authorized_keys\" && echo PRESENT || "
        f"{{ printf '%s\\n' {q} >> \"$HOME/.ssh/authorized_keys\" && echo ADDED; }}"
    )
    rc, out, err = _run_ssh(ssh, cmd, timeout=60)
    res = out.strip().splitlines()[-1] if out.strip() else ""
    if rc != 0 or res not in ("ADDED", "PRESENT"):
        raise DeployError("Не удалось установить SSH-ключ панели: %s"
                          % (err.strip() or out.strip() or "unknown error"))
    return res == "ADDED"


def deploy_agent(
    host: str,
    user: str,
    token: str,
    panel_ip: str,
    port: int = 22,
    remote_dir: str = "/root/awg-agent",
    steps: List[Dict] | None = None,
    password: str = "",
) -> Dict:
    """Deploy or update the agent on `host`, appending progress to `steps`.

    Authenticates with `password` when given, otherwise with the panel's own
    SSH key. After a password login the panel key is installed, so the next
    call needs no password. Returns {"auth": ..., "key_installed": ...}.
    """

    def step(msg: str, ok: bool = True):
        if steps is not None:
            steps.append({"msg": msg, "ok": ok})
        logger.info("deploy %s: %s", host, msg)

    key_pem = None
    if not password:
        key_pem = deploy_key_pem()
        if not key_pem:
            raise DeployError(
                f"Для {host} нет сохранённого SSH-доступа: введите пароль root ещё раз, "
                "панель запомнит узел по своему ключу.")
    elif not DEPLOY_KEY.exists():
        try:
            _generate_deploy_key()
            step("Создан SSH-ключ панели для беспарольных обновлений")
        except DeployError as e:
            step(str(e), ok=False)
            raise

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(TrustOnFirstUsePolicy(host, port))
    try:
        auth = "password" if password else "key"
        step(f"Подключение к {host}:{port} ({user}, по {'паролю' if password else 'ключу'})")
        try:
            ssh.connect(
                host,
                port=port,
                username=user,
                password=password or None,
                key_filename=key_pem,
                timeout=15,
                banner_timeout=30,
                auth_timeout=30,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException as e:
            if not password:
                raise DeployError(
                    f"Ключ панели не принят узлом {host}: введите пароль root ещё раз. ({e})") from e
            raise DeployError(f"Неверный пароль для {user}@{host}: {e}") from e
        step("SSH-соединение установлено")

        if not _check_aws(ssh):
            raise DeployError(f"AmneziaWG не найден на {host} (нужны awg и awg-quick)")

        # Install our key before touching the node: even if install-agent.sh
        # fails below, the next attempt is passwordless.
        key_installed = False
        pub = deploy_public_key()
        if pub:
            added = _install_authorized_key(ssh, pub)
            key_installed = True
            step("SSH-ключ панели установлен на узле" if added
                 else "SSH-ключ панели уже был на узле")

        step("Копирование файлов агента (SFTP)")
        sftp = ssh.open_sftp()
        try:
            _upload_tree(sftp, PANEL_DIR, remote_dir)
            # Pre-seed the agent token so it never appears on the command
            # line; install-agent.sh reuses the value it finds here.
            token_file = Path(AGENT_TOKEN_FILE)
            _ensure_dir(sftp, str(token_file.parent), "/")
            with sftp.open(str(token_file), "w") as f:
                f.write(f"AWG_AGENT_TOKEN={token}\n")
            try:
                sftp.chmod(str(token_file), 0o600)
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
        return {"auth": auth, "key_installed": key_installed}
    finally:
        try:
            ssh.close()
        except Exception:
            pass