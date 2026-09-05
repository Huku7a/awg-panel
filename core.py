#!/usr/bin/env python3
import base64
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import qrcode

logger = logging.getLogger("awg-core")

CONFIG_DIR = Path(os.environ.get("AWG_CONFIG_DIR", "/etc/amnezia/amneziawg"))
STATE_FILE = Path(os.environ.get("AWG_STATE_FILE", "/root/awg-panel/state.json"))
SERVERS_FILE = Path(os.environ.get("AWG_SERVERS_FILE", "/root/awg-panel/servers.json"))
CLIENT_DIR = Path(os.environ.get("AWG_CLIENT_DIR", "/root"))
PANEL_DIR = Path(__file__).resolve().parent

HANDSHAKE_ONLINE_SEC = 180
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")

_lock = threading.Lock()


def iface() -> str:
    return os.environ.get("AWG_INTERFACE", "awg0")


def config_path() -> Path:
    return CONFIG_DIR / f"{iface()}.conf"


def run(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, executable="/bin/bash",
        capture_output=True, text=True, timeout=timeout,
    )


# ----------------------------------------------------------------------
# AWG manipulation
# ----------------------------------------------------------------------

def load_params() -> Dict[str, str]:
    params: Dict[str, str] = {}
    p = CONFIG_DIR / "params"
    if not p.exists():
        raise RuntimeError(f"params file not found: {p}")
    for line in p.read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            params[k.strip()] = v.strip()
    return params


def endpoint(params: Dict[str, str]) -> str:
    ip = params["SERVER_PUB_IP"]
    if ":" in ip and not (ip.startswith("[") and "]" in ip):
        ip = f"[{ip}]"
    return f"{ip}:{params['SERVER_PORT']}"


def backup_config() -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = CONFIG_DIR / f"{iface()}.conf.bak-{ts}"
    shutil.copy2(config_path(), dest)
    return dest


def parse_clients() -> List[Dict]:
    lines = config_path().read_text().splitlines()
    clients: List[Dict] = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i].strip().startswith("### Client "):
            name = lines[i].strip().split("### Client ", 1)[1].strip()
            start = i
            i += 1
            data: Dict = {"name": name, "start": start, "end": None,
                          "pub": "", "psk": "", "ips": "", "ipv4": "", "ipv6": ""}
            while i < n:
                l = lines[i].strip()
                if l.startswith("### Client ") or (l.startswith("[") and l != "[Peer]"):
                    break
                if l.startswith("PublicKey"):
                    data["pub"] = l.split("=", 1)[1].strip()
                elif l.startswith("PresharedKey"):
                    data["psk"] = l.split("=", 1)[1].strip()
                elif l.startswith("AllowedIPs"):
                    data["ips"] = l.split("=", 1)[1].strip()
                    for part in l.split("=", 1)[1].split(","):
                        part = part.strip()
                        try:
                            ip = ipaddress.ip_interface(part)
                            if ip.version == 4:
                                data["ipv4"] = str(ip.ip)
                            else:
                                data["ipv6"] = str(ip.ip)
                        except ValueError:
                            pass
                i += 1
            data["end"] = i
            clients.append(data)
        else:
            i += 1
    return clients


def parse_clients_with_lines(lines: List[str]) -> List[Dict]:
    clients: List[Dict] = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i].strip().startswith("### Client "):
            name = lines[i].strip().split("### Client ", 1)[1].strip()
            start = i
            i += 1
            while i < n:
                l = lines[i].strip()
                if l.startswith("### Client ") or (l.startswith("[") and l != "[Peer]"):
                    break
                i += 1
            clients.append({"name": name, "start": start, "end": i})
        else:
            i += 1
    return clients


def remove_client_block(content: str, name: str) -> str:
    lines = content.split("\n")
    for c in parse_clients_with_lines(lines):
        if c["name"] == name:
            start, end = c["start"], c["end"]
            while end < len(lines) and lines[end].strip() == "":
                end += 1
            del lines[start:end]
            block = "\n".join(lines)
            block = re.sub(r"\n{3,}", "\n\n", block)
            return block.rstrip("\n") + "\n"
    return content


def add_client_block(content: str, name: str, pub: str, psk: str, ips: str) -> str:
    block = (f"\n### Client {name}\n[Peer]\nPublicKey = {pub}\n"
             f"PresharedKey = {psk}\nAllowedIPs = {ips}\n")
    return content.rstrip("\n") + "\n" + block


def apply_config() -> subprocess.CompletedProcess:
    return run(f"awg syncconf {iface()} <(awg-quick strip {iface()})")


def get_status() -> Dict[str, Dict]:
    r = run(f"awg show {iface()} dump")
    status: Dict[str, Dict] = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 8:
            pub = parts[0]
            rx = int(parts[5] or 0)
            tx = int(parts[6] or 0)
            hs = int(parts[4] or 0)
            status[pub] = {
                "pub": pub,
                "endpoint": parts[2],
                "last_handshake": hs,
                "online": bool(hs) and (datetime.now().timestamp() - hs) < HANDSHAKE_ONLINE_SEC,
                "rx": rx,
                "tx": tx,
            }
    return status


def load_state() -> Dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_state(state: Dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    tmp.replace(STATE_FILE)


def load_servers() -> List[Dict]:
    if SERVERS_FILE.exists():
        try:
            data = json.loads(SERVERS_FILE.read_text())
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def save_servers(servers: List[Dict]):
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SERVERS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(servers, indent=2, ensure_ascii=False))
    tmp.replace(SERVERS_FILE)


def find_free_ip(clients: List[Dict], state: Dict) -> Tuple[str, str]:
    params = load_params()
    used_v4 = {f"{'.'.join(params['SERVER_AWG_IPV4'].split('.')[:3])}.1"}
    used_v6 = {params["SERVER_AWG_IPV6"]}
    for c in clients:
        if c["ipv4"]:
            used_v4.add(c["ipv4"])
        if c["ipv6"]:
            used_v6.add(c["ipv6"])
    for d in state.values():
        if d.get("ipv4"):
            used_v4.add(d["ipv4"])
        if d.get("ipv6"):
            used_v6.add(d["ipv6"])
    base_v4 = ".".join(params["SERVER_AWG_IPV4"].split(".")[:3])
    base_v6 = params["SERVER_AWG_IPV6"].split("::", 1)[0]
    for n in range(2, 255):
        v4 = f"{base_v4}.{n}"
        v6 = f"{base_v6}::{n}"
        if v4 not in used_v4 and v6 not in used_v6:
            return v4, v6
    raise RuntimeError("The subnet supports only 253 clients.")


def build_client_conf(params: Dict, client_priv: str, ipv4: str, ipv6: str, psk: str) -> str:
    dns = f"{params['CLIENT_DNS_1']},{params['CLIENT_DNS_2']}" if params.get("CLIENT_DNS_2") else params["CLIENT_DNS_1"]
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {client_priv}",
        f"Address = {ipv4}/32,{ipv6}/128",
        f"DNS = {dns}",
        f"Jc = {params['SERVER_AWG_JC']}",
        f"Jmin = {params['SERVER_AWG_JMIN']}",
        f"Jmax = {params['SERVER_AWG_JMAX']}",
        f"S1 = {params['SERVER_AWG_S1']}",
        f"S2 = {params['SERVER_AWG_S2']}",
        f"H1 = {params['SERVER_AWG_H1']}",
        f"H2 = {params['SERVER_AWG_H2']}",
        f"H3 = {params['SERVER_AWG_H3']}",
        f"H4 = {params['SERVER_AWG_H4']}",
        "",
        "[Peer]",
        f"PublicKey = {params['SERVER_PUB_KEY']}",
        f"PresharedKey = {psk}",
        f"Endpoint = {endpoint(params)}",
        f"AllowedIPs = {params['ALLOWED_IPS']}",
        "",
    ])


def client_conf_file(name: str) -> Path:
    return CLIENT_DIR / f"{iface()}-client-{name}.conf"


def qr_base64(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def client_full_list(state: Dict, status: Dict[str, Dict]) -> List[Dict]:
    out: Dict[str, Dict] = {}
    for c in parse_clients():
        s = status.get(c["pub"], {})
        entry = {
            "name": c["name"],
            "public_key": c["pub"],
            "ipv4": c["ipv4"],
            "ipv6": c["ipv6"],
            "enabled": True,
            "online": bool(s.get("online")),
            "last_handshake": s.get("last_handshake", 0),
            "endpoint": s.get("endpoint", ""),
            "rx": s.get("rx", 0),
            "tx": s.get("tx", 0),
            "rx_h": human_bytes(s.get("rx", 0)),
            "tx_h": human_bytes(s.get("tx", 0)),
        }
        out[c["name"]] = entry
    for name, d in state.items():
        if name not in out:
            out[name] = {
                "name": name,
                "public_key": d.get("pub", ""),
                "ipv4": d.get("ipv4", ""),
                "ipv6": d.get("ipv6", ""),
                "enabled": False,
                "online": False,
                "last_handshake": 0,
                "endpoint": "",
                "rx": 0,
                "tx": 0,
                "rx_h": "0 B",
                "tx_h": "0 B",
            }
    return sorted(out.values(), key=lambda x: x["name"].lower())


# ----------------------------------------------------------------------
# Operations (used by both panel and agent)
# ----------------------------------------------------------------------

def op_create_client(name: str) -> Dict:
    if not NAME_RE.match(name):
        raise ValueError("Name must be 1-15 chars: letters, digits, '_' or '-'")
    with _lock:
        clients = parse_clients()
        state = load_state()
        if any(c["name"] == name for c in clients) or name in state:
            raise ValueError(f"Client '{name}' already exists")
        params = load_params()
        ipv4, ipv6 = find_free_ip(clients, state)

        priv = run("awg genkey").stdout.strip()
        pub = run(f"echo '{priv}' | awg pubkey").stdout.strip()
        psk = run("awg genpsk").stdout.strip()

        conf = build_client_conf(params, priv, ipv4, ipv6, psk)
        client_conf_file(name).write_text(conf)

        backup_config()
        content = config_path().read_text()
        content = add_client_block(content, name, pub, psk, f"{ipv4}/32,{ipv6}/128")
        config_path().write_text(content)

        result = apply_config()
        if result.returncode != 0:
            logger.error("syncconf failed after adding %s: %s", name, result.stderr)
            raise RuntimeError(f"syncconf failed: {result.stderr[:500]}")

        logger.info("Created client %s (%s)", name, ipv4)
        s = get_status().get(pub)
        return {
            "name": name,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "public_key": pub,
            "config": conf,
            "qr": qr_base64(conf),
            "online": bool(s and s.get("online")),
        }


def op_toggle_client(name: str, enabled: bool) -> Dict:
    with _lock:
        clients = parse_clients()
        state = load_state()
        cur = next((c for c in clients if c["name"] == name), None)

        if enabled:
            if cur:
                return {"name": name, "enabled": True, "already": True}
            if name not in state:
                raise ValueError(f"Client '{name}' not found")
            data = state.pop(name)
            backup_config()
            content = config_path().read_text()
            content = add_client_block(content, name, data["pub"], data["psk"], data["ips"])
            config_path().write_text(content)
            result = apply_config()
            if result.returncode != 0:
                state[name] = data
                save_state(state)
                raise RuntimeError(f"syncconf failed: {result.stderr[:500]}")
            save_state(state)
            logger.info("Enabled client %s", name)
            return {"name": name, "enabled": True, "already": False}
        else:
            if not cur:
                if name in state:
                    return {"name": name, "enabled": False, "already": True}
                raise ValueError(f"Client '{name}' not found")
            backup_config()
            content = config_path().read_text()
            content = remove_client_block(content, name)
            config_path().write_text(content)
            result = apply_config()
            if result.returncode != 0:
                raise RuntimeError(f"syncconf failed: {result.stderr[:500]}")
            state[name] = {
                "pub": cur["pub"],
                "psk": cur["psk"],
                "ips": cur["ips"],
                "ipv4": cur["ipv4"],
                "ipv6": cur["ipv6"],
            }
            save_state(state)
            logger.info("Disabled client %s", name)
            return {"name": name, "enabled": False, "already": False}


def op_delete_client(name: str) -> Dict:
    with _lock:
        state = load_state()
        cur = next((c for c in parse_clients() if c["name"] == name), None)
        if not cur and name not in state:
            raise ValueError(f"Client '{name}' not found")
        if cur:
            backup_config()
            content = config_path().read_text()
            content = remove_client_block(content, name)
            config_path().write_text(content)
            result = apply_config()
            if result.returncode != 0:
                raise RuntimeError(f"syncconf failed: {result.stderr[:500]}")
        state.pop(name, None)
        save_state(state)
        f = client_conf_file(name)
        if f.exists():
            f.unlink()
        logger.info("Deleted client %s", name)
        return {"name": name, "deleted": True}


def op_client_config(name: str) -> Tuple[str, str]:
    f = client_conf_file(name)
    if not f.exists():
        raise FileNotFoundError(f"Config file not found for client '{name}'")
    return f.name, f.read_text()


def op_client_qr(name: str) -> str:
    _, conf = op_client_config(name)
    return qr_base64(conf)