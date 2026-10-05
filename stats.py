#!/usr/bin/env python3
"""Connection and traffic statistics for AWG clients.

AWG itself keeps no history: per-peer rx/tx counters live in the kernel and are
wiped whenever the interface is recreated (VDS reboot) or a peer is re-added by
`syncconf`. So this module owns the history instead:

  * a background sampler reads `awg show <iface> dump` every INTERVAL seconds
    and stores the *deltas* in a local SQLite DB (hourly buckets);
  * `peers.total_rx/total_tx` are monotonic accumulators, so "all-time"
    traffic survives any number of counter resets;
  * a reset (reboot or peer re-create) is attributed as "new counter value",
    so post-reset traffic is neither lost nor double counted.

The DB - never the AWG counters - is the source of truth for history. The only
data that can be lost is the tail between the last sample and a reboot (<= one
INTERVAL), because those bytes are already gone from the kernel.
"""
import asyncio
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional

import core

logger = logging.getLogger("awg-stats")

INTERVAL = max(10, int(os.environ.get("AWG_STATS_INTERVAL", "60")))
# History depth is capped at a month by design.
RETENTION_DAYS = min(30, max(1, int(os.environ.get("AWG_STATS_RETENTION_DAYS", "30"))))
BUCKET_SEC = 3600
DAY_SEC = 86400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS events (
    ts   INTEGER NOT NULL,
    kind TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
    pub      TEXT PRIMARY KEY,
    name     TEXT NOT NULL DEFAULT '',
    rx       INTEGER NOT NULL DEFAULT 0,
    tx       INTEGER NOT NULL DEFAULT 0,
    total_rx INTEGER NOT NULL DEFAULT 0,
    total_tx INTEGER NOT NULL DEFAULT 0,
    online   INTEGER NOT NULL DEFAULT 0,
    seen     INTEGER NOT NULL DEFAULT 0,
    resets   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS buckets (
    bucket     INTEGER NOT NULL,
    pub        TEXT NOT NULL,
    rx         INTEGER NOT NULL DEFAULT 0,
    tx         INTEGER NOT NULL DEFAULT 0,
    online_sec REAL    NOT NULL DEFAULT 0,
    sessions   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, pub)
);
CREATE INDEX IF NOT EXISTS buckets_pub ON buckets (pub);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
"""

_sample_lock = threading.Lock()

_UPSERT_BUCKET = """
INSERT INTO buckets (bucket, pub, rx, tx, online_sec, sessions) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(bucket, pub) DO UPDATE SET
    rx         = rx + excluded.rx,
    tx         = tx + excluded.tx,
    online_sec = online_sec + excluded.online_sec,
    sessions   = sessions + excluded.sessions
"""

# excluded.total_* carry the *delta*, so the stored totals only ever grow.
_UPSERT_PEER = """
INSERT INTO peers (pub, name, rx, tx, total_rx, total_tx, online, seen, resets)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(pub) DO UPDATE SET
    name     = excluded.name,
    rx       = excluded.rx,
    tx       = excluded.tx,
    total_rx = peers.total_rx + excluded.total_rx,
    total_tx = peers.total_tx + excluded.total_tx,
    online   = excluded.online,
    seen     = excluded.seen,
    resets   = peers.resets + excluded.resets
"""


class StatsError(Exception):
    """Raised for unusable report parameters (mapped to HTTP 400)."""


# ----------------------------------------------------------------------
# storage
# ----------------------------------------------------------------------

def db_path() -> Path:
    p = os.environ.get("AWG_STATS_FILE", "")
    if p:
        return Path(p)
    return Path(core.STATE_FILE).parent / "stats.db"


def _init(con: sqlite3.Connection):
    con.executescript(_SCHEMA)


@contextmanager
def db():
    p = db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=30.0)
    try:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=30000")
        _init(con)
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _meta_get(con: sqlite3.Connection, key: str, default: str = "") -> str:
    row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def _meta_set(con: sqlite3.Connection, key: str, value: str):
    con.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))


def _prune(con: sqlite3.Connection, now: float):
    cutoff = int(now - RETENTION_DAYS * DAY_SEC)
    con.execute("DELETE FROM buckets WHERE bucket < ?", (cutoff,))
    con.execute("DELETE FROM events WHERE ts < ?", (cutoff,))


# ----------------------------------------------------------------------
# sampling
# ----------------------------------------------------------------------

def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def _client_names() -> Dict[str, str]:
    try:
        return {c["pub"]: c["name"] for c in core.parse_clients() if c.get("pub")}
    except Exception:
        return {}


def sample_now() -> Dict:
    """Take one sample and fold it into the history. Never raises."""
    with _sample_lock:
        now = time.time()
        names = _client_names()
        boot_id = _boot_id()
        try:
            status = core.get_status()
        except Exception:
            logger.exception("stats: cannot read awg status")
            status = {}

        rebooted = False
        resets = 0
        with db() as con:
            stored_boot = _meta_get(con, "boot_id")
            if boot_id and stored_boot and boot_id != stored_boot:
                rebooted = True
                _meta_set(con, "boot_count", str(int(_meta_get(con, "boot_count", "0") or 0) + 1))
                con.execute("INSERT INTO events (ts, kind) VALUES (?, 'boot')", (int(now),))
                logger.info("stats: detected reboot, counter baselines will re-sync")
            if boot_id:
                _meta_set(con, "boot_id", boot_id)

            prev = {r["pub"]: r for r in con.execute("SELECT * FROM peers")}
            bucket = int(now // BUCKET_SEC * BUCKET_SEC)
            for pub, s in status.items():
                p = prev.get(pub)
                rx, tx = int(s.get("rx") or 0), int(s.get("tx") or 0)
                online = 1 if s.get("online") else 0
                if p is None:
                    # first sight: record the baseline, no delta yet
                    d_rx = d_tx = 0
                    dt = 0.0
                    peer_resets = 0
                else:
                    peer_resets = 1 if (rx < p["rx"] or tx < p["tx"]) else 0
                    # a lower counter means a reset (reboot / peer re-created):
                    # everything it shows was transferred after the reset
                    d_rx = rx - p["rx"] if rx >= p["rx"] else rx
                    d_tx = tx - p["tx"] if tx >= p["tx"] else tx
                    dt = max(0.0, min(now - p["seen"], INTERVAL * 2))
                resets += peer_resets
                sessions = 1 if (online and p is not None and not p["online"]) else 0
                con.execute(_UPSERT_BUCKET, (bucket, pub, d_rx, d_tx, dt if online else 0.0, sessions))
                con.execute(_UPSERT_PEER, (pub, names.get(pub, "") or (p["name"] if p else ""),
                                           rx, tx, d_rx, d_tx, online, int(now), peer_resets))
            _meta_set(con, "last_sample", str(int(now)))
            _prune(con, now)

        if status or rebooted:
            logger.info("stats: sample peers=%d resets=%d reboot=%s", len(status), resets, rebooted)
        return {"peers": len(status), "resets": resets, "rebooted": rebooted,
                "ts": int(now), "db": str(db_path())}


async def sampler_worker(interval: Optional[int] = None) -> None:
    """Sample immediately, then once per `interval` seconds, until cancelled."""
    every = interval or INTERVAL
    while True:
        try:
            await asyncio.to_thread(sample_now)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("stats sampler iteration failed")
        await asyncio.sleep(every)


# ----------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------

def _roster(status: Dict[str, Dict]) -> Dict[str, Dict]:
    """Current clients keyed by public key (name, ip, enabled, online)."""
    out: Dict[str, Dict] = {}
    try:
        clients = core.parse_clients()
    except Exception:
        clients = []
    for c in clients:
        s = status.get(c["pub"], {})
        out[c["pub"]] = {
            "name": c["name"], "ipv4": c.get("ipv4", ""), "ipv6": c.get("ipv6", ""),
            "enabled": True, "online": bool(s.get("online")),
            "last_handshake": s.get("last_handshake", 0),
        }
    try:
        state = core.load_state()
    except Exception:
        state = {}
    for name, d in state.items():
        pub = d.get("pub", "")
        if pub and pub not in out:
            out[pub] = {"name": name, "ipv4": d.get("ipv4", ""), "ipv6": d.get("ipv6", ""),
                        "enabled": False, "online": False, "last_handshake": 0}
    return out


def _period(from_ts: Optional[float], to_ts: Optional[float], days: int) -> tuple:
    now = time.time()
    to = float(to_ts) if to_ts is not None else now
    if from_ts is not None:
        frm = float(from_ts)
    else:
        frm = to - max(1, int(days or 7)) * DAY_SEC
    if to <= frm:
        frm = to - DAY_SEC
    truncated = False
    floor_ts = now - RETENTION_DAYS * DAY_SEC
    if frm < floor_ts:
        frm = floor_ts
        truncated = True
    return frm, to, truncated


def _day_offset() -> int:
    """Shift day buckets so they start at local midnight, not UTC midnight."""
    return -int(time.timezone)


def report(from_ts: Optional[float] = None, to_ts: Optional[float] = None,
           days: int = 7, granularity: str = "auto",
           client: str = "") -> Dict:
    """Per-client traffic / uptime / session counts for a period, plus a
    per-bucket series for the chart."""
    if granularity not in ("auto", "hour", "day"):
        raise StatsError("granularity must be 'auto', 'hour' or 'day'")
    frm, to, truncated = _period(from_ts, to_ts, days)
    span = to - frm
    gran = granularity
    if gran == "auto":
        gran = "hour" if span <= 2 * DAY_SEC else "day"

    b_from = int(frm // BUCKET_SEC * BUCKET_SEC)
    b_to = int(to // BUCKET_SEC * BUCKET_SEC) + BUCKET_SEC

    try:
        status = core.get_status()
    except Exception:
        status = {}
    roster = _roster(status)

    with db() as con:
        peer_rows = con.execute(
            "SELECT pub, name, total_rx, total_tx, resets FROM peers").fetchall()
        names = {r["pub"]: r["name"] for r in peer_rows if r["name"]}
        totals = {r["pub"]: (r["total_rx"], r["total_tx"], r["resets"]) for r in peer_rows}
        pub_filter = None
        if client:
            pub_filter = next((p for p, n in names.items() if n == client), None)
            if pub_filter is None:
                pub_filter = next((p for p, i in roster.items() if i["name"] == client), None)
            if pub_filter is None:
                raise StatsError(f"Клиент '{client}' не найден")

        where = "WHERE bucket >= ? AND bucket < ?"
        args: list = [b_from, b_to]
        if pub_filter:
            where += " AND pub = ?"
            args.append(pub_filter)

        per_client: Dict[str, Dict] = {}
        for r in con.execute(
                f"SELECT pub, SUM(rx) AS rx, SUM(tx) AS tx, SUM(online_sec) AS online_sec, "
                f"SUM(sessions) AS sessions FROM buckets {where} GROUP BY pub", args):
            per_client[r["pub"]] = {
                "rx": int(r["rx"] or 0), "tx": int(r["tx"] or 0),
                "online_sec": float(r["online_sec"] or 0), "sessions": int(r["sessions"] or 0),
            }

        if gran == "day":
            off = _day_offset()
            group = f"((bucket + ({off})) / {DAY_SEC}) * {DAY_SEC} - ({off})"
        else:
            group = "bucket"
        series = [
            {"ts": int(r["ts"]), "rx": int(r["rx"] or 0), "tx": int(r["tx"] or 0),
             "online_sec": float(r["online_sec"] or 0)}
            for r in con.execute(
                f"SELECT {group} AS ts, SUM(rx) AS rx, SUM(tx) AS tx, "
                f"SUM(online_sec) AS online_sec FROM buckets {where} "
                f"GROUP BY ts ORDER BY ts", args)
        ]

        cov = con.execute(
            "SELECT MIN(bucket) AS a, MAX(bucket) AS b FROM buckets").fetchone()
        reboot_count = con.execute(
            "SELECT COUNT(*) AS n FROM events WHERE kind = 'boot' AND ts >= ? AND ts < ?",
            (int(frm), int(to) + 1)).fetchone()["n"]
        last_reboot = con.execute(
            "SELECT MAX(ts) AS t FROM events WHERE kind = 'boot'").fetchone()["t"]
        boot_total = int(_meta_get(con, "boot_count", "0") or 0)

    rows: List[Dict] = []
    # With an explicit client filter the table must contain that single client
    # (even if it has no traffic in the period, or was removed from the config).
    pub_list = [pub_filter] if pub_filter else list(set(list(per_client) + list(roster)))
    for pub in pub_list:
        info = roster.get(pub)
        agg = per_client.get(pub)
        if not agg:
            # no activity in the period: only report clients that still exist
            if info is None and not pub_filter:
                continue
            agg = {"rx": 0, "tx": 0, "online_sec": 0.0, "sessions": 0}
        total_rx, total_tx, resets = totals.get(pub, (0, 0, 0))
        rx, tx = agg["rx"], agg["tx"]
        rows.append({
            "name": (info or {}).get("name") or names.get(pub, ""),
            "public_key": pub,
            "ipv4": (info or {}).get("ipv4", ""),
            "enabled": bool((info or {}).get("enabled", False)),
            "online": bool((info or {}).get("online")),
            "last_handshake": (info or {}).get("last_handshake", 0),
            "present": info is not None,
            "rx": rx, "tx": tx,
            "rx_h": core.human_bytes(rx), "tx_h": core.human_bytes(tx),
            "online_sec": round(agg["online_sec"], 1),
            "sessions": agg["sessions"],
            "total_rx": total_rx, "total_tx": total_tx,
            "total_h": core.human_bytes(total_rx + total_tx),
            "resets": resets,
        })
    rows.sort(key=lambda r: (r["rx"] + r["tx"]), reverse=True)
    rows.sort(key=lambda r: not r["present"])

    return {
        "from": int(frm), "to": int(to),
        "granularity": gran,
        "retention_days": RETENTION_DAYS,
        "interval": INTERVAL,
        "truncated": truncated,
        "coverage": {
            "first_sample": int(cov["a"]) if cov and cov["a"] else None,
            "last_sample": int(cov["b"]) + BUCKET_SEC if cov and cov["b"] else None,
        },
        "totals": {
            "rx": sum(r["rx"] for r in rows),
            "tx": sum(r["tx"] for r in rows),
            "online_sec": round(sum(r["online_sec"] for r in rows), 1),
            "sessions": sum(r["sessions"] for r in rows),
            "clients": len(rows),
        },
        "events": {"reboots": int(reboot_count), "last_reboot": last_reboot,
                   "boot_total": boot_total},
        "series": series,
        "clients": rows,
        "client": client or None,
    }