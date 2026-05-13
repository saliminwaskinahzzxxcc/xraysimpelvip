#!/usr/bin/env python3
"""
Xray Simpel VIP - tiny no-dependency Xray account panel.
Runs on Python standard library only.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

APP_NAME = "Xray Simpel VIP"
BASE_DIR = Path(os.environ.get("XRAY_SIMPLE_HOME", Path(__file__).resolve().parent))
DB_PATH = BASE_DIR / "panel.db"
XRAY_CONFIG_PATH = Path(os.environ.get("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json"))
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_API_SERVER = os.environ.get("XRAY_API_SERVER", "127.0.0.1:10085")
PUBLIC_WS_PATHS = {"vmess": "/vmess", "vless": "/vless", "trojan": "/trojan"}
INTERNAL_PORTS = {"vmess": 10001, "vless": 10002, "trojan": 10003}
PROTOCOLS = tuple(PUBLIC_WS_PATHS.keys())
ACTIVE_WINDOW_SECONDS = 180


def now_ts() -> int:
    return int(time.time())


def human_bytes(num: Optional[int]) -> str:
    if num is None:
        return "0 B"
    n = float(max(0, int(num)))
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def parse_quota_gb(value: str) -> int:
    value = (value or "0").strip().replace(",", ".")
    if not value:
        return 0
    try:
        gb = float(value)
    except ValueError:
        raise ValueError("Quota must be a number")
    if gb < 0:
        raise ValueError("Quota cannot be negative")
    if gb == 0:
        return 0
    return int(gb * 1024 * 1024 * 1024)


def fmt_datetime(ts: Optional[int]) -> str:
    if not ts:
        return "Never"
    return dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")


def safe_username(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,32}", value):
        raise ValueError("Username must be 3-32 characters: letters, numbers, _ or - only")
    return value


def protocol_or_error(value: str) -> str:
    value = (value or "").strip().lower()
    if value not in PROTOCOLS:
        raise ValueError("Protocol must be vmess, vless, or trojan")
    return value


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def vmess_b64(data: str) -> str:
    return base64.b64encode(data.encode()).decode().replace("\n", "")


class Store:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    protocol TEXT NOT NULL CHECK(protocol IN ('vmess','vless','trojan')),
                    credential TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    quota_bytes INTEGER NOT NULL DEFAULT 0,
                    used_up INTEGER NOT NULL DEFAULT 0,
                    used_down INTEGER NOT NULL DEFAULT 0,
                    last_counter_up INTEGER NOT NULL DEFAULT 0,
                    last_counter_down INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    disabled_reason TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    last_active INTEGER
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_username_protocol
                    ON accounts(username, protocol);
                """
            )

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_settings(self) -> Dict[str, str]:
        with self.connect() as db:
            return {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM settings")}

    def add_account(self, username: str, protocol: str, quota_bytes: int, expires_at: Optional[int]) -> sqlite3.Row:
        username = safe_username(username)
        protocol = protocol_or_error(protocol)
        credential = str(uuid.uuid4()) if protocol in ("vmess", "vless") else secrets.token_urlsafe(18)
        # Xray stats require email to be set. This is an internal stats label, not a mailbox.
        email = f"{protocol}-{username}-{secrets.token_hex(3)}@xraysimpelvip.local"
        created = now_ts()
        with self.connect() as db:
            try:
                cur = db.execute(
                    """
                    INSERT INTO accounts(username,protocol,credential,email,quota_bytes,created_at,expires_at)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (username, protocol, credential, email, quota_bytes, created, expires_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("That username already exists for this protocol") from exc
            return db.execute("SELECT * FROM accounts WHERE id=?", (cur.lastrowid,)).fetchone()

    def list_accounts(self) -> List[sqlite3.Row]:
        with self.connect() as db:
            return list(db.execute("SELECT * FROM accounts ORDER BY created_at DESC, id DESC"))

    def get_account(self, account_id: int) -> Optional[sqlite3.Row]:
        with self.connect() as db:
            return db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()

    def delete_account(self, account_id: int) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM accounts WHERE id=?", (account_id,))

    def set_enabled(self, account_id: int, enabled: bool, reason: str = "") -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE accounts SET enabled=?, disabled_reason=? WHERE id=?",
                (1 if enabled else 0, "" if enabled else reason, account_id),
            )

    def reset_usage(self, account_id: int) -> None:
        with self.connect() as db:
            db.execute(
                """
                UPDATE accounts
                SET used_up=0, used_down=0, last_counter_up=0, last_counter_down=0,
                    last_active=NULL, disabled_reason=CASE WHEN disabled_reason='quota exceeded' THEN '' ELSE disabled_reason END
                WHERE id=?
                """,
                (account_id,),
            )

    def update_usage(self, updates: List[Tuple[int, int, int, int, int, Optional[int]]]) -> None:
        # account_id, used_up, used_down, last_counter_up, last_counter_down, last_active
        with self.connect() as db:
            db.executemany(
                """
                UPDATE accounts
                SET used_up=?, used_down=?, last_counter_up=?, last_counter_down=?, last_active=COALESCE(?, last_active)
                WHERE id=?
                """,
                [(u, d, cu, cd, la, account_id) for account_id, u, d, cu, cd, la in updates],
            )

    def disable_many_quota(self, ids: Iterable[int]) -> None:
        ids = list(ids)
        if not ids:
            return
        with self.connect() as db:
            db.executemany(
                "UPDATE accounts SET enabled=0, disabled_reason='quota exceeded' WHERE id=?",
                [(i,) for i in ids],
            )

    def disable_expired(self) -> List[int]:
        t = now_ts()
        with self.connect() as db:
            rows = list(
                db.execute(
                    "SELECT id FROM accounts WHERE enabled=1 AND expires_at IS NOT NULL AND expires_at>0 AND expires_at<?",
                    (t,),
                )
            )
            ids = [int(r["id"]) for r in rows]
            if ids:
                db.executemany(
                    "UPDATE accounts SET enabled=0, disabled_reason='expired' WHERE id=?",
                    [(i,) for i in ids],
                )
            return ids


store = Store()


def password_hash(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 250_000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        alg, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    if alg != "pbkdf2_sha256":
        return False
    return hmac.compare_digest(password_hash(password, salt).split("$", 2)[2], digest)


def get_secret() -> bytes:
    secret = store.get_setting("secret")
    if not secret:
        secret = secrets.token_hex(32)
        store.set_setting("secret", secret)
    return secret.encode()


def make_session(username: str) -> str:
    exp = now_ts() + 12 * 3600
    payload = f"{username}|{exp}".encode()
    sig = hmac.new(get_secret(), payload, hashlib.sha256).digest()
    return f"{b64url(payload)}.{b64url(sig)}"


def parse_session(value: str) -> Optional[str]:
    try:
        p64, s64 = value.split(".", 1)
        payload = base64.urlsafe_b64decode(p64 + "=" * (-len(p64) % 4))
        sig = base64.urlsafe_b64decode(s64 + "=" * (-len(s64) % 4))
    except Exception:
        return None
    good = hmac.new(get_secret(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, good):
        return None
    try:
        username, exp = payload.decode().split("|", 1)
        if int(exp) < now_ts():
            return None
        return username
    except Exception:
        return None


def build_xray_config() -> Dict[str, Any]:
    accounts = [a for a in store.list_accounts() if int(a["enabled"]) == 1]
    clients: Dict[str, List[Dict[str, Any]]] = {p: [] for p in PROTOCOLS}
    for a in accounts:
        proto = a["protocol"]
        if proto == "vmess":
            clients[proto].append({"id": a["credential"], "alterId": 0, "email": a["email"]})
        elif proto == "vless":
            clients[proto].append({"id": a["credential"], "email": a["email"], "level": 0})
        elif proto == "trojan":
            clients[proto].append({"password": a["credential"], "email": a["email"], "level": 0})

    inbounds: List[Dict[str, Any]] = [
        {
            "tag": "api",
            "listen": "127.0.0.1",
            "port": 10085,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        }
    ]
    inbounds.append(
        {
            "tag": "vmess-ws",
            "listen": "127.0.0.1",
            "port": INTERNAL_PORTS["vmess"],
            "protocol": "vmess",
            "settings": {"clients": clients["vmess"]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": PUBLIC_WS_PATHS["vmess"]}},
        }
    )
    inbounds.append(
        {
            "tag": "vless-ws",
            "listen": "127.0.0.1",
            "port": INTERNAL_PORTS["vless"],
            "protocol": "vless",
            "settings": {"clients": clients["vless"], "decryption": "none"},
            "streamSettings": {"network": "ws", "wsSettings": {"path": PUBLIC_WS_PATHS["vless"]}},
        }
    )
    inbounds.append(
        {
            "tag": "trojan-ws",
            "listen": "127.0.0.1",
            "port": INTERNAL_PORTS["trojan"],
            "protocol": "trojan",
            "settings": {"clients": clients["trojan"]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": PUBLIC_WS_PATHS["trojan"]}},
        }
    )

    return {
        "log": {"loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log"},
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
            ],
        },
    }


def write_xray_config() -> None:
    XRAY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = build_xray_config()
    tmp = XRAY_CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    shutil.move(str(tmp), str(XRAY_CONFIG_PATH))


def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:
        return 1, "", str(exc)


def restart_xray() -> Tuple[bool, str]:
    if shutil.which("systemctl"):
        code, out, err = run_cmd(["systemctl", "restart", "xray"], timeout=30)
        if code == 0:
            return True, "Xray restarted"
        return False, (err or out or "Failed to restart xray").strip()
    return False, "systemctl not found"


def reload_xray_config() -> Tuple[bool, str]:
    write_xray_config()
    return restart_xray()


def read_xray_stats() -> Dict[str, Dict[str, int]]:
    if not Path(XRAY_BIN).exists():
        return {}
    code, out, err = run_cmd([XRAY_BIN, "api", "statsquery", f"--server={XRAY_API_SERVER}", "-pattern", "user>>>"])
    if code != 0:
        return {}
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return {}
    stats: Dict[str, Dict[str, int]] = {}
    for item in raw.get("stat", []):
        name = item.get("name", "")
        value = int(item.get("value", 0) or 0)
        parts = name.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            email, direction = parts[1], parts[3]
            stats.setdefault(email, {"uplink": 0, "downlink": 0})[direction] = value
    return stats


def sync_traffic(enforce: bool = True) -> Dict[str, Any]:
    store.init_db()
    expired_ids = store.disable_expired() if enforce else []
    stats = read_xray_stats()
    updates = []
    disable_ids: List[int] = []
    for a in store.list_accounts():
        email = a["email"]
        current = stats.get(email, {"uplink": 0, "downlink": 0})
        curr_up = int(current.get("uplink", 0))
        curr_down = int(current.get("downlink", 0))
        last_up = int(a["last_counter_up"] or 0)
        last_down = int(a["last_counter_down"] or 0)
        delta_up = curr_up - last_up if curr_up >= last_up else curr_up
        delta_down = curr_down - last_down if curr_down >= last_down else curr_down
        used_up = int(a["used_up"] or 0) + max(0, delta_up)
        used_down = int(a["used_down"] or 0) + max(0, delta_down)
        last_active = now_ts() if (delta_up + delta_down) > 0 else None
        updates.append((int(a["id"]), used_up, used_down, curr_up, curr_down, last_active))
        quota = int(a["quota_bytes"] or 0)
        if enforce and int(a["enabled"]) == 1 and quota > 0 and used_up + used_down >= quota:
            disable_ids.append(int(a["id"]))
    if updates:
        store.update_usage(updates)
    if disable_ids:
        store.disable_many_quota(disable_ids)
    changed = bool(expired_ids or disable_ids)
    if changed:
        write_xray_config()
        restart_xray()
    return {"ok": True, "stats_found": bool(stats), "quota_disabled": disable_ids, "expired_disabled": expired_ids}


def account_links(a: sqlite3.Row, domain: str) -> Dict[str, str]:
    proto = a["protocol"]
    name = urllib.parse.quote(f"{a['username']}-{proto}")
    cred = urllib.parse.quote(a["credential"])
    path = urllib.parse.quote(PUBLIC_WS_PATHS[proto], safe="")
    tls_common = f"type=ws&security=tls&path={path}&host={domain}&sni={domain}"
    none_common = f"type=ws&security=none&path={path}&host={domain}"
    if proto == "vmess":
        tls_obj = {
            "v": "2",
            "ps": f"{a['username']}-{proto}-443",
            "add": domain,
            "port": "443",
            "id": a["credential"],
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": PUBLIC_WS_PATHS[proto],
            "tls": "tls",
            "sni": domain,
        }
        plain_obj = dict(tls_obj)
        plain_obj.update({"ps": f"{a['username']}-{proto}-80", "port": "80", "tls": ""})
        return {
            "TLS 443": "vmess://" + vmess_b64(json.dumps(tls_obj, separators=(",", ":"))),
            "WS 80": "vmess://" + vmess_b64(json.dumps(plain_obj, separators=(",", ":"))),
        }
    if proto == "vless":
        return {
            "TLS 443": f"vless://{cred}@{domain}:443?{tls_common}#{name}-443",
            "WS 80": f"vless://{cred}@{domain}:80?{none_common}#{name}-80",
        }
    return {
        "TLS 443": f"trojan://{cred}@{domain}:443?{tls_common}#{name}-443",
        "WS 80": f"trojan://{cred}@{domain}:80?{none_common}#{name}-80",
    }



def command_output(cmd: List[str], timeout: int = 2) -> str:
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        if p.returncode == 0:
            return (p.stdout or "").strip()
    except Exception:
        pass
    return ""


def detect_server_ip() -> str:
    saved = store.get_setting("public_ip", "") or ""
    if saved:
        return saved
    out = command_output(["hostname", "-I"])
    for part in out.split():
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", part) and not part.startswith("127."):
            return part
    return "Unknown"


def ram_info() -> Dict[str, Any]:
    mem_total = mem_avail = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            num = int(value.strip().split()[0]) * 1024
            if key == "MemTotal":
                mem_total = num
            elif key == "MemAvailable":
                mem_avail = num
    except Exception:
        pass
    used = max(0, mem_total - mem_avail) if mem_total else 0
    pct = int((used / mem_total) * 100) if mem_total else 0
    return {"total": mem_total, "used": used, "available": mem_avail, "pct": pct}


def uptime_text() -> str:
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        if days:
            return f"{days}d {hours}h {minutes}m"
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except Exception:
        return "Unknown"


def service_state(name: str) -> str:
    out = command_output(["systemctl", "is-active", name])
    return out or "unknown"


def jakarta_time_text() -> str:
    tz = dt.timezone(dt.timedelta(hours=7), "WIB")
    return dt.datetime.now(tz).strftime("%d %b %Y, %H:%M:%S WIB")


def host_info() -> Dict[str, Any]:
    ram = ram_info()
    return {
        "ip": detect_server_ip(),
        "domain": store.get_setting("domain", "example.com") or "example.com",
        "ram": ram,
        "wib": jakarta_time_text(),
        "uptime": uptime_text(),
        "xray": service_state("xray"),
        "nginx": service_state("nginx"),
        "panel": service_state("xraysimpelvip-panel"),
    }


def pct_bar(pct: int) -> str:
    pct = max(0, min(100, int(pct)))
    return f"<div class='meter'><span style='width:{pct}%'></span></div>"



CSS = r"""
:root{
  --bg:#eef3f1;--main:#f8faf9;--card:#ffffff;--soft:#f0fdf4;--soft2:#ecfdf5;
  --text:#10231b;--muted:#6b7f76;--line:#d9e8df;--line2:#c7ead4;
  --green:#16a34a;--green2:#22c55e;--green3:#059669;--dark:#0b2a1a;
  --danger:#dc2626;--dangerbg:#fff1f2;--warn:#b45309;--warnbg:#fffbeb;
  --shadow:0 12px 30px rgba(11,42,26,.07);--shadow2:0 18px 45px rgba(11,42,26,.10);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;font-size:14px}
a{color:inherit;text-decoration:none}h1,h2,h3,p{margin:0}small,.muted{color:var(--muted)}
.shell{display:flex;min-height:100vh}.sidebar{width:252px;position:sticky;top:0;align-self:flex-start;min-height:100vh;background:linear-gradient(180deg,#063c22 0%,#0b5a31 100%);color:#eafff1;padding:16px 13px;box-shadow:10px 0 32px rgba(11,42,26,.12);z-index:8}.brand{display:flex;align-items:center;gap:10px;padding:8px 8px 16px;border-bottom:1px solid rgba(255,255,255,.13)}.logo{width:36px;height:36px;border-radius:11px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.22);display:grid;place-items:center;font-weight:950;font-size:17px}.brand h1{font-size:1rem;letter-spacing:-.02em}.brand small{font-size:.74rem;color:#bff7d0}.navTitle{font-size:.68rem;text-transform:uppercase;letter-spacing:.09em;color:#aff4c6;margin:16px 10px 8px}.nav{display:grid;gap:6px}.nav a{display:flex;align-items:center;gap:9px;min-height:38px;padding:9px 10px;border-radius:13px;color:#f0fff5;font-weight:800;font-size:.84rem;border:1px solid transparent}.nav a:hover,.nav a.active{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.13)}.ico{width:21px;height:21px;border-radius:8px;background:rgba(255,255,255,.13);display:grid;place-items:center;font-size:.78rem;flex:0 0 auto}.sideFoot{margin:16px 8px 0;padding-top:14px;border-top:1px solid rgba(255,255,255,.13);font-size:.75rem;color:#c6f6d7;line-height:1.5}.main{flex:1;min-width:0;padding:18px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}.pageTitle h2{font-size:1.23rem;letter-spacing:-.03em}.pageTitle small{display:block;margin-top:2px}.logoutMini{display:flex;gap:8px;align-items:center}.mobileBrand{display:none}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}.span2{grid-column:span 2}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span12{grid-column:1/-1}.card{background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);overflow:hidden}.pad{padding:15px}.hero{background:linear-gradient(135deg,#fff 0%,#f1fff6 65%,#dcfce7 100%);box-shadow:var(--shadow2)}.sectionTitle{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:12px}.sectionTitle h2{font-size:1rem;letter-spacing:-.02em}.hint{color:var(--muted);line-height:1.45;font-size:.82rem}.stat{position:relative;padding:15px;border-radius:18px;background:#fff;border:1px solid var(--line)}.statLabel{font-size:.79rem;color:var(--muted);font-weight:750}.statVal{font-size:1.65rem;font-weight:950;color:var(--green3);letter-spacing:-.06em;margin-top:6px}.statIcon{position:absolute;right:13px;top:13px;width:28px;height:28px;border-radius:11px;background:var(--soft);display:grid;place-items:center;font-size:1rem}.hostgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.hostitem{background:#fff;border:1px solid var(--line);border-radius:15px;padding:11px;min-width:0}.hostitem b{display:block;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:.92rem}.ports{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.portrow{display:flex;justify-content:space-between;gap:8px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:14px;padding:10px 11px}.portrow code{background:#edfdf3;color:#14532d;border:1px solid #bbf7d0;border-radius:999px;padding:4px 8px;font-weight:950;font-size:.78rem}.svcStatus{display:grid;gap:8px}.svcRow{display:flex;align-items:center;justify-content:space-between;gap:8px;border:1px solid var(--line);border-radius:14px;padding:9px 10px;background:#fff}
.btn{appearance:none;border:0;border-radius:12px;padding:8px 11px;min-height:36px;background:#f7faf8;color:var(--text);font-size:.81rem;font-weight:850;display:inline-flex;align-items:center;justify-content:center;gap:6px;cursor:pointer;touch-action:manipulation;box-shadow:inset 0 0 0 1px rgba(15,23,42,.06)}.btn.primary{background:linear-gradient(135deg,var(--green),var(--green2));color:#fff;box-shadow:0 8px 17px rgba(22,163,74,.18)}.btn.danger{background:var(--dangerbg);color:#991b1b}.btn.ok{background:#dcfce7;color:#166534}.btn.warn{background:var(--warnbg);color:#92400e}.btn:active{transform:scale(.98)}.btn[disabled]{opacity:.7}.row{display:flex;gap:7px;flex-wrap:wrap;align-items:center}.right{margin-left:auto}.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:5px 8px;font-size:.72rem;font-weight:950;background:#f1f5f9;color:#334155}.pill.ok{background:#dcfce7;color:#166534}.pill.off{background:#fee2e2;color:#991b1b}.pill.warn{background:#fef3c7;color:#92400e}.pill.dot:before{content:"";width:7px;height:7px;border-radius:99px;background:currentColor}.meter,.bar{height:8px;border-radius:99px;background:#e5ece8;overflow:hidden;margin-top:8px}.meter span,.bar span{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--green),var(--green2))}.divider{height:1px;background:var(--line);margin:12px 0}
input,select,textarea{width:100%;border:1px solid var(--line2);background:#fff;color:var(--text);border-radius:13px;padding:11px 12px;font-size:16px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--green2);box-shadow:0 0 0 4px rgba(34,197,94,.13)}label{display:block;margin:10px 0 5px;color:#166534;font-size:.78rem;font-weight:850}.formCard{background:#fff;border:1px solid var(--line);border-radius:16px;padding:13px}.formCard h3{font-size:.96rem;display:flex;align-items:center;gap:8px}.miniInfo{background:#f8fffb;border:1px dashed #bbf7d0;border-radius:14px;padding:10px;margin-top:10px;line-height:1.55;color:var(--muted);font-size:.8rem}.flash{margin-bottom:12px;padding:11px 13px;border-radius:14px;border:1px solid #86efac;background:#dcfce7;color:#14532d;font-weight:850}.flash.err{background:#fee2e2;border-color:#fecaca;color:#991b1b}
.tableWrap{overflow:auto;border:1px solid var(--line);border-radius:16px;background:#fff}.userTable{width:100%;border-collapse:collapse;min-width:680px}.userTable th,.userTable td{padding:10px 11px;border-bottom:1px solid var(--line);text-align:left;font-size:.82rem;vertical-align:top}.userTable th{background:#f0fdf4;color:#14532d;font-size:.76rem;text-transform:uppercase;letter-spacing:.05em}.userTable tr:last-child td{border-bottom:0}.userName{font-weight:950;color:#0f2b1b}.svcMenu{border:1px solid var(--line);background:#fafffc;border-radius:14px;overflow:hidden;min-width:220px}.svcMenu summary{list-style:none;cursor:pointer;padding:9px 10px;color:#14532d;font-weight:900}.svcMenu summary::-webkit-details-marker{display:none}.svcMenu summary:after{content:"Open";float:right;color:var(--muted);font-size:.72rem}.svcMenu[open] summary:after{content:"Close"}.svcBody{padding:0 10px 10px}.copybox{background:#0b1f16;color:#d7ffe3;border:1px solid rgba(34,197,94,.35);border-radius:14px;padding:11px;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.76rem;line-height:1.55}.copyrow{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;margin-top:8px}.terminal{background:#07150e;color:#d8ffe4;border:1px solid rgba(34,197,94,.35);border-radius:17px;padding:13px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.78rem;line-height:1.65;white-space:pre-wrap;word-break:break-word;box-shadow:inset 0 0 0 1px rgba(255,255,255,.03)}.loginShell{min-height:100vh;display:grid;place-items:center;padding:16px;background:radial-gradient(circle at top,#dcfce7 0,#f8faf9 46%,#eef3f1 100%)}.login{width:min(430px,100%)}.login .brand{border:0;padding:0 0 15px;color:var(--text)}.login .logo{background:linear-gradient(135deg,var(--green),var(--green2));color:#fff}.footer{margin:16px 0 5px;text-align:center;color:var(--muted);font-size:.75rem}.modalBack{position:fixed;inset:0;z-index:50;background:rgba(15,23,42,.46);display:grid;place-items:center;padding:16px}.modal{width:min(520px,100%);background:#fff;border:1px solid var(--line);border-radius:20px;padding:16px;box-shadow:0 22px 70px rgba(15,23,42,.25)}.modal textarea{height:150px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.copyhint{font-size:.82rem;color:var(--muted);margin:8px 0 12px;line-height:1.5}
@media(max-width:960px){.shell{display:block}.sidebar{position:sticky;top:0;width:auto;min-height:0;padding:10px;box-shadow:0 8px 26px rgba(11,42,26,.12)}.brand{padding:3px 4px 9px}.sideFoot{display:none}.navTitle{display:none}.nav{display:flex;gap:7px;overflow:auto;scrollbar-width:none;padding-top:9px}.nav::-webkit-scrollbar{display:none}.nav a{white-space:nowrap;min-height:34px;padding:8px 10px}.main{padding:12px}.topbar{margin-bottom:10px}.grid{display:block}.card,.stat{margin-bottom:11px}.span2,.span3,.span4,.span5,.span6,.span7,.span8,.span12{grid-column:auto}.hostgrid,.ports{grid-template-columns:1fr 1fr}.pageTitle h2{font-size:1.12rem}.mobileBrand{display:block}.topbar .logoutMini small{display:none}.userTable{min-width:0}.tableWrap{border:0;background:transparent}.userTable,.userTable thead,.userTable tbody,.userTable th,.userTable td,.userTable tr{display:block}.userTable thead{display:none}.userTable tr{background:#fff;border:1px solid var(--line);border-radius:16px;margin-bottom:10px;box-shadow:var(--shadow);overflow:hidden}.userTable td{border-bottom:1px solid var(--line);padding:9px 10px}.userTable td:before{content:attr(data-label);display:block;color:#166534;font-size:.7rem;font-weight:950;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}.svcMenu{min-width:0}.copyrow{grid-template-columns:1fr}.copyrow .btn{width:100%}.row form,.row .btn{flex:1}.row form .btn{width:100%}}
@media(max-width:430px){body{font-size:13px}.main{padding:10px}.sidebar{padding:9px}.logo{width:32px;height:32px}.brand h1{font-size:.95rem}.nav a{font-size:.78rem;padding:7px 9px}.ico{width:19px;height:19px;border-radius:7px}.hostgrid,.ports{grid-template-columns:1fr}.pad{padding:13px}.statVal{font-size:1.48rem}.sectionTitle{display:block}.sectionTitle .row,.sectionTitle form{margin-top:8px}.portrow{padding:9px 10px}.terminal,.copybox{font-size:.72rem}.btn{min-height:37px}}
"""


def layout(title: str, body: str, username: Optional[str] = None, flash: str = "", error: bool = False) -> str:
    safe_title = html.escape(title)
    flash_html = f"<div class='flash {'err' if error else ''}'>{html.escape(flash)}</div>" if flash else ""
    if not username:
        return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'><title>{safe_title}</title><style>{CSS}</style></head><body>{flash_html}{body}<script>{COPY_JS}</script></body></html>"""
    side = f"""
    <aside class='sidebar'>
      <div class='brand'><div class='logo'>X</div><div><h1>VPN Panel</h1><small>xray-optimized</small></div></div>
      <div class='navTitle'>Dashboard</div>
      <nav class='nav'>
        <a class='active' href='/#dashboard'><span class='ico'>▣</span>Dashboard</a>
        <a href='/#status'><span class='ico'>⚙</span>Status Service</a>
        <a href='/#ports'><span class='ico'>↔</span>Info Port</a>
      </nav>
      <div class='navTitle'>Akun Xray</div>
      <nav class='nav'>
        <a href='/#vmess'><span class='ico'>⚡</span>Vmess</a>
        <a href='/#vless'><span class='ico'>V</span>Vless</a>
        <a href='/#trojan'><span class='ico'>T</span>Trojan</a>
      </nav>
      <div class='navTitle'>Manajemen</div>
      <nav class='nav'>
        <a href='/#users'><span class='ico'>☰</span>Daftar User</a>
        <a href='/#server'><span class='ico'>◎</span>Server</a>
      </nav>
      <div class='sideFoot'>Panel: <b>1313</b><br>WS: <b>80 / 443</b><br>Login: <b>{html.escape(username)}</b></div>
    </aside>
    """
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'><title>{safe_title}</title><style>{CSS}</style></head><body><div class='shell'>{side}<main class='main'><div class='topbar'><div class='pageTitle'><h2>{safe_title}</h2><small>Simple Xray panel · Cloudflare WebSocket</small></div><div class='logoutMini'><small>{html.escape(username)}</small><form method='post' action='/logout'><button class='btn' type='submit'>Logout</button></form></div></div>{flash_html}{body}<div class='footer'>Xray Simpel VIP · VMess / VLESS / Trojan · Panel 1313</div></main></div><script>{COPY_JS}</script></body></html>"""


COPY_JS = r"""
function xsvpToast(btn, text, ok){
  if(!btn) return;
  const old = btn.dataset.oldText || btn.innerText;
  btn.dataset.oldText = old;
  btn.innerText = text;
  btn.disabled = true;
  setTimeout(() => { btn.innerText = old; btn.disabled = false; }, ok ? 1200 : 2200);
}
function fallbackCopy(text){
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly','');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  ta.style.top = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, ta.value.length);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch(e) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}
function showManualCopy(text){
  const old = document.getElementById('copyModalBack');
  if(old) old.remove();
  const back = document.createElement('div');
  back.className = 'modalBack';
  back.id = 'copyModalBack';
  const modal = document.createElement('div');
  modal.className = 'modal';
  const title = document.createElement('h2');
  title.textContent = 'Copy manually';
  const hint = document.createElement('div');
  hint.className = 'copyhint';
  hint.textContent = 'Android blocked automatic clipboard. Long-press the box, select all, then copy.';
  const ta = document.createElement('textarea');
  ta.value = text;
  const row = document.createElement('div');
  row.className = 'row';
  row.style.marginTop = '10px';
  const close = document.createElement('button');
  close.className = 'btn primary';
  close.type = 'button';
  close.textContent = 'Close';
  close.onclick = function(){ back.remove(); };
  row.appendChild(close);
  modal.appendChild(title); modal.appendChild(hint); modal.appendChild(ta); modal.appendChild(row);
  back.appendChild(modal); document.body.appendChild(back);
  ta.focus(); ta.select(); ta.setSelectionRange(0, ta.value.length);
}
async function copyRaw(text, btn){
  let ok = false;
  try {
    if(window.navigator && navigator.clipboard && window.isSecureContext){
      await navigator.clipboard.writeText(text);
      ok = true;
    }
  } catch(e) { ok = false; }
  if(!ok) ok = fallbackCopy(text);
  if(ok) xsvpToast(btn, 'Copied', true); else { xsvpToast(btn, 'Manual copy', false); showManualCopy(text); }
}
function copyText(id){
  const el = document.getElementById(id);
  const btn = document.querySelector('[data-copy="'+id+'"]') || event.target;
  if(!el) return;
  const text = el.getAttribute('data-raw') || el.innerText || el.textContent || '';
  copyRaw(text.trim(), btn);
}
function tickWib(){
  const el = document.getElementById('wibClock');
  if(!el) return;
  try{
    const now = new Date();
    el.textContent = now.toLocaleString('en-GB',{timeZone:'Asia/Jakarta',day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) + ' WIB';
  }catch(e){}
}
setInterval(tickWib, 1000); tickWib();
"""


def status_pill(a: sqlite3.Row) -> str:
    if int(a["enabled"]) != 1:
        reason = a["disabled_reason"] or "disabled"
        return f"<span class='pill off dot'>{html.escape(reason)}</span>"
    if a["expires_at"] and int(a["expires_at"]) < now_ts():
        return "<span class='pill warn dot'>expired</span>"
    if a["last_active"] and now_ts() - int(a["last_active"]) <= ACTIVE_WINDOW_SECONDS:
        return "<span class='pill ok dot'>online</span>"
    return "<span class='pill ok dot'>active</span>"


def quota_html(a: sqlite3.Row) -> str:
    used = int(a["used_up"] or 0) + int(a["used_down"] or 0)
    quota = int(a["quota_bytes"] or 0)
    if quota <= 0:
        return f"<small>Quota</small><b style='display:block;margin-top:4px'>{human_bytes(used)} / Unlimited</b><div class='bar'><span style='width:12%'></span></div>"
    pct = min(100, int((used / quota) * 100)) if quota else 0
    return f"<small>Quota</small><b style='display:block;margin-top:4px'>{human_bytes(used)} / {human_bytes(quota)}</b><div class='bar'><span style='width:{pct}%'></span></div><small>{pct}% used</small>"


def protocol_form(proto: str, title: str, icon: str, info: str) -> str:
    sample = f"{proto}01"
    return f"""
    <div class='formCard' id='{html.escape(proto)}'>
      <h3><span class='ico' style='background:#dcfce7;color:#166534'>{html.escape(icon)}</span>{html.escape(title)}</h3>
      <form method='post' action='/add'>
        <input type='hidden' name='protocol' value='{html.escape(proto)}'>
        <label>Username</label><input name='username' placeholder='{html.escape(sample)}' required minlength='3' maxlength='32'>
        <label>Masa Aktif (Hari)</label><input name='expire_days' type='number' min='0' step='1' value='30'>
        <label>Quota GB</label><input name='quota_gb' type='number' min='0' step='0.1' value='10'>
        <div style='height:10px'></div><button class='btn primary' type='submit' style='width:100%'>Buat {html.escape(title.replace('Buat Akun ', ''))} Account</button>
      </form>
      <div class='miniInfo'>{info}</div>
    </div>
    """


def service_rows(info: Dict[str, Any]) -> str:
    items = [("Xray", info["xray"]), ("Nginx", info["nginx"]), ("Panel", info["panel"])]
    out = []
    for name, state in items:
        cls = "ok" if state == "active" else "off"
        out.append(f"<div class='svcRow'><b>{html.escape(name)}</b><span class='pill {cls} dot'>{html.escape(state)}</span></div>")
    return "".join(out)


def dashboard_page(username: str, flash: str = "", error: bool = False) -> str:
    sync_traffic(enforce=True)
    accounts = store.list_accounts()
    info = host_info()
    domain = info["domain"]
    ram = info["ram"]
    enabled = sum(1 for a in accounts if int(a["enabled"]) == 1)
    active = sum(1 for a in accounts if a["last_active"] and now_ts() - int(a["last_active"]) <= ACTIVE_WINDOW_SECONDS)
    used_total = sum(int(a["used_up"] or 0) + int(a["used_down"] or 0) for a in accounts)
    quota_total = sum(int(a["quota_bytes"] or 0) for a in accounts)
    rows = []
    for a in accounts:
        links = account_links(a, domain)
        copy_buttons = []
        for idx, (label, link) in enumerate(links.items()):
            cid = f"u{int(a['id'])}_{idx}"
            copy_buttons.append(f"<div class='copyrow'><div class='copybox' id='{cid}' data-raw='{html.escape(link, quote=True)}'>{html.escape(label)} link</div><button class='btn primary' type='button' data-copy='{cid}' onclick='copyText(\"{cid}\")'>Copy</button></div>")
        actions = f"""
        <div class='row'>
          <a class='btn ok' href='/account?id={int(a['id'])}'>Detail</a>
          <form method='post' action='/toggle?id={int(a['id'])}'><button class='btn {'warn' if int(a['enabled']) else 'ok'}' type='submit'>{'Disable' if int(a['enabled']) else 'Enable'}</button></form>
          <form method='post' action='/delete?id={int(a['id'])}' onsubmit='return confirm("Delete this account?")'><button class='btn danger' type='submit'>Delete</button></form>
        </div>
        """
        rows.append(f"""
        <tr>
          <td data-label='Username'><div class='userName'>{html.escape(a['username'])}</div><small>{html.escape(a['email'])}</small></td>
          <td data-label='Tipe'><span class='pill ok'>{html.escape(a['protocol']).upper()}</span></td>
          <td data-label='Expired'>{fmt_datetime(a['expires_at']) if a['expires_at'] else 'Never'}</td>
          <td data-label='Status'>{status_pill(a)}<div style='margin-top:6px'>{quota_html(a)}</div></td>
          <td data-label='Aksi'><details class='svcMenu'><summary>Service menu</summary><div class='svcBody'>{''.join(copy_buttons)}<div class='divider'></div>{actions}</div></details></td>
        </tr>
        """)
    rows_html = "".join(rows) or "<tr><td colspan='5'>Belum ada akun. Buat akun Vmess, Vless, atau Trojan terlebih dahulu.</td></tr>"
    body = f"""
    <section id='dashboard' class='grid'>
      <div class='card hero pad span8'>
        <div class='sectionTitle'><div><h2>Dashboard</h2><div class='hint'>Panel simple seperti autoscript, tetapi khusus Xray VMess, VLESS, dan Trojan WebSocket.</div></div><span class='pill ok dot'>Online</span></div>
        <div class='hostgrid'>
          <div class='hostitem'><small>IP VPS</small><b>{html.escape(info['ip'])}</b></div>
          <div class='hostitem'><small>Domain Cloudflare</small><b>{html.escape(domain)}</b></div>
          <div class='hostitem'><small>Jakarta WIB</small><b id='wibClock'>{html.escape(info['wib'])}</b></div>
          <div class='hostitem'><small>Uptime</small><b>{html.escape(info['uptime'])}</b></div>
        </div>
      </div>
      <div class='card pad span4' id='server'>
        <div class='sectionTitle'><div><h2>RAM</h2><div class='hint'>Pemakaian memori VPS.</div></div></div>
        <b>{human_bytes(ram['used'])} / {human_bytes(ram['total'])}</b>{pct_bar(ram['pct'])}<small>{ram['pct']}% used</small>
      </div>
      <div class='stat span3'><div class='statIcon'>⚡</div><div class='statLabel'>User Xray</div><div class='statVal'>{len(accounts)}</div></div>
      <div class='stat span3'><div class='statIcon'>✓</div><div class='statLabel'>Enabled</div><div class='statVal'>{enabled}</div></div>
      <div class='stat span3'><div class='statIcon'>●</div><div class='statLabel'>Active Now</div><div class='statVal'>{active}</div></div>
      <div class='stat span3'><div class='statIcon'>↕</div><div class='statLabel'>Traffic</div><div class='statVal' style='font-size:1.05rem;margin-top:11px'>{human_bytes(used_total)}</div><small>Quota pool: {human_bytes(quota_total) if quota_total else 'Unlimited'}</small></div>
    </section>

    <section class='grid'>
      <div class='card pad span7' id='ports'>
        <div class='sectionTitle'><div><h2>Info Port & Protokol</h2><div class='hint'>Port yang aktif untuk client Android seperti v2rayNG / NekoBox.</div></div></div>
        <div class='ports'>
          <div class='portrow'><span>Panel Simpel</span><code>1313</code></div>
          <div class='portrow'><span>Vmess WS</span><code>80, 443</code></div>
          <div class='portrow'><span>Vless WS</span><code>80, 443</code></div>
          <div class='portrow'><span>Trojan WS</span><code>80, 443</code></div>
          <div class='portrow'><span>Path Vmess</span><code>/vmess</code></div>
          <div class='portrow'><span>Path Vless</span><code>/vless</code></div>
          <div class='portrow'><span>Path Trojan</span><code>/trojan</code></div>
          <div class='portrow'><span>Cloudflare TLS</span><code>443</code></div>
        </div>
      </div>
      <div class='card pad span5' id='status'>
        <div class='sectionTitle'><div><h2>⚙ Status Service</h2><div class='hint'>Service utama server.</div></div><form method='post' action='/sync'><button class='btn primary' type='submit'>Refresh</button></form></div>
        <div class='svcStatus'>{service_rows(info)}</div>
      </div>
    </section>

    <section class='grid'>
      <div class='card pad span4'>{protocol_form('vmess','Buat Akun Vmess','⚡','Network: WebSocket<br>Port TLS: 443<br>Port HTTP: 80<br>Path WS: /vmess<br>AlterID: 0')}</div>
      <div class='card pad span4'>{protocol_form('vless','Buat Akun Vless','V','Network: WebSocket<br>Port TLS: 443<br>Port HTTP: 80<br>Path WS: /vless<br>Encryption: none')}</div>
      <div class='card pad span4'>{protocol_form('trojan','Buat Akun Trojan','T','Network: WebSocket<br>Port TLS: 443<br>Port HTTP: 80<br>Path WS: /trojan<br>Password: auto generated')}</div>
    </section>

    <section class='card pad' id='users'>
      <div class='sectionTitle'><div><h2>Daftar User</h2><div class='hint'>Lihat status, quota, copy config, enable/disable, dan hapus akun.</div></div><form method='post' action='/sync'><button class='btn' type='submit'>Refresh</button></form></div>
      <div class='tableWrap'><table class='userTable'><thead><tr><th>Username</th><th>Tipe</th><th>Expired</th><th>Status</th><th>Aksi</th></tr></thead><tbody>{rows_html}</tbody></table></div>
    </section>
    """
    return layout("Dashboard", body, username=username, flash=flash, error=error)


def account_page(a: sqlite3.Row, username: str, flash: str = "", error: bool = False) -> str:
    domain = store.get_setting("domain", "example.com") or "example.com"
    info = host_info()
    links = account_links(a, domain)
    proto = str(a["protocol"]).upper()
    path = PUBLIC_WS_PATHS[a["protocol"]]
    quota = human_bytes(a["quota_bytes"]) if int(a["quota_bytes"] or 0) else "Unlimited"
    exp = fmt_datetime(a["expires_at"]) if a["expires_at"] else "Never"
    output_lines = [
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f" {proto} Account",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"Remarks      : {a['username']}",
        f"Domain       : {domain}",
        f"IP VPS       : {info['ip']}",
        "Port TLS     : 443",
        "Port none TLS: 80",
        f"Network      : ws",
        f"Path         : {path}",
        f"Quota        : {quota}",
        f"Expired On   : {exp}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]
    for label, link in links.items():
        output_lines.append(f"Link {label}: {link}")
        output_lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    output = "\n".join(output_lines)
    link_blocks = []
    for idx, (label, link) in enumerate(links.items()):
        cid = f"link{idx}"
        link_blocks.append(f"<div class='copyrow'><div class='copybox' id='{cid}' data-raw='{html.escape(link, quote=True)}'>{html.escape(link)}</div><button class='btn primary' type='button' data-copy='{cid}' onclick='copyText(\"{cid}\")'>Copy {html.escape(label)}</button></div>")
    body = f"""
    <div class='grid'>
      <div class='card hero pad span4'>
        <div class='sectionTitle'><div><h2>{html.escape(a['username'])}</h2><div class='hint'>Service menu akun {html.escape(proto)}.</div></div>{status_pill(a)}</div>
        <div class='hostgrid' style='grid-template-columns:1fr'>
          <div class='hostitem'><small>Protocol</small><b>{html.escape(proto)}</b></div>
          <div class='hostitem'><small>Host / SNI</small><b>{html.escape(domain)}</b></div>
          <div class='hostitem'><small>IP VPS</small><b>{html.escape(info['ip'])}</b></div>
          <div class='hostitem'><small>Ports</small><b>443 TLS WS · 80 WS</b></div>
          <div class='hostitem'><small>Expired</small><b>{html.escape(exp)}</b></div>
        </div>
        <div class='divider'></div>{quota_html(a)}
        <div class='row' style='margin-top:14px'>
          <a class='btn' href='/#users'>Back</a>
          <form method='post' action='/reset?id={int(a['id'])}'><button class='btn warn' type='submit'>Reset Usage</button></form>
          <form method='post' action='/toggle?id={int(a['id'])}'><button class='btn {'warn' if int(a['enabled']) else 'ok'}' type='submit'>{'Disable' if int(a['enabled']) else 'Enable'}</button></form>
        </div>
      </div>
      <div class='card pad span8'>
        <div class='sectionTitle'><div><h2>Output Account</h2><div class='hint'>Tampilan hasil dibuat seperti output autoscript. Tombol copy aman untuk Android Chrome.</div></div><button class='btn primary' type='button' data-copy='outall' onclick='copyText("outall")'>Copy All</button></div>
        <div class='terminal' id='outall' data-raw='{html.escape(output, quote=True)}'>{html.escape(output)}</div>
        <div class='divider'></div>
        <h2>Client Links</h2>
        <div style='height:8px'></div>
        {''.join(link_blocks)}
      </div>
    </div>
    """
    return layout(f"Account {a['username']}", body, username=username, flash=flash, error=error)


def login_page(flash: str = "", error: bool = False) -> str:
    body = """
    <div class='loginShell'>
      <div class='login card pad'>
        <div class='brand'><div class='logo'>X</div><div><h1>VPN Panel</h1><small>xray-optimized · port 1313</small></div></div>
        <form method='post' action='/login'>
          <label>Username</label><input name='username' autocomplete='username' required>
          <label>Password</label><input name='password' type='password' autocomplete='current-password' required>
          <div style='height:13px'></div><button class='btn primary' type='submit' style='width:100%'>Login Panel</button>
        </form>
      </div>
    </div>
    """
    return layout("Login", body, flash=flash, error=error)


class Handler(BaseHTTPRequestHandler):
    server_version = "XraySimpelVIP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def current_user(self) -> Optional[str]:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get("xsvp_session")
        if not morsel:
            return None
        return parse_session(morsel.value)

    def send_html(self, content: str, status: int = 200, cookie: Optional[str] = None) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookie: Optional[str] = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def read_form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in parsed.items()}

    def require_user(self) -> Optional[str]:
        user = self.current_user()
        if not user:
            self.redirect("/login")
            return None
        return user

    def query_id(self) -> int:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return int(q.get("id", ["0"])[0])

    def do_GET(self) -> None:
        store.init_db()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/login":
            if self.current_user():
                self.redirect("/")
            else:
                self.send_html(login_page())
            return
        user = self.require_user()
        if not user:
            return
        if path == "/":
            self.send_html(dashboard_page(user))
            return
        if path == "/account":
            try:
                a = store.get_account(self.query_id())
            except Exception:
                a = None
            if not a:
                self.send_html(dashboard_page(user, "Account not found", True))
            else:
                sync_traffic(enforce=True)
                a = store.get_account(int(a["id"])) or a
                self.send_html(account_page(a, user))
            return
        self.send_html(layout("Not found", "<div class='card pad'><h2>Not found</h2><a class='btn' href='/'>Back</a></div>", user), 404)

    def do_POST(self) -> None:
        store.init_db()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/login":
            form = self.read_form()
            admin_user = store.get_setting("admin_user", "admin") or "admin"
            admin_hash = store.get_setting("admin_hash", "") or ""
            if form.get("username") == admin_user and verify_password(form.get("password", ""), admin_hash):
                token = make_session(admin_user)
                self.redirect("/", f"xsvp_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200")
            else:
                self.send_html(login_page("Invalid username or password", True), 401)
            return
        if path == "/logout":
            self.redirect("/login", "xsvp_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            return
        user = self.require_user()
        if not user:
            return
        try:
            if path == "/add":
                form = self.read_form()
                quota = parse_quota_gb(form.get("quota_gb", "0"))
                days_raw = form.get("expire_days", "0").strip() or "0"
                days = int(days_raw)
                if days < 0:
                    raise ValueError("Expiry days cannot be negative")
                expires = now_ts() + days * 86400 if days else None
                a = store.add_account(form.get("username", ""), form.get("protocol", ""), quota, expires)
                ok, msg = reload_xray_config()
                if not ok:
                    self.send_html(dashboard_page(user, f"Account created but Xray restart failed: {msg}", True))
                else:
                    self.redirect(f"/account?id={int(a['id'])}")
                return
            if path == "/delete":
                account_id = self.query_id()
                store.delete_account(account_id)
                ok, msg = reload_xray_config()
                self.send_html(dashboard_page(user, "Account deleted" if ok else f"Deleted, but restart failed: {msg}", not ok))
                return
            if path == "/toggle":
                account_id = self.query_id()
                a = store.get_account(account_id)
                if not a:
                    raise ValueError("Account not found")
                store.set_enabled(account_id, not bool(int(a["enabled"])), "manual disable")
                ok, msg = reload_xray_config()
                self.send_html(dashboard_page(user, "Account updated" if ok else f"Updated, but restart failed: {msg}", not ok))
                return
            if path == "/reset":
                account_id = self.query_id()
                store.reset_usage(account_id)
                a = store.get_account(account_id)
                if a and int(a["enabled"]) == 0 and a["disabled_reason"] in ("", "quota exceeded"):
                    store.set_enabled(account_id, True, "")
                ok, msg = reload_xray_config()
                self.send_html(dashboard_page(user, "Usage reset" if ok else f"Reset, but restart failed: {msg}", not ok))
                return
            if path == "/sync":
                result = sync_traffic(enforce=True)
                self.send_html(dashboard_page(user, f"Traffic synced. Quota disabled: {len(result['quota_disabled'])}; expired disabled: {len(result['expired_disabled'])}"))
                return
        except Exception as exc:
            self.send_html(dashboard_page(user, str(exc), True))
            return
        self.send_html(layout("Not found", "<div class='card pad'><h2>Not found</h2><a class='btn' href='/'>Back</a></div>", user), 404)


def init_app(domain: str, admin_user: str, admin_pass: str) -> None:
    store.init_db()
    store.set_setting("domain", domain.strip())
    store.set_setting("admin_user", admin_user.strip() or "admin")
    store.set_setting("admin_hash", password_hash(admin_pass))
    get_secret()
    write_xray_config()


def run_web(host: str, port: int) -> None:
    store.init_db()
    addr = (host, port)
    httpd = ThreadingHTTPServer(addr, Handler)
    print(f"{APP_NAME} listening on http://{host}:{port}")
    httpd.serve_forever()


def run_watcher(interval: int = 60) -> None:
    store.init_db()
    while True:
        try:
            result = sync_traffic(enforce=True)
            print(json.dumps({"ts": now_ts(), **result}), flush=True)
        except Exception as exc:
            print(f"watcher error: {exc}", file=sys.stderr, flush=True)
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("--domain", required=True)
    p_init.add_argument("--admin-user", default="admin")
    p_init.add_argument("--admin-pass", required=True)
    p_web = sub.add_parser("web")
    p_web.add_argument("--host", default="0.0.0.0")
    p_web.add_argument("--port", type=int, default=1313)
    p_watch = sub.add_parser("watcher")
    p_watch.add_argument("--interval", type=int, default=60)
    sub.add_parser("sync")
    sub.add_parser("regen")
    args = parser.parse_args()
    if args.cmd == "init":
        init_app(args.domain, args.admin_user, args.admin_pass)
        print("Initialized")
    elif args.cmd == "web":
        run_web(args.host, args.port)
    elif args.cmd == "watcher":
        run_watcher(args.interval)
    elif args.cmd == "sync":
        print(json.dumps(sync_traffic(enforce=True), indent=2))
    elif args.cmd == "regen":
        write_xray_config()
        ok, msg = restart_xray()
        print(msg)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
