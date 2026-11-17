"""SQLite 持久化层。用标准库 sqlite3，不引入 ORM。"""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    url             TEXT    NOT NULL,
    user_agent      TEXT    NOT NULL DEFAULT '',
    interval_min    INTEGER NOT NULL DEFAULT 360,
    enabled         INTEGER NOT NULL DEFAULT 1,
    strip_pseudo    INTEGER NOT NULL DEFAULT 1,
    content         TEXT,
    content_size    INTEGER DEFAULT 0,
    node_count      INTEGER DEFAULT 0,
    userinfo        TEXT,
    etag            TEXT,
    last_fetch_at   TEXT,
    last_status     TEXT    NOT NULL DEFAULT 'never',
    last_error      TEXT,
    last_ms         INTEGER,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS rulesets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    kind            TEXT    NOT NULL DEFAULT 'remote',
    url             TEXT,
    path            TEXT,
    inline_content  TEXT,
    behavior        TEXT    NOT NULL DEFAULT 'classical',
    format          TEXT    NOT NULL DEFAULT 'text',
    default_target  TEXT    NOT NULL DEFAULT 'Proxies',
    interval_min    INTEGER NOT NULL DEFAULT 1440,
    enabled         INTEGER NOT NULL DEFAULT 1,
    content         TEXT,
    content_size    INTEGER DEFAULT 0,
    rule_count      INTEGER DEFAULT 0,
    last_fetch_at   TEXT,
    last_status     TEXT    NOT NULL DEFAULT 'never',
    last_error      TEXT,
    last_ms         INTEGER,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profile (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    content    TEXT NOT NULL DEFAULT '',
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS front_backends (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    kind            TEXT    NOT NULL DEFAULT 'socks5',
    server          TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    username        TEXT,
    password        TEXT,
    udp             INTEGER NOT NULL DEFAULT 1,
    tls             INTEGER NOT NULL DEFAULT 0,
    sni             TEXT,
    skip_cert_verify INTEGER NOT NULL DEFAULT 0,
    scope           TEXT    NOT NULL DEFAULT 'lan',
    extra_yaml      TEXT,
    note            TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_check_at   TEXT,
    last_check_ok   INTEGER,
    last_check_ms   INTEGER,
    last_check_error TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS front_profiles (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    slug                  TEXT    NOT NULL UNIQUE,
    name                  TEXT    NOT NULL,
    enabled               INTEGER NOT NULL DEFAULT 1,
    role                  TEXT    NOT NULL DEFAULT 'relay',
    source_profile_id     INTEGER NOT NULL DEFAULT 1,
    backend_group_name    TEXT    NOT NULL DEFAULT 'PROXY',
    backend_group_type    TEXT    NOT NULL DEFAULT 'select',
    include_direct        INTEGER NOT NULL DEFAULT 1,
    group_defaults        TEXT    NOT NULL DEFAULT '',
    custom_rules          TEXT    NOT NULL DEFAULT '',
    base_mode             TEXT    NOT NULL DEFAULT 'auto',
    base_url              TEXT    NOT NULL DEFAULT '',
    base_template         TEXT    NOT NULL DEFAULT '',
    rule_provider_proxy   TEXT    NOT NULL DEFAULT 'DIRECT',
    api_port              INTEGER NOT NULL DEFAULT 9090,
    tproxy_port           INTEGER NOT NULL DEFAULT 7893,
    edge_host             TEXT    NOT NULL DEFAULT '',
    token                 TEXT    NOT NULL DEFAULT '',
    created_at            TEXT    NOT NULL,
    updated_at            TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS front_profile_backends (
    profile_id      INTEGER NOT NULL,
    backend_id      INTEGER NOT NULL,
    position        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (profile_id, backend_id)
);

CREATE INDEX IF NOT EXISTS idx_front_pb_profile ON front_profile_backends(profile_id);

CREATE TABLE IF NOT EXISTS front_renders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    trigger     TEXT    NOT NULL,
    sha         TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    content     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_front_renders_profile ON front_renders(profile_id, id DESC);

CREATE TABLE IF NOT EXISTS fetch_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    ref_id     INTEGER NOT NULL,
    ref_slug   TEXT,
    at         TEXT    NOT NULL,
    ok         INTEGER NOT NULL,
    status     TEXT,
    size       INTEGER,
    counts     INTEGER,
    duration_ms INTEGER,
    message    TEXT
);

CREATE INDEX IF NOT EXISTS idx_log_at ON fetch_log(at DESC);
"""

DEFAULT_SETTINGS = {
    "public_base_url": "",
    "default_ua": "clash-verge/v2.3.1",
    # 规则集来源多为网盘/CDN 直链，对 UA 敏感，clash 系 UA 常被 403
    "ruleset_ua": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "auto_refresh": "1",
    "strip_pseudo": "1",
    "fetch_interval_min": "360",
    "ruleset_interval_min": "1440",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def tx():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(sql: str, args: tuple = ()) -> list[sqlite3.Row]:
    conn = connect()
    try:
        return list(conn.execute(sql, args))
    finally:
        conn.close()


def query_one(sql: str, args: tuple = ()):
    conn = connect()
    try:
        return conn.execute(sql, args).fetchone()
    finally:
        conn.close()


def init_db() -> None:
    with tx() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO NOTHING",
                (k, v),
            )
        row = conn.execute("SELECT id FROM profile WHERE id = 1").fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO profile(id, content, updated_at) VALUES(1, '', ?)",
                (now_iso(),),
            )


def _migrate(conn: sqlite3.Connection) -> None:
    """轻量迁移：给老库补上新增的列。"""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(rulesets)")}
    if "path" not in cols:
        conn.execute("ALTER TABLE rulesets ADD COLUMN path TEXT")

    front_cols = {r["name"] for r in conn.execute("PRAGMA table_info(front_profiles)")}
    if front_cols:
        # 老库里的 front 默认 gateway，保持原有 fake-ip 模板行为
        for name, ddl in (
            ("custom_rules", "TEXT NOT NULL DEFAULT ''"),
            ("role", "TEXT NOT NULL DEFAULT 'gateway'"),
            ("api_port", "INTEGER NOT NULL DEFAULT 9090"),
            ("tproxy_port", "INTEGER NOT NULL DEFAULT 7893"),
            ("edge_host", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in front_cols:
                conn.execute(f"ALTER TABLE front_profiles ADD COLUMN {name} {ddl}")

    backend_cols = {r["name"] for r in conn.execute("PRAGMA table_info(front_backends)")}
    if backend_cols:
        for name, ddl in (
            ("scope", "TEXT NOT NULL DEFAULT 'lan'"),
            ("last_check_at", "TEXT"),
            ("last_check_ok", "INTEGER"),
            ("last_check_ms", "INTEGER"),
            ("last_check_error", "TEXT"),
        ):
            if name not in backend_cols:
                conn.execute(f"ALTER TABLE front_backends ADD COLUMN {name} {ddl}")


# ---------- settings ----------

def get_settings() -> dict[str, str]:
    return {r["key"]: r["value"] for r in query("SELECT key, value FROM settings")}


def set_setting(key: str, value: str) -> None:
    with tx() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


# ---------- profile ----------

def get_profile() -> str:
    row = query_one("SELECT content FROM profile WHERE id = 1")
    return (row["content"] if row else "") or ""


def save_profile(content: str) -> None:
    with tx() as conn:
        conn.execute(
            "UPDATE profile SET content = ?, updated_at = ? WHERE id = 1",
            (content, now_iso()),
        )


# ---------- fetch log ----------

def add_log(kind: str, ref_id: int, ref_slug: str, ok: bool, *,
            status: str = "", size: int = 0, counts: int = 0,
            duration_ms: int = 0, message: str = "") -> None:
    with tx() as conn:
        conn.execute(
            "INSERT INTO fetch_log(kind, ref_id, ref_slug, at, ok, status, size, counts, duration_ms, message)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (kind, ref_id, ref_slug, now_iso(), 1 if ok else 0, status,
             size, counts, duration_ms, message[:500]),
        )
        # 只保留最近 500 条
        conn.execute(
            "DELETE FROM fetch_log WHERE id NOT IN (SELECT id FROM fetch_log ORDER BY id DESC LIMIT 500)"
        )


def recent_logs(limit: int = 20) -> list[sqlite3.Row]:
    return query("SELECT * FROM fetch_log ORDER BY id DESC LIMIT ?", (limit,))


# ---------- front renders ----------

def add_front_render(profile_id: int, content: str, trigger: str) -> None:
    """保存渲染快照；内容没变化时跳过，只保留最近 50 份。"""
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    with tx() as conn:
        row = conn.execute(
            "SELECT sha FROM front_renders WHERE profile_id = ? ORDER BY id DESC LIMIT 1",
            (profile_id,),
        ).fetchone()
        if row is not None and row["sha"] == sha:
            return
        conn.execute(
            "INSERT INTO front_renders(profile_id, at, trigger, sha, size, content)"
            " VALUES(?,?,?,?,?,?)",
            (profile_id, now_iso(), trigger, sha, len(content.encode("utf-8")), content),
        )
        conn.execute(
            "DELETE FROM front_renders WHERE profile_id = ? AND id NOT IN"
            " (SELECT id FROM front_renders WHERE profile_id = ? ORDER BY id DESC LIMIT 50)",
            (profile_id, profile_id),
        )


def front_renders(profile_id: int, limit: int = 20) -> list[sqlite3.Row]:
    return query(
        "SELECT id, at, trigger, sha, size, content FROM front_renders"
        " WHERE profile_id = ? ORDER BY id DESC LIMIT ?",
        (profile_id, limit),
    )


def set_backend_check(backend_id: int, ok: bool, latency_ms: int | None, error: str = "") -> None:
    with tx() as conn:
        conn.execute(
            "UPDATE front_backends SET last_check_at=?, last_check_ok=?, last_check_ms=?,"
            " last_check_error=?, updated_at=? WHERE id=?",
            (now_iso(), 1 if ok else 0, latency_ms, (error or "")[:500], now_iso(), backend_id),
        )
