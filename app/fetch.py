"""订阅源与规则集的抓取、解析、缓存。"""
from __future__ import annotations

import base64
import re
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

from . import db
from .config import DEFAULT_UA, FETCH_TIMEOUT
from .util import parse_userinfo

# 机场常把"流量/到期"做成真实节点挂在订阅里，用于在客户端展示。
# 这些节点本身可用，但会污染 url-test 的候选集，默认过滤。
_PSEUDO_RE = re.compile(
    r"^\s*(traffic|expire|expires|expiry|剩余|到期|过期|流量|套餐|官网|公告|群组|订阅)\b"
    r"|\b(traffic|expire)\s*:",
    re.IGNORECASE,
)


def is_pseudo(name: str) -> bool:
    return bool(_PSEUDO_RE.search(name or ""))


def _strip_bom(text: str) -> str:
    return text.lstrip("\ufeff")


def parse_provider_payload(raw: str) -> tuple[list[dict[str, Any]], str]:
    """把机场订阅内容解析成节点列表。

    支持：
      - 原生 Clash YAML（含 proxies 段）
      - 裸 YAML 列表
      - base64 包裹的上述内容
    返回 (proxies, note)
    """
    text = _strip_bom(raw)
    note = ""

    def _try(t: str):
        data = yaml.safe_load(t)
        if isinstance(data, dict):
            proxies = data.get("proxies")
            if isinstance(proxies, list):
                return proxies
            return None
        if isinstance(data, list) and all(isinstance(x, dict) for x in data):
            return data
        return None

    proxies = _try(text)

    if proxies is None:
        # 可能是 base64 订阅
        compact = "".join(text.split())
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "replace")
            proxies = _try(decoded)
            if proxies is not None:
                note = "（内容为 base64，已解码）"
        except Exception:
            proxies = None

    if proxies is None:
        raise ValueError("未在订阅内容中找到 proxies 段，且无法按 base64 解码")

    cleaned: list[dict[str, Any]] = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        if not p.get("name") or not p.get("server"):
            continue
        cleaned.append(p)
    if not cleaned:
        raise ValueError("proxies 段存在但没有有效节点（缺 name/server）")
    return cleaned, note


def count_rules(text: str) -> int:
    """统计规则条数。

    规则集有两种常见格式：
      - Surge / Clash 文本：每行一条 `DOMAIN-SUFFIX,xxx`
      - rule-provider YAML：`payload:` 下面是一个列表
    分别统计，避免把 `payload:` 这行也算成一条规则。
    """
    t = _strip_bom(text)
    lines = t.splitlines()
    head = [l.strip() for l in lines[:30]]
    if any(l.startswith("payload:") or l == "payload" for l in head):
        return sum(1 for l in lines if l.strip().startswith("-"))

    n = 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        n += 1
    return n


def _diff_names(old: str | None, new: list[dict]) -> str:
    old_names = set()
    if old:
        try:
            data = yaml.safe_load(old)
            if isinstance(data, dict):
                old_names = {p.get("name") for p in (data.get("proxies") or []) if isinstance(p, dict)}
        except Exception:
            pass
    new_names = {p.get("name") for p in new}
    if not old_names:
        return f"首次抓取 {len(new_names)} 个节点"
    added = len(new_names - old_names)
    removed = len(old_names - new_names)
    return f"+{added} / -{removed}"


async def _get(url: str, ua: str | None) -> tuple[str, dict, int, int]:
    headers = {
        "User-Agent": ua or DEFAULT_UA,
        "Accept": "*/*",
    }
    started = time.perf_counter()
    async with httpx.AsyncClient(
        timeout=FETCH_TIMEOUT, follow_redirects=True, verify=False,
        headers=headers,
    ) as client:
        resp = await client.get(url)
        elapsed = int((time.perf_counter() - started) * 1000)
        resp.raise_for_status()
        return resp.text, dict(resp.headers), resp.status_code, elapsed


async def refresh_source(source_id: int) -> tuple[bool, str]:
    row = db.query_one("SELECT * FROM sources WHERE id = ?", (source_id,))
    if row is None:
        return False, "订阅源不存在"

    try:
        text, headers, status, ms = await _get(row["url"], row["user_agent"] or None)
        proxies, note = parse_provider_payload(text)
        if row["strip_pseudo"]:
            kept = [p for p in proxies if not is_pseudo(p["name"])]
            removed = len(proxies) - len(kept)
            if removed:
                note = (note + f" 过滤伪节点 {removed} 个").strip()
            proxies = kept
        if not proxies:
            raise ValueError("过滤伪节点后没有剩余节点")

        payload = yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
        diff = _diff_names(row["content"], proxies)
        userinfo = headers.get("subscription-userinfo") or headers.get("Subscription-Userinfo")
        info = parse_userinfo(userinfo)
        message = " ".join(x for x in (diff, note) if x)

        with db.tx() as conn:
            conn.execute(
                "UPDATE sources SET content=?, content_size=?, node_count=?, userinfo=?, etag=?,"
                " last_fetch_at=?, last_status='ok', last_error=NULL, last_ms=?, updated_at=?"
                " WHERE id=?",
                (payload, len(payload.encode("utf-8")), len(proxies),
                 yaml.safe_dump(info, allow_unicode=True) if info else None,
                 headers.get("etag"), db.now_iso(), ms, db.now_iso(), source_id),
            )
        db.add_log("source", source_id, row["slug"], True, status=str(status),
                   size=len(payload.encode("utf-8")), counts=len(proxies),
                   duration_ms=ms, message=message)
        return True, message
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        with db.tx() as conn:
            conn.execute(
                "UPDATE sources SET last_fetch_at=?, last_status='error', last_error=?, updated_at=?"
                " WHERE id=?",
                (db.now_iso(), msg, db.now_iso(), source_id),
            )
        db.add_log("source", source_id, row["slug"], False, message=msg)
        return False, msg


async def refresh_ruleset(ruleset_id: int) -> tuple[bool, str]:
    row = db.query_one("SELECT * FROM rulesets WHERE id = ?", (ruleset_id,))
    if row is None:
        return False, "规则集不存在"

    try:
        ms = 0
        if row["kind"] == "inline":
            text = row["inline_content"] or ""
            status = "inline"
        elif row["kind"] == "file":
            if not row["path"]:
                raise ValueError("本地规则集缺少文件路径")
            from .config import RULESETS_ROOT
            p = Path(row["path"])
            if not p.is_absolute():
                p = RULESETS_ROOT / p
            if not p.is_file():
                raise ValueError(f"文件不存在：{p}")
            text = p.read_text(encoding="utf-8", errors="replace")
            status = "file"
        else:
            if not row["url"]:
                raise ValueError("远程规则集缺少 URL")
            ua = db.get_settings().get("ruleset_ua") or db.DEFAULT_SETTINGS["ruleset_ua"]
            text, _headers, status_code, ms = await _get(row["url"], ua)
            status = str(status_code)

        text = _strip_bom(text).replace("\r\n", "\n").replace("\r", "\n")
        n = count_rules(text)
        if n == 0:
            raise ValueError("规则集内容为空（没有任何有效行）")

        with db.tx() as conn:
            conn.execute(
                "UPDATE rulesets SET content=?, content_size=?, rule_count=?,"
                " last_fetch_at=?, last_status='ok', last_error=NULL, last_ms=?, updated_at=?"
                " WHERE id=?",
                (text, len(text.encode("utf-8")), n, db.now_iso(), ms, db.now_iso(), ruleset_id),
            )
        db.add_log("ruleset", ruleset_id, row["slug"], True, status=status,
                   size=len(text.encode("utf-8")), counts=n, duration_ms=ms,
                   message=f"{n} 条规则")
        return True, f"{n} 条规则"
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        with db.tx() as conn:
            conn.execute(
                "UPDATE rulesets SET last_fetch_at=?, last_status='error', last_error=?, updated_at=?"
                " WHERE id=?",
                (db.now_iso(), msg, db.now_iso(), ruleset_id),
            )
        db.add_log("ruleset", ruleset_id, row["slug"], False, message=msg)
        return False, msg
