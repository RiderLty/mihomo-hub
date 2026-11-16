"""后台定时刷新。"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from . import db
from .config import SCHEDULER_ENABLED, SCHEDULER_TICK
from .fetch import refresh_ruleset, refresh_source

log = logging.getLogger("mihomo-hub.scheduler")


def _due(last_fetch_at: str | None, interval_min: int | None) -> bool:
    if not last_fetch_at:
        return True
    try:
        last = datetime.fromisoformat(last_fetch_at)
    except Exception:  # noqa: BLE001
        return True
    if last.tzinfo is None:
        last = last.astimezone()
    return datetime.now(last.tzinfo) >= last + timedelta(minutes=interval_min or 360)


async def tick_once() -> tuple[int, int]:
    """跑一轮，返回 (刷新成功的源, 刷新成功的规则集)。"""
    settings = db.get_settings()
    if settings.get("auto_refresh", "1") != "1":
        return 0, 0

    ok_src = 0
    for row in db.query("SELECT * FROM sources WHERE enabled = 1 ORDER BY id"):
        if _due(row["last_fetch_at"], row["interval_min"]):
            ok, msg = await refresh_source(row["id"])
            log.info("refresh source %s -> %s (%s)", row["slug"], ok, msg)
            ok_src += 1 if ok else 0
            await asyncio.sleep(1)

    ok_rules = 0
    for row in db.query("SELECT * FROM rulesets WHERE enabled = 1 ORDER BY id"):
        if _due(row["last_fetch_at"], row["interval_min"]):
            ok, msg = await refresh_ruleset(row["id"])
            log.info("refresh ruleset %s -> %s (%s)", row["slug"], ok, msg)
            ok_rules += 1 if ok else 0
            await asyncio.sleep(1)

    return ok_src, ok_rules


async def loop() -> None:
    if not SCHEDULER_ENABLED:
        log.info("scheduler disabled")
        return
    log.info("scheduler started, tick=%ss", SCHEDULER_TICK)
    while True:
        try:
            await tick_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("scheduler tick failed")
        await asyncio.sleep(SCHEDULER_TICK)
