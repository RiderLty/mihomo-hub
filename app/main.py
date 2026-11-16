"""mihomo-hub：机场节点与规则的缓存中心。

职责只有两个：
  1. 由服务端定时拉取机场订阅，避免多客户端各自拉取触发限流；
  2. 托管「骨架配置」与规则集，客户端用 proxy-providers / rule-providers 自取。
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db, profile as profile_mod, urls
from .config import APP_NAME, APP_VERSION
from .fetch import refresh_ruleset, refresh_source
from .scheduler import loop as scheduler_loop
from .util import ensure_unique, human_size, mask_secret, slugify

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mihomo-hub")

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(HERE / "templates"))


def _short_ts(value) -> str:
    if not value:
        return "\u2014"
    s = str(value)
    return s[5:16].replace("T", " ") if len(s) >= 16 else s


def _bytes_h(value) -> str:
    from .util import bytes_to_human
    try:
        return bytes_to_human(float(value))
    except (TypeError, ValueError):
        return "\u2014"


def _epoch_date(value) -> str:
    import datetime as _dt
    try:
        return _dt.datetime.fromtimestamp(int(float(value))).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return "\u2014"


templates.env.filters["human_size"] = human_size
templates.env.filters["mask_secret"] = mask_secret
templates.env.filters["ts"] = _short_ts
templates.env.filters["bytes_h"] = _bytes_h
templates.env.filters["epoch_date"] = _epoch_date


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    task = None
    try:
        import asyncio
        task = asyncio.create_task(scheduler_loop())
        yield
    finally:
        if task:
            task.cancel()


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


# ---------------------------------------------------------------- helpers

def base_url(request: Request) -> str:
    """决定写进骨架里的对外地址。

    优先级：面板设置（反向代理域名） > 反向代理转发头 > 请求的 Host。
    详见 urls.resolve_base_url。
    """
    return urls.resolve_base_url(request)


def go(url: str, msg: str | None = None, err: str | None = None) -> RedirectResponse:
    params = []
    if msg:
        params.append("msg=" + quote(msg))
    if err:
        params.append("err=" + quote(err))
    if params:
        url += ("&" if "?" in url else "?") + "&".join(params)
    return RedirectResponse(url, status_code=303)


def _slug_taken(table: str, slug: str, exclude_id: int | None = None) -> bool:
    if exclude_id is None:
        row = db.query_one(f"SELECT id FROM {table} WHERE slug = ?", (slug,))
    else:
        row = db.query_one(f"SELECT id FROM {table} WHERE slug = ? AND id != ?", (slug, exclude_id))
    return row is not None


def _nodes_of(content: str | None) -> list[dict]:
    if not content:
        return []
    try:
        data = yaml.safe_load(content)
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, dict):
        return [p for p in (data.get("proxies") or []) if isinstance(p, dict)]
    return []


def _userinfo_of(row) -> dict | None:
    raw = row["userinfo"]
    if not raw:
        return None
    try:
        return yaml.safe_load(raw)
    except Exception:  # noqa: BLE001
        return None


def _ctx(request: Request, **kw) -> dict:
    ctx = {
        "request": request,
        "app_name": APP_NAME,
        "version": APP_VERSION,
        "base": base_url(request),
        "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"),
    }
    ctx.update(kw)
    return ctx


def render(request: Request, name: str, **kw):
    return templates.TemplateResponse(request=request, name=name, context=_ctx(request, **kw))


# ---------------------------------------------------------------- pages

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    sources = db.query("SELECT * FROM sources ORDER BY id")
    rulesets = db.query("SELECT * FROM rulesets ORDER BY id")
    logs = db.recent_logs(15)
    total_nodes = sum((s["node_count"] or 0) for s in sources)
    total_rules = sum((r["rule_count"] or 0) for r in rulesets)
    prof = db.get_profile()
    issues = profile_mod.validate(
        prof, {s["slug"] for s in sources}, {r["slug"] for r in rulesets}, base_url(request)
    ) if prof.strip() else []
    return render(
        request, "index.html",
        sources=sources, rulesets=rulesets, logs=logs,
        total_nodes=total_nodes, total_rules=total_rules,
        issues=issues,
        profile_ready=bool(prof.strip()),
    )


@app.post("/refresh-all")
async def refresh_all():
    srcs = db.query("SELECT id, slug FROM sources WHERE enabled = 1")
    rss = db.query("SELECT id, slug FROM rulesets WHERE enabled = 1")
    ok = fail = 0
    for r in srcs:
        good, _ = await refresh_source(r["id"])
        ok += 1 if good else 0
        fail += 0 if good else 1
    for r in rss:
        good, _ = await refresh_ruleset(r["id"])
        ok += 1 if good else 0
        fail += 0 if good else 1
    return go("/", msg=f"刷新完成：成功 {ok}，失败 {fail}" if fail else f"刷新完成：{ok} 项全部成功")


# ---------------------------------------------------------------- sources

@app.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request):
    rows = db.query("SELECT * FROM sources ORDER BY id")
    return render(
        request, "sources.html", sources=rows,
        default_ua=db.get_settings().get("default_ua", ""),
        default_interval=db.get_settings().get("fetch_interval_min", "360"),
    )


@app.post("/sources/add")
async def source_add(
    name: str = Form(...),
    url: str = Form(...),
    interval_min: int = Form(360),
    user_agent: str = Form(""),
    strip_pseudo: str = Form(""),
    slug: str = Form(""),
):
    name = name.strip()
    url = url.strip()
    if not name or not url:
        return go("/sources", err="名称和 URL 不能为空")
    want = slugify(slug or name, "src")
    final = ensure_unique(want, lambda s: _slug_taken("sources", s))
    now = db.now_iso()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO sources(slug, name, url, user_agent, interval_min, enabled, strip_pseudo,"
            " created_at, updated_at) VALUES(?,?,?,?,?,1,?,?,?)",
            (final, name, url, user_agent.strip(), max(5, interval_min),
             1 if strip_pseudo else 0, now, now),
        )
        sid = cur.lastrowid
    ok, msg = await refresh_source(sid)
    if ok:
        return go(f"/sources/{sid}", msg=f"已添加并抓取成功：{msg}")
    return go(f"/sources/{sid}", err=f"已添加，但抓取失败：{msg}")


@app.get("/sources/{sid}", response_class=HTMLResponse)
async def source_detail(request: Request, sid: int):
    row = db.query_one("SELECT * FROM sources WHERE id = ?", (sid,))
    if row is None:
        return go("/sources", err="订阅源不存在")
    nodes = _nodes_of(row["content"])
    logs = db.query(
        "SELECT * FROM fetch_log WHERE kind='source' AND ref_id=? ORDER BY id DESC LIMIT 20", (sid,)
    )
    return render(
        request, "source_detail.html",
        s=row, nodes=nodes, logs=logs, userinfo=_userinfo_of(row),
    )


@app.post("/sources/{sid}/refresh")
async def source_refresh(sid: int):
    ok, msg = await refresh_source(sid)
    return go(f"/sources/{sid}", msg=msg if ok else None, err=None if ok else msg)


@app.post("/sources/{sid}/update")
async def source_update(
    sid: int,
    name: str = Form(...),
    url: str = Form(...),
    interval_min: int = Form(360),
    user_agent: str = Form(""),
    strip_pseudo: str = Form(""),
    enabled: str = Form(""),
    slug: str = Form(""),
):
    want = slugify(slug or name, "src")
    final = ensure_unique(want, lambda s: _slug_taken("sources", s, exclude_id=sid))
    with db.tx() as conn:
        conn.execute(
            "UPDATE sources SET slug=?, name=?, url=?, user_agent=?, interval_min=?,"
            " strip_pseudo=?, enabled=?, updated_at=? WHERE id=?",
            (final, name.strip(), url.strip(), user_agent.strip(), max(5, interval_min),
             1 if strip_pseudo else 0, 1 if enabled else 0, db.now_iso(), sid),
        )
    return go(f"/sources/{sid}", msg="已保存")


@app.post("/sources/{sid}/delete")
async def source_delete(sid: int):
    with db.tx() as conn:
        conn.execute("DELETE FROM sources WHERE id = ?", (sid,))
    return go("/sources", msg="已删除")


# ---------------------------------------------------------------- rulesets

@app.get("/rulesets", response_class=HTMLResponse)
async def rulesets_page(request: Request):
    rows = db.query("SELECT * FROM rulesets ORDER BY id")
    return render(
        request, "rulesets.html", rulesets=rows,
        default_interval=db.get_settings().get("ruleset_interval_min", "1440"),
        import_dir=default_import_dir(),
    )


@app.post("/rulesets/add")
async def ruleset_add(
    name: str = Form(...),
    kind: str = Form("remote"),
    url: str = Form(""),
    path: str = Form(""),
    inline_content: str = Form(""),
    behavior: str = Form("classical"),
    format: str = Form("text"),
    default_target: str = Form("Proxies"),
    interval_min: int = Form(1440),
    slug: str = Form(""),
):
    name = name.strip()
    if not name:
        return go("/rulesets", err="名称不能为空")
    if kind == "remote" and not url.strip():
        return go("/rulesets", err="远程规则集必须填 URL")
    if kind == "file" and not path.strip():
        return go("/rulesets", err="本地规则集必须填文件路径")
    if kind == "inline" and not inline_content.strip():
        return go("/rulesets", err="内联规则集内容不能为空")
    want = slugify(slug or name, "rules")
    final = ensure_unique(want, lambda s: _slug_taken("rulesets", s))
    now = db.now_iso()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO rulesets(slug, name, kind, url, path, inline_content, behavior, format,"
            " default_target, interval_min, enabled, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (final, name, kind, url.strip() or None, path.strip() or None,
             inline_content or None, behavior, format,
             default_target.strip() or "Proxies", max(5, interval_min), now, now),
        )
        rid = cur.lastrowid
    ok, msg = await refresh_ruleset(rid)
    if ok:
        return go(f"/rulesets/{rid}", msg=f"已添加：{msg}")
    return go(f"/rulesets/{rid}", err=f"已添加，但读取失败：{msg}")


@app.get("/rulesets/{rid}", response_class=HTMLResponse)
async def ruleset_detail(request: Request, rid: int):
    row = db.query_one("SELECT * FROM rulesets WHERE id = ?", (rid,))
    if row is None:
        return go("/rulesets", err="规则集不存在")
    preview = (row["content"] or "").splitlines()[:400]
    logs = db.query(
        "SELECT * FROM fetch_log WHERE kind='ruleset' AND ref_id=? ORDER BY id DESC LIMIT 20", (rid,)
    )
    return render(request, "ruleset_detail.html", r=row, preview=preview, logs=logs)


@app.post("/rulesets/{rid}/refresh")
async def ruleset_refresh(rid: int):
    ok, msg = await refresh_ruleset(rid)
    return go(f"/rulesets/{rid}", msg=msg if ok else None, err=None if ok else msg)


@app.post("/rulesets/{rid}/update")
async def ruleset_update(
    rid: int,
    name: str = Form(...),
    kind: str = Form("remote"),
    url: str = Form(""),
    path: str = Form(""),
    inline_content: str = Form(""),
    behavior: str = Form("classical"),
    format: str = Form("text"),
    default_target: str = Form("Proxies"),
    interval_min: int = Form(1440),
    enabled: str = Form(""),
    slug: str = Form(""),
):
    want = slugify(slug or name, "rules")
    final = ensure_unique(want, lambda s: _slug_taken("rulesets", s, exclude_id=rid))
    with db.tx() as conn:
        conn.execute(
            "UPDATE rulesets SET slug=?, name=?, kind=?, url=?, path=?, inline_content=?, behavior=?,"
            " format=?, default_target=?, interval_min=?, enabled=?, updated_at=? WHERE id=?",
            (final, name.strip(), kind, url.strip() or None, path.strip() or None,
             inline_content or None, behavior, format, default_target.strip() or "Proxies",
             max(5, interval_min), 1 if enabled else 0, db.now_iso(), rid),
        )
    ok, msg = await refresh_ruleset(rid)
    if ok:
        return go(f"/rulesets/{rid}", msg=f"已保存：{msg}")
    return go(f"/rulesets/{rid}", err=f"已保存，但读取失败：{msg}")


@app.post("/rulesets/{rid}/delete")
async def ruleset_delete(rid: int):
    with db.tx() as conn:
        conn.execute("DELETE FROM rulesets WHERE id = ?", (rid,))
    return go("/rulesets", msg="已删除")


# ---------------------------------------------------------------- ruleset import

_TARGET_HINTS = [
    ("hijacking", "REJECT"),
    ("streamingse", "StreamingSE"),
    ("streaming", "Streaming"),
    ("china", "DIRECT"),
    ("unbreak", "DIRECT"),
    ("force-direct", "DIRECT"),
    ("force-proxy", "Proxies"),
    ("local", "DIRECT"),
    ("alibaba", "DIRECT"),
    ("speedtest", "DIRECT"),
    ("emby", "DIRECT"),
    ("gfwlist", "Proxies"),
    ("global", "Proxies"),
    ("telegram", "Telegram"),
    ("apple", "Apple"),
    ("microsoft", "MicroSoft"),
    ("netease", "Netease"),
    ("netflix", "Streaming"),
    ("youtube", "Streaming"),
    ("bilibili", "StreamingSE"),
    ("iqiyi", "StreamingSE"),
    ("hkmtmedia", "StreamingSE"),
    ("game", "Proxies"),
    ("google", "Proxies"),
]


def guess_target(filename: str) -> str:
    low = (filename or "").lower()
    for key, target in _TARGET_HINTS:
        if key in low:
            return target
    return "Proxies"


def default_import_dir() -> str:
    from .config import RULESETS_ROOT
    for cand in ("subconverter-config@master/ruleset", "rulesets", "rules"):
        if (RULESETS_ROOT / cand).is_dir():
            return cand
    return ""


@app.post("/rulesets/import")
async def rulesets_import(dir_path: str = Form(""), overwrite: str = Form("")):
    from .config import RULESETS_ROOT
    raw = dir_path.strip() or default_import_dir()
    if not raw:
        return go("/rulesets", err="请填写规则集目录")
    base = Path(raw)
    if not base.is_absolute():
        base = RULESETS_ROOT / base
    if not base.is_dir():
        return go("/rulesets", err=f"目录不存在：{base}")

    files = sorted(base.rglob("*.list"))
    if not files:
        return go("/rulesets", err=f"目录里没有 .list 文件：{base}")

    created = updated = skipped = failed = 0
    for f in files:
        try:
            rel = str(f.relative_to(RULESETS_ROOT))
        except ValueError:
            rel = str(f)

        slug = slugify(f.stem, "rules")
        row = db.query_one("SELECT id FROM rulesets WHERE slug = ?", (slug,))
        if row is not None and not overwrite:
            skipped += 1
            continue

        now = db.now_iso()
        if row is None:
            # 同名不同目录（例如 apple.list 与 Apple.list）时用父目录前缀区分
            if _slug_taken("rulesets", slug):
                slug = ensure_unique(
                    slugify(f"{f.parent.name}-{f.stem}", "rules"),
                    lambda s: _slug_taken("rulesets", s),
                )
            with db.tx() as conn:
                cur = conn.execute(
                    "INSERT INTO rulesets(slug, name, kind, path, behavior, format,"
                    " default_target, interval_min, enabled, created_at, updated_at)"
                    " VALUES(?,?,'file',?,'classical','text',?,1440,1,?,?)",
                    (slug, f.stem, rel, guess_target(f.stem), now, now),
                )
                rid = cur.lastrowid
            created += 1
        else:
            rid = row["id"]
            with db.tx() as conn:
                conn.execute(
                    "UPDATE rulesets SET kind='file', path=?, updated_at=? WHERE id=?",
                    (rel, now, rid),
                )
            updated += 1

        ok, _msg = await refresh_ruleset(rid)
        if not ok:
            failed += 1

    return go("/rulesets",
              msg=f"导入完成：新增 {created}，更新 {updated}，跳过 {skipped}，读取失败 {failed}")


# ---------------------------------------------------------------- profile

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    sources = db.query("SELECT * FROM sources ORDER BY id")
    rulesets = db.query("SELECT * FROM rulesets ORDER BY id")
    prof = db.get_profile()
    issues = profile_mod.validate(
        prof, {s["slug"] for s in sources}, {r["slug"] for r in rulesets}, base_url(request)
    ) if prof.strip() else [{"level": "warn", "message": "还没有内容，点「应用起始模板」开始"}]
    return render(
        request, "profile.html", content=prof, issues=issues,
        sources=sources, rulesets=rulesets,
    )


@app.post("/profile/save")
async def profile_save(content: str = Form("")):
    db.save_profile(content)
    return go("/profile", msg="已保存")


@app.post("/profile/starter")
async def profile_starter(source_slug: str = Form("")):
    sources = db.query("SELECT * FROM sources ORDER BY id")
    if not sources:
        return go("/sources", err="先添加一个订阅源，再生成骨架")
    slug = source_slug.strip() or sources[0]["slug"]
    if not any(s["slug"] == slug for s in sources):
        return go("/profile", err=f"订阅源 '{slug}' 不存在")

    rulesets = db.query("SELECT * FROM rulesets WHERE enabled = 1 ORDER BY id")
    pairs = [
        (r["slug"], r["default_target"] or "Proxies", r["behavior"] or "classical", r["format"] or "text")
        for r in rulesets
    ]
    content = profile_mod.starter_template(slug, pairs)
    db.save_profile(content)
    return go("/profile", msg=f"已生成骨架（节点源 {slug}，规则集 {len(pairs)} 个）")


@app.get("/profile.yaml")
async def profile_yaml(request: Request):
    content = db.get_profile()
    if not content.strip():
        return PlainTextResponse("# 骨架尚未配置，请先在 mihomo-hub 的「配置骨架」页面生成\n", status_code=404)
    rendered = profile_mod.render(content, base_url(request))
    return Response(rendered, media_type="text/yaml; charset=utf-8",
                    headers={"Cache-Control": "no-store"})


@app.get("/profile/download")
async def profile_download(request: Request):
    rendered = profile_mod.render(db.get_profile(), base_url(request))
    return Response(rendered, media_type="text/yaml; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="config.yaml"'})


# ---------------------------------------------------------------- machine endpoints

@app.get("/api/providers/{slug}.yaml")
async def provider_yaml(slug: str):
    row = db.query_one("SELECT * FROM sources WHERE slug = ? AND enabled = 1", (slug,))
    if row is None:
        return PlainTextResponse(f"# 订阅源 '{slug}' 不存在或已禁用\n", status_code=404)
    if not row["content"]:
        return PlainTextResponse(f"# 订阅源 '{slug}' 尚未抓取成功\n", status_code=404)
    return Response(row["content"], media_type="text/yaml; charset=utf-8",
                    headers={"Cache-Control": "no-cache"})


@app.get("/api/rulesets/{slug}.list")
async def ruleset_list(slug: str):
    row = db.query_one("SELECT * FROM rulesets WHERE slug = ? AND enabled = 1", (slug,))
    if row is None:
        return PlainTextResponse(f"# 规则集 '{slug}' 不存在或已禁用\n", status_code=404)
    if not row["content"]:
        return PlainTextResponse(f"# 规则集 '{slug}' 尚未抓取成功\n", status_code=404)
    return Response(row["content"], media_type="text/plain; charset=utf-8",
                    headers={"Cache-Control": "no-cache"})


@app.get("/api/status")
async def api_status():
    sources = db.query("SELECT slug, name, node_count, last_fetch_at, last_status FROM sources")
    rulesets = db.query("SELECT slug, name, rule_count, last_fetch_at, last_status FROM rulesets")
    return JSONResponse({
        "sources": [dict(r) for r in sources],
        "rulesets": [dict(r) for r in rulesets],
        "profile_ready": bool(db.get_profile().strip()),
    })


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


# ---------------------------------------------------------------- settings

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    from .config import DATA_DIR, DB_PATH
    detected = urls.detect_base_url(request)
    return render(
        request, "settings.html", settings=db.get_settings(),
        data_dir=str(DATA_DIR), db_path=str(DB_PATH),
        detected_base=detected,
        detected_private=urls.is_private_base(detected),
        auto_detecting=not urls.configured_base_url(),
    )


@app.post("/settings/save")
async def settings_save(
    request: Request,
    public_base_url: str = Form(""),
    default_ua: str = Form(""),
    ruleset_ua: str = Form(""),
    auto_refresh: str = Form(""),
    strip_pseudo: str = Form(""),
    fetch_interval_min: str = Form("360"),
    ruleset_interval_min: str = Form("1440"),
):
    try:
        base = urls.normalize_base_url(public_base_url, urls.detect_scheme(request))
    except ValueError as exc:
        return go("/settings", err=f"对外地址无效：{exc}")

    db.set_setting("public_base_url", base)
    db.set_setting("default_ua", default_ua.strip() or "clash-verge/v2.3.1")
    db.set_setting("ruleset_ua", ruleset_ua.strip() or db.DEFAULT_SETTINGS["ruleset_ua"])
    db.set_setting("auto_refresh", "1" if auto_refresh else "0")
    db.set_setting("strip_pseudo", "1" if strip_pseudo else "0")
    db.set_setting("fetch_interval_min", fetch_interval_min.strip() or "360")
    db.set_setting("ruleset_interval_min", ruleset_interval_min.strip() or "1440")
    return go("/settings", msg="已保存")
