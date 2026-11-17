"""mihomo-hub：机场节点与规则的缓存中心。

职责只有两个：
  1. 由服务端定时拉取机场订阅，避免多客户端各自拉取触发限流；
  2. 托管「骨架配置」与规则集，客户端用 proxy-providers / rule-providers 自取。
"""
from __future__ import annotations

import json
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db, front as front_mod, profile as profile_mod, urls
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


# ---------------------------------------------------------------- front helpers

def _json_dict(value) -> dict:
    if not value:
        return {}
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _front_row(row) -> dict:
    data = dict(row)
    data["group_defaults"] = _json_dict(data.get("group_defaults"))
    return data


def _front_backends(profile_id: int):
    return db.query(
        "SELECT b.* FROM front_backends b"
        " JOIN front_profile_backends pb ON pb.backend_id = b.id"
        " WHERE pb.profile_id = ? ORDER BY pb.position, b.id",
        (profile_id,),
    )


def _save_front_backends(conn, profile_id: int, backend_ids) -> None:
    conn.execute("DELETE FROM front_profile_backends WHERE profile_id = ?", (profile_id,))
    seen: set[int] = set()
    position = 0
    for raw in backend_ids or []:
        try:
            backend_id = int(raw)
        except (TypeError, ValueError):
            continue
        if backend_id in seen:
            continue
        exists = conn.execute("SELECT id FROM front_backends WHERE id = ?", (backend_id,)).fetchone()
        if exists is None:
            continue
        seen.add(backend_id)
        conn.execute(
            "INSERT INTO front_profile_backends(profile_id, backend_id, position) VALUES(?,?,?)",
            (profile_id, backend_id, position),
        )
        position += 1


def _backend_usage(backend_id: int):
    return db.query(
        "SELECT p.id, p.name, p.slug FROM front_profiles p"
        " JOIN front_profile_backends pb ON pb.profile_id = p.id"
        " WHERE pb.backend_id = ? ORDER BY p.id",
        (backend_id,),
    )


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


# ---------------------------------------------------------------- front profiles

@app.get("/fronts", response_class=HTMLResponse)
async def fronts_page(request: Request):
    rows = db.query("SELECT * FROM front_profiles ORDER BY id")
    fronts = []
    for row in rows:
        f = _front_row(row)
        f["_base"] = front_mod.front_base(request, f)
        f["_backends"] = _front_backends(f["id"])
        f["_sub_url"] = front_mod.subscription_url(f["_base"], f["slug"], f["token"])
        fronts.append(f)
    return render(
        request, "fronts.html",
        fronts=fronts,
        backends=db.query("SELECT * FROM front_backends WHERE enabled = 1 ORDER BY name"),
        detected_base=urls.detect_base_url(request),
    )


@app.post("/fronts/add")
async def front_add(
    name: str = Form(...),
    slug: str = Form(""),
    backend_group_name: str = Form("PROXY"),
    backend_ids: list[int] = Form([]),
):
    name = name.strip()
    if not name:
        return go("/fronts", err="名称不能为空")
    group_name = (
        backend_group_name or front_mod.DEFAULT_BACKEND_GROUP
    ).strip() or front_mod.DEFAULT_BACKEND_GROUP
    if not front_mod.valid_group_name(group_name):
        return go("/fronts", err=f"后端分组名不合法：{group_name}")

    want = slugify(slug or name, "front")
    final = ensure_unique(want, lambda s: _slug_taken("front_profiles", s))
    now = db.now_iso()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO front_profiles(slug, name, enabled, source_profile_id, backend_group_name,"
            " backend_group_type, include_direct, group_defaults, base_mode, base_url, base_template,"
            " rule_provider_proxy, token, created_at, updated_at)"
            " VALUES(?,?,1,1,?,?,1,'','auto','',?, 'DIRECT', ?, ?, ?)",
            (final, name, group_name, front_mod.DEFAULT_GROUP_TYPE,
             front_mod.DEFAULT_BASE_TEMPLATE, secrets.token_urlsafe(24), now, now),
        )
        fid = cur.lastrowid
        _save_front_backends(conn, fid, backend_ids)
    return go(f"/fronts/{fid}", msg="已创建，可以继续调整分类默认值和基础模板")


@app.get("/fronts/{fid}", response_class=HTMLResponse)
async def front_detail(request: Request, fid: int):
    row = db.query_one("SELECT * FROM front_profiles WHERE id = ?", (fid,))
    if row is None:
        return go("/fronts", err="前置配置不存在")

    f = _front_row(row)
    backends = _front_backends(fid)
    source = db.get_profile()
    base = front_mod.front_base(request, f)
    groups, issues = front_mod.target_groups(source, f, base)

    preview = None
    try:
        text = front_mod.render_front(f, backends, source, base)
        preview = text.splitlines()
        issues = issues + front_mod.validate_generated(text, f)
    except front_mod.FrontError as exc:
        issues.append({"level": "error", "message": str(exc)})

    return render(
        request, "front_detail.html",
        f=f,
        backends=db.query("SELECT * FROM front_backends ORDER BY name"),
        selected_ids={b["id"] for b in backends},
        target_groups=groups,
        issues=issues,
        preview=preview[:400] if preview else [],
        sub_url=front_mod.subscription_url(base, f["slug"], f["token"]),
        base=base,
        detected_base=urls.detect_base_url(request),
        global_base=urls.configured_base_url() or urls.detect_base_url(request),
        group_types=["select", "fallback", "url-test", "load-balance"],
    )


@app.post("/fronts/{fid}/update")
async def front_update(
    request: Request,
    fid: int,
    name: str = Form(...),
    slug: str = Form(""),
    enabled: str = Form(""),
    backend_group_name: str = Form("PROXY"),
    backend_group_type: str = Form("select"),
    include_direct: str = Form(""),
    base_mode: str = Form("auto"),
    base_url: str = Form(""),
    base_template: str = Form(""),
    rule_provider_proxy: str = Form("DIRECT"),
    custom_rules: str = Form(""),
    backend_ids: list[int] = Form([]),
):
    row = db.query_one("SELECT id FROM front_profiles WHERE id = ?", (fid,))
    if row is None:
        return go("/fronts", err="前置配置不存在")

    name = name.strip()
    if not name:
        return go(f"/fronts/{fid}", err="名称不能为空")

    group_name = (
        backend_group_name or front_mod.DEFAULT_BACKEND_GROUP
    ).strip() or front_mod.DEFAULT_BACKEND_GROUP
    if not front_mod.valid_group_name(group_name):
        return go(f"/fronts/{fid}", err=f"后端分组名不合法：{group_name}")

    group_type = backend_group_type if backend_group_type in (
        "select", "fallback", "url-test", "load-balance"
    ) else front_mod.DEFAULT_GROUP_TYPE
    mode = base_mode if base_mode in ("auto", "global", "custom") else "auto"
    custom = (base_url or "").strip()
    if mode == "custom" and custom:
        try:
            custom = urls.normalize_base_url(custom, urls.detect_scheme(request))
        except ValueError as exc:
            return go(f"/fronts/{fid}", err=f"自定义 hub 地址无效：{exc}")

    template = base_template if (base_template or "").strip() else front_mod.DEFAULT_BASE_TEMPLATE
    template_error = front_mod.check_base_template(template, urls.detect_base_url(request))
    if template_error:
        return go(f"/fronts/{fid}", err=f"基础模板无效：{template_error}")

    provider_proxy = (rule_provider_proxy or "DIRECT").strip()
    if provider_proxy not in ("DIRECT", group_name):
        provider_proxy = "DIRECT"

    form = await request.form()
    overrides: dict[str, str] = {}
    for gname, value in zip(form.getlist("group_name"), form.getlist("group_default")):
        if value in ("PROXY", "DIRECT"):
            overrides[str(gname)] = value

    want = slugify(slug or name, "front")
    final = ensure_unique(want, lambda s: _slug_taken("front_profiles", s, exclude_id=fid))
    with db.tx() as conn:
        conn.execute(
            "UPDATE front_profiles SET slug=?, name=?, enabled=?, backend_group_name=?,"
            " backend_group_type=?, include_direct=?, group_defaults=?, custom_rules=?,"
            " base_mode=?, base_url=?, base_template=?, rule_provider_proxy=?, updated_at=?"
            " WHERE id=?",
            (final, name, 1 if enabled else 0, group_name, group_type,
             1 if include_direct else 0, json.dumps(overrides, ensure_ascii=False),
             custom_rules.strip(), mode, custom, template, provider_proxy, db.now_iso(), fid),
        )
        _save_front_backends(conn, fid, backend_ids)
    return go(f"/fronts/{fid}", msg="已保存")


@app.post("/fronts/{fid}/token")
async def front_token(fid: int):
    with db.tx() as conn:
        conn.execute(
            "UPDATE front_profiles SET token=?, updated_at=? WHERE id=?",
            (secrets.token_urlsafe(24), db.now_iso(), fid),
        )
    return go(f"/fronts/{fid}", msg="已生成新的访问令牌，客户端订阅地址需要同步更新")


@app.post("/fronts/{fid}/reset-template")
async def front_reset_template(fid: int):
    with db.tx() as conn:
        conn.execute(
            "UPDATE front_profiles SET base_template=?, updated_at=? WHERE id=?",
            (front_mod.DEFAULT_BASE_TEMPLATE, db.now_iso(), fid),
        )
    return go(f"/fronts/{fid}", msg="基础模板已恢复为默认值")


@app.post("/fronts/{fid}/delete")
async def front_delete(fid: int):
    with db.tx() as conn:
        conn.execute("DELETE FROM front_profile_backends WHERE profile_id = ?", (fid,))
        conn.execute("DELETE FROM front_profiles WHERE id = ?", (fid,))
    return go("/fronts", msg="已删除")


@app.get("/fronts/{fid}/download")
async def front_download(request: Request, fid: int):
    row = db.query_one("SELECT * FROM front_profiles WHERE id = ?", (fid,))
    if row is None:
        return go("/fronts", err="前置配置不存在")
    f = _front_row(row)
    base = front_mod.front_base(request, f)
    try:
        text = front_mod.render_front(f, _front_backends(fid), db.get_profile(), base)
    except front_mod.FrontError as exc:
        return PlainTextResponse(f"# 生成失败：{exc}\n", status_code=500)
    return Response(
        text, media_type="text/yaml; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{f["slug"]}.yaml"'},
    )


@app.get("/api/fronts/{slug}.yaml")
async def front_yaml(request: Request, slug: str, token: str = ""):
    row = db.query_one("SELECT * FROM front_profiles WHERE slug = ? AND enabled = 1", (slug,))
    if row is None:
        return PlainTextResponse("# 前置配置不存在或已禁用\n", status_code=404)
    f = _front_row(row)
    if f["token"] and not secrets.compare_digest(str(token), str(f["token"])):
        return PlainTextResponse("# token 无效\n", status_code=404)
    base = front_mod.front_base(request, f)
    try:
        text = front_mod.render_front(f, _front_backends(f["id"]), db.get_profile(), base)
    except front_mod.FrontError as exc:
        return PlainTextResponse(f"# 生成失败：{exc}\n", status_code=500)
    return Response(text, media_type="text/yaml; charset=utf-8", headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------- backends

@app.get("/backends", response_class=HTMLResponse)
async def backends_page(request: Request):
    rows = db.query("SELECT * FROM front_backends ORDER BY name")
    usage = {row["id"]: _backend_usage(row["id"]) for row in rows}
    return render(request, "backends.html", backends=rows, usage=usage)


@app.post("/backends/add")
async def backend_add(
    name: str = Form(...),
    kind: str = Form("socks5"),
    server: str = Form(...),
    port: int = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    note: str = Form(""),
    sni: str = Form(""),
    udp: str = Form(""),
    tls: str = Form(""),
    skip_cert_verify: str = Form(""),
    extra_yaml: str = Form(""),
):
    name = name.strip()
    server = server.strip()
    if not name or not server:
        return go("/backends", err="名称和 server 不能为空")
    if not front_mod.valid_backend_name(name):
        return go("/backends", err=f"后端名称不合法：{name}")
    if not 0 < port < 65536:
        return go("/backends", err="端口必须在 1-65535 之间")
    if db.query_one("SELECT id FROM front_backends WHERE name = ?", (name,)):
        return go("/backends", err=f"后端名称已存在：{name}")

    extra = (extra_yaml or "").strip()
    if extra:
        try:
            data = yaml.safe_load(extra)
        except Exception as exc:  # noqa: BLE001
            return go("/backends", err=f"高级 YAML 解析失败：{exc}")
        if data is not None and not isinstance(data, dict):
            return go("/backends", err="高级 YAML 必须是映射")

    now = db.now_iso()
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO front_backends(name, kind, server, port, username, password, udp, tls, sni,"
            " skip_cert_verify, extra_yaml, note, enabled, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (name, kind.strip() or "socks5", server, port, username.strip() or None,
             password or None, 1 if udp else 0, 1 if tls else 0, sni.strip() or None,
             1 if skip_cert_verify else 0, extra or None, note.strip() or None, now, now),
        )
        bid = cur.lastrowid
    return go(f"/backends/{bid}", msg="已添加")


@app.get("/backends/{bid}", response_class=HTMLResponse)
async def backend_detail(request: Request, bid: int):
    row = db.query_one("SELECT * FROM front_backends WHERE id = ?", (bid,))
    if row is None:
        return go("/backends", err="后端不存在")
    return render(request, "backend_detail.html", b=row, usage=_backend_usage(bid))


@app.post("/backends/{bid}/update")
async def backend_update(
    bid: int,
    name: str = Form(...),
    kind: str = Form("socks5"),
    server: str = Form(...),
    port: int = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    note: str = Form(""),
    sni: str = Form(""),
    udp: str = Form(""),
    tls: str = Form(""),
    skip_cert_verify: str = Form(""),
    extra_yaml: str = Form(""),
    enabled: str = Form(""),
):
    row = db.query_one("SELECT id FROM front_backends WHERE id = ?", (bid,))
    if row is None:
        return go("/backends", err="后端不存在")
    name = name.strip()
    server = server.strip()
    if not name or not server:
        return go(f"/backends/{bid}", err="名称和 server 不能为空")
    if not front_mod.valid_backend_name(name):
        return go(f"/backends/{bid}", err=f"后端名称不合法：{name}")
    if not 0 < port < 65536:
        return go(f"/backends/{bid}", err="端口必须在 1-65535 之间")
    other = db.query_one("SELECT id FROM front_backends WHERE name = ? AND id != ?", (name, bid))
    if other is not None:
        return go(f"/backends/{bid}", err=f"后端名称已存在：{name}")

    extra = (extra_yaml or "").strip()
    if extra:
        try:
            data = yaml.safe_load(extra)
        except Exception as exc:  # noqa: BLE001
            return go(f"/backends/{bid}", err=f"高级 YAML 解析失败：{exc}")
        if data is not None and not isinstance(data, dict):
            return go(f"/backends/{bid}", err="高级 YAML 必须是映射")

    with db.tx() as conn:
        conn.execute(
            "UPDATE front_backends SET name=?, kind=?, server=?, port=?, username=?, password=?,"
            " udp=?, tls=?, sni=?, skip_cert_verify=?, extra_yaml=?, note=?, enabled=?, updated_at=?"
            " WHERE id=?",
            (name, kind.strip() or "socks5", server, port, username.strip() or None,
             password or None, 1 if udp else 0, 1 if tls else 0, sni.strip() or None,
             1 if skip_cert_verify else 0, extra or None, note.strip() or None,
             1 if enabled else 0, db.now_iso(), bid),
        )
    return go(f"/backends/{bid}", msg="已保存")


@app.post("/backends/{bid}/delete")
async def backend_delete(bid: int):
    row = db.query_one("SELECT id FROM front_backends WHERE id = ?", (bid,))
    if row is None:
        return go("/backends", err="后端不存在")
    usage = _backend_usage(bid)
    if usage:
        names = "、".join(str(u["name"]) for u in usage)
        return go(f"/backends/{bid}", err=f"这个后端仍被前置配置使用：{names}")
    with db.tx() as conn:
        conn.execute("DELETE FROM front_profile_backends WHERE backend_id = ?", (bid,))
        conn.execute("DELETE FROM front_backends WHERE id = ?", (bid,))
    return go("/backends", msg="已删除")


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
