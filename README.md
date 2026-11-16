# mihomo-hub

机场只做「节点提供方」，规则和分组自己管——一个给 mihomo 客户端用的配置中心。

## 为什么要有它

传统做法是 subconverter：服务端把机场订阅 + 规则集**炸开重组成一份完整 YAML**，客户端只能吃这份成品。
问题在于：

- 每改一条规则就要重新生成整份配置；
- 机场的全局配置（`sniffer` / `unified-delay` / `ipv6`）在转换中被丢掉；
- 规则集依赖第三方网盘直链，随时 403；
- 三层链路（拉订阅 → 转换 → 后处理），出问题难定位。

mihomo 原生支持 `proxy-providers` 和 `rule-providers`，客户端可以自己去取节点和规则。
所以这个项目只做三件事：

1. **服务端拉机场**——多台设备共用一个缓存，不会各自去撞机场的请求次数限制；
2. **托管规则集**——远程 URL 抓到本地，客户端只读本地；
3. **托管骨架**——一份几十行的 YAML，只有 provider 地址、分组和规则引用。

客户端拿到的是骨架，节点和规则在**运行时**由 mihomo 自己拉取合并（磁盘上不会生成完整配置）。

## 架构

```
                  ┌──────────────────────────────┐
  机场订阅  ──────▶│  mihomo-hub (FastAPI)        │
  (Clash YAML)    │                              │
                  │  SQLite: 源 / 规则集 / 骨架   │
  远程规则集 ────▶│  定时刷新 + 抓取历史          │
                  └───────────┬──────────────────┘
                              │  /profile.yaml
                              │  /api/providers/<slug>.yaml
                              │  /api/rulesets/<slug>.list
                              ▼
                  ┌──────────────────────────────┐
                  │  客户端 mihomo                │
                  │  proxy-providers → 节点       │
                  │  rule-providers  → 规则       │
                  │  内存中合并 → 路由表           │
                  └──────────────────────────────┘
```

## 快速开始

依赖与虚拟环境由 [uv](https://docs.astral.sh/uv/) 管理（`pyproject.toml` + `uv.lock`）。

```bash
cd mihomo-hub
uv sync          # 按 uv.lock 建 .venv 并安装依赖
uv run run.py    # 启动，监听 8091
```

打开 <http://127.0.0.1:8091>。

常用命令：

| 命令 | 作用 |
|---|---|
| `uv sync` | 按锁文件同步环境 |
| `uv run run.py` | 在项目环境里运行 |
| `uv add <pkg>` | 新增依赖（自动更新 `pyproject.toml` 与 `uv.lock`） |
| `uv lock --upgrade` | 升级全部依赖并重写锁文件 |
| `uv tree` | 查看依赖树 |

`.python-version` 固定为 3.12；`requires-python` 声明为 `>=3.10`。

### 使用流程

1. **订阅源** → 填机场订阅 URL（UA 默认 `clash-verge/v2.3.1`，机场据此返回原生 Clash YAML）。
   添加后会立刻抓取一次，页面能看到节点数、大小、机场流量。
2. **规则集** → 远程 URL 或直接粘贴。`behavior`/`format` 要和列表格式对上
   （Surge 风格的 `DOMAIN-SUFFIX,foo.com` 用 `classical` + `text`）。
3. **配置骨架** → 选节点来源，点「应用起始模板」。会生成 18 个分组
   （含一个可在「单节点 / 一致性哈希 / 轮询」之间切换的 `Custom` 组）。
   之后可以随便改，保存即生效。
4. 把 `http://<你的地址>:8091/profile.yaml` 填进 mihomo 客户端订阅。

### 端点

| 路径 | 用途 |
|---|---|
| `GET /profile.yaml` | 骨架（`{{base}}` 已替换为实际地址），客户端订阅这个 |
| `GET /api/providers/<slug>.yaml` | 机场缓存，**只有 proxies 段** |
| `GET /api/rulesets/<slug>.list` | 规则集原文（`text/plain`） |
| `GET /api/status` | JSON 状态，方便接监控 |
| `GET /healthz` | 健康检查 |

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `MIHOMO_HUB_DATA` | `./data` | SQLite 与缓存目录（Docker 里挂卷） |
| `MIHOMO_HUB_HOST` | `0.0.0.0` | 监听地址 |
| `MIHOMO_HUB_PORT` | `8091` | 监听端口 |
| `MIHOMO_HUB_BASE_URL` | 空 | 对外地址；留空则按请求头推断 |
| `MIHOMO_HUB_UA` | `clash-verge/v2.3.1` | 拉机场的 UA |
| `MIHOMO_HUB_SCHEDULER` | `1` | `0` 关闭后台刷新 |
| `MIHOMO_HUB_TICK` | `30` | 调度器检查间隔（秒） |
| `MIHOMO_HUB_TIMEOUT` | `30` | 抓取超时（秒） |

## Docker

```bash
docker build -t mihomo-hub .
docker run -d --name mihomo-hub \
  -p 8091:8091 \
  -v /volume1/docker/mihomo-hub:/data \
  -e MIHOMO_HUB_BASE_URL=http://192.168.1.10:8091 \
  mihomo-hub
```

或直接 `docker compose up -d`。

镜像内用 `uv sync --frozen --no-dev` 安装依赖，构建可复现（锁定在 `uv.lock`）。

> `MIHOMO_HUB_BASE_URL` 建议显式设置：如果客户端从别的网段访问，
> 自动推断出来的地址会是不可达的内网 IP。

## 设计说明

**为什么不做「服务端组装成完整配置」**

只有需要喂给不支持 providers 的客户端（Stash / 小火箭 / 旧版 Clash）时才需要。
本项目面向纯 mihomo 环境，少一层就少一处出错的地方。

**规则集为什么本地缓存**

1. 网盘直链对 UA、来源 IP 敏感，实测同一个链接在不同机器上一会儿 200 一会儿 403；
2. 规则集挂了不应该影响客户端启动——缓存能兜底；
3. 想换源只改一处，客户端不用动。

**伪节点过滤**

机场常把「流量 36.62 GB / 100 GB」「到期 2026-12-05」做成真实节点用于展示。
它们会污染 `url-test` 的候选集，默认按名称特征过滤掉。

## 已知限制

- 只服务支持 `proxy-providers` 的客户端（mihomo / Clash Meta 系）。
- 服务端不做鉴权，请只在可信网络里暴露，或自己在前面加一层反代认证。
- `SRC-IP-CIDR` 类规则依赖客户端能看到的真实源 IP；如果链路上还有一层 NAT，会失效。
- 规则集只存原文不解析，格式写错时 mihomo 会静默加载 0 条——`behavior` / `format` 要填对。

## 目录

```
app/
  config.py     环境变量
  db.py         SQLite schema 与读写
  fetch.py      抓取 / 解析 / 缓存 / 差异统计
  profile.py    骨架模板、渲染、校验
  scheduler.py  后台定时刷新
  main.py       路由与 Web UI
  templates/    Jinja2 页面
  static/       样式与少量 JS
data/           SQLite 与缓存（gitignored）
pyproject.toml  项目元数据与依赖声明
uv.lock         锁定完整依赖图
```
