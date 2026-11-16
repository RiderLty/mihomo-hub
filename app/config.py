"""运行期配置：全部通过环境变量注入，便于后续 Docker 化。"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# 数据目录（sqlite + 缓存），Docker 里挂卷即可
DATA_DIR = Path(os.getenv("MIHOMO_HUB_DATA", str(BASE_DIR / "data"))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "hub.sqlite3"

# 监听地址
HOST = os.getenv("MIHOMO_HUB_HOST", "0.0.0.0")
PORT = int(os.getenv("MIHOMO_HUB_PORT", "8091"))

# 对外地址（反向代理域名）在面板「设置」里维护，并持久化到 SQLite；
# 留空时按请求头自动检测，不提供环境变量入口。

# 拉取机场订阅时默认使用的 UA。机场通常按 UA 返回不同格式，
# clash 系 UA 才会返回原生 Clash YAML。
DEFAULT_UA = os.getenv("MIHOMO_HUB_UA", "clash-verge/v2.3.1")

# 本地规则集的根目录：规则集 path 为相对路径时，相对它解析
RULESETS_ROOT = Path(
    os.getenv("MIHOMO_HUB_RULESETS", str(BASE_DIR))
).resolve()

# 网络
FETCH_TIMEOUT = float(os.getenv("MIHOMO_HUB_TIMEOUT", "30"))

# 后台调度
SCHEDULER_ENABLED = os.getenv("MIHOMO_HUB_SCHEDULER", "1") not in ("0", "false", "False")
SCHEDULER_TICK = int(os.getenv("MIHOMO_HUB_TICK", "30"))

APP_NAME = "mihomo-hub"
APP_VERSION = "0.1.0"
