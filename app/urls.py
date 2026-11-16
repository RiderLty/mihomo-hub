"""对外地址解析。

优先级：
  1. 面板「设置」里保存的对外地址（反向代理域名）；
  2. 反向代理转发头（Forwarded / X-Forwarded-Proto / X-Forwarded-Host /
     X-Forwarded-Port / X-Forwarded-Ssl）；
  3. 请求自身的 scheme + Host 头。

不直接依赖 ``request.base_url``：TLS 通常在反向代理上终止，而 uvicorn 只信任
来自白名单（默认 127.0.0.1）的 X-Forwarded-*；容器 / 独立反代场景下上游往往
不是 127.0.0.1，请求头会被忽略，从而把内网地址写进订阅。
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from starlette.requests import Request

from . import db

# 主机名 + 可选端口；IPv6 用 [::1] 形式
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]*(?::\d{1,5})?$")
_IPV6_RE = re.compile(r"^\[[0-9a-f:.]+\](?::\d{1,5})?$")
_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _first(value: str | None) -> str:
    """逗号分隔的转发头只取第一个（最靠近客户端的那一跳）。"""
    if not value:
        return ""
    return value.split(",")[0].strip()


def _parse_forwarded(value: str | None) -> dict[str, str]:
    """解析 RFC 7239 的 Forwarded 头，只取第一个元素。"""
    if not value:
        return {}
    out: dict[str, str] = {}
    for part in value.split(",")[0].split(";"):
        key, sep, val = part.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        if key in ("proto", "host"):
            out[key] = val.strip().strip('"')
    return out


def _clean_host(raw: str) -> str:
    """把可能带 scheme / 路径 / userinfo 的值整理成 host[:port]。"""
    value = (raw or "").strip()
    if not value:
        return ""
    if "://" in value:
        value = urlsplit(value).netloc
    elif "/" in value:
        # 既没有 scheme 又带路径，不是合法的 host[:port] 头
        return ""
    value = value.strip()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.lower()


def _valid_host(host: str) -> bool:
    if not host or not (_HOST_RE.match(host) or _IPV6_RE.match(host)):
        return False
    if _has_port(host):
        port = int(host.rsplit(":", 1)[1])
        if not 0 < port < 65536:
            return False
    return True


def _has_port(host: str) -> bool:
    if host.startswith("["):
        return "]:" in host
    return host.count(":") == 1


def _strip_default_port(host: str, scheme: str) -> str:
    default = _DEFAULT_PORTS.get(scheme)
    suffix = f":{default}"
    if default and host.endswith(suffix):
        return host[: -len(suffix)]
    return host


def detect_scheme(request: Request) -> str:
    forwarded = _parse_forwarded(request.headers.get("forwarded"))
    ssl_header = _first(request.headers.get("x-forwarded-ssl")).lower()
    forwarded_port = _first(request.headers.get("x-forwarded-port"))
    port_hint = {"443": "https", "80": "http"}.get(forwarded_port, "")
    candidates = [
        forwarded.get("proto", ""),
        _first(request.headers.get("x-forwarded-proto")),
        "https" if ssl_header in ("on", "1", "true") else "",
        "https" if _first(request.headers.get("front-end-https")).lower() == "on" else "",
        port_hint,
        request.url.scheme,
    ]
    for value in candidates:
        value = (value or "").strip().lower()
        if value in _SCHEMES:
            return value
    return "http"


def detect_host(request: Request) -> str:
    forwarded = _parse_forwarded(request.headers.get("forwarded"))
    candidates = [
        forwarded.get("host", ""),
        _first(request.headers.get("x-forwarded-host")),
        _first(request.headers.get("host")),
    ]
    for raw in candidates:
        host = _clean_host(raw)
        if host and _valid_host(host):
            return host

    # 没有任何可用 Host 头时退回 ASGI scope
    hostname = request.url.hostname or "127.0.0.1"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = request.url.port
    if port and port != _DEFAULT_PORTS.get(request.url.scheme):
        return f"{hostname}:{port}"
    return hostname


def detect_base_url(request: Request) -> str:
    """按反向代理头自动推断对外地址。"""
    scheme = detect_scheme(request)
    host = detect_host(request)

    forwarded_port = _first(request.headers.get("x-forwarded-port"))
    if forwarded_port.isdigit() and not _has_port(host):
        host = f"{host}:{forwarded_port}"
    host = _strip_default_port(host, scheme)
    return f"{scheme}://{host}"


def normalize_base_url(value: str, default_scheme: str = "http") -> str:
    """校验并规范化面板里填写的地址。

    - 没写 scheme 时补上 default_scheme（通常是当前访问协议）；
    - 去掉末尾斜杠与默认端口；
    - 允许带路径前缀（反代挂在子路径下时用得上）。
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"

    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    if scheme not in _SCHEMES:
        raise ValueError("只支持 http:// 或 https://")
    host = _clean_host(parts.netloc)
    if not host or not _valid_host(host):
        raise ValueError(f"主机名不合法：{parts.netloc or '(空)'}")
    host = _strip_default_port(host, scheme)
    path = parts.path.rstrip("/")
    return f"{scheme}://{host}{path}"


def configured_base_url() -> str:
    return (db.get_settings().get("public_base_url") or "").strip().rstrip("/")


def resolve_base_url(request: Request) -> str:
    """面板配置优先；没配置就按请求自动检测。"""
    configured = configured_base_url()
    if not configured:
        return detect_base_url(request)
    try:
        return normalize_base_url(configured, detect_scheme(request))
    except ValueError:
        # 库里存了非法值（例如手工改坏），退回自动检测而不是生成坏地址
        return detect_base_url(request)


def is_private_base(base: str) -> bool:
    """判断地址是否指向内网 / 本机，用于在设置页给出提示。"""
    host = _clean_host(urlsplit(base).netloc)
    if not host:
        return False
    if host.startswith("["):
        name = host[1:host.find("]")] if "]" in host else host[1:]
    else:
        name = host.split(":", 1)[0]
    if name == "localhost" or name.endswith((".local", ".lan", ".home.arpa")):
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local
