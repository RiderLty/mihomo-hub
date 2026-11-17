"""前置配置（Front Profile）：两层分流里的边缘侧配置。

规则完全复制 NAS 骨架，只把每个分类分组的成员换成 ``[PROXY, DIRECT]``，
其中 ``PROXY`` 再指向由多个后端地址组成的后端池。这样：

- 路由器上每个分类仍可单独选 PROXY / DIRECT，直连流量不会进 NAS；
- NAS（glash）上同名分组再选具体节点，形成两层选择；
- 后端池是所有地点共享的，家里用 glash，外出用 F50 Pro 等，只换后端。
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from urllib.parse import quote, urlsplit

import httpx
import yaml

from . import urls
from .profile import render as render_placeholders

BUILTIN_TARGETS = {"DIRECT", "REJECT", "PASS", "GLOBAL", "COMPATIBLE"}
DEFAULT_BACKEND_GROUP = "PROXY"
DEFAULT_GROUP_TYPE = "select"
DEFAULT_RULE_PROVIDER_PROXY = "DIRECT"

SAFE_DIRECT_RULES = [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
]

# 默认基础模板：边缘设备自己的端口 / DNS / sniffer。
# 下面四段动态内容生成时会被覆盖，手改无效。
DEFAULT_BASE_TEMPLATE = """\
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
external-controller: 0.0.0.0:9090
tproxy-port: 7893

geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  mmdb: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
  geosite: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  asn: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  override-destination: true
  sniff:
    TLS:
      ports: [443]
    HTTP:
      ports: [80, 8080-8880]
    QUIC:
      ports: [443]

dns:
  enable: true
  ipv6: false
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - '*.localdomain'
    - '*.home.arpa'
    - '*.example'
    - '*.invalid'
    - '*.test'
    - '*.localhost'
    - time.*.com
    - ntp.*.com
    - stun.*.*
  nameserver:
    - tls://223.5.5.5
    - tls://119.29.29.29
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
  nameserver-policy:
    'geosite:cn,private':
      - tls://223.5.5.5
      - tls://119.29.29.29

# 以下由 mihomo-hub 生成并覆盖
proxies: []
proxy-groups: []
rule-providers: {}
rules: []
"""

# 中继角色（r7 这类 TPROXY 边缘设备）：不接管 DNS、不用 fake-ip，
# 域名分流靠 sniffer；tproxy-port 由 front 配置注入。
RELAY_BASE_TEMPLATE = """\
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
external-controller: 0.0.0.0:9090
tproxy-port: 7893

geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  mmdb: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
  geosite: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  asn: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  override-destination: true
  sniff:
    TLS:
      ports: [443]
    HTTP:
      ports: [80, 8080-8880]
    QUIC:
      ports: [443]

# relay 角色不接管 DNS，也不要 fake-ip：
# 一旦 fake-ip 生效而设备自身流量不走 TPROXY，设备自己会解析到 198.18.x.x 而断网。
dns:
  enable: true
  ipv6: false
  listen: 0.0.0.0:1053
  enhanced-mode: redir-host
  nameserver:
    - tls://223.5.5.5
    - tls://119.29.29.29
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
  nameserver-policy:
    'geosite:cn,private':
      - tls://223.5.5.5
      - tls://119.29.29.29

# 以下由 mihomo-hub 生成并覆盖
proxies: []
proxy-groups: []
rule-providers: {}
rules: []
"""

ROLE_TEMPLATES = {
    "relay": RELAY_BASE_TEMPLATE,
    "gateway": DEFAULT_BASE_TEMPLATE,
}


def role_template(role: str) -> str:
    return RELAY_BASE_TEMPLATE if (role or "").strip() == "relay" else DEFAULT_BASE_TEMPLATE


class FrontError(Exception):
    """前置配置无法生成。"""


# ---------------------------------------------------------------- helpers

def _group_members(group) -> list[str]:
    if not isinstance(group, dict):
        return []
    members = group.get("proxies")
    if not isinstance(members, list):
        return []
    return [str(x) for x in members]


def source_groups(source: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    groups = source.get("proxy-groups") or []
    if not isinstance(groups, list):
        return out
    for group in groups:
        if isinstance(group, dict) and group.get("name"):
            out[str(group["name"])] = group
    return out


def first_member(source: dict, name: str) -> str:
    members = _group_members(source_groups(source).get(name))
    return members[0] if members else ""


def heuristic_policy(source: dict, name: str) -> str:
    """默认跟 NAS 一致：NAS 分组第一项是 DIRECT 就直连，否则交给 NAS。"""
    first = first_member(source, name).strip().upper()
    return "DIRECT" if first == "DIRECT" else "PROXY"


def effective_policy(source: dict, name: str, overrides: dict) -> str:
    override = (overrides or {}).get(name)
    if override in ("PROXY", "DIRECT"):
        return override
    return heuristic_policy(source, name)


def rule_target(rule: str) -> str | None:
    """取一条 mihomo 规则的出口字段。"""
    text = (rule or "").strip()
    if not text:
        return None
    parts = [p.strip() for p in text.split(",")]
    if not parts:
        return None
    kind = parts[0].upper()
    if kind == "MATCH":
        return parts[1] if len(parts) >= 2 and parts[1] else None
    if kind in ("AND", "OR", "NOT"):
        # 逻辑规则里目标在最后；括号内的逗号会被拆开，但目标仍取最后一段
        return parts[-1] if len(parts) >= 2 and parts[-1] else None
    if len(parts) >= 3 and parts[2]:
        return parts[2]
    return None


def collect_targets(source: dict, backend_group: str, extra_rules=None) -> dict[str, int]:
    """按首次出现顺序收集规则里需要 shim 的目标分组。"""
    counts: dict[str, int] = {}
    rules = list(source.get("rules") or [])
    rules += list(extra_rules or [])
    for rule in rules:
        if not isinstance(rule, str):
            continue
        target = rule_target(rule)
        if not target:
            continue
        if target.upper() in BUILTIN_TARGETS or target == backend_group:
            continue
        counts[target] = counts.get(target, 0) + 1
    return counts


def valid_group_name(name: str) -> bool:
    return bool(name) and name.upper() not in BUILTIN_TARGETS and "," not in name


def valid_backend_name(name: str) -> bool:
    return bool(name) and name.upper() not in BUILTIN_TARGETS and "," not in name


def valid_role(role: str) -> bool:
    return (role or "").strip() in ROLE_TEMPLATES


def port_or_default(value, default: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 0 < port < 65536 else default


def parse_custom_rules(text: str) -> list[str]:
    """附加规则：每行一条，允许带 YAML 列表前缀 ``- ``。"""
    out: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        elif line == "-":
            continue
        if line:
            out.append(line)
    return out


def subscription_url(base: str, slug: str, token: str = "") -> str:
    url = f"{base.rstrip('/')}/api/fronts/{slug}.yaml"
    if token:
        url += "?token=" + quote(token, safe="")
    return url


def front_base(request, front: dict) -> str:
    """前置配置的 hub 地址：auto 按订阅请求推断，global 用全局设置，custom 手填。"""
    mode = (front.get("base_mode") or "auto").strip()
    if mode == "custom":
        value = (front.get("base_url") or "").strip()
        if value:
            try:
                return urls.normalize_base_url(value, urls.detect_scheme(request))
            except ValueError:
                pass
    if mode == "global":
        return urls.resolve_base_url(request)
    return urls.detect_base_url(request)


# ---------------------------------------------------------------- loading

def load_source(text: str, base: str) -> dict:
    if not (text or "").strip():
        raise FrontError("还没有 NAS 骨架内容，请先在「配置骨架」页面生成")
    try:
        doc = yaml.safe_load(render_placeholders(text, base))
    except Exception as exc:  # noqa: BLE001
        raise FrontError(f"NAS 骨架 YAML 解析失败：{exc}") from exc
    if not isinstance(doc, dict):
        raise FrontError("NAS 骨架顶层必须是 YAML 映射")
    return doc


def load_base(template: str, base: str) -> dict:
    raw = template if (template or "").strip() else DEFAULT_BASE_TEMPLATE
    try:
        doc = yaml.safe_load(render_placeholders(raw, base))
    except Exception as exc:  # noqa: BLE001
        raise FrontError(f"基础模板 YAML 解析失败：{exc}") from exc
    if not isinstance(doc, dict):
        raise FrontError("基础模板顶层必须是 YAML 映射")
    return doc


def check_base_template(template: str, base: str = "http://localhost") -> str:
    try:
        load_base(template, base)
    except FrontError as exc:
        return str(exc)
    return ""


# ---------------------------------------------------------------- generation

def _backend_dict(backend) -> dict:
    name = str(backend["name"] or "").strip()
    if not valid_backend_name(name):
        raise FrontError(f"后端名称不合法：{name or '(空)'}")

    kind = str(backend["kind"] or "socks5").strip() or "socks5"
    server = str(backend["server"] or "").strip()
    if not server:
        raise FrontError(f"后端 {name} 缺少 server")
    try:
        port = int(backend["port"])
    except (TypeError, ValueError):
        raise FrontError(f"后端 {name} 的端口不合法") from None
    if not 0 < port < 65536:
        raise FrontError(f"后端 {name} 的端口不合法")

    data: dict = {"name": name, "type": kind, "server": server, "port": port}
    if backend["username"]:
        data["username"] = backend["username"]
    if backend["password"]:
        data["password"] = backend["password"]
    if backend["udp"]:
        data["udp"] = True
    if backend["tls"]:
        data["tls"] = True
    if backend["sni"]:
        data["sni"] = backend["sni"]
    if backend["skip_cert_verify"]:
        data["skip-cert-verify"] = True

    extra_raw = backend["extra_yaml"]
    if extra_raw and str(extra_raw).strip():
        try:
            extra = yaml.safe_load(extra_raw)
        except Exception as exc:  # noqa: BLE001
            raise FrontError(f"后端 {name} 的高级 YAML 解析失败：{exc}") from exc
        if extra is not None and not isinstance(extra, dict):
            raise FrontError(f"后端 {name} 的高级 YAML 必须是映射")
        if extra:
            extra.pop("name", None)
            data.update(extra)
    return data


def build_proxies(backends) -> list[dict]:
    out = []
    for backend in backends:
        if not backend["enabled"]:
            continue
        out.append(_backend_dict(backend))
    if not out:
        raise FrontError("没有启用任何后端，请先在「代理后端」里添加并选中")
    names = [p["name"] for p in out]
    if len(names) != len(set(names)):
        raise FrontError("启用的后端名称有重复")
    return out


def build_backend_group(front: dict, proxies: list[dict]) -> dict:
    name = (front.get("backend_group_name") or DEFAULT_BACKEND_GROUP).strip() or DEFAULT_BACKEND_GROUP
    if not valid_group_name(name):
        raise FrontError(f"后端分组名不合法：{name}")
    if name in {p["name"] for p in proxies}:
        raise FrontError(f"后端分组名 {name} 与某个后端名称冲突")

    group_type = (front.get("backend_group_type") or DEFAULT_GROUP_TYPE).strip() or DEFAULT_GROUP_TYPE
    if group_type not in ("select", "fallback", "url-test", "load-balance", "relay"):
        group_type = DEFAULT_GROUP_TYPE

    proxies_order = [p["name"] for p in proxies]
    if front.get("include_direct"):
        proxies_order.append("DIRECT")

    group: dict = {"name": name, "type": group_type, "proxies": proxies_order}
    if group_type in ("fallback", "url-test", "load-balance"):
        group["url"] = "http://www.gstatic.com/generate_204"
        group["interval"] = 300
        if group_type == "load-balance":
            group["strategy"] = "consistent-hashing"
    return group


def build_shims(source: dict, backend_group: str, overrides: dict, extra_rules=None) -> list[dict]:
    shims = []
    for target in collect_targets(source, backend_group, extra_rules):
        policy = effective_policy(source, target, overrides)
        members = ["DIRECT", backend_group] if policy == "DIRECT" else [backend_group, "DIRECT"]
        shims.append({"name": target, "type": "select", "proxies": members})
    return shims


def _rebase_hub_url(url: str, base: str) -> str:
    """源骨架里如果是写死的 hub 地址，改写成当前前置配置的 base。"""
    if not isinstance(url, str):
        return url
    marker = "/api/rulesets/"
    idx = url.find(marker)
    if idx < 0:
        return url
    return base.rstrip("/") + url[idx:]


def build_rule_providers(source: dict, base: str, provider_proxy: str, backend_group: str) -> dict:
    raw = source.get("rule-providers") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    for name, cfg in raw.items():
        if not isinstance(cfg, dict):
            continue
        item = dict(cfg)
        if isinstance(item.get("url"), str):
            item["url"] = _rebase_hub_url(item["url"], base)
        if provider_proxy in ("DIRECT", backend_group):
            item["proxy"] = provider_proxy
        out[str(name)] = item
    return out


def _host_direct_rule(host: str) -> str | None:
    host = (host or "").strip()
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return f"DOMAIN,{host},DIRECT"
    if ip.version == 6:
        return f"IP-CIDR6,{host}/128,DIRECT,no-resolve"
    return f"IP-CIDR,{host}/32,DIRECT,no-resolve"


def _private_source_rule(host: str) -> str | None:
    """后端 / hub 自己发出的流量必须直连，避免回环。"""
    host = (host or "").strip()
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version != 4 or not (ip.is_private or ip.is_loopback or ip.is_link_local):
        return None
    return f"SRC-IP-CIDR,{host}/32,DIRECT,no-resolve"


def build_rules(
    source: dict,
    backend_group: str,
    base: str,
    backends,
    custom_rules=None,
) -> list[str]:
    rules = [str(r) for r in (source.get("rules") or []) if isinstance(r, (str, int, float))]
    existing = set(rules)
    prepend: list[str] = []

    def add(rule: str) -> None:
        if rule and rule not in existing and rule not in prepend:
            prepend.append(rule)

    # 后端自身必须直连，否则 MATCH 会把“连接后端”也送进后端
    for backend in backends:
        if not backend["enabled"]:
            continue
        server = str(backend["server"] or "")
        rule = _host_direct_rule(server)
        if rule:
            add(rule)
        rule = _private_source_rule(server)
        if rule:
            add(rule)

    # hub 的地址也直连，保证规则集能直接下载
    hub_host = urlsplit(base).hostname or ""
    rule = _host_direct_rule(hub_host)
    if rule:
        add(rule)
    rule = _private_source_rule(hub_host)
    if rule:
        add(rule)

    for rule in SAFE_DIRECT_RULES:
        add(rule)

    # 每台边缘设备自己的附加规则：源 IP、BT 端口、IPv6 直连等
    for rule in custom_rules or []:
        add(str(rule))

    rules = prepend + rules
    if not any(str(r).strip().upper().startswith("MATCH") for r in rules):
        rules.append(f"MATCH,{backend_group}")
    return rules


def render_front(front: dict, backends, source_text: str, base: str) -> str:
    role = (front.get("role") or "relay").strip()
    if role not in ROLE_TEMPLATES:
        role = "relay"
    source = load_source(source_text, base)
    template = (front.get("base_template") or "").strip() or role_template(role)
    doc = load_base(template, base)

    proxies = build_proxies(backends)
    backend_group_name = (
        front.get("backend_group_name") or DEFAULT_BACKEND_GROUP
    ).strip() or DEFAULT_BACKEND_GROUP
    backend_group = build_backend_group(front, proxies)
    overrides = front.get("group_defaults") or {}
    custom = parse_custom_rules(front.get("custom_rules") or "")
    shims = build_shims(source, backend_group_name, overrides, custom)
    provider_proxy = (front.get("rule_provider_proxy") or DEFAULT_RULE_PROVIDER_PROXY).strip()

    doc["proxies"] = proxies
    doc["proxy-groups"] = [backend_group] + shims
    doc["rule-providers"] = build_rule_providers(source, base, provider_proxy, backend_group_name)
    doc["rules"] = build_rules(source, backend_group_name, base, backends, custom)
    doc.pop("proxy-providers", None)

    # 中继 / 网关都提供 Controller；relay 必须带 tproxy-port
    doc["external-controller"] = f"0.0.0.0:{port_or_default(front.get('api_port'), 9090)}"
    if role == "relay" or "tproxy-port" in doc:
        doc["tproxy-port"] = port_or_default(front.get("tproxy_port"), 7893)

    body = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
    return (
        f"# mihomo-hub front profile: {front.get('name') or front.get('slug') or ''}\n"
        f"# role: {role}; rules copied from NAS profile; targets are front shim groups\n"
        f"{body}"
    )


# ---------------------------------------------------------------- inspection

def target_groups(source_text: str, front: dict, base: str) -> tuple[list[dict], list[dict]]:
    """给面板用的分类分组列表：默认值、NAS 首项、引用次数。"""
    issues: list[dict] = []
    try:
        source = load_source(source_text, base)
    except FrontError as exc:
        return [], [{"level": "error", "message": str(exc)}]

    backend_group = (
        front.get("backend_group_name") or DEFAULT_BACKEND_GROUP
    ).strip() or DEFAULT_BACKEND_GROUP
    overrides = front.get("group_defaults") or {}
    custom = parse_custom_rules(front.get("custom_rules") or "")
    groups = source_groups(source)
    out: list[dict] = []
    for name, count in collect_targets(source, backend_group, custom).items():
        first = first_member(source, name) or "—"
        heuristic = heuristic_policy(source, name)
        override = overrides.get(name)
        override = override if override in ("PROXY", "DIRECT") else ""
        effective = override or heuristic
        out.append({
            "name": name,
            "source_first": first,
            "count": count,
            "heuristic": heuristic,
            "override": override,
            "effective": effective,
            "known": name in groups,
        })
        if name not in groups:
            issues.append({
                "level": "warn",
                "message": f"NAS 骨架的规则目标 '{name}' 不是已定义分组，已为它生成 shim",
            })
    if backend_group in collect_targets(source, "", custom):
        issues.append({
            "level": "warn",
            "message": (
                f"NAS 规则直接引用了后端分组名 '{backend_group}'，"
                "这个分类无法单独切直连"
            ),
        })
    return out, issues


def validate_generated(text: str, front: dict) -> list[dict]:
    issues: list[dict] = []
    try:
        doc = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        return [{"level": "error", "message": f"生成的 YAML 解析失败：{exc}"}]
    if not isinstance(doc, dict):
        return [{"level": "error", "message": "生成的配置不是 YAML 映射"}]

    if "proxy-providers" in doc:
        issues.append({
            "level": "warn",
            "message": "生成结果里仍有 proxy-providers，脚本身份可能有误",
        })

    proxies = doc.get("proxies") or []
    proxy_names = {
        str(p.get("name")) for p in proxies
        if isinstance(p, dict) and p.get("name")
    }
    if len(proxy_names) != len(proxies):
        issues.append({"level": "error", "message": "有后端缺少名称或名称重复"})

    groups = doc.get("proxy-groups") or []
    group_names = {
        str(g.get("name")) for g in groups
        if isinstance(g, dict) and g.get("name")
    }
    if len(group_names) != len(groups):
        issues.append({"level": "error", "message": "有分组缺少名称或名称重复"})

    allowed = proxy_names | group_names | BUILTIN_TARGETS
    for group in groups:
        if not isinstance(group, dict):
            continue
        gname = group.get("name", "?")
        for ref in group.get("proxies") or []:
            if str(ref) not in allowed:
                issues.append({
                    "level": "error",
                    "message": f"分组 '{gname}' 引用了不存在的代理 '{ref}'",
                })
        if group.get("use"):
            issues.append({
                "level": "warn",
                "message": f"分组 '{gname}' 使用了 proxy-provider，前置配置里不应出现",
            })

    providers = doc.get("rule-providers") or {}
    if not isinstance(providers, dict):
        providers = {}
        issues.append({"level": "error", "message": "rule-providers 必须是映射"})

    rules = doc.get("rules") or []
    has_match = False
    for rule in rules:
        if not isinstance(rule, str):
            continue
        target = rule_target(rule)
        parts = [p.strip() for p in rule.split(",")]
        if parts and parts[0].upper() == "RULE-SET":
            if len(parts) >= 2 and parts[1] not in providers:
                issues.append({
                    "level": "error",
                    "message": f"规则 '{rule}' 引用了不存在的 rule-provider '{parts[1]}'",
                })
        if target:
            if target not in allowed:
                issues.append({
                    "level": "error",
                    "message": f"规则 '{rule}' 的出口 '{target}' 未定义",
                })
        if parts and parts[0].upper() == "MATCH":
            has_match = True

    if not has_match:
        issues.append({"level": "warn", "message": "生成结果里没有 MATCH 兜底规则"})
    if not rules:
        issues.append({"level": "warn", "message": "NAS 骨架没有 rules，前置配置不会分流"})

    backend_group = (front.get("backend_group_name") or DEFAULT_BACKEND_GROUP).strip()
    if backend_group and backend_group not in group_names:
        issues.append({"level": "error", "message": f"后端分组 '{backend_group}' 没有生成"})

    role = (front.get("role") or "relay").strip()
    if not doc.get("external-controller"):
        issues.append({
            "level": "error" if role == "relay" else "warn",
            "message": "没有 external-controller，边缘设备无法挂面板或做健康检查",
        })

    sniffer = doc.get("sniffer") or {}
    sniffer_ok = isinstance(sniffer, dict) and bool(sniffer.get("enable"))
    if role == "relay":
        if "tproxy-port" not in doc:
            issues.append({"level": "error", "message": "relay 角色缺少 tproxy-port"})
        if not sniffer_ok:
            issues.append({
                "level": "error",
                "message": "relay 角色必须开启 sniffer（域名分流依赖 TLS SNI）",
            })
        dns = doc.get("dns") or {}
        if isinstance(dns, dict) and str(dns.get("enhanced-mode") or "").lower() == "fake-ip":
            issues.append({
                "level": "error",
                "message": "relay 角色不能使用 fake-ip，否则边缘设备自身可能断网",
            })
        sniff = sniffer.get("sniff") if isinstance(sniffer, dict) else None
        if isinstance(sniff, dict) and "QUIC" not in sniff:
            issues.append({
                "level": "warn",
                "message": "sniffer 没有 QUIC，UDP/443 会退化到 IP 规则",
            })
    else:
        if "tproxy-port" not in doc:
            issues.append({
                "level": "warn",
                "message": "gateway 没有 tproxy-port，透明代理可能不可用",
            })
        if not sniffer_ok:
            issues.append({"level": "warn", "message": "建议给 gateway 开启 sniffer"})
    return issues


# ---------------------------------------------------------------- provider urls

_PROVIDER_URL_CACHE: dict[str, tuple[float, dict]] = {}
_PROVIDER_URL_TTL = 60.0


async def _probe_url(client: httpx.AsyncClient, url: str) -> tuple[bool, int | None, str]:
    try:
        resp = await client.head(url)
        if resp.status_code in (400, 405, 501):
            resp = await client.get(url)
    except Exception:
        try:
            resp = await client.get(url)
        except Exception as exc:  # noqa: BLE001
            return False, None, f"{type(exc).__name__}: {exc}"
    if resp.status_code < 400:
        return True, resp.status_code, ""
    return False, resp.status_code, f"HTTP {resp.status_code}"


async def check_provider_urls(text: str) -> list[dict]:
    """检查生成配置里每个 rule-provider URL 是否可达，结果缓存 60 秒。"""
    try:
        doc = yaml.safe_load(text) or {}
    except Exception as exc:  # noqa: BLE001
        return [{"name": "", "url": "", "ok": False, "status": None,
                 "error": f"YAML 解析失败：{exc}", "cached": False}]
    providers = doc.get("rule-providers") or {}
    if not isinstance(providers, dict):
        return []

    jobs: list[tuple[str, str]] = []
    for name, cfg in providers.items():
        if isinstance(cfg, dict) and isinstance(cfg.get("url"), str):
            jobs.append((str(name), cfg["url"]))
    if not jobs:
        return []

    async def check_one(name: str, url: str) -> dict:
        now = time.monotonic()
        cached = _PROVIDER_URL_CACHE.get(url)
        if cached and cached[0] > now:
            item = dict(cached[1])
            item["name"] = name
            item["cached"] = True
            return item
        ok, status, error = await _probe_url(client, url)
        item = {"name": name, "url": url, "ok": ok, "status": status,
                "error": error, "cached": False}
        _PROVIDER_URL_CACHE[url] = (now + _PROVIDER_URL_TTL, dict(item))
        return item

    async with httpx.AsyncClient(
        timeout=5, follow_redirects=True, verify=False,
    ) as client:
        return list(await asyncio.gather(*(check_one(n, u) for n, u in jobs)))
