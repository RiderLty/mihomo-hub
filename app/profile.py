"""骨架配置：起始模板、渲染、校验。

客户端订阅的是“骨架”——只有 providers 的 URL、分组和规则，
节点与规则由 mihomo 运行时自己去拉。
"""
from __future__ import annotations

import re
import yaml

from .urls import is_private_base

BASE_PLACEHOLDER = "{{base}}"

_LOOKAHEAD = re.compile(r"\(\?[=!<]")
_HUB_ENDPOINT_RE = re.compile(r"https?://[^\s'\"#]+/api/(?:providers|rulesets)/[^\s'\"#]+")


def render(text: str, base: str) -> str:
    """把 {{base}} 换成实际对外地址。"""
    return (text or "").replace(BASE_PLACEHOLDER, base.rstrip("/"))


def _local_slug(url: str, marker: str) -> str | None:
    """从 /api/providers/xxx.yaml 这类地址里取出 slug。"""
    if not url:
        return None
    m = re.search(rf"/{marker}/([^/?#]+?)(?:\.(?:yaml|yml|list|txt|mrs))?(?:[?#]|$)", url)
    return m.group(1) if m else None


def validate(text: str, proxy_slugs: set[str], rule_slugs: set[str],
             base: str = "http://localhost") -> list[dict]:
    """返回问题列表：[{level: 'error'|'warn', message}]"""
    issues: list[dict] = []
    if not (text or "").strip():
        issues.append({"level": "error", "message": "骨架还是空的，先「应用起始模板」或自己写一份"})
        return issues

    # 写死的内网地址：通过反向代理访问时客户端拉不到，提醒改用 {{base}}
    literal = sorted({
        u.rstrip(".,;)]}")
        for u in _HUB_ENDPOINT_RE.findall(text)
        if is_private_base(u)
    })
    if literal:
        more = f" 等 {len(literal)} 处" if len(literal) > 1 else ""
        issues.append({
            "level": "warn",
            "message": (
                f"骨架里写死了内网地址 {literal[0]}{more}，建议改成 "
                f"{BASE_PLACEHOLDER}/api/...；否则通过反向代理访问的客户端拉不到规则"
            ),
        })

    # 先渲染再解析：模板里的 {{base}} 单独存在时不是合法 YAML
    try:
        doc = yaml.safe_load(render(text, base))
    except Exception as exc:  # noqa: BLE001
        issues.append({"level": "error", "message": f"YAML 解析失败：{exc}"})
        return issues

    if not isinstance(doc, dict):
        issues.append({"level": "error", "message": "顶层必须是一个 YAML 映射"})
        return issues

    providers = doc.get("proxy-providers") or {}
    rule_providers = doc.get("rule-providers") or {}
    groups = doc.get("proxy-groups") or []
    rules = doc.get("rules") or []

    if not providers:
        issues.append({"level": "warn", "message": "没有定义 proxy-providers，客户端将没有节点可用"})

    for name, cfg in providers.items():
        url = (cfg or {}).get("url", "")
        slug = _local_slug(url, "providers")
        if slug and slug not in proxy_slugs:
            issues.append({
                "level": "error",
                "message": f"proxy-providers.{name} 指向的订阅源 '{slug}' 在 hub 里不存在",
            })

    for name, cfg in rule_providers.items():
        url = (cfg or {}).get("url", "")
        slug = _local_slug(url, "rulesets")
        if slug and slug not in rule_slugs:
            issues.append({
                "level": "error",
                "message": f"rule-providers.{name} 指向的规则集 '{slug}' 在 hub 里不存在",
            })

    group_names = {g.get("name") for g in groups if isinstance(g, dict)}
    if not groups:
        issues.append({"level": "warn", "message": "没有定义 proxy-groups，规则里无法指定出口"})

    for g in groups:
        if not isinstance(g, dict):
            continue
        name = g.get("name", "?")
        for used in g.get("use") or []:
            if used not in providers:
                issues.append({
                    "level": "error",
                    "message": f"分组 '{name}' 引用了不存在的 proxy-provider '{used}'",
                })
        for ref in g.get("proxies") or []:
            ref = str(ref)
            if ref in ("DIRECT", "REJECT", "PASS", "COMPATIBLE"):
                continue
            if ref not in group_names and ref not in providers:
                issues.append({
                    "level": "warn",
                    "message": f"分组 '{name}' 里的 '{ref}' 既不是已定义的分组，也不在节点提供商中",
                })
        if g.get("type") == "select" and not (g.get("proxies") or g.get("use")):
            issues.append({"level": "error", "message": f"分组 '{name}' 是 select 但没有任何候选项"})
        for key in ("filter", "exclude-filter", "exclude-type"):
            val = g.get(key)
            if isinstance(val, str) and _LOOKAHEAD.search(val):
                issues.append({
                    "level": "error",
                    "message": f"分组 '{name}' 的 {key} 使用了 lookahead 正则，mihomo(Go RE2) 不支持",
                })

    rule_set_names = set(rule_providers.keys())
    for r in rules:
        if not isinstance(r, str):
            continue
        parts = [p.strip() for p in r.split(",")]
        if not parts:
            continue
        if parts[0] == "RULE-SET" and len(parts) >= 3:
            if parts[1] not in rule_set_names:
                issues.append({
                    "level": "error",
                    "message": f"规则 '{r}' 引用了不存在的 rule-provider '{parts[1]}'",
                })
            target = parts[2]
            if target not in group_names and target not in ("DIRECT", "REJECT", "PASS"):
                issues.append({
                    "level": "error",
                    "message": f"规则 '{r}' 的出口 '{target}' 未定义",
                })
        elif parts[0] == "MATCH" and len(parts) >= 2:
            if parts[1] not in group_names and parts[1] not in ("DIRECT", "REJECT"):
                issues.append({"level": "error", "message": f"MATCH 指向未定义的分组 '{parts[1]}'"})

    if rules and not any(isinstance(r, str) and r.strip().upper().startswith("MATCH")
                         for r in rules):
        issues.append({"level": "warn", "message": "最后没有 MATCH 兜底规则，未命中的流量会被拒绝"})

    return issues


def _clip(text: str) -> str:
    return text.strip("\n") + "\n"


def _rule_providers_block(rulesets: list[tuple[str, str, str, str]]) -> str:
    """生成 rule-providers 段。rulesets: [(slug, target, behavior, format)]"""
    if not rulesets:
        return "rule-providers: {}\n# 在「规则集」页面添加后重新生成，这里会自动出现对应条目\n"
    out = ["rule-providers:"]
    for slug, _target, behavior, fmt in rulesets:
        out += [
            f"  {slug}:",
            "    type: http",
            f"    behavior: {behavior or 'classical'}",
            f"    format: {fmt or 'text'}",
            f"    url: {{{{base}}}}/api/rulesets/{slug}.list",
            "    interval: 86400",
            f"    path: ./ruleset/{slug}.list",
        ]
    return "\n".join(out) + "\n"


def starter_template(provider_slug: str, rulesets: list[tuple[str, str, str, str]]) -> str:
    """生成起始骨架。

    rulesets: [(slug, target, behavior, format)]，按顺序插入 RULE-SET。
    分组结构沿用原有 urltest.ini 的设计（18 组），
    但把 subconverter 的 lookahead 正则换成了 RE2 兼容写法。
    """
    rule_set_lines = "\n".join(
        f"  - RULE-SET,{slug},{target}" for slug, target, _b, _f in rulesets
    ) or "  # 还没有规则集，可在「规则集」页面添加后重新生成"
    rule_providers = _rule_providers_block(rulesets)

    return _clip(f"""\
# ============================================================
# mihomo 配置骨架 —— 由 mihomo-hub 生成/维护
# 客户端订阅地址：{{{{base}}}}/profile.yaml
#
# 设计：节点来自 proxy-providers，规则来自 rule-providers，
#       本文件只负责“分组”和“把规则指向分组”。
# ============================================================

mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
external-controller: 0.0.0.0:9090

# 国内直连 GitHub 拉不动 geo 数据，统一走 jsDelivr 镜像
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

# ---------------- 节点来源 ----------------
proxy-providers:
  {provider_slug}:
    type: http
    url: {{{{base}}}}/api/providers/{provider_slug}.yaml
    interval: 21600          # 客户端兜底刷新，实际以 hub 的缓存为准
    path: ./providers/{provider_slug}.yaml
    health-check:
      enable: true
      url: http://www.gstatic.com/generate_204
      interval: 600

# ---------------- 规则来源 ----------------
{rule_providers}
# ---------------- 分组 ----------------
proxy-groups:
  - name: UrlTest
    type: url-test
    use: [{provider_slug}]
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

  - name: 负载均衡-哈希
    type: load-balance
    strategy: consistent-hashing
    use: [{provider_slug}]
    filter: '港|HK|Hong Kong'
    url: http://www.gstatic.com/generate_204
    interval: 300

  - name: 负载均衡-轮询
    type: load-balance
    strategy: round-robin
    use: [{provider_slug}]
    filter: '港|HK|Hong Kong'
    url: http://www.gstatic.com/generate_204
    interval: 300

  - name: HK
    type: select
    use: [{provider_slug}]
    filter: '港|HK|Hong Kong'

  - name: SG
    type: select
    use: [{provider_slug}]
    filter: '新|狮城|SG|Singapore'

  - name: TW
    type: select
    use: [{provider_slug}]
    filter: '台|新北|彰化|TW|Taiwan'

  - name: JP
    type: select
    use: [{provider_slug}]
    filter: '日本|东京|大阪|埼玉|JP|Japan'

  - name: US
    type: select
    use: [{provider_slug}]
    filter: '美|洛杉矶|硅谷|达拉斯|费利蒙|凤凰城|芝加哥|圣何塞|西雅图|US|USA'

  - name: Proxies
    type: select
    use: [{provider_slug}]
    proxies: [UrlTest, DIRECT, HK, SG, JP, US, TW]

  - name: Custom
    type: select
    proxies: [UrlTest, 负载均衡-哈希, 负载均衡-轮询, HK, SG, JP, US, TW]

  - name: Apple
    type: select
    proxies: [DIRECT, Proxies]

  - name: MicroSoft
    type: select
    proxies: [DIRECT, Proxies]

  - name: Telegram
    type: select
    proxies: [Proxies, HK, SG]

  - name: Streaming
    type: select
    proxies: [Proxies, HK, SG, JP, US, TW]

  - name: Netease
    type: select
    proxies: [DIRECT, Proxies]

  - name: StreamingSE
    type: select
    proxies: [DIRECT, Proxies, HK, TW]

# ---------------- 规则 ----------------
rules:
  # —— 私有地址直连：必须放在最前 ——
  # 否则内网互访（含 hub 自己的 provider 拉取、局域网设备）会被送进代理
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve

  # —— 自定义规则 ——
  # 放在这里，优先级高于下面所有公共规则集。示例（改成你自己的）：
  #   - DOMAIN-SUFFIX,example.com,Proxies
  #   - DOMAIN,api.example.net,Streaming
  #   - DOMAIN-SUFFIX,intranet.example.com,DIRECT
  #   - SRC-IP-CIDR,192.168.1.50/32,DIRECT
  #   - DST-PORT,22,DIRECT

  # —— 公共规则集 ——
{rule_set_lines}

  # —— 兜底 ——
  - GEOIP,CN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,Proxies
""")
