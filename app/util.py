"""通用小工具。"""
from __future__ import annotations

import re
import unicodedata

_ASCII_OK = re.compile(r"[^a-z0-9]+")


def slugify(text: str, fallback: str = "item") -> str:
    """把名称转成 URL 友好的 slug。

    中文无法直接音译，退化为 fallback（调用方应保证唯一性）。
    """
    norm = unicodedata.normalize("NFKD", text or "")
    ascii_only = norm.encode("ascii", "ignore").decode("ascii").lower()
    slug = _ASCII_OK.sub("-", ascii_only).strip("-")
    return slug or fallback


def ensure_unique(slug: str, exists) -> str:
    """exists(slug)->bool，冲突时追加 -2/-3..."""
    if not exists(slug):
        return slug
    i = 2
    while exists(f"{slug}-{i}"):
        i += 1
    return f"{slug}-{i}"


def human_size(n: int | None) -> str:
    if not n:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "B" else f"{int(v)} {u}"
        v /= 1024
    return f"{n} B"


def mask_secret(value: str | None, keep: int = 4) -> str:
    if not value:
        return ""
    s = str(value)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * 8}{s[-keep:]}"


def parse_userinfo(header_value: str | None) -> dict | None:
    """解析机场的 subscription-userinfo 头。

    形如: upload=1234; download=5678; total=107374182400; expire=1735689600
    """
    if not header_value:
        return None
    out: dict[str, str] = {}
    for part in header_value.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    if not out:
        return None
    return out


def bytes_to_human(num: int | float | None) -> str:
    if num is None:
        return "-"
    try:
        n = float(num)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "GB", "TB"):
        pass
    gb = n / (1024 ** 3)
    if gb >= 1024:
        return f"{gb / 1024:.2f} TB"
    if gb >= 1:
        return f"{gb:.2f} GB"
    mb = n / (1024 ** 2)
    if mb >= 1:
        return f"{mb:.0f} MB"
    return f"{n:.0f} B"
