from __future__ import annotations

import json

from django import template

register = template.Library()


@register.filter
def pct(v):
    if v is None or v == "":
        return "N/A"
    try:
        return f"{float(v) * 100:.1f}%"
    except (TypeError, ValueError):
        return "N/A"


@register.filter
def num(v, digits=3):
    if v is None or v == "":
        return "N/A"
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int):
        return f"{v:,}".replace(",", " ")
    try:
        f = float(v)
        if f.is_integer() and abs(f) < 1e15:
            return f"{int(f):,}".replace(",", " ")
        return f"{f:.{int(digits)}f}"
    except (TypeError, ValueError):
        return str(v)


@register.filter
def get(d, key):
    if isinstance(d, dict):
        return d.get(key)
    return None


@register.filter
def short(v, n=12):
    s = "" if v is None else str(v)
    return s if len(s) <= int(n) else s[: int(n)] + "…"


@register.filter
def pretty(v):
    return json.dumps(v, indent=1, ensure_ascii=False, default=str)


@register.filter
def items_sorted(d):
    if not isinstance(d, dict):
        return []
    return sorted(d.items())
