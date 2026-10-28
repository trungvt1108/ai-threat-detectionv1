"""Three local roles mapped to Django groups. Checked server-side on every view (deny by default).

admin   : sources, datasets, training/promotion/thresholds, rules, suppressions, retention, raw-identity policy
analyst : redacted evidence, triage/notes/feedback, reports, suppressions (scoped, expiring)
viewer  : read-only redacted views
"""

from __future__ import annotations

from functools import wraps

from django.contrib.auth.models import Group
from django.http import HttpResponseForbidden
from django.shortcuts import redirect

from ai_threat_detection.conf import get_config

ROLE_GROUPS = {"admin": "atd_admin", "analyst": "atd_analyst", "viewer": "atd_viewer"}
RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def ensure_groups() -> None:
    for g in ROLE_GROUPS.values():
        Group.objects.get_or_create(name=g)


def user_role(user) -> str | None:
    if not getattr(user, "is_authenticated", False) or not user.is_active:
        return None
    if user.is_superuser:
        return "admin"
    names = set(user.groups.values_list("name", flat=True))
    for role in ("admin", "analyst", "viewer"):
        if ROLE_GROUPS[role] in names:
            return role
    return None


def has_role(user, minimum: str) -> bool:
    r = user_role(user)
    return r is not None and RANK[r] >= RANK[minimum]


def can_view_raw_identity(user) -> bool:
    return get_config().allow_raw_identity_view and user_role(user) == "admin"


def role_required(minimum: str):
    def deco(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(f"/login/?next={request.path}")
            if not has_role(request.user, minimum):
                return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
            return view(request, *args, **kwargs)

        return wrapper

    return deco


def set_role(user, role: str) -> None:
    if role not in ROLE_GROUPS:
        raise ValueError("unknown role")
    ensure_groups()
    user.groups.remove(*Group.objects.filter(name__in=ROLE_GROUPS.values()))
    user.groups.add(Group.objects.get(name=ROLE_GROUPS[role]))
