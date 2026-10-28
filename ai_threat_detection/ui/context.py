from ai_threat_detection.accounts.roles import has_role, user_role


def console_context(request):
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return {}
    from ai_threat_detection.alerts.models import Notification

    return {
        "atd_role": user_role(user),
        "atd_is_admin": has_role(user, "admin"),
        "atd_is_analyst": has_role(user, "analyst"),
        "atd_unread": Notification.objects.filter(read_at__isnull=True).count(),
    }
