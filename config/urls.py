from django.conf import settings
from django.urls import include, path, re_path

urlpatterns = [
    path("", include("ai_threat_detection.ui.urls")),
]

if getattr(settings, "ATD_SERVE_STATIC", False):
    # Loopback single-analyst console: serve the app's own static files without DEBUG.
    from django.contrib.staticfiles.views import serve

    urlpatterns += [re_path(r"^static/(?P<path>.*)$", serve, {"insecure": True})]
