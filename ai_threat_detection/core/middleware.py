"""Browser-facing protections for a loopback console.

* CrossSiteBlockMiddleware: rejects requests a browser marks as cross-site
  (Sec-Fetch-Site: cross-site) and unsafe-method requests whose Origin is not
  this host — so another website open in the same browser cannot drive the
  console on 127.0.0.1. ALLOWED_HOSTS blocks DNS-rebinding Host headers.
* SecurityHeadersMiddleware: strict CSP (local assets only, no inline script),
  no-store for app pages.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from django.http import HttpResponseForbidden

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class CrossSiteBlockMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        site = request.headers.get("Sec-Fetch-Site", "")
        if site == "cross-site":
            return HttpResponseForbidden("Cross-site request blocked.")
        if request.method in UNSAFE:
            origin = request.headers.get("Origin")
            if origin and origin != "null":
                host = request.get_host()
                if urlsplit(origin).netloc != host:
                    return HttpResponseForbidden("Origin not allowed.")
            elif origin == "null":
                return HttpResponseForbidden("Opaque origin not allowed.")
        return self.get_response(request)


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        resp = self.get_response(request)
        resp.setdefault("Content-Security-Policy", CSP)
        resp.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if not request.path.startswith("/static/"):
            resp.setdefault("Cache-Control", "no-store")
        return resp
