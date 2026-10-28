"""Keyed, stable pseudonyms for identities (IP, user, host).

HMAC-SHA256(key, scope|kind|canonical value). Stable for a given key + scope, so
events can be grouped and correlated. This is pseudonymization, not anonymization:
anyone holding the key (or able to enumerate candidate values against it) can
link pseudonyms back. Changing the key or scope breaks correlation with older data.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress

from .keys import PSEUDONYM_KEY, key_id, load_key

PSEUDONYM_SCHEME = "hmac-sha256-trunc16-v1"


def canonical_identity(kind: str, value: str) -> str:
    v = str(value).strip()
    if kind == "ip":
        try:
            return ipaddress.ip_address(v).compressed
        except ValueError:
            return v.lower()
    return v.lower()


class Pseudonymizer:
    def __init__(self, key: bytes, scope: str = "global"):
        self._key = key
        self.scope = scope
        self.key_id = key_id(key)

    @classmethod
    def from_local_key(cls, scope: str = "global") -> Pseudonymizer:
        return cls(load_key(PSEUDONYM_KEY), scope=scope)

    def pseudonym(self, kind: str, value: str | None) -> str | None:
        if value is None:
            return None
        canon = canonical_identity(kind, value)
        if not canon:
            return None
        msg = f"{self.scope}\x1f{kind}\x1f{canon}".encode()
        digest = hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:16]
        return f"{kind}_{digest}"

    def manifest(self) -> dict[str, str]:
        return {"scheme": PSEUDONYM_SCHEME, "key_id": self.key_id, "scope": self.scope}
