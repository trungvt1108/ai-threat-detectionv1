from __future__ import annotations

from .auth_json import AuthJsonAdapter
from .auth_syslog import AuthSyslogAdapter
from .base import Adapter
from .http_combined import HttpCombinedAdapter
from .http_json import HttpJsonAdapter
from .suricata_eve import SuricataEveAdapter

ADAPTERS: dict[str, Adapter] = {
    a.name: a
    for a in (
        HttpJsonAdapter(),
        HttpCombinedAdapter(),
        AuthJsonAdapter(),
        AuthSyslogAdapter(),
        SuricataEveAdapter(),
    )
}


def get_adapter(name: str) -> Adapter:
    try:
        return ADAPTERS[name]
    except KeyError:
        raise ValueError(f"Unsupported source type: {name!r}") from None
