#!/usr/bin/env python
"""Django management entry point for AI Threat Detection."""

import os
import sys


def _safe_stdio() -> None:
    # Output contains Vietnamese text; legacy Windows code pages (cp1252) cannot encode it.
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main() -> None:
    _safe_stdio()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
