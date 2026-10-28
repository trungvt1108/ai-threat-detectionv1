"""Streaming, bounded reading of NDJSON / JSON-array log files.

Every record carries a byte offset and line number so imports are idempotent
(identity = file key + offset) and resumable from a checkpoint. Lines longer
than ``max_line_bytes`` are skipped up to the next newline and reported; the
trailing unterminated line is only returned when the caller says the file is
final (batch import), never while following a file that may still be written.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

BLOCK = 1024 * 1024
HEAD_BYTES = 4096


@dataclass
class RawRecord:
    offset: int
    line_no: int
    data: bytes
    end_offset: int
    status: str  # ok | oversized | partial


@dataclass
class FileIdentity:
    file_key: str
    size: int
    stat_id: str


def head_key(path: Path, require_newline: bool = False) -> str | None:
    """Fingerprint of the first line (<= 4 KiB). Stable while a file is appended to,
    changes when the file is rotated/replaced. Returns None for empty files or, when
    ``require_newline``, while the first line is still incomplete."""
    with open(path, "rb") as fh:
        head = fh.read(HEAD_BYTES)
    if not head:
        return None
    nl = head.find(b"\n")
    if nl >= 0:
        head = head[:nl]
    elif require_newline and len(head) < HEAD_BYTES:
        return None
    return hashlib.sha256(b"atd-head-v1\x00" + head).hexdigest()[:32]


def identify(path: Path, require_newline: bool = False) -> FileIdentity | None:
    st = os.stat(path)
    key = head_key(path, require_newline)
    if key is None:
        return None
    return FileIdentity(file_key=key, size=st.st_size, stat_id=f"{st.st_dev}:{st.st_ino}")


def iter_lines(
    fh: BinaryIO, start_offset: int, start_line_no: int, max_line_bytes: int, final: bool
) -> Iterator[RawRecord]:
    fh.seek(start_offset)
    offset = start_offset
    line_no = start_line_no
    buf = bytearray()
    buf_start = offset
    skipping = False
    while True:
        block = fh.read(BLOCK)
        if not block:
            break
        pos = 0
        while pos < len(block):
            nl = block.find(b"\n", pos)
            if nl < 0:
                chunk = block[pos:]
                if skipping:
                    offset += len(chunk)
                else:
                    buf.extend(chunk)
                    offset += len(chunk)
                    if len(buf) > max_line_bytes:
                        line_no += 1
                        yield RawRecord(buf_start, line_no, b"", offset, "oversized")
                        buf.clear()
                        skipping = True
                pos = len(block)
                continue
            chunk = block[pos:nl]
            offset += len(chunk) + 1
            if skipping:
                skipping = False
            else:
                buf.extend(chunk)
                line_no += 1
                if len(buf) > max_line_bytes:
                    yield RawRecord(buf_start, line_no, b"", offset, "oversized")
                else:
                    yield RawRecord(buf_start, line_no, bytes(buf), offset, "ok")
            buf.clear()
            buf_start = offset
            pos = nl + 1
    if buf and not skipping and final:
        line_no += 1
        yield RawRecord(buf_start, line_no, bytes(buf), offset, "partial")


def decode_json_object(data: bytes, is_first: bool = False) -> tuple[dict[str, Any] | None, str | None]:
    """Parse one line. Returns (object, None), (None, reason) or (None, None) for blank."""
    if is_first and data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    data = data.rstrip(b"\r")
    if not data.strip():
        return None, None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid_utf8"
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None, "invalid_json"
    if not isinstance(obj, dict):
        return None, "not_json_object"
    return obj, None


def looks_like_json_array(path: Path) -> bool:
    with open(path, "rb") as fh:
        head = fh.read(64).lstrip(b"\xef\xbb\xbf").lstrip()
    return head.startswith(b"[")


def iter_json_array(path: Path, max_bytes: int) -> Iterator[tuple[int, dict[str, Any] | None, str | None]]:
    """Whole-file JSON array (bounded by ``max_bytes``). Yields (index, obj, reason)."""
    size = os.stat(path).st_size
    if size > max_bytes:
        raise ValueError("json_array_too_large")
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        arr = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid_json_array") from None
    if not isinstance(arr, list):
        raise ValueError("invalid_json_array")
    for i, item in enumerate(arr):
        if isinstance(item, dict):
            yield i, item, None
        else:
            yield i, None, "not_json_object"
