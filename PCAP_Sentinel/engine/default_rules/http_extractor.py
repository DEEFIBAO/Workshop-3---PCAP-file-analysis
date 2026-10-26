"""Provided helper: HTTP/1.x requests and their responses from reassembled TCP streams.

``extract_http(connections)`` returns one dict per request (in capture order):

    connection_id, client_ip, client_port, server_ip, server_port
    method, target, path, query, version, host, user_agent, content_type
    body                 up to 2048 characters of the request body (kept in memory for rules; rules
                         must never copy secrets into evidence - use engine.default_rules.redaction)
    has_authorization, authorization_scheme, cookie_names, cookie_fps
    timestamp, frames
    response             None, or {"status", "reason", "timestamp", "frame", "location", "content_type",
                                   "set_cookie_fps", "db_error"}

Limitations: HTTP/1.x in clear text only (HTTPS and HTTP/2 are not visible); responses are paired to
requests by order within a connection; request bodies using chunked encoding are skipped.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from engine.default_rules.tcp_streams import Connection, join_runs, mark_at

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000}
MAX_BODY_CHARS = 2048
_SALT = os.urandom(8)
_REQUEST_LINE = re.compile(rb"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) (\S{1,4096}) HTTP/(1\.[01])\r?\n")
_STATUS_LINE = re.compile(rb"HTTP/(1\.[01]) (\d{3})[ \t]*([^\r\n]{0,80})\r?\n")
_DB_ERRORS = [
    (re.compile(rb"you have an error in your sql syntax", re.I), "MySQL syntax error"),
    (re.compile(rb"unclosed quotation mark|quoted string not properly terminated", re.I), "SQL quote error"),
    (re.compile(rb"\bora-\d{5}\b", re.I), "Oracle error"),
    (re.compile(rb"sqlstate\[|sqlite3?::|pg_query\(|syntax error at or near|odbc .*driver", re.I), "SQL driver error"),
    (re.compile(rb"\bsql error\b|database error", re.I), "SQL/database error text"),
]


def _fp(value: str) -> str:
    return hashlib.blake2s(_SALT + value.encode("latin-1", "replace"), digest_size=6).hexdigest()


def _headers(block: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in block.split(b"\n")[1:]:
        line = raw.rstrip(b"\r").decode("latin-1")
        if ":" in line:
            name, value = line.split(":", 1)
            out.setdefault(name.strip().lower(), value.strip())
    return out


def _split_head(data: bytes, start: int):
    """Return (header_block, body_start) or (None, None) if the header is incomplete."""
    crlf, lf = data.find(b"\r\n\r\n", start), data.find(b"\n\n", start)
    candidates = [(i, 4) for i in (crlf,) if i >= 0] + [(i, 2) for i in (lf,) if i >= 0]
    if not candidates:
        return None, None
    index, size = min(candidates)
    return data[start:index], index + size


def is_http_connection(conn: Connection) -> bool:
    if conn.server_port in HTTP_PORTS:
        return bool(conn.bytes_c2s)
    chunks = conn.c2s.chunks(cap=512)
    return bool(chunks) and _REQUEST_LINE.match(chunks[0]["data"]) is not None


def _parse_requests(conn: Connection) -> List[dict]:
    requests: List[dict] = []
    for run in join_runs(conn.c2s.chunks()):
        data, pos = run["data"], 0
        while pos < len(data):
            match = _REQUEST_LINE.search(data, pos)
            if not match:
                break
            head, body_start = _split_head(data, match.start())
            frame, timestamp = mark_at(run, match.start())
            block = head if head is not None else data[match.start():match.start() + 8192]
            headers = _headers(block)
            try:
                length = max(0, int(headers.get("content-length", "0")))
            except ValueError:
                length = 0
            body = b""
            if body_start is not None:
                body = data[body_start:body_start + min(length, MAX_BODY_CHARS)]
            target = match.group(2).decode("latin-1")
            try:
                parts = urlsplit(target)
                path, query = parts.path or "/", parts.query
            except ValueError:
                path, query = target.split("?")[0], ""
            auth = headers.get("authorization", "")
            cookies = [c.strip() for c in headers.get("cookie", "").split(";") if "=" in c]
            requests.append({
                "connection_id": conn.id, "client_ip": conn.client_ip, "client_port": conn.client_port,
                "server_ip": conn.server_ip, "server_port": conn.server_port,
                "method": match.group(1).decode(), "target": target[:2048], "path": path, "query": query,
                "version": match.group(3).decode(), "host": headers.get("host"),
                "user_agent": headers.get("user-agent"), "content_type": headers.get("content-type"),
                "body": body.decode("latin-1"), "has_authorization": bool(auth),
                "authorization_scheme": auth.split(" ", 1)[0].title() if auth else None,
                "cookie_names": [c.split("=", 1)[0].strip() for c in cookies],
                "cookie_fps": [_fp(c.split("=", 1)[1].strip()) for c in cookies],
                "timestamp": timestamp, "frames": [frame] if frame is not None else [], "response": None,
            })
            if body_start is None:
                break
            pos = body_start + length if length else body_start
    return requests


def _parse_responses(conn: Connection) -> List[dict]:
    responses: List[dict] = []
    for run in join_runs(conn.s2c.chunks()):
        data, pos = run["data"], 0
        while pos < len(data):
            match = _STATUS_LINE.search(data, pos)
            if not match:
                break
            head, body_start = _split_head(data, match.start())
            frame, timestamp = mark_at(run, match.start())
            block = head if head is not None else data[match.start():match.start() + 8192]
            headers = _headers(block)
            body_end = len(data)
            following = None
            if body_start is not None:
                try:
                    length = int(headers["content-length"]) if "content-length" in headers else None
                except ValueError:
                    length = None
                if length is not None:
                    body_end = min(len(data), body_start + max(length, 0))
                else:
                    following = _STATUS_LINE.search(data, body_start)
                    body_end = following.start() if following else len(data)
            sample = data[body_start:body_start + 4096] if body_start is not None else b""
            db_error = next((label for pattern, label in _DB_ERRORS if pattern.search(sample)), None)
            set_cookies = [v for k, v in _header_items(block) if k == "set-cookie"]
            responses.append({
                "status": int(match.group(2)), "reason": match.group(3).decode("latin-1").strip(),
                "timestamp": timestamp, "frame": frame, "location": headers.get("location"),
                "content_type": headers.get("content-type"),
                "set_cookie_fps": [_fp(c.split(";", 1)[0].split("=", 1)[1].strip()) for c in set_cookies if "=" in c],
                "db_error": db_error,
            })
            if body_start is None:
                break
            pos = max(body_end, body_start)
    return responses


def _header_items(block: bytes):
    for raw in block.split(b"\n")[1:]:
        line = raw.rstrip(b"\r").decode("latin-1")
        if ":" in line:
            name, value = line.split(":", 1)
            yield name.strip().lower(), value.strip()


def extract_http(connections: List[Connection]) -> List[dict]:
    transactions: List[dict] = []
    for conn in connections:
        if not is_http_connection(conn):
            continue
        requests = _parse_requests(conn)
        responses = _parse_responses(conn)
        for index, request in enumerate(requests):
            if index < len(responses):
                request["response"] = responses[index]
        transactions.extend(requests)
    transactions.sort(key=lambda t: (t["timestamp"] is None, t["timestamp"] or 0, t["frames"][:1]))
    return transactions
