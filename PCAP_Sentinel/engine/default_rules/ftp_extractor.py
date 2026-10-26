"""Provided helper: FTP control-channel sessions from reassembled TCP streams.

``extract_ftp_sessions(connections)`` returns one dict per FTP control connection (server port 21):

    client_ip, client_port, server_ip, server_port, connection_id, first_ts, last_ts, frames
    banner      first server line (e.g. "220 (vsFTPd 2.0.7)") or None
    logins      [{"user", "outcome": "success"|"failure"|"error"|"unknown", "timestamp", "frames",
                  "reply_code", "password_fp"}]          (password_fp = per-run salted fingerprint)
    transfers   [{"command": RETR|STOR|STOU|APPE, "filename", "outcome": "completed"|"failed"|"unknown",
                  "reply_codes", "timestamp", "frames"}]
    listings    number of LIST/NLST/MLSD commands
    tls_requested  True if AUTH TLS/SSL was seen (later traffic is encrypted)

Limitations: only the control channel is parsed (never the data channel). Passwords are NEVER
stored - only a salted fingerprint so rules can count *distinct* guesses.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import List

from engine.default_rules.tcp_streams import Connection, iter_lines

_SALT = os.urandom(8)                      # random per process: fingerprints cannot be replayed offline
_REPLY = re.compile(r"^(\d{3})([ -])(.*)$")
FTP_PORTS = {21}
DATA_COMMANDS = {"RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD"}
FILE_COMMANDS = {"RETR", "STOR", "STOU", "APPE"}
KNOWN_COMMANDS = DATA_COMMANDS | {"USER", "PASS", "AUTH", "QUIT", "CWD", "PWD", "TYPE", "PASV", "EPSV",
                                  "PORT", "EPRT", "DELE", "MKD", "RMD", "RNFR", "RNTO", "SYST", "FEAT", "OPTS"}


def _fingerprint(secret: str) -> str:
    return hashlib.blake2s(_SALT + secret.encode("latin-1", "replace"), digest_size=6).hexdigest()


def _printable(text: str, limit: int = 200) -> str:
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)[:limit]


def _events(conn: Connection) -> List[dict]:
    events: List[dict] = []
    for line in iter_lines(conn.c2s.chunks()):
        parts = line["line"].strip().split(" ", 1)
        command = parts[0].upper()
        if command in KNOWN_COMMANDS:
            events.append({"kind": "command", "command": command, "argument": parts[1] if len(parts) > 1 else "",
                           "frames": line["frames"], "timestamp": line["timestamp"]})
    multiline = None
    for line in iter_lines(conn.s2c.chunks()):
        match = _REPLY.match(line["line"])
        if multiline:
            if match and match.group(1) == multiline and match.group(2) == " ":
                multiline = None
            continue
        if not match:
            continue
        if match.group(2) == "-":
            multiline = match.group(1)
        events.append({"kind": "reply", "code": int(match.group(1)), "text": match.group(3),
                       "frames": line["frames"], "timestamp": line["timestamp"]})
    events.sort(key=lambda e: (e["frames"][-1], e["kind"] != "reply"))
    return events


def extract_ftp_sessions(connections: List[Connection]) -> List[dict]:
    sessions: List[dict] = []
    for conn in connections:
        if conn.server_port not in FTP_PORTS or not (conn.bytes_c2s or conn.bytes_s2c):
            continue
        session = {"connection_id": conn.id, "client_ip": conn.client_ip, "client_port": conn.client_port,
                   "server_ip": conn.server_ip, "server_port": conn.server_port, "first_ts": conn.first_ts,
                   "last_ts": conn.last_ts, "frames": [], "banner": None, "logins": [], "transfers": [],
                   "listings": 0, "tls_requested": False}
        user, pending_logins, pending_data = "", [], []
        for event in _events(conn):
            session["frames"].extend(event["frames"])
            if event["kind"] == "reply":
                code = event["code"]
                if session["banner"] is None and code == 220:
                    session["banner"] = _printable(f"{code} {event['text']}", 80)
                if pending_logins and code not in (331, 332, 150, 125, 226, 250, 220, 221, 200, 215, 227, 229):
                    login = pending_logins.pop(0)
                    login["reply_code"] = code
                    login["outcome"] = ("success" if code in (230, 202) else
                                        "failure" if code in (530, 430) else "error")
                elif pending_logins and code in (230, 202):
                    login = pending_logins.pop(0)
                    login.update(reply_code=code, outcome="success")
                if pending_data:
                    head = pending_data[0]
                    if code in (150, 125):
                        head["opened"] = True
                    elif code in (226, 250) or code >= 400:
                        pending_data.pop(0)
                        head["reply_codes"].append(code)
                        head["outcome"] = "completed" if code in (226, 250) else "failed"
                    if code in (150, 125):
                        head["reply_codes"].append(code)
                continue
            command, argument = event["command"], event["argument"]
            if command == "USER":
                user = _printable(argument, 64)
            elif command == "PASS":
                login = {"user": user, "outcome": "unknown", "timestamp": event["timestamp"],
                         "frames": list(event["frames"]), "reply_code": None,
                         "password_fp": _fingerprint(argument)}
                session["logins"].append(login)
                pending_logins.append(login)
            elif command == "AUTH":
                session["tls_requested"] = True
            elif command in DATA_COMMANDS:
                if command in FILE_COMMANDS:
                    item = {"command": command, "filename": _printable(argument), "outcome": "unknown",
                            "reply_codes": [], "timestamp": event["timestamp"], "frames": list(event["frames"]),
                            "opened": False}
                    session["transfers"].append(item)
                else:
                    session["listings"] += 1
                    item = {"command": command, "reply_codes": [], "outcome": "unknown", "opened": False}
                pending_data.append(item)
        sessions.append(session)
    return sessions
