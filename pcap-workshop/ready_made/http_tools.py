"""READY-MADE: pairs up website (HTTP) requests with the server's answers.

    for x in http_exchanges(packets):
        x["client"], x["server"], x["port"]   # who asked, who answered, server port
        x["method"], x["path"], x["body"]     # e.g. "POST", "/admin/login.php", "username=admin&password=..."
        x["status"]                           # the server's answer, e.g. 200, 401, 404 (None if no answer seen)
        x["time"]                             # when the request was sent

Think of it as Wireshark's "Follow HTTP Stream", done for every connection at once.
Only plain HTTP can be read like this; HTTPS is encrypted, so it never shows up here.
"""
from urllib.parse import unquote_plus

METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def is_request(payload):
    return payload.startswith(METHODS)


def is_response(payload):
    return payload.startswith(b"HTTP/")


def _text(data):
    return data.decode("latin-1", errors="replace")


def http_exchanges(packets):
    pending = {}    # connection -> requests still waiting for an answer
    exchanges = []

    for p in packets:
        payload = p.get("payload") or b""
        if p.get("proto") != "TCP" or not payload:
            continue

        if is_request(payload):
            head, _, body = payload.partition(b"\r\n\r\n")
            first_line = head.split(b"\r\n", 1)[0].split(b" ")
            x = {
                "time": p["time"],
                "client": p["src"],
                "server": p["dst"],
                "port": p["dport"],
                "method": _text(first_line[0]),
                "path": unquote_plus(_text(first_line[1])) if len(first_line) > 1 else "/",
                "headers": _text(head),
                "body": unquote_plus(_text(body)),
                "status": None,
                "response": "",
            }
            exchanges.append(x)
            conn = (p["src"], p["sport"], p["dst"], p["dport"])
            pending.setdefault(conn, []).append(x)

        elif is_response(payload):
            conn = (p["dst"], p["dport"], p["src"], p["sport"])   # same connection, other direction
            waiting = pending.get(conn)
            if waiting:
                x = waiting.pop(0)
                parts = payload.split(b" ", 2)
                x["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                x["response"] = _text(payload[:2000])

    return exchanges
