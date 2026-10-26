"""Provided helper: DNS messages (UDP port 53) decoded from packets.

``extract_dns(packets)`` returns one dict per well-formed DNS message:

    packet_number, timestamp, client_ip, server_ip, client_port, is_response, id, rcode, qname (lower
    case, no trailing dot), qtype (int), qtype_name, ancount, size (DNS payload bytes)

Limitations: UDP only (DNS over TCP/TLS/HTTPS is not decoded); only the first question is read;
compressed names are followed with a strict jump limit.
"""
from __future__ import annotations

import struct
from typing import List, Optional, Tuple

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
          33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 65: "HTTPS", 255: "ANY"}


def _read_name(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    labels, jumps, end = [], 0, None
    while True:
        if offset >= len(data):
            return None, offset
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data) or jumps > 10:
                return None, offset
            if end is None:
                end = offset + 2
            offset, jumps = ((length & 0x3F) << 8) | data[offset + 1], jumps + 1
            continue
        if length > 63 or offset + 1 + length > len(data):
            return None, offset
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
        if sum(len(x) + 1 for x in labels) > 255:
            return None, offset
    return ".".join(labels).lower(), (end if end is not None else offset)


def extract_dns(packets: List[dict]) -> List[dict]:
    messages: List[dict] = []
    for packet in packets:
        if packet["protocol"] != "UDP" or 53 not in (packet["source_port"], packet["destination_port"]):
            continue
        data = packet["payload"]
        if len(data) < 12:
            continue
        ident, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
        is_response = bool(flags & 0x8000)
        if qdcount != 1 or (flags >> 11) & 0xF > 5:           # only plain single-question messages
            continue
        name, offset = _read_name(data, 12)
        if name is None or offset + 4 > len(data):
            continue
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        client = ("destination_ip", "destination_port") if is_response else ("source_ip", "source_port")
        server = ("source_ip", "source_port") if is_response else ("destination_ip", "destination_port")
        messages.append({
            "packet_number": packet["packet_number"], "timestamp": packet["timestamp"],
            "client_ip": packet[client[0]], "client_port": packet[client[1]], "server_ip": packet[server[0]],
            "is_response": is_response, "id": ident, "rcode": flags & 0xF, "qname": name, "qtype": qtype,
            "qtype_name": QTYPES.get(qtype, str(qtype)), "ancount": ancount,
            "size": packet["payload_length"] if packet["payload_length"] is not None else len(data),
        })
    return messages
