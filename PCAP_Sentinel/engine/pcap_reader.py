"""PCAP reader: turn a capture file into normalised packet dictionaries.

Pipeline position:   capture file --> read_pcap() --> packets --> analyze_traffic()

``read_pcap(file_path)`` returns ``(packets, capture_info)``.

Packet dictionary (every key is ALWAYS present; ``None`` means "not available",
which is different from 0):

    packet_number     int    1-based frame number (matches Wireshark)
    timestamp         float  seconds since the Unix epoch, or None
    captured_length   int    bytes stored in the capture
    original_length   int    bytes on the wire (None if unknown)
    link_type         str    e.g. "Ethernet"
    ip_version        int    4, 6 or None
    source_ip         str    or None (ARP: sender protocol address)
    destination_ip    str    or None
    ttl               int    IPv4 TTL / IPv6 hop limit, or None
    ip_protocol       int    IP protocol / next-header number, or None
    protocol          str    "TCP" "UDP" "ICMP" "ICMPv6" "ARP" or "OTHER"
    source_port       int    TCP/UDP only, else None
    destination_port  int
    tcp_flags         str    letters from "FSRPAUEC", e.g. "S", "SA", "PA"; None if not TCP
    tcp_seq, tcp_ack, tcp_window   int or None
    icmp_type, icmp_code           int or None (ICMP and ICMPv6)
    payload           bytes  application bytes captured (b"" when none)
    payload_length    int    application bytes the headers say exist (may exceed len(payload)
                             if the capture was truncated), or None if unknown
    fragment          bool   True for a non-first IPv4 fragment (no transport header)
    truncated         bool   packet shorter than its headers claim
    malformed         bool   headers could not be decoded sensibly
    note              str    short explanation when truncated / malformed / unsupported, else None
"""
from __future__ import annotations

import ipaddress
import os
import struct
from typing import List, Optional, Tuple

from engine.default_rules.capture_files import CaptureReader, PcapFormatError, LINK_TYPE_NAMES

# Safety valve for very large uploads (memory). Raise it if you analyse big files locally.
MAX_PACKETS = 250_000

TCP_FLAG_LETTERS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
                    ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80))
IPV6_EXTENSION_HEADERS = {0, 43, 44, 51, 60}          # hop-by-hop, routing, fragment, AH, dest-options


def blank_packet(number: int, timestamp, captured: int, original, link_name: str) -> dict:
    return {
        "packet_number": number, "timestamp": timestamp, "captured_length": captured,
        "original_length": original, "link_type": link_name,
        "ip_version": None, "source_ip": None, "destination_ip": None, "ttl": None,
        "ip_protocol": None, "protocol": "OTHER", "source_port": None, "destination_port": None,
        "tcp_flags": None, "tcp_seq": None, "tcp_ack": None, "tcp_window": None,
        "icmp_type": None, "icmp_code": None, "payload": b"", "payload_length": None,
        "fragment": False, "truncated": False, "malformed": False, "note": None,
    }


def _flags_to_text(value: int) -> str:
    return "".join(letter for letter, bit in TCP_FLAG_LETTERS if value & bit)


def _strip_link_layer(data: bytes, link_type: int) -> Tuple[Optional[int], int, Optional[str]]:
    """Return (ethertype, offset_of_network_header, problem). ethertype None = unsupported."""
    if link_type == 1:                                           # Ethernet II (+ VLAN tags)
        if len(data) < 14:
            return None, 0, "shorter than an Ethernet header"
        ethertype, offset = struct.unpack("!H", data[12:14])[0], 14
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(data) >= offset + 4:
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
        return ethertype, offset, None
    if link_type == 113:                                         # Linux cooked capture v1
        if len(data) < 16:
            return None, 0, "shorter than a Linux cooked header"
        return struct.unpack("!H", data[14:16])[0], 16, None
    if link_type == 276:                                         # Linux cooked capture v2
        if len(data) < 20:
            return None, 0, "shorter than a Linux cooked v2 header"
        return struct.unpack("!H", data[0:2])[0], 20, None
    if link_type == 0:                                           # BSD loopback: 4-byte family
        if len(data) < 4:
            return None, 0, "shorter than a loopback header"
        family = struct.unpack("<I", data[:4])[0]
        return (0x0800 if family == 2 else 0x86DD if family in (10, 24, 28, 30) else None), 4, None
    if link_type in (12, 101, 228, 229):                         # raw IP: version nibble decides
        if not data:
            return None, 0, "empty packet"
        version = data[0] >> 4
        return (0x0800 if version == 4 else 0x86DD if version == 6 else None), 0, None
    return None, 0, "unsupported link-layer type"


def _decode_transport(item: dict, proto: int, data: bytes, offset: int, end: int) -> None:
    """Fill TCP/UDP/ICMP fields. ``data[offset:end]`` is the transport segment."""
    segment = data[offset:end]
    if proto == 6:                                               # TCP
        item["protocol"] = "TCP"
        if len(segment) < 20:
            item.update(truncated=True, note="truncated TCP header")
            return
        sport, dport, seq, ack, off_flags, window = struct.unpack("!HHIIHH", segment[:16])
        header_len = (off_flags >> 12) * 4
        item.update(source_port=sport, destination_port=dport, tcp_seq=seq, tcp_ack=ack,
                    tcp_flags=_flags_to_text(off_flags & 0xFF), tcp_window=window)
        if header_len < 20:
            item.update(malformed=True, note="invalid TCP data offset")
            return
        if header_len > len(segment):
            item.update(truncated=True, note="truncated TCP options")
            return
        item["payload"] = segment[header_len:]
    elif proto == 17:                                            # UDP
        item["protocol"] = "UDP"
        if len(segment) < 8:
            item.update(truncated=True, note="truncated UDP header")
            return
        sport, dport, length = struct.unpack("!HHH", segment[:6])
        item.update(source_port=sport, destination_port=dport)
        item["payload"] = segment[8:] if length < 8 else segment[8:length]
    elif proto in (1, 58):                                       # ICMP / ICMPv6
        item["protocol"] = "ICMP" if proto == 1 else "ICMPv6"
        if len(segment) < 4:
            item.update(truncated=True, note="truncated ICMP header")
            return
        item["icmp_type"], item["icmp_code"] = segment[0], segment[1]
        item["payload"] = segment[8:] if len(segment) > 8 else b""
    else:
        item["payload"] = segment


def _decode_ipv4(item: dict, data: bytes, offset: int) -> None:
    if len(data) < offset + 20:
        item.update(truncated=True, note="truncated IPv4 header")
        return
    first = data[offset]
    ihl = (first & 0x0F) * 4
    if first >> 4 != 4 or ihl < 20:
        item.update(malformed=True, note="invalid IPv4 header")
        return
    total_len, frag, ttl, proto = struct.unpack("!HHBB", data[offset + 2:offset + 8])[0], \
        struct.unpack("!H", data[offset + 6:offset + 8])[0], data[offset + 8], data[offset + 9]
    item.update(ip_version=4, ttl=ttl, ip_protocol=proto,
                source_ip=str(ipaddress.IPv4Address(data[offset + 12:offset + 16])),
                destination_ip=str(ipaddress.IPv4Address(data[offset + 16:offset + 20])))
    if total_len < ihl:
        item.update(malformed=True, note="IPv4 total length smaller than header")
        return
    end = min(offset + total_len, len(data))                     # also trims Ethernet padding
    if offset + total_len > len(data):
        item.update(truncated=True, note="packet shorter than IPv4 total length (snaplen?)")
    if (frag & 0x1FFF) != 0:                                      # later fragment: no transport header
        item.update(fragment=True, protocol="OTHER", payload=data[offset + ihl:end])
        return
    transport_len = total_len - ihl
    _decode_transport(item, proto, data, offset + ihl, end)
    if item["protocol"] in ("TCP",):
        header = ((data[offset + ihl + 12] >> 4) * 4) if len(data) > offset + ihl + 12 else 20
        item["payload_length"] = max(transport_len - header, 0)
    elif item["protocol"] == "UDP":
        item["payload_length"] = max(transport_len - 8, 0)
    elif item["protocol"] in ("ICMP", "ICMPv6"):
        item["payload_length"] = max(transport_len - 8, 0)
    else:
        item["payload_length"] = max(transport_len, 0)


def _decode_ipv6(item: dict, data: bytes, offset: int) -> None:
    if len(data) < offset + 40:
        item.update(truncated=True, note="truncated IPv6 header")
        return
    payload_len, next_header, hop = struct.unpack("!HBB", data[offset + 4:offset + 8])
    item.update(ip_version=6, ttl=hop,
                source_ip=str(ipaddress.IPv6Address(data[offset + 8:offset + 24])),
                destination_ip=str(ipaddress.IPv6Address(data[offset + 24:offset + 40])))
    cursor, hops = offset + 40, 0
    end = min(offset + 40 + payload_len, len(data)) if payload_len else len(data)
    while next_header in IPV6_EXTENSION_HEADERS and hops < 8:
        if len(data) < cursor + 8:
            item.update(truncated=True, note="truncated IPv6 extension header")
            return
        following = data[cursor]
        if next_header == 44:                                    # fragment header (8 bytes)
            if struct.unpack("!H", data[cursor + 2:cursor + 4])[0] & 0xFFF8:
                item.update(fragment=True, ip_protocol=data[cursor], protocol="OTHER")
                return
            cursor += 8
        elif next_header == 51:                                  # AH uses 4-byte units
            cursor += (data[cursor + 1] + 2) * 4
        else:
            cursor += (data[cursor + 1] + 1) * 8
        next_header, hops = following, hops + 1
    item["ip_protocol"] = next_header
    if payload_len and offset + 40 + payload_len > len(data):
        item.update(truncated=True, note="packet shorter than IPv6 payload length (snaplen?)")
    _decode_transport(item, next_header, data, cursor, end)
    total = max((payload_len or len(data) - offset - 40) - (cursor - offset - 40), 0)
    item["payload_length"] = total if item["protocol"] not in ("TCP", "UDP", "ICMPv6") else max(
        total - (20 if item["protocol"] == "TCP" else 8), 0)
    if item["protocol"] == "TCP" and len(data) > cursor + 12:
        item["payload_length"] = max(total - (data[cursor + 12] >> 4) * 4, 0)


def parse_frame(frame: dict) -> dict:
    """Decode one raw frame (from CaptureReader) into a packet dictionary."""
    data = frame["data"]
    link_name = LINK_TYPE_NAMES.get(frame["link_type"], f"Unsupported ({frame['link_type']})")
    item = blank_packet(frame["number"], frame["timestamp"], len(data), frame["original_length"], link_name)
    if frame["original_length"] is not None and len(data) < frame["original_length"]:
        item["truncated"] = True
        item["note"] = "capture snaplen shorter than the packet"
    try:
        ethertype, offset, problem = _strip_link_layer(data, frame["link_type"])
        if problem:
            item.update(malformed=problem.startswith("shorter"), note=problem)
        elif ethertype == 0x0800:
            _decode_ipv4(item, data, offset)
        elif ethertype == 0x86DD:
            _decode_ipv6(item, data, offset)
        elif ethertype == 0x0806 and len(data) >= offset + 28:   # ARP (IPv4 over Ethernet)
            item.update(protocol="ARP", source_ip=str(ipaddress.IPv4Address(data[offset + 14:offset + 18])),
                        destination_ip=str(ipaddress.IPv4Address(data[offset + 24:offset + 28])),
                        icmp_type=struct.unpack("!H", data[offset + 6:offset + 8])[0])
            item["note"] = item["note"] or None
        elif ethertype is not None:
            item["note"] = item["note"] or f"non-IP ethertype 0x{ethertype:04x}"
    except (struct.error, ValueError, IndexError):
        item.update(malformed=True, note="packet could not be decoded")
    return item


def read_pcap(file_path: str, max_packets: int = MAX_PACKETS) -> Tuple[List[dict], dict]:
    """Read a capture and return ``(packets, capture_info)``.

    ``capture_info`` keys: file_size_bytes, format, link_types (list of names), snaplen,
    packet_count, file_truncated, read_limit_reached, warnings (list of str),
    unsupported_packets, malformed_packets, truncated_packets.

    Raises ``PcapFormatError`` when the file is not a PCAP/PCAPNG capture.
    """
    reader = CaptureReader(file_path)
    packets: List[dict] = []
    limit_reached = False
    for frame in reader.frames():
        if len(packets) >= max_packets:
            limit_reached = True
            break
        packets.append(parse_frame(frame))
    warnings = list(reader.warnings)
    if limit_reached:
        warnings.append(f"Only the first {max_packets} packets were analysed (memory safety limit).")
    link_names = sorted(reader.link_types.values())
    info = {
        "file_size_bytes": reader.file_size, "format": reader.format, "link_types": link_names,
        "snaplen": reader.snaplen, "packet_count": len(packets),
        "file_truncated": reader.file_truncated, "read_limit_reached": limit_reached,
        "warnings": warnings,
        "unsupported_packets": sum(1 for p in packets if p["note"] and "unsupported" in p["note"]),
        "malformed_packets": sum(1 for p in packets if p["malformed"]),
        "truncated_packets": sum(1 for p in packets if p["truncated"]),
    }
    return packets, info
