"""TASK 1 - PCAP reader: turn a capture file into normalised packet dictionaries.

WHERE IT FITS
    capture file --> read_pcap()  --> packets --> analyze_traffic() --> rules --> build_report()

WHAT IS ALREADY DONE FOR YOU
    * engine/default_rules/capture_files.py  ->  CaptureReader: opens .pcap/.pcapng safely and hands you
      RAW FRAMES (bytes). It does NOT understand Ethernet/IP/TCP - that is YOUR job below.
    * blank_packet() below builds a packet dictionary with every key set to "not available".

WHAT YOU MUST WRITE
    parse_frame(frame)  -> one packet dictionary        (decode the bytes with the struct module)
    read_pcap(path)     -> (packets, capture_info)

THE PACKET DICTIONARY (every key is ALWAYS present; None means "not available" - that is NOT the same as 0)
    packet_number     int    1-based frame number (matches Wireshark)
    timestamp         float  seconds since 1970, or None
    captured_length   int    bytes stored in the capture
    original_length   int    bytes on the wire (None if unknown)
    link_type         str    e.g. "Ethernet"
    ip_version        int    4, 6 or None
    source_ip         str    or None          (ARP: the sender's protocol address)
    destination_ip    str    or None
    ttl               int    IPv4 TTL / IPv6 hop limit, or None
    ip_protocol       int    IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6), or None
    protocol          str    "TCP" "UDP" "ICMP" "ICMPv6" "ARP" or "OTHER"
    source_port       int    TCP/UDP only, else None
    destination_port  int
    tcp_flags         str    letters from "FSRPAUEC" in that order, e.g. "S", "SA", "PA"; None if not TCP
    tcp_seq, tcp_ack, tcp_window   int or None
    icmp_type, icmp_code           int or None (ICMP and ICMPv6)
    payload           bytes  application bytes (b"" when none)
    payload_length    int    application bytes the headers say exist (can exceed len(payload) if the capture
                             was cut short), or None if unknown
    fragment          bool   True for a non-first IPv4 fragment (it has no TCP/UDP header)
    truncated         bool   the packet is shorter than its headers claim
    malformed         bool   the headers make no sense
    note              str    short reason when truncated / malformed / unsupported, else None

capture_info (returned by read_pcap) must contain:
    file_size_bytes, format, link_types (list of names), snaplen, packet_count, file_truncated, read_limit_reached,
    warnings (list of str), unsupported_packets, malformed_packets, truncated_packets

FRAME DICTIONARY you receive from CaptureReader.frames():
    {"number": 1, "timestamp": 1700000000.5 or None, "link_type": 1, "data": b"...", "original_length": 74}

HEADER CHEAT-SHEET (offsets in bytes from the start of each header; network byte order -> use "!" in struct)
    Ethernet II (14 bytes): dst MAC 0-5 | src MAC 6-11 | EtherType 12-13  (0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP,
                            0x8100 = a 4-byte VLAN tag follows; the real EtherType is 2 bytes later)
    IPv4 (20+ bytes):  byte 0 = version<<4 | header_length_in_32bit_words | total length 2-3 | TTL 8 |
                       protocol 9 | source 12-15 | destination 16-19 | flags+fragment offset 6-7 (offset = & 0x1FFF)
    IPv6 (40 bytes):   payload length 4-5 | next header 6 | hop limit 7 | source 8-23 | destination 24-39
                       (extension headers: next-header values 0, 43, 44, 51, 60 - skip them to find TCP/UDP)
    TCP (20+ bytes):   src port 0-1 | dst port 2-3 | seq 4-7 | ack 8-11 | data offset = high nibble of byte 12
                       (x4 = header length) | flags = byte 13 (FIN 0x01 SYN 0x02 RST 0x04 PSH 0x08 ACK 0x10 URG 0x20
                       ECE 0x40 CWR 0x80) | window 14-15
    UDP (8 bytes):     src port 0-1 | dst port 2-3 | length 4-5
    ICMP / ICMPv6:     type byte 0 | code byte 1   (the payload starts at byte 8)
    ARP (28 bytes, IPv4 over Ethernet): sender IP 14-17 | target IP 24-27
    Tip: ipaddress.ip_address(raw_bytes) turns 4 or 16 raw bytes into the text form.

HOW YOU KNOW YOU ARE DONE
    python -m unittest tests.test_student_tasks.Task1PcapReader -v     (contract tests)
    python -m unittest tests.test_pcap_reader -v                       (full reader tests, incl. IPv6, VLAN, damage)

SUGGESTED ORDER (each step makes more tests pass)
    Tier 1  Ethernet -> IPv4 -> TCP / UDP / ICMP, timestamps, payload, read_pcap loop        (dashboard works)
    Tier 2  IPv6 (+ extension headers), VLAN tags, ARP, raw-IP link types, IPv4 fragments,
            truncated / malformed flags, never crashing on a bad packet                      (all tests pass)
"""
from __future__ import annotations

import ipaddress   # noqa: F401  (you will want this)
import struct      # noqa: F401  (and this)
from typing import List, Tuple

from engine.default_rules.capture_files import CaptureReader, PcapFormatError, LINK_TYPE_NAMES  # noqa: F401

# Safety valve for very large uploads (memory). Raise it if you analyse big files locally.
MAX_PACKETS = 250_000

# (letter, bit) pairs in the order the letters must appear in packet["tcp_flags"].
TCP_FLAG_LETTERS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
                    ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80))


def blank_packet(number: int, timestamp, captured: int, original, link_name: str) -> dict:
    """PROVIDED. A packet dictionary with every key present and 'not available' values."""
    return {
        "packet_number": number, "timestamp": timestamp, "captured_length": captured,
        "original_length": original, "link_type": link_name,
        "ip_version": None, "source_ip": None, "destination_ip": None, "ttl": None,
        "ip_protocol": None, "protocol": "OTHER", "source_port": None, "destination_port": None,
        "tcp_flags": None, "tcp_seq": None, "tcp_ack": None, "tcp_window": None,
        "icmp_type": None, "icmp_code": None, "payload": b"", "payload_length": None,
        "fragment": False, "truncated": False, "malformed": False, "note": None,
    }


def parse_frame(frame: dict) -> dict:
    """Decode ONE raw frame into a packet dictionary.

    Receives: a frame dict from CaptureReader (see the top of this file).
    Returns:  a packet dictionary. NEVER raise on a damaged packet - set malformed/truncated and a note instead.

    TODO 1.1  Start with blank_packet(frame["number"], frame["timestamp"], len(frame["data"]), frame["original_length"], link_name)
              where link_name = LINK_TYPE_NAMES.get(frame["link_type"], "Unsupported (...)").
    TODO 1.2  If original_length is bigger than len(data) the capture cut the packet short: set truncated=True.
    TODO 1.3  Ethernet: read the EtherType at bytes 12-13. 0x0800 -> IPv4. (Other values: leave protocol "OTHER".)
    TODO 1.4  IPv4: read the header length, TTL, protocol and both addresses. Set ip_version, ttl, ip_protocol, source_ip,
              destination_ip. The transport header starts at <ethernet 14> + <IPv4 header length>.
              Use the IPv4 "total length" field to ignore Ethernet padding at the end of short frames.
    TODO 1.5  TCP (protocol 6): ports, seq, ack, window, flags (convert the flag byte to letters using TCP_FLAG_LETTERS),
              header length from the data offset, payload = everything after the TCP header,
              payload_length = IPv4 total length - IPv4 header - TCP header.
    TODO 1.6  UDP (17): ports and payload (after 8 bytes). ICMP (1): icmp_type, icmp_code, payload after byte 8.
    TODO 1.7  (Tier 2) IPv6, VLAN (0x8100), ARP (0x0806), link types 101/12/228/229 (raw IP, no Ethernet header),
              ICMPv6 (58), IPv4 fragments (offset != 0 -> fragment=True, no ports), truncated headers.
              Wrap the decoding in try/except (struct.error, IndexError, ValueError) and set malformed=True.
    """
    raise NotImplementedError("TODO (Task 1): implement parse_frame() in engine/pcap_reader.py")


def read_pcap(file_path: str, max_packets: int = MAX_PACKETS) -> Tuple[List[dict], dict]:
    """Read a capture file and return ``(packets, capture_info)``.

    TODO 2.1  reader = CaptureReader(file_path)   (raises PcapFormatError for non-captures - let it propagate).
    TODO 2.2  Loop over reader.frames(), calling parse_frame() for each one. Stop after ``max_packets`` and remember
              that you hit the limit (add a warning text such as "Only the first N packets were analysed").
    TODO 2.3  Build capture_info with every key listed at the top of this file. reader.file_size, reader.format,
              reader.snaplen, reader.file_truncated and reader.warnings are ready for you; link_types is
              sorted(reader.link_types.values()). Count malformed / truncated / unsupported packets from the packet list
              (unsupported = a note that contains the word "unsupported").
    TODO 2.4  Return (packets, capture_info).
    """
    raise NotImplementedError("TODO (Task 1): implement read_pcap() in engine/pcap_reader.py")
