"""Deterministic synthetic capture builder for the tests (no Scapy, no network, no real attacks).

    b = PcapBuilder()
    b.tcp(ts, "10.0.0.1", 40000, "10.0.0.2", 80, "S", seq=1)
    b.save("out.pcap")

Scenario helpers below build realistic multi-packet behaviour (handshakes, FTP logins, HTTP requests,
DNS lookups, floods, scans). Everything is derived from the arguments - nothing is random unless
you pass a seed - so a fixture is byte-for-byte reproducible.
"""
import ipaddress
import random
import struct

FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}
T0 = 1_700_000_000.0


def _checksum_free(data):               # checksums are not verified by the reader; keep them zero
    return data


class PcapBuilder:
    def __init__(self, start=T0, linktype=1, vlan=None, nanosecond=False):
        self.start, self.linktype, self.vlan, self.nano = start, linktype, vlan, nanosecond
        self.frames = []
        self.ip_id = 0

    # ---------------------------------------------------------------- low level
    def raw(self, ts, data, original_length=None):
        self.frames.append((ts, data, original_length))

    def _eth(self, payload, ethertype):
        eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
        if self.vlan:
            eth += struct.pack("!HHH", 0x8100, self.vlan, ethertype)
        else:
            eth += struct.pack("!H", ethertype)
        return eth + payload

    def _ip(self, src, dst, proto, transport, ttl=64):
        a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        if a.version == 6:
            ip = struct.pack("!IHBB", 6 << 28, len(transport), proto, ttl) + a.packed + b.packed
            ethertype = 0x86DD
        else:
            self.ip_id = (self.ip_id + 1) & 0xFFFF
            ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(transport), self.ip_id, 0, ttl, proto, 0) + a.packed + b.packed
            ethertype = 0x0800
        return self._wrap(ip + transport, ethertype)

    def _wrap(self, packet, ethertype):
        if self.linktype == 1:
            return self._eth(packet, ethertype)
        return packet                                        # raw IP link types

    # ------------------------------------------------------------ protocol layers
    def tcp(self, ts, src, sport, dst, dport, flags="A", seq=0, ack=0, payload=b"", window=64240):
        bits = sum(FLAG_BITS[f] for f in flags)
        header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, bits, window, 0, 0)
        self.raw(ts, self._ip(src, dst, 6, header + payload))

    def udp(self, ts, src, sport, dst, dport, payload=b""):
        self.raw(ts, self._ip(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload))

    def icmp(self, ts, src, dst, icmp_type=8, code=0, payload=b"\x00" * 32):
        v6 = ipaddress.ip_address(src).version == 6
        self.raw(ts, self._ip(src, dst, 58 if v6 else 1, struct.pack("!BBHI", icmp_type, code, 0, 0) + payload))

    def arp(self, ts, sender, target):
        body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + b"\x02\x00\x00\x00\x00\x01" + ipaddress.ip_address(sender).packed \
               + b"\x00" * 6 + ipaddress.ip_address(target).packed
        self.raw(ts, self._eth(body, 0x0806))

    # ------------------------------------------------------------------- output
    def to_bytes(self, pcapng=False):
        return self._pcapng() if pcapng else self._pcap()

    def _pcap(self):
        magic = b"\x4d\x3c\xb2\xa1" if self.nano else b"\xd4\xc3\xb2\xa1"
        out = magic + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, self.linktype)
        scale = 1e9 if self.nano else 1e6
        for ts, data, orig in sorted(self.frames, key=lambda f: f[0]):
            sec = int(ts)
            out += struct.pack("<IIII", sec, int(round((ts - sec) * scale)), len(data), orig or len(data)) + data
        return out

    def _pcapng(self):
        def block(kind, body):
            body += b"\x00" * (-len(body) % 4)
            return struct.pack("<II", kind, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        out += block(1, struct.pack("<HHI", self.linktype, 0, 65535))
        for ts, data, orig in sorted(self.frames, key=lambda f: f[0]):
            ticks = int(round(ts * 1e6))
            out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), orig or len(data)) + data)
        return out

    def save(self, path, pcapng=False):
        with open(path, "wb") as handle:
            handle.write(self.to_bytes(pcapng))
        return path


# ------------------------------------------------------------------------ scenario helpers
def handshake(b, ts, client, cport, server, sport, cseq=1000, sseq=5000, gap=0.001, complete=True):
    b.tcp(ts, client, cport, server, sport, "S", seq=cseq)
    b.tcp(ts + gap, server, sport, client, cport, "SA", seq=sseq, ack=cseq + 1)
    if complete:
        b.tcp(ts + 2 * gap, client, cport, server, sport, "A", seq=cseq + 1, ack=sseq + 1)
    return ts + 3 * gap, cseq + 1, sseq + 1


def send(b, ts, src, sport, dst, dport, seq, ack, data, gap=0.001, chunk=None):
    """Send application bytes (optionally split into TCP segments) and the peer's ACK."""
    pieces = [data] if not chunk else [data[i:i + chunk] for i in range(0, len(data), chunk)]
    for piece in pieces:
        b.tcp(ts, src, sport, dst, dport, "PA", seq=seq, ack=ack, payload=piece)
        seq += len(piece)
        ts += gap
    b.tcp(ts, dst, dport, src, sport, "A", seq=ack, ack=seq)
    return ts + gap, seq


def tcp_conversation(b, ts, client, cport, server, sport, request=b"hello", response=b"world", close=True):
    ts, cseq, sseq = handshake(b, ts, client, cport, server, sport)
    ts, cseq = send(b, ts, client, cport, server, sport, cseq, sseq, request)
    ts, sseq = send(b, ts, server, sport, client, cport, sseq, cseq, response)
    if close:
        b.tcp(ts, client, cport, server, sport, "FA", seq=cseq, ack=sseq)
        b.tcp(ts + 0.001, server, sport, client, cport, "FA", seq=sseq, ack=cseq + 1)
        b.tcp(ts + 0.002, client, cport, server, sport, "A", seq=cseq + 1, ack=sseq + 1)
    return ts + 0.01


def ftp_login(b, ts, client, cport, server, user, password, success=False, banner=b"220 (test FTP)\r\n", chunk=None):
    """One FTP control connection with a single login attempt."""
    ts, cseq, sseq = handshake(b, ts, client, cport, server, 21)
    ts, sseq = send(b, ts, server, 21, client, cport, sseq, cseq, banner)
    ts, cseq = send(b, ts, client, cport, server, 21, cseq, sseq, f"USER {user}\r\n".encode())
    ts, sseq = send(b, ts, server, 21, client, cport, sseq, cseq, b"331 Please specify the password.\r\n")
    ts, cseq = send(b, ts, client, cport, server, 21, cseq, sseq, f"PASS {password}\r\n".encode(), chunk=chunk)
    reply = b"230 Login successful.\r\n" if success else b"530 Login incorrect.\r\n"
    ts, sseq = send(b, ts, server, 21, client, cport, sseq, cseq, reply)
    return ts, cseq, sseq


def ftp_commands(b, ts, client, cport, server, cseq, sseq, commands):
    """commands: list of (client_line, [server_lines])."""
    for line, replies in commands:
        ts, cseq = send(b, ts, client, cport, server, 21, cseq, sseq, line.encode() + b"\r\n")
        for reply in replies:
            ts, sseq = send(b, ts, server, 21, client, cport, sseq, cseq, reply.encode() + b"\r\n")
    return ts, cseq, sseq


def http_exchange(b, ts, client, cport, server, request, response, sport=80, chunk=None):
    ts, cseq, sseq = handshake(b, ts, client, cport, server, sport)
    ts, cseq = send(b, ts, client, cport, server, sport, cseq, sseq, request, chunk=chunk)
    ts, sseq = send(b, ts, server, sport, client, cport, sseq, cseq, response, chunk=chunk)
    b.tcp(ts, client, cport, server, sport, "FA", seq=cseq, ack=sseq)
    return ts + 0.01


def http_request(method, path, host="example.test", body=b"", headers=None):
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test-agent\r\n"
    for k, v in (headers or {}).items():
        head += f"{k}: {v}\r\n"
    if body:
        head += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
    return (head + "\r\n").encode() + body


def http_response(status=200, reason="OK", body=b"<html>ok</html>", headers=None):
    head = f"HTTP/1.1 {status} {reason}\r\nServer: test\r\nContent-Length: {len(body)}\r\n"
    for k, v in (headers or {}).items():
        head += f"{k}: {v}\r\n"
    return (head + "\r\n").encode() + body


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.strip(".").split(".")) + b"\x00"


def dns_query(b, ts, client, cport, server, name, qid=1, qtype=1, response_size=None, answered=True):
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    b.udp(ts, client, cport, server, 53, struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question)
    if answered:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, 4) + b"\x5d\xb8\xd8\x22"
        message = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer
        if response_size:
            message += b"\x00" * max(0, response_size - len(message))
        b.udp(ts + 0.01, server, 53, client, cport, message)


def dns_response_only(b, ts, victim, vport, server, name, qid, size=700, qtype=255):
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    message = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question
    b.udp(ts, server, 53, victim, vport, message + b"\x00" * max(0, size - len(message)))


def syn_burst(b, ts, sources, target, port, count, rate, answered=False, completed=False, rst=False):
    """``count`` SYNs at ``rate`` per second, from the given source addresses (each with a fresh source port)."""
    for i in range(count):
        src, sport, t = sources[i % len(sources)], 10000 + i, ts + i / rate
        b.tcp(t, src, sport, target, port, "S", seq=1000 + i)
        if answered:
            b.tcp(t + 0.0005, target, port, src, sport, "SA", seq=7000 + i, ack=1001 + i)
            if completed:
                b.tcp(t + 0.001, src, sport, target, port, "A", seq=1001 + i, ack=7001 + i)
            elif rst:
                b.tcp(t + 0.001, src, sport, target, port, "R", seq=1001 + i)
    return ts + count / rate


def background_traffic(b, ts, n=5):
    """Ordinary small web + DNS traffic between a few hosts."""
    for i in range(n):
        dns_query(b, ts, "192.0.2.10", 33000 + i, "192.0.2.53", f"www{i % 2}.example.test", qid=100 + i)
        ts = http_exchange(b, ts + 0.1, "192.0.2.10", 40000 + i, "192.0.2.80", http_request("GET", f"/page{i}.html"),
                           http_response(200, body=b"hello"))
        ts += 2.0
    return ts
