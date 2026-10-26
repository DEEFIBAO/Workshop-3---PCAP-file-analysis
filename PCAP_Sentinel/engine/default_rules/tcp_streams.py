"""Provided helper: group TCP packets into connections and reassemble byte streams.

The application parsers (FTP / HTTP) need *messages*, not single packets, because one message can
span several TCP segments and several messages can share one segment. This module gives them
ordered, de-duplicated bytes per connection direction.

Bounded on purpose: at most ``MAX_STREAM_BYTES`` per direction and ``MAX_CONNECTIONS`` in total, so
a hostile capture cannot exhaust memory. Missing segments (capture loss) are recorded as gaps and
parsers restart at the next chunk instead of guessing.
"""
from __future__ import annotations

from typing import Dict, Iterator, List, Optional, Tuple

MAX_STREAM_BYTES = 1 << 20
MAX_CONNECTIONS = 100_000


class Stream:
    """One direction of a TCP connection."""

    def __init__(self):
        self.isn: Optional[int] = None                      # sequence number of the SYN, if seen
        self._segments: List[tuple] = []                    # (seq, frame, timestamp, data)
        self.payload_packets = 0

    def add(self, packet: dict) -> None:
        if packet["payload"] and packet["tcp_seq"] is not None:
            self._segments.append((packet["tcp_seq"], packet["packet_number"], packet["timestamp"], packet["payload"]))
            self.payload_packets += 1

    def chunks(self, cap: int = MAX_STREAM_BYTES) -> List[dict]:
        """Ordered, de-duplicated chunks: ``{"frame","timestamp","data","after_gap"}``."""
        if not self._segments:
            return []
        base = (self.isn + 1) & 0xFFFFFFFF if self.isn is not None else self._segments[0][0]

        def relative(seq: int) -> int:                      # signed 32-bit distance from base
            return ((seq - base + 0x80000000) & 0xFFFFFFFF) - 0x80000000

        ordered = sorted(((relative(s), f, t, d) for s, f, t, d in self._segments),
                         key=lambda row: (row[0], row[1]))
        out: List[dict] = []
        next_seq, total = None, 0
        for rel, frame, timestamp, data in ordered:
            end = rel + len(data)
            if next_seq is None:
                next_seq = rel
            if end <= next_seq:
                continue                                    # retransmission / duplicate
            gap = rel > next_seq and bool(out)
            if rel < next_seq:
                data = data[next_seq - rel:]                # overlap: keep only new bytes
            out.append({"frame": frame, "timestamp": timestamp, "data": data, "after_gap": gap})
            next_seq = end
            total += len(data)
            if total >= cap:
                break
        return out


class Connection:
    """A TCP connection with a client side (initiator) and a server side."""

    def __init__(self, client: Tuple[str, int], server: Tuple[str, int], index: int):
        self.id = index
        self.client_ip, self.client_port = client
        self.server_ip, self.server_port = server
        self.c2s, self.s2c = Stream(), Stream()
        self.syn_seen = self.synack_seen = self.handshake_complete = False
        self.rst_by: Optional[str] = None                   # "client" / "server"
        self.fin_seen = False
        self.first_ts = self.last_ts = None
        self.first_frame = None
        self.packet_count = 0
        self.bytes_c2s = self.bytes_s2c = 0

    def stream(self, direction: str) -> Stream:
        return self.c2s if direction == "c2s" else self.s2c


def _orient(packet: dict) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Guess (client, server) for a connection first seen mid-stream: the lower port is the server."""
    a = (packet["source_ip"], packet["source_port"])
    b = (packet["destination_ip"], packet["destination_port"])
    return (a, b) if a[1] >= b[1] else (b, a)


def build_connections(packets: List[dict]) -> List[Connection]:
    """Group TCP packets into connections (a new SYN on a finished/used 4-tuple starts a new one)."""
    active: Dict[tuple, Connection] = {}
    connections: List[Connection] = []
    for packet in packets:
        if packet["protocol"] != "TCP" or packet["source_ip"] is None or packet["source_port"] is None:
            continue
        a = (packet["source_ip"], packet["source_port"])
        b = (packet["destination_ip"], packet["destination_port"])
        key = (a, b) if a <= b else (b, a)
        flags = packet["tcp_flags"] or ""
        is_syn = "S" in flags and "A" not in flags
        conn = active.get(key)
        if conn is not None and is_syn:
            same_isn = conn.c2s.isn == packet["tcp_seq"] and (conn.client_ip, conn.client_port) == a
            if not same_isn and (conn.packet_count > 1 or conn.rst_by or conn.fin_seen):
                conn = None                                  # port reuse -> new connection
        if conn is None:
            if len(connections) >= MAX_CONNECTIONS:
                continue
            client, server = (a, b) if is_syn else ((b, a) if ("S" in flags and "A" in flags) else _orient(packet))
            conn = Connection(client, server, len(connections))
            connections.append(conn)
            active[key] = conn
            conn.first_ts, conn.first_frame = packet["timestamp"], packet["packet_number"]
        from_client = (packet["source_ip"], packet["source_port"]) == (conn.client_ip, conn.client_port)
        stream = conn.c2s if from_client else conn.s2c
        conn.packet_count += 1
        if packet["timestamp"] is not None:
            conn.last_ts = packet["timestamp"]
        if is_syn and stream.isn is None:
            stream.isn, conn.syn_seen = packet["tcp_seq"], True
        elif "S" in flags and "A" in flags:
            conn.synack_seen = True
            if stream.isn is None:
                stream.isn = packet["tcp_seq"]
        elif conn.synack_seen and from_client and "R" not in flags and not conn.handshake_complete:
            conn.handshake_complete = True
        if "R" in flags:
            conn.rst_by = "client" if from_client else "server"
        if "F" in flags:
            conn.fin_seen = True
        if packet["payload"]:
            stream.add(packet)
            if from_client:
                conn.bytes_c2s += len(packet["payload"])
            else:
                conn.bytes_s2c += len(packet["payload"])
    return connections


def iter_lines(chunks: List[dict], max_line: int = 4096) -> Iterator[dict]:
    """Yield text lines from chunks: ``{"line","frames","timestamp"}`` (frames that carried the line)."""
    buffer = bytearray()
    frames: List[int] = []
    for chunk in chunks:
        if chunk["after_gap"]:
            buffer.clear()
            frames = []
        buffer.extend(chunk["data"])
        frames.append(chunk["frame"])
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                if len(buffer) > max_line:                   # not line-oriented text: drop it
                    buffer.clear()
                    frames = [chunk["frame"]]
                break
            raw = bytes(buffer[:newline]).rstrip(b"\r")
            del buffer[:newline + 1]
            yield {"line": raw.decode("latin-1"), "frames": frames or [chunk["frame"]],
                   "timestamp": chunk["timestamp"]}
            frames = [chunk["frame"]] if buffer else []


def join_runs(chunks: List[dict]) -> List[dict]:
    """Join chunks into gap-free runs: ``{"data": bytes, "marks": [(offset, frame, timestamp)]}``."""
    runs: List[dict] = []
    for chunk in chunks:
        if chunk["after_gap"] or not runs:
            runs.append({"data": bytearray(), "marks": []})
        run = runs[-1]
        run["marks"].append((len(run["data"]), chunk["frame"], chunk["timestamp"]))
        run["data"].extend(chunk["data"])
    for run in runs:
        run["data"] = bytes(run["data"])
    return runs


def mark_at(run: dict, offset: int) -> Tuple[Optional[int], Optional[float]]:
    """Which frame / timestamp carried the byte at ``offset`` of a run?"""
    frame, timestamp = None, None
    for start, mark_frame, mark_ts in run["marks"]:
        if start > offset:
            break
        frame, timestamp = mark_frame, mark_ts
    return frame, timestamp
