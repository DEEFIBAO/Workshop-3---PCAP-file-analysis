import os
import struct
import tempfile
import unittest

from engine.default_rules.capture_files import PcapFormatError
from engine.pcap_reader import read_pcap
from tests.helpers import run, ids
from tests.pcap_factory import PcapBuilder, T0, tcp_conversation, background_traffic


def read(data):
    handle, path = tempfile.mkstemp()
    with os.fdopen(handle, "wb") as f:
        f.write(data)
    try:
        return read_pcap(path)
    finally:
        os.remove(path)


class ReaderTests(unittest.TestCase):
    def test_tcp_fields_and_contract(self):
        b = PcapBuilder()
        b.tcp(T0, "10.0.0.1", 4000, "10.0.0.2", 80, "SA", seq=7, ack=9, payload=b"abc")
        packets, info = read(b.to_bytes())
        p = packets[0]
        self.assertEqual((p["source_ip"], p["destination_port"], p["tcp_flags"], p["tcp_seq"], p["payload"], p["payload_length"]),
                         ("10.0.0.1", 80, "SA", 7, b"abc", 3))
        self.assertEqual(p["packet_number"], 1)
        self.assertEqual(info["packet_count"], 1)
        self.assertEqual(info["format"], "pcap")

    def test_pcapng_nanosecond_and_vlan(self):
        for kwargs, ng in (({}, True), ({"nanosecond": True}, False), ({"vlan": 100}, False)):
            b = PcapBuilder(**kwargs)
            b.udp(T0 + 0.5, "10.0.0.1", 1, "10.0.0.2", 53, b"x")
            packets, _ = read(b.to_bytes(ng))
            self.assertEqual(len(packets), 1, kwargs)
            self.assertAlmostEqual(packets[0]["timestamp"], T0 + 0.5, places=3)
            self.assertEqual(packets[0]["protocol"], "UDP")

    def test_ipv6_tcp_udp_icmp(self):
        b = PcapBuilder()
        b.tcp(T0, "2001:db8::1", 5000, "2001:db8::2", 443, "S", seq=1)
        b.udp(T0 + 1, "2001:db8::1", 5000, "2001:db8::2", 53, b"zz")
        b.icmp(T0 + 2, "2001:db8::1", "2001:db8::2", icmp_type=128)
        packets, _ = read(b.to_bytes())
        self.assertEqual([p["protocol"] for p in packets], ["TCP", "UDP", "ICMPv6"])
        self.assertEqual({p["ip_version"] for p in packets}, {6})
        self.assertEqual(packets[2]["icmp_type"], 128)

    def test_raw_ip_link_type(self):
        b = PcapBuilder(linktype=101)
        b.tcp(T0, "10.0.0.1", 4000, "10.0.0.2", 80, "S")
        packets, info = read(b.to_bytes())
        self.assertEqual(packets[0]["protocol"], "TCP")
        self.assertIn("Raw IP", info["link_types"])

    def test_arp_is_not_ip_traffic_but_is_counted(self):
        b = PcapBuilder()
        b.arp(T0, "10.0.0.1", "10.0.0.2")
        packets, _ = read(b.to_bytes())
        self.assertEqual(packets[0]["protocol"], "ARP")
        self.assertIsNone(packets[0]["source_port"])

    def test_empty_capture_is_valid(self):
        report = run(PcapBuilder().to_bytes())
        self.assertEqual(report["counts"]["findings"], 0)
        self.assertEqual(report["statistics"]["totals"]["packets"], 0)
        self.assertIsNone(report["capture"]["duration_seconds"])          # unavailable, not 0
        self.assertEqual(report["observations"][0]["title"], "Empty capture")

    def test_invalid_file_raises_format_error(self):
        for blob in (b"", b"not a capture at all", b"\x00" * 100):
            with self.assertRaises(PcapFormatError):
                read(blob)

    def test_truncated_file_returns_partial_packets_and_flag(self):
        b = PcapBuilder()
        tcp_conversation(b, T0, "10.0.0.1", 4000, "10.0.0.2", 80)
        data = b.to_bytes()
        packets, info = read(data[:-7])
        self.assertTrue(info["file_truncated"])
        self.assertGreater(len(packets), 3)
        self.assertTrue(info["warnings"])
        report = run(data[:-7])
        self.assertTrue(any("truncated" in o["detail"].lower() or "ends" in o["detail"].lower() for o in report["observations"]))

    def test_implausible_record_length_stops_safely(self):
        header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        data = header + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 10) + b"x" * 20
        packets, info = read(data)
        self.assertEqual(packets, [])
        self.assertTrue(info["file_truncated"])

    def test_unsupported_link_type_does_not_crash_and_is_reported(self):
        header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 147)   # user-defined DLT
        data = header + struct.pack("<IIII", 1, 0, 4, 4) + b"abcd"
        packets, info = read(data)
        self.assertEqual(packets[0]["protocol"], "OTHER")
        self.assertEqual(info["unsupported_packets"], 1)
        report = run(data)
        self.assertEqual(report["counts"]["findings"], 0)

    def test_snaplen_truncated_and_malformed_packets_are_flagged(self):
        b = PcapBuilder()
        b.tcp(T0, "10.0.0.1", 4000, "10.0.0.2", 80, "PA", payload=b"x" * 100)
        frame = b.frames[0][1]
        b.frames[0] = (T0, frame[:60], len(frame))                   # cut by a short snaplen
        b.raw(T0 + 1, b"\x02" * 12 + b"\x08\x00" + b"\x45")           # IPv4 header cut short
        b.raw(T0 + 2, b"\x01\x02")                                    # shorter than Ethernet
        packets, info = read(b.to_bytes())
        self.assertTrue(packets[0]["truncated"])
        self.assertGreaterEqual(info["truncated_packets"], 2)
        self.assertGreaterEqual(info["malformed_packets"], 1)
        run(b.to_bytes())

    def test_missing_timestamps_are_unavailable_not_zero(self):
        # a PCAPNG Simple Packet Block has no timestamp
        def block(kind, body):
            body += b"\x00" * (-len(body) % 4)
            return struct.pack("<II", kind, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        frame = PcapBuilder()._eth(b"", 0x0806)
        data = (block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535))
                + block(3, struct.pack("<I", len(frame)) + frame))
        report = run(data, pcapng=True)
        self.assertIsNone(report["capture"]["duration_seconds"])
        self.assertIsNone(report["statistics"]["traffic_rate"])
        self.assertEqual(report["statistics"]["data_quality"]["packets_without_timestamp"], 1)

    def test_ipv4_non_first_fragment_has_no_ports(self):
        b = PcapBuilder()
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 28, 1, 0x0001, 64, 6, 0) + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + b"\x00" * 8
        b.raw(T0, b._eth(ip, 0x0800))
        packets, _ = read(b.to_bytes())
        self.assertTrue(packets[0]["fragment"])
        self.assertIsNone(packets[0]["destination_port"])

    def test_max_packets_limit_is_reported(self):
        b = PcapBuilder()
        for i in range(10):
            b.udp(T0 + i, "10.0.0.1", 1, "10.0.0.2", 2, b"x")
        handle, path = tempfile.mkstemp()
        os.write(handle, b.to_bytes()); os.close(handle)
        packets, info = read_pcap(path, max_packets=4)
        os.remove(path)
        self.assertEqual(len(packets), 4)
        self.assertTrue(info["read_limit_reached"])


class RobustnessTests(unittest.TestCase):
    def test_mutated_captures_never_crash_the_pipeline(self):
        """Seeded byte-mutation fuzzing of valid captures: the pipeline either analyses them or raises PcapFormatError."""
        import random
        from tests.test_rules import ftp_attack, web_get
        b = PcapBuilder()
        background_traffic(b, T0, 3)
        ftp_attack(b, T0 + 30, "198.51.100.30", "192.0.2.21", 12)
        web_get(b, T0 + 60, "198.51.100.9", 40001, "192.0.2.80", "/x?id=1%20UNION%20SELECT%201")
        b.udp(T0 + 61, "2001:db8::1", 5, "2001:db8::2", 53, b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01")
        originals = [b.to_bytes(), b.to_bytes(pcapng=True)]
        rng = random.Random(1234)
        for round_number in range(150):
            data = bytearray(rng.choice(originals))
            for _ in range(rng.randint(1, 40)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            if rng.random() < 0.3:
                del data[rng.randrange(len(data)):]
            try:
                run(bytes(data), pcapng=bytes(data[:4]) == b"\x0a\x0d\x0d\x0a")
            except PcapFormatError:
                pass


class VisibilityTests(unittest.TestCase):
    def test_headers_only_capture_invents_no_application_findings(self):
        b = PcapBuilder()
        for i in range(30):                       # connections with no payload at all (e.g. encrypted / stripped)
            tcp_conversation(b, T0 + i, "10.0.0.1", 40000 + i, "10.0.0.2", 21, request=b"", response=b"")
        report = run(b)
        self.assertEqual(report["counts"]["findings"], 0)
        self.assertTrue(any(o["title"] == "No application-layer visibility" for o in report["observations"]))

    def test_tls_traffic_is_reported_as_encrypted_not_inspected(self):
        b = PcapBuilder()
        for i in range(12):
            tcp_conversation(b, T0 + i, "10.0.0.1", 41000 + i, "10.0.0.2", 443,
                             request=b"\x16\x03\x01\x00\x20" + b"A" * 30, response=b"\x16\x03\x03\x00\x10" + b"B" * 16)
        report = run(b)
        self.assertEqual(report["counts"]["findings"], 0)
        self.assertEqual(report["statistics"]["application_protocols"]["tls_connections"], 12)
        self.assertTrue(any(o["title"] == "Encrypted traffic" for o in report["observations"]))


if __name__ == "__main__":
    unittest.main()
