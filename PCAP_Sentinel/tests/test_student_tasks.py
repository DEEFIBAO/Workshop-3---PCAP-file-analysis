"""Contract tests for the four workshop files. Run these FIRST:

    python -m unittest tests.test_student_tasks -v

Each class tests one file through its documented interface only (what goes in, what must come out).
"""
import os
import tempfile
import unittest

from engine.ddos_rule import DDoSDetectionRule
from engine.default_rules import enrich_context
from engine.pcap_reader import read_pcap
from engine.report_builder import build_report, build_observations, normalise_finding
from engine.traffic_analyzer import analyze_traffic
from tests.pcap_factory import PcapBuilder, T0, syn_burst, tcp_conversation

PACKET_KEYS = {"packet_number", "timestamp", "captured_length", "original_length", "link_type", "ip_version", "source_ip",
               "destination_ip", "ttl", "ip_protocol", "protocol", "source_port", "destination_port", "tcp_flags", "tcp_seq",
               "tcp_ack", "tcp_window", "icmp_type", "icmp_code", "payload", "payload_length", "fragment", "truncated",
               "malformed", "note"}


def read_bytes(data):
    handle, path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(handle, "wb") as f:
        f.write(data)
    try:
        return read_pcap(path)
    finally:
        os.remove(path)


def sample_capture():
    b = PcapBuilder()
    tcp_conversation(b, T0, "10.0.0.1", 40000, "10.0.0.2", 80, request=b"GET / HTTP/1.1\r\n\r\n", response=b"HTTP/1.1 200 OK\r\n\r\n")
    b.udp(T0 + 2, "10.0.0.1", 5000, "10.0.0.53", 53, b"abc")
    b.icmp(T0 + 3, "10.0.0.1", "10.0.0.2", 8)
    return b


class Task1PcapReader(unittest.TestCase):
    def test_returns_packets_and_info(self):
        packets, info = read_bytes(sample_capture().to_bytes())
        self.assertIsInstance(packets, list)
        self.assertIsInstance(info, dict)
        self.assertEqual(info["packet_count"], len(packets))
        self.assertEqual(info["format"], "pcap")

    def test_every_packet_has_exactly_the_documented_keys(self):
        packets, _ = read_bytes(sample_capture().to_bytes())
        for p in packets:
            self.assertEqual(set(p), PACKET_KEYS)
        self.assertEqual([p["packet_number"] for p in packets], list(range(1, len(packets) + 1)))

    def test_tcp_udp_icmp_fields(self):
        b = PcapBuilder()
        b.tcp(T0, "10.0.0.1", 4000, "10.0.0.2", 80, "PA", seq=7, ack=9, payload=b"abc")
        b.udp(T0 + 1, "10.0.0.1", 5000, "10.0.0.53", 53, b"xy")
        b.icmp(T0 + 2, "10.0.0.1", "10.0.0.2", 8)
        tcp, udp, icmp = read_bytes(b.to_bytes())[0]
        self.assertEqual((tcp["protocol"], tcp["source_ip"], tcp["destination_ip"], tcp["source_port"], tcp["destination_port"]),
                         ("TCP", "10.0.0.1", "10.0.0.2", 4000, 80))
        self.assertEqual((tcp["tcp_flags"], tcp["tcp_seq"], tcp["tcp_ack"], tcp["payload"], tcp["payload_length"]), ("PA", 7, 9, b"abc", 3))
        self.assertEqual((udp["protocol"], udp["destination_port"], udp["payload"]), ("UDP", 53, b"xy"))
        self.assertEqual((icmp["protocol"], icmp["icmp_type"], icmp["source_port"]), ("ICMP", 8, None))
        self.assertEqual(tcp["ip_version"], 4)
        self.assertAlmostEqual(udp["timestamp"] - tcp["timestamp"], 1.0, places=3)

    def test_flags_are_letters_in_a_fixed_order(self):
        b = PcapBuilder()
        for flags in ("S", "SA", "FA", "R", "PA"):
            b.tcp(T0, "10.0.0.1", 1, "10.0.0.2", 2, flags)
        got = {p["tcp_flags"] for p in read_bytes(b.to_bytes())[0]}
        self.assertEqual(got, {"S", "SA", "FA", "R", "PA"})

    def test_ipv6_and_vlan_and_arp(self):                       # Tier 2
        b = PcapBuilder(vlan=7)
        b.tcp(T0, "2001:db8::1", 1, "2001:db8::2", 443, "S")
        b.arp(T0 + 1, "10.0.0.1", "10.0.0.2")
        v6, arp = read_bytes(b.to_bytes())[0]
        self.assertEqual((v6["ip_version"], v6["protocol"], v6["destination_port"]), (6, "TCP", 443))
        self.assertEqual((arp["protocol"], arp["source_ip"]), ("ARP", "10.0.0.1"))

    def test_bad_input_is_handled(self):                        # Tier 2
        from engine.default_rules.capture_files import PcapFormatError
        with self.assertRaises(PcapFormatError):
            read_bytes(b"not a pcap")
        data = sample_capture().to_bytes()
        packets, info = read_bytes(data[:-5])
        self.assertTrue(info["file_truncated"])
        self.assertGreater(len(packets), 0)


class Task2TrafficAnalyzer(unittest.TestCase):
    def setUp(self):
        self.packets, self.info = read_bytes(sample_capture().to_bytes())
        self.context = analyze_traffic(self.packets, self.info)
        self.summary = self.context["summary"]

    def test_context_shape(self):
        for key in ("packets", "capture_info", "config", "flows", "summary"):
            self.assertIn(key, self.context)
        for key in ("capture", "totals", "protocols", "top_sources", "top_destinations", "top_destination_ports", "tcp",
                    "flows", "traffic_rate", "data_quality"):
            self.assertIn(key, self.summary)

    def test_totals_protocols_and_hosts(self):
        n = len(self.packets)
        self.assertEqual(self.summary["totals"]["packets"], n)
        self.assertEqual(self.summary["totals"]["captured_bytes"], sum(p["captured_length"] for p in self.packets))
        protocols = {p["protocol"]: p for p in self.summary["protocols"]}
        self.assertEqual(sum(p["packets"] for p in protocols.values()), n)
        self.assertEqual(protocols["UDP"]["packets"], 1)
        self.assertEqual(self.summary["protocols"][0]["protocol"], "TCP")          # largest first
        self.assertEqual(self.summary["top_sources"][0]["ip"], "10.0.0.1")
        self.assertEqual(set(self.summary["top_sources"][0]), {"ip", "packets", "bytes"})

    def test_service_ports_ignore_ephemeral_reply_ports(self):
        ports = {(p["protocol"], p["port"]): p for p in self.summary["top_destination_ports"]}
        self.assertEqual(ports[("TCP", 80)]["service"], "HTTP")
        self.assertNotIn(("TCP", 40000), ports)

    def test_tcp_counts(self):
        tcp = self.summary["tcp"]
        self.assertEqual((tcp["connection_attempts"], tcp["synack_responses"]), (1, 1))
        self.assertEqual(tcp["retransmissions"], 0)

    def test_flows(self):
        flow = self.context["flows"][0]
        self.assertEqual(flow["protocol"], "TCP")
        self.assertEqual(flow["packets"], max(f["packets"] for f in self.context["flows"]))
        self.assertGreater(flow["duration"], 0)
        self.assertEqual(self.summary["flows"]["total"], len(self.context["flows"]))

    def test_time_and_rate(self):
        cap = self.summary["capture"]
        self.assertAlmostEqual(cap["duration_seconds"], self.packets[-1]["timestamp"] - self.packets[0]["timestamp"], places=3)
        self.assertEqual(cap["packet_count"], len(self.packets))
        self.assertIsNotNone(self.summary["traffic_rate"]["peak"]["packets"])

    def test_unavailable_is_none_not_zero(self):
        empty = analyze_traffic([], {})
        self.assertIsNone(empty["summary"]["capture"]["duration_seconds"])
        self.assertIsNone(empty["summary"]["traffic_rate"])
        self.assertEqual(empty["summary"]["totals"]["packets"], 0)
        untimed = [dict(p, timestamp=None) for p in self.packets]
        s = analyze_traffic(untimed, {})["summary"]
        self.assertIsNone(s["capture"]["duration_seconds"])
        self.assertIsNone(s["traffic_rate"])
        self.assertEqual(s["data_quality"]["packets_without_timestamp"], len(untimed))

    def test_retransmissions_counted(self):
        p = dict(self.packets[3])                              # a data segment
        again = analyze_traffic(self.packets + [p], self.info)["summary"]["tcp"]["retransmissions"]
        self.assertEqual(again, 1)


class Task3ReportBuilder(unittest.TestCase):
    FINDING = {"rule_id": "demo", "name": "Demo", "severity": "High", "confidence": "Medium", "classification": "indicator",
               "summary": "s", "first_seen": T0 + 5, "last_seen": T0 + 9, "packet_numbers": [3, 4]}

    def context(self):
        packets, info = read_bytes(sample_capture().to_bytes())
        return enrich_context(analyze_traffic(packets, info))

    def test_report_schema(self):
        report = build_report(self.context(), [self.FINDING])
        for key in ("schema_version", "generated_at", "capture", "headline", "counts", "observations", "statistics",
                    "findings", "rules_run", "rule_errors", "processing_errors", "limitations"):
            self.assertIn(key, report)
        self.assertEqual(report["counts"]["findings"], 1)
        self.assertEqual(report["counts"]["by_severity"]["High"], 1)
        self.assertEqual(report["counts"]["by_classification"]["indicator"], 1)

    def test_finding_is_normalised_with_elapsed_time(self):
        f = build_report(self.context(), [self.FINDING])["findings"][0]
        self.assertEqual(f["id"], "F1")
        self.assertAlmostEqual(f["first_seen_elapsed"], 5 - 0, delta=0.01)
        self.assertNotIn("first_seen", f)
        for key in ("evidence", "recommendation", "limitations", "stats", "source_ips", "destination_ips", "thresholds"):
            self.assertIn(key, f)
        self.assertEqual(f["first_seen_utc"][:4], "2023")

    def test_invalid_values_are_repaired_and_reported(self):
        f = normalise_finding({"severity": "Catastrophic", "confidence": "??"}, T0, 3)
        self.assertEqual((f["severity"], f["confidence"], f["id"]), ("Low", "Low", "F3"))
        self.assertEqual(len(f["normalisation_notes"]), 2)

    def test_sorting_most_severe_first_then_earliest(self):
        mk = lambda sev, t: dict(self.FINDING, severity=sev, first_seen=t)
        report = build_report(self.context(), [mk("Low", 1), mk("High", 9), mk("High", 2), mk("Informational", 0)])
        self.assertEqual([f["severity"] for f in report["findings"]], ["High", "High", "Low", "Informational"])
        self.assertLess(report["findings"][0]["first_seen_elapsed"], report["findings"][1]["first_seen_elapsed"])
        self.assertEqual([f["id"] for f in report["findings"]], ["F1", "F2", "F3", "F4"])

    def test_no_findings_headline_is_honest_and_report_is_json_safe(self):
        import json
        report = build_report(self.context(), [])
        self.assertIn("does not prove", report["headline"])
        json.dumps(report)

    def test_observation_titles_the_dashboard_tests_look_for(self):
        self.assertEqual(build_observations({"totals": {"packets": 0}})[0]["title"], "Empty capture")
        titles = {o["title"] for o in build_observations({"capture": {}, "totals": {"packets": 3, "captured_bytes": 9},
                  "application_protocols": {"packets_with_application_payload": 0, "tls_connections": 2}})}
        self.assertIn("No application-layer visibility", titles)
        self.assertIn("Encrypted traffic", titles)
        self.assertIn("TCP behaviour", {o["title"] for o in build_observations(self.context()["summary"])})


class Task4SynFloodRule(unittest.TestCase):
    def ctx(self, builder):
        packets, info = read_bytes(builder.to_bytes())
        return enrich_context(analyze_traffic(packets, info))

    def server_chatter(self, b):
        tcp_conversation(b, T0 - 60, "10.9.9.9", 40100, "192.0.2.80", 80)

    def test_flood_is_detected_with_the_shared_finding_format(self):
        b = PcapBuilder(); self.server_chatter(b)
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 300, rate=100)
        found = DDoSDetectionRule().detect(self.ctx(b))
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual((f["rule_id"], f["destination_ip"], f["destination_ports"], f["source_ip"]), ("syn_flood", "192.0.2.80", [80], "198.51.100.66"))
        self.assertEqual((f["severity"], f["confidence"], f["classification"]), ("High", "High", "inferred"))
        self.assertIsNotNone(f["first_seen"]); self.assertGreater(f["last_seen"], f["first_seen"])
        self.assertGreaterEqual(f["packet_count"], 100)

    def test_port_scan_is_not_a_flood(self):
        b = PcapBuilder()
        for i in range(300):
            b.tcp(T0 + i * 0.01, "198.51.100.66", 40000, "192.0.2.80", 1 + i, "S", seq=i)
        self.assertEqual(DDoSDetectionRule().detect(self.ctx(b)), [])

    def test_completed_handshakes_are_not_half_open(self):
        b = PcapBuilder()
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 300, rate=100, answered=True, completed=True)
        self.assertEqual(DDoSDetectionRule().detect(self.ctx(b)), [])

    def test_below_threshold_and_retransmissions(self):
        b = PcapBuilder(); self.server_chatter(b)
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 99, rate=100)
        for i in range(300):
            b.tcp(T0 + 50 + i * 0.01, "198.51.100.67", 40000, "192.0.2.80", 80, "S", seq=1)   # same SYN repeated
        self.assertEqual(DDoSDetectionRule().detect(self.ctx(b)), [])

    def test_threshold_is_configurable_and_unknown_names_rejected(self):
        b = PcapBuilder(); self.server_chatter(b)
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 60, rate=100)
        ctx = self.ctx(b)
        self.assertEqual(DDoSDetectionRule().detect(ctx), [])
        self.assertEqual(len(DDoSDetectionRule(syn_threshold=50).detect(ctx)), 1)
        with self.assertRaises(TypeError):
            DDoSDetectionRule(threshold=50)

    def test_lower_confidence_when_replies_are_not_visible(self):
        b = PcapBuilder()
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 300, rate=100)
        self.assertEqual(DDoSDetectionRule().detect(self.ctx(b))[0]["confidence"], "Low")

    def test_distributed_flood_reports_many_sources(self):
        b = PcapBuilder(); self.server_chatter(b)
        syn_burst(b, T0, [f"203.0.113.{i}" for i in range(1, 41)], "192.0.2.80", 80, 300, rate=100)
        f = DDoSDetectionRule().detect(self.ctx(b))[0]
        self.assertEqual(f["stats"]["distinct_sources"], 40)


if __name__ == "__main__":
    unittest.main()
