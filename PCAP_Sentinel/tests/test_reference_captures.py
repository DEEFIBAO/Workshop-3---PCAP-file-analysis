"""Regression tests on the three supplied captures. They assert behaviours and the evidence behind them,
never frame numbers or IP addresses, and they check the reference repo's labels against the packets."""
import json
import unittest

from app import analyze_capture
from tests.helpers import SAMPLES, of, ids


def load(name):
    return analyze_capture(str(SAMPLES / name), name)


class Capture1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = load("Networkcapture1.pcap")

    def test_no_pipeline_errors(self):
        self.assertEqual((self.r["rule_errors"], self.r["processing_errors"]), ([], []))

    def test_ftp_password_guessing_ending_in_a_successful_login(self):
        f = of(self.r, "ftp_brute_force")
        self.assertEqual(len(f), 1)
        f = f[0]
        self.assertGreater(f["stats"]["failures"], 100)
        self.assertGreater(f["stats"]["distinct_passwords"], 100)
        self.assertTrue(f["stats"]["success_after_failures"])
        self.assertEqual((f["severity"], f["confidence"], f["classification"]), ("High", "High", "inferred"))

    def test_plaintext_ftp_authentication_is_observed_for_each_client(self):
        f = of(self.r, "plaintext_credentials")
        self.assertGreaterEqual(len(f), 2)
        self.assertTrue(all(x["classification"] == "observed" for x in f))

    def test_sensitive_file_retrieval_after_failed_logins(self):
        downloads = [f for f in of(self.r, "ftp_file_transfer") if "download" in f["name"]]
        self.assertEqual(len(downloads), 1)
        d = downloads[0]
        self.assertEqual(d["severity"], "High")
        self.assertGreater(d["stats"]["failed_logins_before"], 100)
        self.assertTrue(any("sensitive" in e for e in d["evidence"]))
        self.assertTrue(any("226" in e for e in d["evidence"]))

    def test_the_legitimate_uploader_is_not_accused_of_brute_force(self):
        attacker = of(self.r, "ftp_brute_force")[0]["source_ip"]
        uploads = [f for f in of(self.r, "ftp_file_transfer") if "upload" in f["name"]]
        self.assertTrue(uploads)
        self.assertTrue(all(u["source_ip"] != attacker and u["severity"] == "Low" for u in uploads))

    def test_no_flood_or_scan_claims_without_evidence(self):
        self.assertFalse(ids(self.r) & {"syn_flood", "udp_flood", "icmp_flood", "tcp_port_scan"})

    def test_no_password_appears_anywhere_in_the_report(self):
        text = json.dumps(self.r)
        for secret in ("cmpsem055", "academia"):
            self.assertNotIn(secret, text)


class Capture2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = load("Networkcapture2.pcap")

    def test_no_pipeline_errors(self):
        self.assertEqual((self.r["rule_errors"], self.r["processing_errors"]), ([], []))

    def test_repeated_ftp_authentication_across_many_short_connections(self):
        f = of(self.r, "ftp_brute_force")
        self.assertEqual(len(f), 1)
        self.assertGreater(f[0]["stats"]["failures"], 1000)
        self.assertFalse(f[0]["stats"]["success_after_failures"])
        self.assertEqual(f[0]["severity"], "High")

    def test_early_syns_are_a_port_scan_not_a_syn_flood(self):
        scans = of(self.r, "tcp_port_scan")
        self.assertEqual(len(scans), 1)
        s = scans[0]
        self.assertIn("vertical", s["name"])
        self.assertGreaterEqual(s["stats"]["distinct_ports"], 20)
        self.assertLess(s["last_seen_elapsed"] - s["first_seen_elapsed"], 10)         # a few seconds, not a sustained flood
        self.assertGreater(s["stats"]["outcomes"].get("closed (reset)", 0), 10)       # closed ports answered with resets
        self.assertEqual(s["confidence"], "High")
        self.assertNotIn("syn_flood", ids(self.r))                                    # the repository's "SYN flood" label is not supported

    def test_ftp_connection_churn_is_not_mistaken_for_a_half_open_flood(self):
        # thousands of SYNs to the FTP port, but the handshakes complete -> the flood rule must stay quiet
        syn = next(o for o in self.r["observations"] if o["title"] == "TCP behaviour")
        self.assertIn("connection attempts", syn["detail"])
        self.assertGreater(self.r["statistics"]["tcp"]["connection_attempts"], 4000)
        self.assertNotIn("syn_flood", ids(self.r))

    def test_plaintext_authentication_and_redaction(self):
        self.assertTrue(of(self.r, "plaintext_credentials"))
        self.assertNotIn("eeeeeeee", json.dumps(self.r))

    def test_general_statistics_are_present(self):
        s = self.r["statistics"]
        self.assertEqual(s["totals"]["packets"], 81189)
        self.assertIn("ICMP", {p["protocol"] for p in s["protocols"]})
        self.assertIsNotNone(s["traffic_rate"])
        self.assertEqual(s["data_quality"]["malformed_packets"], 0)


class CompSocIncident(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = load("compsoc-incident.pcap")

    def test_no_pipeline_errors(self):
        self.assertEqual((self.r["rule_errors"], self.r["processing_errors"]), ([], []))

    def test_reconnaissance_by_path_enumeration(self):
        f = of(self.r, "web_enumeration")
        self.assertEqual(len(f), 1)
        self.assertGreaterEqual(f[0]["stats"]["distinct_paths"], 6)
        self.assertGreater(f[0]["stats"]["error_ratio"], 0.5)

    def test_slow_login_brute_force_with_401s(self):
        f = of(self.r, "http_auth_brute_force")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["stats"]["failures"], 12)
        self.assertEqual(f[0]["source_ip"], of(self.r, "web_enumeration")[0]["source_ip"])      # same actor as the recon

    def test_sql_injection_attempts_with_database_error_and_cautious_wording(self):
        f = of(self.r, "web_attack_patterns")
        self.assertEqual(len(f), 1)
        f = f[0]
        self.assertEqual(f["classification"], "indicator")                           # an attempt, not proof of exploitation
        self.assertEqual(f["stats"]["db_error_responses"], 1)
        text = " ".join(f["evidence"])
        self.assertIn("NOT proof", text)
        self.assertIn("session cookie", text)

    def test_http_200_is_not_treated_as_login_success(self):
        f = of(self.r, "http_auth_brute_force")[0]
        self.assertIn("MAY be a successful login", " ".join(f["evidence"]))

    def test_benign_visitors_and_dns_are_not_flagged(self):
        flagged = {ip for f in self.r["findings"] for ip in f["source_ips"]}
        self.assertEqual(len(flagged), 1)                                            # only the attacker address
        self.assertFalse(ids(self.r) & {"dns_tunnelling", "dns_amplification", "syn_flood", "tcp_port_scan"})

    def test_plaintext_http_login_is_observed_and_redacted(self):
        self.assertTrue(of(self.r, "plaintext_credentials"))
        self.assertNotIn("admin123", json.dumps(self.r))


if __name__ == "__main__":
    unittest.main()
