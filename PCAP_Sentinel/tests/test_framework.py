import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from engine import default_rules
from engine.default_rules import enrich_context, load_default_rules, run_rules
from engine.default_rules.base_rule import BaseRule
from engine.default_rules.redaction import redact_text, safe_excerpt
from engine.default_rules.windows import episodes_by_count, episodes_by_distinct
from engine.report_builder import build_report
from engine.traffic_analyzer import analyze_traffic
from engine.pcap_reader import read_pcap
from tests.helpers import ROOT, run
from tests.pcap_factory import PcapBuilder, T0, background_traffic

EXPECTED_RULES = {"syn_flood", "udp_flood", "icmp_flood", "traffic_burst", "tcp_port_scan", "udp_port_scan", "icmp_suspicious",
                  "tcp_reset_burst", "risky_services", "ftp_brute_force", "http_auth_brute_force", "plaintext_credentials",
                  "ftp_file_transfer", "web_attack_patterns", "web_enumeration", "dns_tunnelling", "dns_amplification"}


class RuleRegistrationTests(unittest.TestCase):
    def test_all_default_rules_are_discovered_automatically(self):
        found = {r.rule_id for r in load_default_rules()}
        self.assertEqual(found, EXPECTED_RULES - {"syn_flood"})            # syn_flood is the student-owned rule (engine/ddos_rule.py)

    def test_every_rule_documents_itself(self):
        for rule in load_default_rules():
            self.assertTrue(rule.name and rule.category and rule.description and rule.limitations and rule.false_positives, rule.rule_id)

    def test_unknown_parameter_is_rejected(self):
        with self.assertRaises(TypeError):
            load_default_rules({"udp_flood": {"packet_treshold": 1}})

    def test_a_new_rule_module_is_picked_up_without_touching_app_or_report_builder(self):
        folder = Path(tempfile.mkdtemp())
        (folder / "zz_custom_rule.py").write_text(
            "from engine.default_rules.base_rule import BaseRule\n"
            "class CustomRule(BaseRule):\n"
            "    rule_id='custom_demo'; name='Custom demo'; category='Demo'; description='d'; limitations='l'; false_positives='f'\n"
            "    defaults={'min_packets': 3}\n"
            "    def detect(self, context):\n"
            "        n=len(context['packets'])\n"
            "        return [self.finding(summary=f'{n} packets', severity='Low', confidence='Medium')] if n>=self.params['min_packets'] else []\n")
        default_rules.__path__.append(str(folder))
        try:
            rules = load_default_rules({"custom_demo": {"min_packets": 2}})
            self.assertIn("custom_demo", {r.rule_id for r in rules})
            b = PcapBuilder(); background_traffic(b, T0, 2)
            handle = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False); handle.write(b.to_bytes()); handle.close()
            packets, info = read_pcap(handle.name)
            ctx = enrich_context(analyze_traffic(packets, info))
            report = build_report(ctx, run_rules(ctx, rules))
            self.assertIn("custom_demo", {f["rule_id"] for f in report["findings"]})
            self.assertIn("custom_demo", {r["rule_id"] for r in report["rules_run"]})
        finally:
            default_rules.__path__.remove(str(folder))
            sys.modules.pop("engine.default_rules.zz_custom_rule", None)
            shutil.rmtree(folder)

    def test_crashing_rule_is_reported_not_hidden_and_does_not_stop_others(self):
        class Broken(BaseRule):
            rule_id = "broken"; name = "Broken"
            def detect(self, context): raise RuntimeError("boom")

        class Bad(BaseRule):
            rule_id = "bad"; name = "Bad"
            def detect(self, context): return [self.finding(summary="x", severity="Critical", confidence="High")]

        class Fine(BaseRule):
            rule_id = "fine"; name = "Fine"
            def detect(self, context): return [self.finding(summary="ok", severity="Low", confidence="High")]
        ctx = {"packets": []}
        findings = run_rules(ctx, [Broken(), Bad(), Fine()])
        self.assertEqual([f["rule_id"] for f in findings], ["fine"])
        self.assertEqual({e["rule_id"] for e in ctx["rule_errors"]}, {"broken", "bad"})
        self.assertEqual({r["rule_id"]: r["status"] for r in ctx["rules_run"]}, {"broken": "error", "bad": "error", "fine": "ok"})


class ReportBuilderTests(unittest.TestCase):
    def test_arbitrary_finding_is_normalised_generically(self):
        ctx = {"summary": {"capture": {"first_timestamp": 100.0}, "totals": {"packets": 1}}}
        report = build_report(ctx, [{"rule_id": "x", "severity": "Catastrophic", "first_seen": 105.5, "last_seen": 106, "bytes": b"raw", "stats": {"s": {1, 2}}}])
        f = report["findings"][0]
        self.assertEqual((f["severity"], f["first_seen_elapsed"], f["last_seen_elapsed"]), ("Low", 5.5, 6.0))
        self.assertTrue(f["normalisation_notes"])
        json.dumps(report)

    def test_sorted_by_severity_then_time_and_counts(self):
        mk = lambda sev, t: {"rule_id": "r", "severity": sev, "confidence": "High", "classification": "observed", "first_seen": t}
        report = build_report({"summary": {}}, [mk("Low", 1), mk("High", 9), mk("High", 2), mk("Informational", 0)])
        self.assertEqual([f["severity"] for f in report["findings"]], ["High", "High", "Low", "Informational"])
        self.assertEqual(report["findings"][0]["first_seen_elapsed"], None)       # no capture start available -> unavailable, not 0
        self.assertEqual(report["counts"]["by_severity"], {"High": 2, "Medium": 0, "Low": 1, "Informational": 1})

    def test_empty_findings_report_has_full_schema_and_honest_headline(self):
        b = PcapBuilder(); background_traffic(b, T0, 2)
        report = run(b)
        for key in ("schema_version", "capture", "headline", "counts", "observations", "statistics", "findings", "rules_run",
                    "rule_errors", "processing_errors", "limitations"):
            self.assertIn(key, report)
        self.assertEqual(report["findings"], [])
        self.assertIn("does not prove", report["headline"])
        self.assertGreaterEqual(len(report["rules_run"]), len(EXPECTED_RULES))


class StatisticsTests(unittest.TestCase):
    def test_general_statistics_content(self):
        b = PcapBuilder(); background_traffic(b, T0, 4)
        s = run(b)["statistics"]
        self.assertEqual(s["totals"]["packets"], s["capture"]["packet_count"])
        self.assertEqual(sum(p["packets"] for p in s["protocols"]), s["totals"]["packets"])
        self.assertTrue(s["top_sources"] and s["top_destinations"] and s["top_destination_ports"])
        self.assertEqual({p["service"] for p in s["top_destination_ports"] if p["port"] == 80}, {"HTTP"})
        self.assertGreater(s["flows"]["total"], 0)
        self.assertEqual(s["tcp"]["retransmissions"], 0)
        self.assertIsNotNone(s["traffic_rate"]["average_pps"])

    def test_retransmissions_are_counted(self):
        b = PcapBuilder()
        b.tcp(T0, "10.0.0.1", 4000, "10.0.0.2", 80, "PA", seq=1, payload=b"abc")
        b.tcp(T0 + 0.2, "10.0.0.1", 4000, "10.0.0.2", 80, "PA", seq=1, payload=b"abc")
        self.assertEqual(run(b)["statistics"]["tcp"]["retransmissions"], 1)

    def test_single_packet_has_zero_duration_but_no_average_rate(self):
        b = PcapBuilder(); b.udp(T0, "10.0.0.1", 1, "10.0.0.2", 2, b"x")
        s = run(b)["statistics"]
        self.assertEqual(s["capture"]["duration_seconds"], 0.0)
        self.assertIsNone(s["traffic_rate"]["average_pps"])           # undefined, not 0 and not infinity

    def test_long_capture_widens_bins_and_stays_bounded(self):
        b = PcapBuilder()
        for i in range(0, 20):
            b.udp(T0 + i * 86400, "10.0.0.1", 1, "10.0.0.2", 2, b"x")
        r = run(b)["statistics"]["traffic_rate"]
        self.assertLessEqual(len(r["series"]), 121)


class HelperTests(unittest.TestCase):
    def test_episodes_by_count(self):
        times = [0, 1, 2, 3, 100, 101, 102, 103, 104, 500]
        eps = episodes_by_count(times, lambda t: t, 5, 4)
        self.assertEqual([len(e) for e in eps], [4, 5])

    def test_episodes_by_distinct(self):
        items = [(i, i % 3) for i in range(30)] + [(1000 + i, i) for i in range(10)]
        eps = episodes_by_distinct(items, lambda x: x[0], lambda x: x[1], 20, 5)
        self.assertEqual(len(eps), 1)
        self.assertEqual(len({x[1] for x in eps[0]}), 10)

    def test_redaction(self):
        text = "POST /l password=Hunter2&user=a\nAuthorization: Basic QWxhZGRpbjpvcGVu\nPASS secret123\n{\"api_key\": \"abc\"}"
        out = redact_text(text)
        for secret in ("Hunter2", "QWxhZGRpbjpvcGVu", "secret123", "abc"):
            self.assertNotIn(secret, out)
        self.assertIn("user=a", out)
        self.assertNotIn("\x00", safe_excerpt("a\x00b" * 50))

    def test_finding_strings_are_redacted_even_if_a_rule_forgets(self):
        class Leaky(BaseRule):
            rule_id = "leaky"; name = "Leaky"
            def detect(self, context):
                return [self.finding(summary="saw password=abc123 in request", severity="Low", confidence="Low", evidence=["PASS hunter2"])]
        out = Leaky().detect({})[0]
        self.assertNotIn("abc123", json.dumps(out))
        self.assertNotIn("hunter2", json.dumps(out))


class UITests(unittest.TestCase):
    def test_dashboard_has_no_rule_specific_logic(self):
        html = (ROOT / "templates" / "index.html").read_text()
        for rule_id in EXPECTED_RULES:
            self.assertNotIn(rule_id, html)
        for word in ("brute", "syn_flood", "sql", "ftp_", "port_scan"):
            self.assertNotIn(word, html.lower(), word)

    def test_report_builder_has_no_rule_specific_logic(self):
        source = (ROOT / "engine" / "report_builder.py").read_text() + (ROOT / "app.py").read_text()
        for rule_id in EXPECTED_RULES:
            self.assertNotIn(f'"{rule_id}"', source)

    @unittest.skipUnless(shutil.which("node"), "node is not installed - the dashboard script was not executed")
    def test_dashboard_script_renders_findings_and_empty_reports_without_errors(self):
        import subprocess
        b = PcapBuilder(); background_traffic(b, T0, 3)
        empty = run(b)
        from tests.test_rules import ftp_attack
        b2 = PcapBuilder(); ftp_attack(b2, T0, "198.51.100.30", "192.0.2.21", 15)
        full = run(b2)
        script = (ROOT / "templates" / "index.html").read_text().split("<script>")[1].split("</script>")[0]
        harness = """
const els={};const mk=()=>({innerHTML:'',textContent:'',disabled:false,classList:{add(){},remove(){},toggle(){}},addEventListener(){}, files:[]});
global.document={getElementById:id=>els[id]??(els[id]=mk()),querySelectorAll:()=>[]};
global.fetch=async()=>({});
""" + script + """
for (const report of REPORTS){ render(report); if(!els.findings.innerHTML.length) throw new Error('no findings html'); }
console.log('rendered', REPORTS.length, 'reports; last findings html length', els.findings.innerHTML.length);
"""
        harness = "const REPORTS=" + json.dumps([empty, full]) + ";\n" + harness
        out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)


if __name__ == "__main__":
    unittest.main()
