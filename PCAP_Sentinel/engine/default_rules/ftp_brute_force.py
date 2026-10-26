"""Rule: repeated FTP password submissions (brute force / password guessing)."""
from __future__ import annotations

from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, group_by


class FTPBruteForceRule(BaseRule):
    rule_id = "ftp_brute_force"
    name = "Possible FTP brute-force / password guessing"
    category = "Authentication"
    description = "Many FTP PASS submissions from one client to one server, judged by the server's 230/530 replies."
    defaults = {"attempt_threshold": 10, "window_seconds": 300.0, "min_failures": 5}
    limitations = ("Only the clear-text FTP control channel is read (FTPS/SFTP are invisible). Passwords are never "
                   "stored; guesses are counted through a salted fingerprint. Login outcomes come from server reply codes.")
    false_positives = "Scripts or clients with a wrong saved password retrying automatically; many users behind one NAT address."

    def detect(self, context: dict) -> List[dict]:
        rows = []
        for s in context["ftp_sessions"]:
            for login in s["logins"]:
                if login["timestamp"] is not None:
                    rows.append({**login, "client": s["client_ip"], "server": s["server_ip"], "port": s["server_port"]})
        findings = []
        for (client, server, port), items in group_by(rows, lambda r: (r["client"], r["server"], r["port"])).items():
            items.sort(key=lambda r: (r["timestamp"], r["frames"][0]))
            for ep in episodes_by_count(items, lambda r: r["timestamp"], self.params["window_seconds"],
                                        self.params["attempt_threshold"]):
                outcomes = Counter(r["outcome"] for r in ep)
                fails, wins = outcomes["failure"], outcomes["success"]
                visible = fails + wins > 0
                if visible and fails < self.params["min_failures"]:
                    continue                                      # e.g. a user who simply logs in a lot
                first, last = ep[0]["timestamp"], ep[-1]["timestamp"]
                guesses = len({r["password_fp"] for r in ep})
                users = sorted({r["user"] for r in ep if r["user"]})
                after_fail = [r for r in items if r["outcome"] == "success" and r["timestamp"] >= first]
                compromised = bool(after_fail) and fails >= self.params["min_failures"]
                confidence = ("High" if fails >= self.params["attempt_threshold"] and guesses >= 5 else
                              "Medium" if visible else "Low")
                severity = "High" if compromised or (confidence == "High") else "Medium"
                evidence = [f"{len(ep)} PASS submissions in {last - first:.0f}s from {client} to {server}:{port}",
                            f"server replies: {fails} failed login (530), {wins} successful (230), {outcomes['unknown'] + outcomes['error']} unanswered/other",
                            f"{guesses} distinct password guesses; {len(users)} username(s) tried: {', '.join(users[:3]) or 'n/a'}"]
                if compromised:
                    evidence.append("A successful login (230) from the same client followed the failures - the account may be compromised.")
                findings.append(self.finding(
                    summary=(f"{len(ep)} FTP login attempts from {client} to {server} within {last - first:.0f}s "
                             f"({fails} rejected" + (", then a successful login" if compromised else "") + ")."),
                    severity=severity, confidence=confidence, classification="inferred",
                    explanation=("A real user rarely submits this many passwords. The attempts were repeated quickly against "
                                 "the same FTP server and the server rejected most of them, which is how password guessing looks."
                                 if visible else "Many PASS commands were sent but the server's replies are not visible, so outcomes are unknown."),
                    evidence=evidence,
                    stats={"attempts": len(ep), "failures": fails, "successes": wins, "distinct_passwords": guesses,
                           "usernames": len(users), "attempts_per_minute": round(60 * len(ep) / max(last - first, 1), 1),
                           "success_after_failures": compromised},
                    source_ips=[client], destination_ips=[server], destination_ports=[port], protocol="FTP",
                    first_seen=first, last_seen=last, window_seconds=self.params["window_seconds"],
                    packet_numbers=[n for r in ep for n in r["frames"]],
                    recommendation=("Lock accounts or add delays after repeated failures, restrict FTP by source address, move to SFTP/FTPS "
                                    "with MFA or keys, and reset credentials if a login succeeded.")))
        return findings
