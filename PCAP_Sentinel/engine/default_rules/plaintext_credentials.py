"""Rule: authentication data sent over unencrypted protocols (observed fact, secrets redacted)."""
from __future__ import annotations

from typing import List
from urllib.parse import parse_qsl

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.http_auth_brute_force import has_password_field
from engine.default_rules.windows import group_by


class PlaintextCredentialsRule(BaseRule):
    rule_id = "plaintext_credentials"
    name = "Credentials sent in clear text"
    category = "Insecure protocols"
    description = "FTP USER/PASS, HTTP Basic authentication or HTTP login forms visible without encryption."
    defaults = {}
    limitations = "Detects that credentials were exposed to anyone who can capture traffic; it says nothing about whether they were valid."
    false_positives = "Training or lab traffic, and credentials that are deliberately dummy values."

    def detect(self, context: dict) -> List[dict]:
        findings = []
        ftp = [s for s in context["ftp_sessions"] if s["logins"]]
        for (client, server, port), sessions in group_by(ftp, lambda s: (s["client_ip"], s["server_ip"], s["server_port"])).items():
            logins = [l for s in sessions for l in s["logins"]]
            users = sorted({l["user"] for l in logins if l["user"]})
            findings.append(self._found(
                "FTP", client, server, port, f"{len(logins)} FTP USER/PASS exchange(s) were visible in clear text",
                [f"{len(logins)} PASS command(s) across {len(sessions)} connection(s)", f"usernames: {', '.join(users[:3]) or 'n/a'}", "password values are not stored or shown"],
                [t for l in logins for t in l["frames"]], [l["timestamp"] for l in logins], len(logins)))
        http = [t for t in context["http_transactions"]]
        for (client, server, port, mech), txs in group_by(
                [t for t in http if t["authorization_scheme"] == "Basic"],
                lambda t: (t["client_ip"], t["server_ip"], t["server_port"], "HTTP Basic authentication")).items():
            findings.append(self._found("HTTP", client, server, port, f"HTTP Basic credentials were sent in {len(txs)} request(s)",
                                        [f"Authorization: Basic header present in {len(txs)} request(s) (base64 is trivially reversible)"],
                                        [n for t in txs for n in t["frames"]], [t["timestamp"] for t in txs], len(txs)))
        forms = [t for t in http if t["method"] in ("POST", "PUT") and t["body"] and has_password_field(t)]
        for (client, server, port, path), txs in group_by(forms, lambda t: (t["client_ip"], t["server_ip"], t["server_port"], t["path"])).items():
            names = sorted({k for t in txs for k, _ in parse_qsl(t["body"], keep_blank_values=True) if "pass" in k.lower() or "pwd" in k.lower()})
            findings.append(self._found("HTTP", client, server, port, f"{len(txs)} HTTP form submission(s) to {path} carried a password field in clear text",
                                        [f"password field name(s): {', '.join(names) or 'present'} (values redacted)", f"{len(txs)} POST request(s) to {path}"],
                                        [n for t in txs for n in t["frames"]], [t["timestamp"] for t in txs], len(txs)))
        return findings

    def _found(self, proto, client, server, port, headline, evidence, frames, times, count) -> dict:
        times = [t for t in times if t is not None]
        return self.finding(
            title=f"Credentials exposed in clear text ({proto})", summary=f"{client} -> {server}:{port}: {headline}.",
            severity="Medium", confidence="High", classification="observed",
            explanation=f"{proto} authentication was sent without encryption, so anyone able to see this traffic could read the credentials.",
            evidence=evidence, stats={"events": count}, source_ips=[client], destination_ips=[server], destination_ports=[port],
            protocol=proto, first_seen=min(times) if times else None, last_seen=max(times) if times else None,
            packet_numbers=frames,
            recommendation=f"Replace {proto} logins with an encrypted alternative (SFTP/FTPS, HTTPS), and treat any exposed credentials as compromised.")
