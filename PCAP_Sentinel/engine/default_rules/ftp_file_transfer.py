"""Rule: FTP file transfers, with context from failed/successful logins by the same client."""
from __future__ import annotations

import re
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import group_by

SENSITIVE_NAME = re.compile(r"(confiden|secret|passw|shadow|credential|private|id_rsa|\.pem|\.pfx|\.kdbx|backup|\.sql|\.env|payroll|salary|financ|customer|\bssn\b)", re.I)


class FTPFileTransferRule(BaseRule):
    rule_id = "ftp_file_transfer"
    name = "FTP file transfer"
    category = "Data movement"
    description = "FTP RETR (download) and STOR (upload) commands with the server's 226 transfer-complete reply."
    defaults = {"failed_logins_before": 5}
    limitations = "File contents travel on a separate data connection which is not inspected; filename sensitivity is a keyword heuristic."
    false_positives = "Routine file transfers by legitimate users."

    def detect(self, context: dict) -> List[dict]:
        findings = []
        failures = {}
        for s in context["ftp_sessions"]:
            for l in s["logins"]:
                if l["outcome"] == "failure" and l["timestamp"] is not None:
                    failures.setdefault((s["client_ip"], s["server_ip"]), []).append(l["timestamp"])
        rows = [{**t, "client": s["client_ip"], "server": s["server_ip"], "port": s["server_port"]}
                for s in context["ftp_sessions"] for t in s["transfers"]]
        for (client, server, port, command), items in group_by(rows, lambda r: (r["client"], r["server"], r["port"], r["command"])).items():
            done = [r for r in items if r["outcome"] == "completed"]
            if not done:
                continue
            times = [r["timestamp"] for r in done if r["timestamp"] is not None]
            prior = sum(1 for t in failures.get((client, server), []) if times and t <= max(times))
            sensitive = [r["filename"] for r in done if SENSITIVE_NAME.search(r["filename"])]
            after_failures = prior >= self.params["failed_logins_before"]
            download = command == "RETR"
            severity = ("High" if download and after_failures else "Medium" if (download and sensitive) or after_failures else "Low")
            names = [r["filename"] for r in done][:5]
            evidence = [f"{len(done)} completed {'download(s) (RETR)' if download else 'upload(s) (STOR)'}: {', '.join(names)}",
                        "server replied 226 (transfer complete) for each"]
            if sensitive:
                evidence.append(f"filename keyword(s) suggest sensitive content: {', '.join(sensitive[:3])} (heuristic)")
            if after_failures:
                evidence.append(f"{prior} failed FTP logins from this client preceded the transfer")
            findings.append(self.finding(
                title=f"FTP file {'download' if download else 'upload'} completed",
                summary=f"{client} {'downloaded' if download else 'uploaded'} {len(done)} file(s) {'from' if download else 'to'} {server}.",
                severity=severity, confidence="High", classification="observed",
                explanation=("The client issued " + ("RETR" if download else "STOR") + " and the server answered 226. "
                             + ("Because the same client had many failed logins first, this may be data theft after a successful guess." if after_failures
                                else "On its own this is normal FTP behaviour; it matters when combined with suspicious logins or sensitive filenames.")),
                evidence=evidence, stats={"transfers": len(done), "failed_logins_before": prior, "sensitive_names": len(sensitive)},
                source_ips=[client], destination_ips=[server], destination_ports=[port], protocol="FTP",
                first_seen=min(times) if times else None, last_seen=max(times) if times else None,
                packet_numbers=[n for r in done for n in r["frames"]],
                recommendation="Verify the transfer was authorised, review the file's sensitivity, and prefer encrypted transfer (SFTP/FTPS) with strong authentication."))
        return findings
