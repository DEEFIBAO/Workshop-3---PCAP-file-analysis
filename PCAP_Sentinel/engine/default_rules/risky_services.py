"""Rule: repeated use of legacy / administrative / commonly abused services."""
from __future__ import annotations

from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import group_by

RISKY_PORTS = {23: "Telnet (clear-text remote shell)", 69: "TFTP (unauthenticated file transfer)",
               135: "Microsoft RPC", 139: "NetBIOS session", 445: "SMB file sharing", 3389: "RDP remote desktop",
               5900: "VNC remote desktop", 4444: "common reverse-shell/backdoor port", 1337: "common backdoor port",
               31337: "common backdoor port", 12345: "common backdoor port", 6667: "IRC (often used for botnets)"}


class RiskyServicesRule(BaseRule):
    rule_id = "risky_services"
    name = "Legacy or administrative service in use"
    category = "Connection anomalies"
    description = "Completed connections to clear-text, remote-administration or backdoor-associated ports, or several of them from one client."
    defaults = {"min_connections": 3, "combination_ports": 3}
    limitations = "Based on port numbers only; a service can run on any port and these ports can host legitimate software."
    false_positives = "Administrators using RDP/SMB/VNC internally; legacy devices that still use Telnet or TFTP."

    def detect(self, context: dict) -> List[dict]:
        done = [c for c in context["connections"] if c.handshake_complete and c.server_port in RISKY_PORTS]
        findings = []
        for (client, server, port), conns in group_by(done, lambda c: (c.client_ip, c.server_ip, c.server_port)).items():
            if len(conns) >= self.params["min_connections"]:
                findings.append(self.finding(
                    title=f"Repeated connections to {RISKY_PORTS[port].split(' (')[0]}",
                    summary=f"{client} completed {len(conns)} connections to {server}:{port} ({RISKY_PORTS[port]}).",
                    severity="Low", confidence="Medium", classification="observed",
                    explanation="This port is associated with clear-text administration or commonly abused services; repeated use deserves a check that it is expected.",
                    evidence=[f"{len(conns)} completed TCP connections", f"{sum(c.bytes_c2s + c.bytes_s2c for c in conns)} payload bytes exchanged"],
                    stats={"connections": len(conns)}, source_ips=[client], destination_ips=[server],
                    destination_ports=[port], protocol="TCP", first_seen=conns[0].first_ts, last_seen=conns[-1].last_ts,
                    packet_numbers=[c.first_frame for c in conns],
                    recommendation="Confirm the service is authorised; prefer encrypted alternatives (SSH, SFTP) and restrict access by firewall."))
        for (client, server), conns in group_by(done, lambda c: (c.client_ip, c.server_ip)).items():
            ports = sorted({c.server_port for c in conns})
            if len(ports) >= self.params["combination_ports"]:
                findings.append(self.finding(
                    title="Unusual combination of administrative services",
                    summary=f"{client} completed connections to {len(ports)} different sensitive services on {server}.",
                    severity="Low", confidence="Low", classification="indicator",
                    explanation="Using several remote-administration / file-sharing ports on one host is typical of lateral movement or post-exploitation, though also of administrators.",
                    evidence=["ports: " + ", ".join(f"{p} ({RISKY_PORTS[p].split(' (')[0]})" for p in ports)],
                    stats={"distinct_ports": len(ports)}, source_ips=[client], destination_ips=[server],
                    destination_ports=ports, protocol="TCP", first_seen=conns[0].first_ts, last_seen=conns[-1].last_ts,
                    packet_numbers=[c.first_frame for c in conns],
                    recommendation="Verify the client is an authorised admin host and review authentication logs on the target."))
        return findings
