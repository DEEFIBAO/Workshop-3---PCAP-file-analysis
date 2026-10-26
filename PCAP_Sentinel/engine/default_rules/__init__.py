"""Provided plumbing for the detection rules (students do not edit this package).

THE ANALYSIS CONTEXT - one dictionary shared by every rule
    context["packets"]            list of packet dicts           (built by engine/pcap_reader.py)
    context["capture_info"]       dict about the file            (built by engine/pcap_reader.py)
    context["summary"]            general statistics             (built by engine/traffic_analyzer.py)
    context["flows"]              list of conversations          (built by engine/traffic_analyzer.py)
    -- added by enrich_context() below, so rules never repeat this work --
    context["index"]              {"tcp","udp","icmp","syn_only","synack","rst"} lists of packets
    context["connections"]        TCP connections with reassembled streams (tcp_streams.py)
    context["ftp_sessions"]       FTP control sessions            (ftp_extractor.py)
    context["http_transactions"]  HTTP requests + responses       (http_extractor.py)
    context["dns_messages"]       DNS queries / responses         (dns_extractor.py)

ADDING A NEW RULE: drop a module in this folder containing a ``BaseRule`` subclass. It is discovered
automatically - no change to app.py, the report builder or the dashboard.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Dict, Iterable, List, Optional

from engine.default_rules.base_rule import BaseRule

log = logging.getLogger("pcap_sentinel")


def load_default_rules(overrides: Optional[Dict[str, dict]] = None) -> List[BaseRule]:
    """Instantiate every BaseRule subclass defined in this package (sorted by module name).

    ``overrides`` maps ``rule_id`` -> {parameter: value}, e.g. ``{"udp_flood": {"packet_threshold": 300}}``.
    """
    overrides = overrides or {}
    rules: List[BaseRule] = []
    for module_info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        for obj in vars(module).values():
            if (isinstance(obj, type) and issubclass(obj, BaseRule) and obj is not BaseRule
                    and obj.__module__ == module.__name__):
                rules.append(obj(**overrides.get(obj.rule_id, {})))
    return rules


def enrich_context(context: dict) -> dict:
    """Build the shared indexes and application-protocol views once (adds keys to ``context``)."""
    from engine.default_rules.tcp_streams import build_connections
    from engine.default_rules.ftp_extractor import extract_ftp_sessions
    from engine.default_rules.http_extractor import extract_http
    from engine.default_rules.dns_extractor import extract_dns

    packets = context.get("packets", [])
    errors = context.setdefault("processing_errors", [])
    index = {"tcp": [], "udp": [], "icmp": [], "syn_only": [], "synack": [], "rst": []}
    for packet in packets:
        proto = packet["protocol"]
        if proto == "TCP":
            index["tcp"].append(packet)
            flags = packet["tcp_flags"] or ""
            if "S" in flags and "A" not in flags and "R" not in flags:
                index["syn_only"].append(packet)
            elif "S" in flags and "A" in flags:
                index["synack"].append(packet)
            if "R" in flags:
                index["rst"].append(packet)
        elif proto == "UDP":
            index["udp"].append(packet)
        elif proto in ("ICMP", "ICMPv6"):
            index["icmp"].append(packet)
    context["index"] = index

    def attempt(name: str, function, default):
        try:
            return function()
        except Exception as exc:                      # recorded and shown in the report, never hidden
            log.exception("%s failed", name)
            errors.append(f"{name} failed: {type(exc).__name__}: {exc}")
            return default

    context["connections"] = attempt("TCP reassembly", lambda: build_connections(packets), [])
    context["ftp_sessions"] = attempt("FTP parser", lambda: extract_ftp_sessions(context["connections"]), [])
    context["http_transactions"] = attempt("HTTP parser", lambda: extract_http(context["connections"]), [])
    context["dns_messages"] = attempt("DNS parser", lambda: extract_dns(packets), [])

    tls = sum(1 for c in context["connections"]
              if (ch := c.c2s.chunks(cap=8)) and len(ch[0]["data"]) >= 3 and ch[0]["data"][0] == 0x16 and ch[0]["data"][1] == 3)
    payload_packets = sum(1 for p in index["tcp"] + index["udp"] if p["payload"])
    transactions = context["http_transactions"]
    summary = context.setdefault("summary", {})
    summary["application_protocols"] = {
        "http_requests": len(transactions),
        "http_responses": sum(1 for t in transactions if t["response"]),
        "ftp_control_sessions": len(context["ftp_sessions"]),
        "ftp_login_attempts": sum(len(s["logins"]) for s in context["ftp_sessions"]),
        "dns_queries": sum(1 for m in context["dns_messages"] if not m["is_response"]),
        "dns_responses": sum(1 for m in context["dns_messages"] if m["is_response"]),
        "tls_connections": tls,
        "packets_with_application_payload": payload_packets,
    }
    return context


def run_rules(context: dict, rules: Iterable[BaseRule]) -> List[dict]:
    """Run every rule; a crashing rule is reported in ``context['rule_errors']`` instead of hiding."""
    findings: List[dict] = []
    context["rules_run"], context["rule_errors"] = [], []
    for rule in rules:
        status, produced = "ok", []
        try:
            produced = list(rule.detect(context) or [])
        except Exception as exc:
            log.exception("rule %s failed", rule.rule_id)
            status = "error"
            context["rule_errors"].append({"rule_id": rule.rule_id, "error": f"{type(exc).__name__}: {exc}"})
        findings.extend(produced)
        context["rules_run"].append({**rule.info(), "findings": len(produced), "status": status})
    return findings
