"""Report builder: turn the context + rule findings into the JSON the dashboard displays.

Pipeline position:   rule findings --> build_report(context, findings) --> report (JSON-safe dict)

It must work for ANY rule, so it never mentions a specific rule - it only normalises the shared
finding format described in engine/default_rules/base_rule.py.

Report layout (this is the contract with templates/index.html):
    schema_version, generated_at
    capture        copy of summary["capture"]  (app.py adds "filename")
    headline       one sentence for the top of the page
    counts         {"findings", "by_severity": {...}, "by_classification": {...}}
    observations   [{"level": "info"|"warning", "title", "detail"}]  general, non-attack facts
    statistics     the full summary block from the analyzer
    findings       normalised findings, most severe first (see normalise_finding)
    rules_run      [{rule_id, name, category, description, thresholds, limitations, false_positive_risk, findings, status}]
    rule_errors, processing_errors     lists of strings/dicts (a failed rule is shown, never hidden)
    limitations    caveats every reader should see
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, List, Optional

SEVERITIES = ("High", "Medium", "Low", "Informational")
CONFIDENCES = ("High", "Medium", "Low")
CLASSIFICATIONS = ("observed", "indicator", "inferred")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

STATIC_LIMITATIONS = [
    "No findings does not mean a capture is safe: this is a rule-based educational detector covering a documented set of common behaviours, not a full IDS.",
    "Encrypted traffic (HTTPS, SSH, FTPS, DoH) cannot be inspected; only metadata is available for it.",
    "Findings are indicators for a human to verify (for example in Wireshark and server logs), not proof of compromise or of service impact.",
    "Rates and time windows use the packet timestamps stored in the capture; missing, duplicated or dropped packets can change results.",
]


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, float) and value != value:
        return None
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


def _utc(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def normalise_finding(raw: dict, start: Optional[float], number: int) -> dict:
    item = dict(raw)
    notes = []
    if item.get("severity") not in SEVERITIES:
        notes.append(f"invalid severity {item.get('severity')!r} replaced by Low")
        item["severity"] = "Low"
    if item.get("confidence") not in CONFIDENCES:
        notes.append(f"invalid confidence {item.get('confidence')!r} replaced by Low")
        item["confidence"] = "Low"
    if item.get("classification") not in CLASSIFICATIONS:
        item["classification"] = "indicator"
    defaults = {"rule_id": "unknown_rule", "name": "Suspicious activity", "category": "General", "summary": "A rule reported suspicious activity.",
                "explanation": "", "evidence": [], "stats": {}, "source_ips": [], "destination_ips": [], "source_ports": [],
                "destination_ports": [], "protocol": None, "window_seconds": None, "packet_numbers": [], "recommendation": "",
                "limitations": "", "false_positive_risk": "", "thresholds": {}}
    for key, default in defaults.items():
        item.setdefault(key, default)
    item.setdefault("packet_count", len(item["packet_numbers"]))
    first, last = item.pop("first_seen", None), item.pop("last_seen", None)
    item["first_seen_elapsed"] = round(first - start, 3) if first is not None and start is not None else None
    item["last_seen_elapsed"] = round(last - start, 3) if last is not None and start is not None else None
    item["first_seen_utc"], item["last_seen_utc"] = _utc(first), _utc(last)
    item["id"] = f"F{number}"
    item["normalisation_notes"] = notes
    item["_sort"] = (SEVERITY_ORDER[item["severity"]], first if first is not None else float("inf"))
    return item


def build_observations(summary: dict) -> List[dict]:
    out: List[dict] = []
    cap, totals = summary.get("capture") or {}, summary.get("totals") or {}
    if not totals.get("packets"):
        return [{"level": "warning", "title": "Empty capture", "detail": "The file is a valid capture but contains no packets."}]
    duration = cap.get("duration_seconds")
    out.append({"level": "info", "title": "Capture size",
                "detail": f"{totals['packets']} packets, {totals.get('captured_bytes', 0)} captured bytes"
                          + (f" over {duration:.1f} s." if duration is not None else "; no usable timestamps, so duration is unavailable.")})
    protocols = summary.get("protocols") or []
    if protocols:
        out.append({"level": "info", "title": "Protocol mix", "detail": ", ".join(f"{p['protocol']} {p['percent']}%" for p in protocols[:5])})
    if summary.get("top_sources"):
        top = summary["top_sources"][0]
        out.append({"level": "info", "title": "Busiest sender", "detail": f"{top['ip']} sent {top['packets']} packets."})
    rate = summary.get("traffic_rate")
    if rate and rate.get("peak"):
        out.append({"level": "info", "title": "Traffic rate",
                    "detail": f"Peak {rate['peak']['packets_per_second']} packets/s in a {rate['window_seconds']} s window"
                              + (f"; average {rate['average_pps']} packets/s." if rate.get("average_pps") is not None else ".")})
    tcp = summary.get("tcp") or {}
    if tcp.get("packets"):
        out.append({"level": "info", "title": "TCP behaviour",
                    "detail": f"{tcp.get('connection_attempts', 0)} connection attempts (SYN-only), {tcp.get('reset_packets', 0)} resets, {tcp.get('retransmissions', 0)} retransmissions."})
    apps = summary.get("application_protocols") or {}
    seen = [f"{apps[k]} {label}" for k, label in (("http_requests", "HTTP requests"), ("ftp_login_attempts", "FTP login attempts"),
                                                   ("dns_queries", "DNS queries")) if apps.get(k)]
    if seen:
        out.append({"level": "info", "title": "Readable application traffic", "detail": ", ".join(seen) + "."})
    if apps.get("tls_connections"):
        out.append({"level": "info", "title": "Encrypted traffic", "detail": f"{apps['tls_connections']} TLS connection(s): their content cannot be inspected."})
    if apps and not apps.get("packets_with_application_payload"):
        out.append({"level": "warning", "title": "No application-layer visibility",
                    "detail": "No application payload is present (headers only, or everything is encrypted), so application-level rules had nothing to examine."})
    quality = summary.get("data_quality") or {}
    for key, label in (("truncated_packets", "truncated"), ("malformed_packets", "malformed"), ("unsupported_packets", "unsupported-link-layer")):
        if quality.get(key):
            out.append({"level": "warning", "title": "Data quality", "detail": f"{quality[key]} {label} packet(s)."})
    for text in list(quality.get("warnings") or []) + list(quality.get("notes") or []):
        out.append({"level": "warning", "title": "Data quality", "detail": text})
    return out


def build_report(context: dict, findings: List[dict]) -> dict:
    summary = context.get("summary") or {}
    start = (summary.get("capture") or {}).get("first_timestamp")
    normalised = [normalise_finding(f, start, i + 1) for i, f in enumerate(findings)]
    normalised.sort(key=lambda f: f["_sort"])
    for number, item in enumerate(normalised, start=1):
        item["id"] = f"F{number}"
        del item["_sort"]
    by_severity = Counter(f["severity"] for f in normalised)
    by_class = Counter(f["classification"] for f in normalised)
    if normalised:
        headline = f"{len(normalised)} finding(s) for review: " + ", ".join(f"{by_severity[s]} {s}" for s in SEVERITIES if by_severity[s]) + "."
    else:
        headline = "No known attack pattern matched. This does not prove the capture is benign - see the limitations."
    report = {
        "schema_version": "2.0", "generated_at": datetime.now(timezone.utc).isoformat(),
        "capture": dict(summary.get("capture") or {}), "headline": headline,
        "counts": {"findings": len(normalised), "by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
                   "by_classification": {c: by_class.get(c, 0) for c in CLASSIFICATIONS}},
        "observations": build_observations(summary), "statistics": summary, "findings": normalised,
        "rules_run": context.get("rules_run", []), "rule_errors": context.get("rule_errors", []),
        "processing_errors": context.get("processing_errors", []), "limitations": list(STATIC_LIMITATIONS),
    }
    return _jsonable(report)
