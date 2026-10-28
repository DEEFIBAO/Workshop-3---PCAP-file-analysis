"""TASK 3 - Report builder: turn the context + rule findings into the JSON the dashboard displays.

WHERE IT FITS
    rule findings --> build_report(context, findings) --> report --> templates/index.html

IMPORTANT DESIGN RULE: this file must work for ANY rule - including rules that do not exist yet. Never write code
that mentions a specific rule. You only normalise the shared finding format (see engine/default_rules/base_rule.py).

A FINDING (what each rule returns) has: rule_id, name, category, severity, confidence, classification, summary,
explanation, evidence (list), stats (dict), source_ips, destination_ips, source_ports, destination_ports, protocol,
first_seen / last_seen (epoch seconds or None), window_seconds, packet_numbers, packet_count, recommendation,
limitations, false_positive_risk, thresholds.
    severity       one of SEVERITIES        (how bad if real)
    confidence     one of CONFIDENCES       (how strong the evidence is)
    classification one of CLASSIFICATIONS   (observed fact / suspicious indicator / inferred attack type)

THE REPORT you must return (this is the contract with the dashboard):
    schema_version  "2.0"                     generated_at   ISO UTC text
    capture         copy of summary["capture"]  (app.py adds the filename afterwards)
    headline        one sentence. With findings: "N finding(s) for review: 2 High, 1 Low." Without findings the text
                    must say that this does NOT prove the capture is benign (tests look for the words "does not prove").
    counts          {"findings": N, "by_severity": {every severity: count}, "by_classification": {every class: count}}
    observations    list from build_observations()
    statistics      the whole summary dict
    findings        normalised findings, most severe first, ties by earliest time; ids "F1", "F2", ... AFTER sorting
    rules_run       context.get("rules_run", [])        rule_errors  context.get("rule_errors", [])
    processing_errors context.get("processing_errors", [])         limitations  list(STATIC_LIMITATIONS)
The whole report must survive json.dumps (sets, bytes etc. are not JSON): the provided _jsonable() cleans it up.

HOW YOU KNOW YOU ARE DONE
    python -m unittest tests.test_student_tasks.Task3ReportBuilder -v
    python -m unittest tests.test_framework.ReportBuilderTests -v
"""
from __future__ import annotations

from collections import Counter   # noqa: F401
from datetime import datetime, timezone
from typing import Any, List, Optional

SEVERITIES = ("High", "Medium", "Low", "Informational")
CONFIDENCES = ("High", "Medium", "Low")
CLASSIFICATIONS = ("observed", "indicator", "inferred")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}     # High -> 0 ... Informational -> 3

STATIC_LIMITATIONS = [
    "No findings does not mean a capture is safe: this is a rule-based educational detector covering a documented set of common behaviours, not a full IDS.",
    "Encrypted traffic (HTTPS, SSH, FTPS, DoH) cannot be inspected; only metadata is available for it.",
    "Findings are indicators for a human to verify (for example in Wireshark and server logs), not proof of compromise or of service impact.",
    "Rates and time windows use the packet timestamps stored in the capture; missing, duplicated or dropped packets can change results.",
]


def _jsonable(value: Any) -> Any:
    """PROVIDED. Make a structure JSON-safe (sets -> lists, bytes -> a short placeholder, odd objects -> text)."""
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
    """PROVIDED. Epoch seconds -> ISO-8601 UTC text (None stays None)."""
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def normalise_finding(raw: dict, start: Optional[float], number: int) -> dict:
    """Make one finding safe for the dashboard.

    Receives: ``raw`` (a finding), ``start`` (epoch time of the first packet, or None), ``number`` (1-based).
    Returns:  a NEW dict (do not modify ``raw``) with
        * severity not in SEVERITIES  -> "Low";  confidence not in CONFIDENCES -> "Low";  classification not in
          CLASSIFICATIONS -> "indicator". Every repair adds a sentence to a list stored in item["normalisation_notes"]
          (that list is always present, empty when nothing was repaired).
        * every missing key filled with a harmless default (empty list / dict / string, None) so the dashboard never
          crashes on a sloppy rule. packet_count defaults to len(packet_numbers).
        * first_seen / last_seen REMOVED and replaced by first_seen_elapsed / last_seen_elapsed (seconds since ``start``,
          rounded to 3 places; None when either value is unavailable - never 0) and first_seen_utc / last_seen_utc.
        * item["id"] = f"F{number}".
    TODO  Implement the above. (Sorting happens in build_report; you may keep a temporary sort key in the dict, but
          remove it before returning the final report.)
    """
    raise NotImplementedError("TODO (Task 3): normalise_finding()")


def build_observations(summary: dict) -> List[dict]:
    """General, NON-attack facts about the capture, shown separately from security findings.

    Return a list of {"level": "info" | "warning", "title": str, "detail": str}.
    The tests look for these exact titles:
        "Empty capture"                   (level warning)  when summary["totals"]["packets"] is 0 - return ONLY this one
        "TCP behaviour"                   connection attempts / resets / retransmissions from summary["tcp"]
        "Encrypted traffic"               when summary["application_protocols"]["tls_connections"] > 0
        "No application-layer visibility" (warning) when application_protocols exists but
                                          packets_with_application_payload is 0 (headers only / all encrypted)
    Also welcome (pick any): capture size and duration ("duration unavailable" when it is None), protocol mix, busiest sender,
    peak traffic rate, readable HTTP/FTP/DNS counts, and one "Data quality" warning per truncated / malformed /
    unsupported count, per summary["data_quality"]["warnings"] text and per ["notes"] text.
    Use .get() with defaults: a key may be missing or None. Never print "0" for something that is unavailable.
    """
    raise NotImplementedError("TODO (Task 3): build_observations()")


def build_report(context: dict, findings: List[dict]) -> dict:
    """Assemble the report described at the top of this file and return ``_jsonable(report)``.

    TODO  1. summary = context.get("summary") or {};  start = summary["capture"]["first_timestamp"] (may be None).
          2. normalise every finding, sort (severity order, then first_seen; findings without a time go last),
             then renumber ids F1, F2, ... in the final order.
          3. Count by severity / classification (include zero counts for every known value).
          4. Write the headline, collect the observations and fill every key of the report.
          5. return _jsonable(report)
    """
    raise NotImplementedError("TODO (Task 3): build_report()")
