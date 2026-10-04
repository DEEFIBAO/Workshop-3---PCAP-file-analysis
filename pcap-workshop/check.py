"""READY-MADE: checks your work. Nobody needs to change this file.

  python check.py              check every piece and show a scoreboard
  python check.py portscan     check one piece and list the alerts it found
                               (portscan, bruteforce, dns, cleartext, ports, analyzer, reader)
"""
import importlib
import json
import sys
import traceback

from ready_made.reader import read_packets

ATTACK = "samples/attack-demo.pcap"
CLEAN = "samples/clean-traffic.pcap"

# name -> (module, how many alerts the attack sample should give: (at least, at most))
DETECTORS = {
    "portscan": ("your_code.detect_portscan", (1, 1)),
    "bruteforce": ("your_code.detect_bruteforce", (1, 1)),
    "dns": ("your_code.detect_dns", (1, 2)),       # 2 if the bonus is done
    "cleartext": ("your_code.detect_cleartext", (3, 3)),
    "ports": ("your_code.detect_ports", (1, 1)),
}
ALERT_KEYS = {"detector", "severity", "title", "src", "dst", "detail"}
SEVERITIES = {"high", "medium", "low"}

_cache = {}


def packets(path):
    if path not in _cache:
        _cache[path] = read_packets(path)
    return _cache[path]


def where_it_broke():
    """The last line of the traceback that points at the group's own code."""
    lines = [l for l in traceback.format_exc().splitlines() if "your_code" in l]
    err = traceback.format_exc().strip().splitlines()[-1]
    return f"{err}\n         at {lines[-1].strip()}" if lines else err


def problems_with(alerts):
    if not isinstance(alerts, list):
        return ["detect() must return a list"]
    found = []
    for a in alerts:
        if not isinstance(a, dict):
            found.append(f"each alert must be a dict, got {type(a).__name__}")
            continue
        missing = ALERT_KEYS - a.keys()
        if missing:
            found.append(f"alert is missing key(s): {', '.join(sorted(missing))}")
        if a.get("severity") not in SEVERITIES:
            found.append(f"severity must be high, medium or low, not {a.get('severity')!r}")
        try:
            json.dumps(a)
        except TypeError:
            found.append("alert contains bytes or another type the web page can't receive (use plain text)")
    return sorted(set(found))


def check_detector(name, verbose):
    module_name, (low, high) = DETECTORS[name]
    try:
        module = importlib.import_module(module_name)
        attack = module.detect(packets(ATTACK))
        clean = module.detect(packets(CLEAN))
    except Exception:
        return "X ", f"crashed: {where_it_broke()}", []
    issues = problems_with(attack) + problems_with(clean)
    if issues:
        return "X ", "; ".join(issues), attack
    if not attack and not clean:
        return "--", "not started yet (returns no alerts)", attack
    if clean:
        return "X ", f"{len(clean)} alert(s) on the CLEAN sample; it should give none", attack
    if not low <= len(attack) <= high:
        want = f"{low}" if low == high else f"{low}-{high}"
        return "X ", f"{len(attack)} alert(s) on the attack sample, expected {want}", attack
    return "OK", f"{len(attack)} alert(s) on the attack sample, none on the clean one", attack


def check_analyzer(verbose):
    try:
        from your_code.analyzer import analyze
        report = analyze(ATTACK)
        clean = analyze(CLEAN)
    except Exception:
        return "X ", f"crashed: {where_it_broke()}", None
    keys = {"file", "packets", "protocols", "risk_score", "alerts"}
    if not isinstance(report, dict) or keys - report.keys():
        return "X ", f"the report needs these keys: {', '.join(sorted(keys))}", report
    if not report["alerts"] and not report["protocols"] and report["risk_score"] == 0:
        return "--", "not started yet (no alerts, protocols or risk score)", report
    if sum(report["protocols"].values()) != report["packets"]:
        return "X ", "protocol counts don't add up to the number of packets", report
    if not 0 <= report["risk_score"] <= 100:
        return "X ", f"risk_score must be 0-100, got {report['risk_score']}", report
    if clean["alerts"] or clean["risk_score"]:
        return "X ", "the clean sample should give no alerts and a risk score of 0", report
    return "OK", f"{len(report['alerts'])} alerts, risk score {report['risk_score']}", report


def main():
    which = sys.argv[1].lower() if len(sys.argv) > 1 else None
    names = list(DETECTORS) + ["analyzer"]
    if which not in (None, "reader", *names):
        print(f"Unknown piece '{which}'. Choose from: reader, {', '.join(names)}")
        return

    print("Reading the sample captures...")
    if which == "reader":
        p = packets(ATTACK)
        print(f"\n{len(p)} packets in {ATTACK}. The first three look like this:\n")
        for one in p[:3]:
            print(one, "\n")
        return
    packets(ATTACK), packets(CLEAN)
    print()

    for name in ([which] if which else names):
        if name == "analyzer":
            mark, msg, report = check_analyzer(which)
        else:
            mark, msg, alerts = check_detector(name, which)
        print(f"[{mark}] {name:<11} {msg}")
        if which and name != "analyzer":
            for a in alerts if isinstance(alerts, list) else []:
                print("        ", a)
        if which == "analyzer" and isinstance(report, dict):
            print(json.dumps(report, indent=2, default=str))

    if not which:
        print("\nOK = working   -- = not started   X = needs fixing")
        print("Check one piece in detail with:  python check.py <name>")


if __name__ == "__main__":
    main()
