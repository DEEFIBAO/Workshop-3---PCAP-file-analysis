"""READY-MADE: finds every detector in your_code/ and runs it safely.

Any file in your_code/ whose name starts with  detect_  and that has a
detect(packets) function is picked up AUTOMATICALLY. Nothing to register:
make  your_code/detect_my_idea.py  and it appears on the website and in check.py.

If a detector crashes (a typo, an unfinished TODO...), the rest still run.
The crash shows up as a "low" alert saying which file broke and why,
so the website keeps working while people experiment.
"""
import importlib
import os
import pkgutil
import sys
import traceback

import your_code

ALERT_KEYS = ("detector", "severity", "title", "src", "dst", "detail")


def detector_names():
    """['detect_bruteforce', 'detect_dns', ...] - every detect_*.py in your_code/."""
    return sorted(m.name for m in pkgutil.iter_modules(your_code.__path__) if m.name.startswith("detect_"))


def _problem(name, title, detail):
    return {"detector": name, "severity": "low", "title": title,
            "src": "", "dst": "", "detail": f"your_code/{name}.py: {detail}"}


def _last_line_in_your_code():
    """e.g. "ZeroDivisionError: division by zero (line 12)" - short enough for the web page."""
    kind, err, tb = sys.exc_info()
    frames = [f for f in traceback.extract_tb(tb) if "your_code" in f.filename]
    if isinstance(err, SyntaxError):
        return f"SyntaxError: {err.msg} (line {err.lineno})"
    elif frames:
        where = f" (line {frames[-1].lineno})"
    else:
        where = ""
    return f"{kind.__name__}: {err}{where}"


def run_all(packets):
    """Run every detector and return all their alerts in one list."""
    alerts = []
    for name in detector_names():
        try:
            module = importlib.import_module(f"your_code.{name}")
        except Exception:
            alerts.append(_problem(name, "Detector has an error", _last_line_in_your_code()))
            continue
        if not hasattr(module, "detect"):
            continue  # not a detector (no detect function yet)
        alerts.extend(run_safely(name, module, packets))
    return alerts


def run_safely(name, module, packets):
    try:
        found = module.detect(packets)
    except Exception:
        return [_problem(name, "Detector crashed", _last_line_in_your_code())]
    if not isinstance(found, list):
        return [_problem(name, "Detector returned the wrong thing", "detect() must return a list of alerts")]

    good = []
    for a in found:
        if not isinstance(a, dict) or any(k not in a for k in ALERT_KEYS):
            return [_problem(name, "Alert in the wrong shape", f"each alert needs the keys: {', '.join(ALERT_KEYS)}")]
        # make sure the web page can always show it (bytes, numbers... -> text)
        good.append({k: (v if isinstance(v, (str, int, float)) or v is None else str(v)) for k, v in a.items()})
    return good
