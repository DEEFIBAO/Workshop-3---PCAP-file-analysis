import json
import os
import tempfile
from pathlib import Path

from app import analyze_capture

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def run(builder_or_bytes, overrides=None, pcapng=False, name="synthetic.pcap"):
    """Write a capture to a temp file, run the full pipeline, return the report (must be JSON-safe)."""
    data = builder_or_bytes if isinstance(builder_or_bytes, bytes) else builder_or_bytes.to_bytes(pcapng)
    handle, path = tempfile.mkstemp(suffix=".pcapng" if pcapng else ".pcap")
    try:
        with os.fdopen(handle, "wb") as f:
            f.write(data)
        report = analyze_capture(path, name, rule_overrides=overrides or {})
    finally:
        os.remove(path)
    json.dumps(report)
    assert report["rule_errors"] == [], report["rule_errors"]
    assert report["processing_errors"] == [], report["processing_errors"]
    return report


def of(report, rule_id):
    return [f for f in report["findings"] if f["rule_id"] == rule_id]


def ids(report):
    return {f["rule_id"] for f in report["findings"]}
