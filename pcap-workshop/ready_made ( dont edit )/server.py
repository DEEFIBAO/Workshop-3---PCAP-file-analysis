"""READY-MADE: the web server. Nobody needs to change this file.

Start it from the main folder:   python start.py
Then open:  http://127.0.0.1:8000

Routes:
  GET  /              -> web/index.html
  GET  /api/demo      -> a made-up Report, so the web page can be built before the analyzer works
  POST /api/analyze   -> takes an uploaded capture (form field "file"), runs your_code/analyzer.py,
                         and returns the real Report as JSON

The server reloads by itself when you save a .py file.
"""
import os
import tempfile
import traceback

from flask import Flask, jsonify, request, send_file

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the main project folder
app = Flask(__name__)

DEMO_REPORT = {
    "file": "demo-only.pcap",
    "packets": 11071,
    "protocols": {"TCP": 10179, "UDP": 852, "OTHER": 40},
    "risk_score": 100,
    "alerts": [
        {"detector": "port_scan", "severity": "high", "title": "Port scan",
         "src": "10.0.0.66", "dst": "192.168.1.30", "detail": "300 different ports probed"},
        {"detector": "brute_force", "severity": "high", "title": "Brute force on SSH",
         "src": "10.0.0.66", "dst": "192.168.1.30", "detail": "61 connection attempts to port 22"},
        {"detector": "dns", "severity": "medium", "title": "Many failed DNS lookups",
         "src": "192.168.1.11", "dst": "192.168.1.1", "detail": "35 names that don't exist"},
        {"detector": "cleartext", "severity": "high", "title": "Cleartext login",
         "src": "192.168.1.11", "dst": "192.168.1.20", "detail": "HTTP Basic login on port 80"},
        {"detector": "malware_ports", "severity": "medium", "title": "Traffic to malware port 4444",
         "src": "192.168.1.12", "dst": "203.0.113.66", "detail": "21 packets carrying data (Metasploit)"},
    ],
}


@app.get("/")
def page():
    path = os.path.join(ROOT, "web", "index.html")
    if not os.path.exists(path):
        return "<p>The server is running, but web/index.html is missing.</p>"
    return send_file(path)


@app.get("/favicon.ico")
def favicon():
    return "", 204  # no tab icon; this just stops a harmless 404 in the browser console


@app.get("/api/demo")
def demo():
    return jsonify(DEMO_REPORT)


@app.post("/api/analyze")
def analyze_upload():
    upload = request.files.get("file")
    if upload is None or upload.filename == "":
        return jsonify(error="No file received. Send it in a form field called 'file'."), 400

    try:
        from your_code.analyzer import analyze
    except Exception:
        return jsonify(error="Couldn't load your_code/analyzer.py", details=traceback.format_exc()), 500

    suffix = os.path.splitext(upload.filename)[1] or ".pcap"
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        upload.save(tmp_path)
        report = analyze(tmp_path)
    except Exception:
        return jsonify(error="analyze() crashed", details=traceback.format_exc()), 500
    finally:
        os.remove(tmp_path)

    report["file"] = upload.filename
    return jsonify(report)

