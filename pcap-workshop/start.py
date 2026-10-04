"""READY-MADE: starts the PCAP Sentinel web server.

Run from this folder:   python start.py
Then open:              http://127.0.0.1:8000      (Ctrl+C to stop)
"""
from ready_made.server import app

if __name__ == "__main__":
    print("PCAP Sentinel: open http://127.0.0.1:8000 in your browser (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=8000, debug=True)
