"""A - The analyzer. It joins everything together.

analyze(path) must return a Report shaped like this (keep these exact keys):
  {"file": "attack-demo.pcap",
   "packets": 11071,                                   # how many packets
   "protocols": {"TCP": 10179, "UDP": 852, "OTHER": 40},
   "risk_score": 100,                                  # 0 to 100
   "alerts": [ ...every alert from every detector... ]}

TEST IT ON ITS OWN:  python check.py analyzer
"""
import os

from ready_made.reader import read_packets
from your_code import detect_portscan, detect_bruteforce, detect_dns, detect_cleartext, detect_ports

DETECTORS = [detect_portscan, detect_bruteforce, detect_dns, detect_cleartext, detect_ports]
POINTS = {"high": 20, "medium": 8, "low": 3}


def analyze(path):
    packets = read_packets(path)

    alerts = []
    # TODO 1: for each module in DETECTORS, call module.detect(packets) and add its alerts to the list

    protocols = {}
    # TODO 2: count how many packets have each p["proto"]  e.g. {"TCP": 10179, "UDP": 852}

    risk_score = 0
    # TODO 3: add up POINTS for every alert's severity, but never go above 100

    return {
        "file": os.path.basename(path),
        "packets": len(packets),
        "protocols": protocols,
        "risk_score": risk_score,
        "alerts": alerts,
    }

