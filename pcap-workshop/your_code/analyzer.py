"""A - The analyzer. It joins everything together.

analyze(path) must return a Report shaped like this (keep these exact keys):
  {"file": "attack-demo.pcap",
   "packets": 11071,                                   # how many packets
   "protocols": {"TCP": 10179, "UDP": 852, "OTHER": 40},
   "risk_score": 100,                                  # 0 to 100
   "alerts": [ ...every alert from every detector... ]}

Every your_code/detect_*.py is found automatically by ready_made/loader.py,
so when someone adds a new detector it joins the report with no changes here.

TEST IT ON ITS OWN:  python check.py analyzer

IDEAS: WHAT ELSE THE ANALYZER COULD DO
  - Sort the alerts: high first, then medium, then low.
  - Remove duplicates: two detectors reporting the same thing about the same computers.
  - "Most suspicious computers": count alerts per src and add a top-3 list to the report.
  - Timeline: when did the capture start and end? (smallest and biggest p["time"])
  - Top talkers: which 5 computers sent the most packets?
  - A plain-English verdict: risk 0 "Looks clean", under 40 "Worth a look", 40+ "Investigate now".
    (Add new keys to the report; the web page can show them if someone adds a line there.)
"""
import os

from ready_made.loader import run_all
from ready_made.reader import read_packets

POINTS = {"high": 20, "medium": 8, "low": 3}


def analyze(path):
    packets = read_packets(path)

    alerts = []
    # TODO 1: run every detector and collect the alerts.
    #         run_all(packets) does it for you: it returns one list with every detector's alerts
    #         (and keeps going even if one detector crashes).

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
