"""MAKE YOUR OWN DETECTOR

1. Copy this file and name the copy  detect_something.py  (it MUST start with detect_).
2. Write your rule in detect(). That's it: it joins the website and the report automatically.
3. Test it:   python check.py something      (the name after detect_)
   check.py makes sure it doesn't crash, gives alerts in the right shape,
   and stays quiet on the clean sample.

WHAT YOU GET
  packets is a list of dicts, one per packet:
    p["time"]      seconds since 1970          p["proto"]    "TCP", "UDP" or "OTHER"
    p["src"]       who sent it                 p["dst"]      who it's for
    p["sport"]     sender's port               p["dport"]    receiver's port
    p["flags"]     TCP flags e.g. "S", "SA"    p["payload"]  the data, as bytes
    p["dns_query"] looked-up name (DNS only)   p["dns_rcode"] 0 OK / 3 no such name (replies)
  For websites:  from ready_made.http_tools import http_exchanges  (see that file)

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "my_idea", "severity": "high" | "medium" | "low", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

THE PATTERN THAT ALWAYS WORKS
  1. Loop over the packets and take notes in a dict (counts, sets of things, lists of times).
  2. After the loop, go through your notes and decide: over the limit -> make an alert.

IDEAS FOR A NEW DETECTOR (none of these exist yet)
  - SYN flood (denial of service): thousands of "S" packets to one dst in a few seconds.
  - Ping flood: lots of ICMP (p["proto"] == "OTHER") to one dst.
  - Beaconing: one computer contacting the same address at a perfectly steady rhythm.
  - Data theft: one computer uploading far more bytes than it downloads.
  - Suspicious downloads: b"MZ" at the start of HTTP data = a Windows .exe arriving.
  - Ransomware signs: one computer touching many machines on port 445 (file sharing).
  - Clear-text secrets: AWS keys (b"AKIA"), private keys (b"BEGIN RSA PRIVATE KEY").
  - New devices: an IP that appears halfway through the capture and starts talking to everything.
  - Your own: look at a capture in Wireshark, spot something odd, and turn it into a rule!
"""


def detect(packets):
    alerts = []

    # 1. take notes
    notes = {}
    for p in packets:
        pass  # TODO

    # 2. decide
    for key, value in notes.items():
        pass  # TODO: if over the limit, alerts.append({...})

    return alerts
