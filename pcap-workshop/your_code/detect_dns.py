"""D3 - Suspicious DNS detector.

Lookups for names that don't exist, a sign of some malware.

THE RULE
  The looked-up name is in p["dns_query"] (None if the packet isn't DNS).
  A DNS reply with p["dns_rcode"] == 3 means "no such name".
  The computer that asked is the reply's p["dst"].
  Collect the DIFFERENT failed names per asking computer.
  20 or more -> one "medium" alert for that computer.

BONUS
  Queries (p["dns_rcode"] is None) longer than 60 characters can mean data is
  being smuggled out inside DNS. Add a "medium" alert, one per domain (not per packet!).
  Hint: "abc.data.tunnel-cdn.net" -> the domain is the last two parts: "tunnel-cdn.net".

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "dns", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py dns
  Expected on attack-demo.pcap:  1 alert for 192.168.1.11 (35 failed names). Bonus: 1 alert for tunnel-cdn.net
  Expected on clean-traffic.pcap: no alerts

IDEAS: WHAT ELSE THIS MODULE COULD DO
  - Random-looking names (e.g. "xk2j9qpz.com") are made up by malware to find its boss.
    Score how random a name is: lots of digits, few vowels, very long words.
  - Many lookups to subdomains of ONE domain = data being sent out piece by piece.
  - A computer asking a DNS server that isn't the usual one (e.g. straight to 8.8.8.8
    when everyone else uses the router) can mean malware avoiding company filters.
  - Look-alike domains: "paypa1.com", "rnicrosoft.com" (swap letters/digits and compare
    against a short list of real names).
  - Lookups for known bad words: "ngrok", "duckdns", "pastebin", "tor2web".
  - Tie it together: which computer looked up a bad name and THEN connected to it?
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts
