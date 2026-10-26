# PCAP Sentinel (completed reference version)

A small, **rule-based, educational** PCAP threat-hunting tool for the BCU Computing Society workshops.
Upload an unfamiliar `.pcap` / `.pcapng` and get general traffic statistics plus explained findings for a documented set of
common behaviours. It is **not** a commercial IDS and **not** AI: it can miss attacks, and *no findings does not mean a
capture is safe*.

## Quick start

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt                      # Flask is the only dependency
python app.py                                        # http://127.0.0.1:5000
python -m unittest discover -s tests -t . -v         # run the whole test-suite
```

Dependencies: **Flask only.** The PCAP/PCAPNG parser is a small bounded pure-Python decoder (`struct`), not Scapy: it keeps
installation to one package, streams the file instead of loading everything, never executes or interprets payloads, and
matches the "standard library first" style of Workshop 1. The trade-off is that it supports a defined set of protocols
(below) instead of everything Scapy knows.

## Architecture

```
PCAP_Sentinel/
├── app.py                       Flask controller (provided)
├── engine/
│   ├── pcap_reader.py           WORKSHOP TASK 1  frames -> packet dictionaries
│   ├── traffic_analyzer.py      WORKSHOP TASK 2  statistics, flows, rates -> context
│   ├── report_builder.py        WORKSHOP TASK 3  findings + context -> dashboard report
│   ├── ddos_rule.py             WORKSHOP TASK 4  SYN-flood rule (shared rule interface)
│   └── default_rules/           everything else is provided
│       ├── base_rule.py         the shared rule + finding interface
│       ├── __init__.py          rule discovery, context enrichment, rule runner
│       ├── capture_files.py     safe PCAP/PCAPNG file framing
│       ├── tcp_streams.py       TCP connections + bounded reassembly (out-of-order, duplicates, gaps)
│       ├── ftp_/http_/dns_extractor.py   protocol views built once for all rules
│       ├── windows.py, redaction.py, services.py
│       └── <one module per detection rule>
├── samples/                     the three reference captures (see samples/README.md)
├── templates/index.html         generic dashboard (no rule-specific code)
└── tests/                       pcap_factory.py (synthetic captures) + unittest suites
```

**Data flow:** `read_pcap` → `analyze_traffic` → `enrich_context` → `run_rules` → `build_report` → JSON → dashboard.

* **Packet**: a plain dict with a fixed key set (documented at the top of `pcap_reader.py`). `None` = unavailable, never 0.
* **Context**: one dict shared by every rule: `packets`, `summary`, `flows`, plus pre-built `index`, `connections`,
  `ftp_sessions`, `http_transactions`, `dns_messages` (so rules never re-parse the capture).
* **Finding**: produced only through `BaseRule.finding()`: `rule_id, name, category, severity` (impact if real),
  `confidence` (strength of evidence), `classification` (**observed** fact / **indicator** / **inferred** attack type),
  `summary, explanation` (why it fired), `evidence, stats, source/destination IPs and ports, protocol,
  first/last seen, window, packet numbers, recommendation, limitations, false_positive_risk, thresholds`.
  All strings are redacted of passwords, tokens and Authorization/Cookie values.
* **Adding a rule**: drop a `BaseRule` subclass into `engine/default_rules/`. It is discovered automatically; `app.py`, the
  report builder and the dashboard need no change (tested in `test_framework.py`).
* **Tuning**: every threshold is in the rule's `defaults`; override in `RULE_OVERRIDES` in `app.py`
  (`{"<rule_id>": {"<param>": value}}`). Unknown parameter names raise an error.

## Detection rules

| Rule id | Looks for | Key defaults | Main limitation / false-positive risk |
|---|---|---|---|
| `syn_flood` (`ddos_rule.py`) | ≥ N unique SYN-only packets to **one** dst IP:port in a window, mostly not completing the handshake; distributed (many sources) or single source | 100 SYN / 5 s; ignore if ≥ 50 % completed | Replies must be visible to judge handshakes (else confidence Low). Load tests, NAT |
| `udp_flood` | ≥ N UDP packets to one host in a window with little reverse traffic | 500 pkts / 5 s; reverse ≤ 20 % | One-way streams (RTP, syslog, NetFlow). DNS responses excluded (see amplification) |
| `icmp_flood` | echo-request rate to one host; unsolicited echo-reply floods from many sources | 100 / 5 s; ≥ 3 sources | Monitoring tools, `ping -f` by admins |
| `traffic_burst` | generic spike vs. the median busy second (informational only) | ≥ 500 pkts and ≥ 10× median per 1 s | Bulk transfers, backups. Says *that* it spiked, not *why* |
| `tcp_port_scan` | vertical (≥ 15 ports/host) and horizontal (≥ 10 hosts/port) SYN / NULL / FIN / XMAS probes in 60 s that mostly do not become real connections (judged per distinct target) | see rule | Outcomes need target replies. Browsers/crawlers, health checkers, FTP passive ports |
| `udp_port_scan` | ≥ 20 ports/host with small payloads, strengthened by ICMP port-unreachable | 20 ports / 60 s | VoIP/RTP/game port ranges |
| `icmp_suspicious` | ping sweeps (≥ 10 hosts), large echo payloads (≥ 256 B, ≥ 5), ICMP redirects | see rule | Discovery tools, MTU tests |
| `tcp_reset_burst` | ≥ 50 RSTs from one host to another in 10 s (informational) | 50 / 10 s | Symptom only: scans, restarts, firewalls |
| `risky_services` | repeated *completed* connections to Telnet/TFTP/SMB/RDP/VNC/backdoor ports; ≥ 3 such services from one client | 3 connections | Port numbers only; legitimate admins |
| `ftp_brute_force` | ≥ 10 `PASS` submissions in 300 s judged by server 230/530 replies; counts distinct guesses; flags success after failures | 10 / 300 s; ≥ 5 failures | Clear-text FTP only (FTPS/SFTP invisible). Auto-retrying clients, NAT |
| `http_auth_brute_force` | ≥ 8 login submissions in 300 s to one endpoint with ≥ 5 `401/403`; notes (never proves) possible success via redirect+cookie | 8 / 300 s | Clear-text HTTP only. A 200 is **not** treated as failure or success |
| `plaintext_credentials` | FTP `USER/PASS`, HTTP Basic, HTTP password form fields visible in clear text (observed fact) | – | Says credentials were exposed, not that they were valid |
| `ftp_file_transfer` | `RETR`/`STOR` with a `226` reply; escalates after many failed logins or sensitive-looking names | 5 prior failures | Data channel not inspected; keyword heuristic |
| `web_attack_patterns` | SQL-injection, directory-traversal and JNDI strings in URL/body/User-Agent (URL-decoded); lone quote counts only if a DB error is returned | – | An *attempt*, not proof. Owner scanners, devs |
| `web_enumeration` | ≥ 6 distinct paths in 60 s mostly erroring or sensitive-looking; request bursts (≥ 100 / 10 s) | see rule | Crawlers, owner scanners, SPAs |
| `dns_tunnelling` | ≥ 10 unique long (≥ 20) high-entropy (≥ 3.5 bit/char) labels under one parent domain in 300 s | see rule | CDNs, AV/cloud look-ups with random labels |
| `dns_amplification` | unsolicited large responses to a host that sent no matching query; very high response/query byte ratio | 20 responses / 10 s | Needs the queries in the capture; UDP only |

Protocol coverage: Ethernet (+VLAN), Linux cooked (SLL/SLL2), BSD loopback and raw-IP link types; IPv4 (incl. fragments) and
IPv6 (extension headers); TCP, UDP, ICMP, ICMPv6, ARP. Application parsing is limited to **FTP control, HTTP/1.x and DNS over
UDP**, done on reassembled TCP streams (segmentation, retransmission, out-of-order delivery and capture gaps handled).

## What the two reference captures actually show

Verified from the packets (and by `tests/test_reference_captures.py`), not copied from labels:

* **Network capture 1**: a legitimate host uploads files over FTP; a second host submits hundreds of distinct FTP passwords
  (server `530`), later receives a `230`, and downloads a sensitive-named file (`RETR` + `226`).
* **Network capture 2**: frames ≈ 32–88 are a **half-open SYN scan** (≈ 24 ports from one source, closed ports answer
  `RST/ACK`, one open port gets `SYN → SYN-ACK → RST`). It is **not** a SYN flood: SYNs are spread across ports. Afterwards ≈ 4,700
  short FTP connections each try a login; their handshakes complete, so the flood rule correctly stays quiet.
* **compsoc-incident**: path enumeration (mostly 403/404), 12 login `POST`s answered `401` at a slow pace, a lone-quote
  `POST` answered by an SQL error, a tautology `POST` answered `302` + `Set-Cookie`, and that cookie later used on admin pages.
  The tool reports this as *consistent with* a login bypass, **not proof**.

## Known limitations and blind spots

* Encrypted traffic (HTTPS, SSH, FTPS, DoH/DoT) is only visible as metadata; encrypted-FTP and TLS are reported as such.
* No TCP-DNS, HTTP/2, QUIC, SMB, RDP, TLS-fingerprinting or malware-signature analysis. No file extraction (nothing is ever executed).
* Thresholds are generic defaults, not tuned to your network; tune them in `app.py`.
* A capture taken on one side of a link hides replies; rules then lower confidence or say outcomes are unknown.
* Slow attacks spread beyond a rule's time window are not linked together.
* Uploads are limited to 25 MB and the first 250,000 packets (memory safety; ≈ 1.2 KB RAM per packet).
* `pcapng` is supported for standard blocks (SHB/IDB/EPB/SPB); compressed or exotic block types are skipped.
* Known false-positive families are listed per rule above and shown in each finding.

## Tests

```bash
python -m unittest discover -s tests -t . -v        # 160 tests
python -m unittest tests.test_student_tasks -v      # contract tests for the four workshop files
```

Synthetic captures come from `tests/pcap_factory.py` (pure-stdlib, deterministic; no Scapy, no network, no real attacks).
Result of the last run in the build environment (Python 3.12, Flask 3.1.3): **160 tests, 0 failures, 0 errors, 0 skipped.**

| File | Tests | Covers |
|---|---|---|
| `test_pcap_reader.py` | 17 | decoding (IPv4/IPv6/VLAN/ARP/raw IP, pcapng, ns timestamps), empty/invalid/truncated/unsupported/malformed input, missing timestamps, packet limit, 150-case mutation fuzzing, no-payload and TLS-only captures |
| `test_rules.py` | 72 | every rule: positive + negative + threshold/window tests, benign traffic, mixed capture, different IPs/ports/timing/IPv6, duplicates, out-of-order and segmented streams, redaction |
| `test_reference_captures.py` | 20 | the three supplied captures (behaviours + evidence, no frame numbers or IPs) |
| `test_framework.py` | 19 | rule discovery, new-rule drop-in, crashing rules reported, report normalisation, statistics, helpers, redaction, no rule-specific code in UI/report builder, dashboard script executed with Node |
| `test_app.py` | 5 | upload, rejection, truncated file, size limit |
| `test_student_tasks.py` | 27 | contracts for the four workshop files |
