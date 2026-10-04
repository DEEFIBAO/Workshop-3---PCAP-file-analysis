# PCAP Sentinel: 60-minute group build

Upload a packet capture, and this tool lists the attacks inside it.
Some parts are **ready-made**. Your group builds the rest in one hour.

## The folder

```
pcap-sentinel-git/
├── ready_made/          DON'T EDIT: already works
│   ├── reader.py          turns a .pcap file into a list of packets
│   └── server.py          the website's back end
├── your_code/           THE GROUP BUILDS THESE: one file per person
│   ├── detect_portscan.py    D1  port scans
│   ├── detect_bruteforce.py  D2  password guessing
│   ├── detect_dns.py         D3  suspicious DNS
│   ├── detect_cleartext.py   D4  unencrypted passwords
│   ├── detect_ports.py       D5  malware ports
│   └── analyzer.py           A   joins all the detectors into one report
├── web/
│   └── index.html       W   the web page (the group finishes it)
├── samples/             two test captures: one with attacks, one without
├── start.py             DON'T EDIT: starts the website
└── check.py             DON'T EDIT: tells you if your piece works
```

## Setup (once, before the session)

1. Install **Python 3** from python.org. On Windows, tick **"Add Python to PATH"**.
2. Get this repository onto your computer (see "Using Git" below).
3. Open a terminal **in this folder** and run:
   ```
   pip install -r requirements.txt
   ```
4. Check it works:
   ```
   python check.py reader
   ```
   You should see `11071 packets`. (On Windows, a warning about "libpcap" is normal and harmless.)

## During the session

1. Open **your** file. The rule you need to build is written at the top, and the gaps are marked `TODO`.
2. Test it whenever you like:
   ```
   python check.py portscan      (or bruteforce, dns, cleartext, ports, analyzer)
   ```
   `OK` = working, `--` = not started, `X` = needs fixing (it says why).
3. Building the web page? Run `python start.py` and open http://127.0.0.1:8000.
   Until the join it shows made-up demo data, so you don't have to wait for anyone.
4. See the whole group's progress: `python check.py`

**Finished when:** `python check.py` shows `OK` on every line, and uploading
`samples/attack-demo.pcap` on the web page shows **8 alerts, risk score 100**.

## Using Git

**One person (the organiser), once:**

1. Open GitHub Desktop → *File → Add local repository* → choose this folder → *create a repository* if asked.
2. Click **Publish repository**, then add your group as collaborators on GitHub
   (repository → *Settings → Collaborators*).

**Everyone else, once:** GitHub Desktop → *File → Clone repository* → pick the repo.

**While working:**

- Only edit **your own file**. That way, two people never change the same file, and Git never has a conflict.
- To share your work: write a short summary → **Commit to main** → **Push origin**.
- To get everyone else's work: **Fetch origin**, then **Pull**.
- At the join (0:35), everyone pushes, then the person running the demo pulls and runs `python check.py`.

Prefer the command line? Use `git pull`, then `git add your_code/detect_dns.py`,
`git commit -m "DNS detector"` and `git push`.
