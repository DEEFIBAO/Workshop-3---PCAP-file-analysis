# workshop 3 - PCAP file analysis

collaborative / solo workshop

## Scenario:

as a newfound cybersecurity agent you've been called to an organization over a distressing situation where there's been a software attack. after briefly chatting with the employees, you realize they aren't too knowledgeable with online safety. you fish around the drives and also see that the files has been encrypted.

with the tool being made today, we'll use it to fish for what where, when and why the issue came to be


## TASKS (2 parts):
- Part 1: develop a tool to effectively oversee Packet Capture files (PCAP) and detect threats. 

- Part 2: provide constant overall software tool improvements by using GIT / GITHUB (predicted 45 min duration)


- Extra Cred: workshop 1 - integrate workshop 1's reconnaissance tool with today's activity for A multipurpose use 

## __PART 1__ (predicted 1 hr duration)

step 1: download the File "pcap-workshop", should contain the following:
```text
pcap-workshop/
├── ready_made/      reader.py + server.py, already working (nobody edits these)
├── your_code/       the 5 detectors + analyzer, decide who's doing which file with your group 
├── web/             index.html, the web page the group finishes (free too modify it to distinctify )
├── samples/         the two test captures
├── start.py         runs the website:   python start.py
├── check.py         tests people's work: python check.py
└── README.md        setup and Git instructions for the group
```
inside the "your code" sub-folder is where the modules are to be located and modified in. The group / individual would decide on what they'd want to target and develop. "your code" holds 6 modules to be downloaded and opened (each holds their own rules written at the top) and modified heres what you'll see:
```text
├── detect_portscan.py     
├── detect_cleartext.py             
├── detect_dns.py       
├── detect_ports.py        
├── analyzer.py         
└── detect_bruteforce.py        
```
note: ignore "__init__.py" as this tells python that the folder is a package

step 2: use github and create your own repo:





once all modules are completed, the group can use "check.py" to test if it functions as expected and move onto other activities


step 2:

## __PART 2__ (predicted 45min duration)












## FYI:
what's GIT / GITHUB?

GitHub is a cloud-based platform used by developers to store, manage, track, and share their software code. It acts as a central hub where programming projects are saved, allowing multiple people to work on the same project simultaneously without overwriting each other's work

At its core, GitHub is built on top of Git, an open-source version control system that tracks the entire history of changes made to files

![GIT version control guide](https://user-images.githubusercontent.com/14274827/91470661-9d5a8780-e8b2-11ea-9ccb-0d813d2e35d1.png)

### project keywords:
- automation
- tool dev
- digital forensics
- networks
- detection
- GITHUB

