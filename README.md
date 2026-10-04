![SCA STUDENT COMPUTING ASSOCIATION LOGO IMAGE](https://media.licdn.com/dms/image/v2/D4E22AQG76kA0aGcpMw/feedshare-shrink_480/B4EZ4CUGyDJcAk-/0/1778155286118?e=1792627200&v=beta&t=4pxQzB73I5JCSVvfKFKoq2Xu1iIVxGCxlnpZYaWJG-Q)

# workshop 3 - PCAP file analysis

collaborative / solo workshop

## Scenario:

as a newfound cybersecurity agent you've been called to an organization over a distressing situation where there's been a software attack. after briefly chatting with the employees, you realize they aren't too knowledgeable with online safety. you fish around the drives and also see that the files has been encrypted.

with the tool being made today, we'll use it to fish for what where, when and why the issue came to be


## TASKS (2 parts):
- LO1: develop a tool to effectively oversee Packet Capture files (PCAP) and detect threats. 

- LO2 provide constant overall software tool improvements by using GIT / GITHUB (predicted 45 min duration)
  
- Extra Cred: workshop 1 - integrate workshop 1's reconnaissance tool with today's activity for A multipurpose use 

## __PART 1__ (predicted 1 hr duration)

### step 1: download the File "pcap-workshop", should contain the following:
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
inside the "your code" sub-folder is where the modules are to be located and modified in. The group / individual would decide on what they'd want to target and develop. "your code" holds 6 modules to be downloaded and opened and modified, here's what you'll see (each holds their own rules written at the top of the Miscrosoft v code):
```text
├── detect_portscan.py     
├── detect_cleartext.py             
├── detect_dns.py       
├── detect_ports.py        
├── analyzer.py         
└── detect_bruteforce.py        
```
note: ignore "__init__.py" as this tells python that the folder is a package

### step 2: setup Github and create your own repo:

To tie this in with the use of git, the file would be pushed onto GitHub for everyone to be able to frequently push their own updated modules collectively

users must have a GitHub account, use this URL to log in/sign up (using your school email gives access to the GitHub Dev pack):

<ins>get set up (everyone, once)</ins>
1. check if GIT is already installed with "git --version" on a power shell terminal (if you see Git version X.XX.X __skip the next step as its installed__)
2. as GIT is missing, download it from  git-scm.com/download/win and accept the default options or
```text
use winget install --id Git.Git -e
```
3. still on the same power shell page, do the following
```text
   - git config --global user.name "Your Name"
   - git config --global user.email ""
   - git config --global init.defaultBranch main
```
(FY1, if theirs a group that doesn't have the capabilities with GIT, a technical coordinator will assist)

<ins> connect computer to Github(once) </ins>

4. Github needs authentication that that a "git push" has really came from you. a key will be needed. the key will have two parts that's a public and private. you'll make a __key__, a pair of matching files. The private half will be on the computer and Github has the public half. To make the key:
```text
   - git config --global user.email ""ssh-keygen -t ed25519 -C ""
```
show the public half so you can copy it. Then copy the whole line it prints, It starts with ssh-ed25519 and ends with your email
```text
Get-Content $HOME\.ssh\id_ed25519.pub
```
5. Give it to Github by:
   - clicking on the profile
   - settings
   - SSH and GPG keys
   - New SSH key
   - (give it a nice name)
   - paste the line into "key"
   - click "Add SSH key"
  
6. test it, use the command: 
```text
ssh -T git@github.com
```
type "yes" when asked on the terminal and it'll respond with the following to say you're authenticated.
```text
Hi (your-username)! You've successful authenticated
```
__keep the other half hidden to prevent breach__

<ins>create a reposotory</ins>
on the Github site, to create a Repository, do the following:
  -click the + on the top right and choose "new repository"
  - give it a name (no spaces, use  hypens - )
  - choose public (anyone can see it) or private (yourself and the chosen view can see it)
  - turn on "Add a README" which gives the repo a front page
  - click create repository


<ins>add a file through Github</ins>
 - open your repo on Github
 - Click add file -> upload files and then drag the files in
 - write a short commit message
 - click commit changes

<ins>add a file through terminal</ins>
 - put the file in your project folder
 - -check that git status has noticed it with
```text
git status
```
- Mark it to be saved by doing the following:
 ```text
 - git add (insert file naame)
 - git commit -m "(write a short message)"
 - git push
```

 ### step 3 invite your team!

 <ins>the owner to the repo does this once for each teammate: </ins>
 - open the repo on github and the click settings tab
 - under "access" click collaborators (Github may ask for a passsword)
 - click "add people" and type teammates username
 - click "add name to repo" and they'll get an invite

<ins>for the teammates to do be connected:</ins>
 - accept the invitation email
 - open the repo on github, click the green "code" button -> SSH tab and copy the address
 - in the terminal where you want the file (e.g your documents folder) do the following:
```text
git clone git@github.com:owner-name/roup-project.git
```
```text
cd group-project
```

## Part 2: DEVELOP! get to developing... leave some pizza for me

once all modules are completed, the group can use "check.py" to test if it functions as expected and move onto other activities

 <img width="633" height="629" alt="Screenshot 2026-10-04 115948" src="https://github.com/user-attachments/assets/cc1231f2-07d7-4311-8dc9-0611baecb4b7" />





## FYI:

### needed websites and applications
__websites__
- GitHub - a website that stores repositories (cool kids call's them Repos) online so people can share them (web link )
- Codespace - a coding workspace with Git and Python that can run in the browser (web link )

__applications__
- Git - a tool that'll tracks the changes. ,Most OS have it and works the same. You can check with "git --version".

### what's GIT / GITHUB?

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

