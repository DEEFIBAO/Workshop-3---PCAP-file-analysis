
# Workshop 3 – PCAP File Analysis

*Collaborative or solo workshop*

## Scenario

As a newly hired cybersecurity agent, you've been called to an organisation after a software attack. After chatting with the employees, you realise they don't know much about online safety. You look around the drives and find that the files have been encrypted.

Using the tool you build today, you'll dig through the network traffic to find out **what** happened, **where**, **when** and **why**.

## Tasks

| | Task | Time |
|---|---|---|
| **LO1** | Build a tool that reads packet capture (PCAP) files and detects threats | ~1 hr |
| **LO2** | Keep improving the tool as a team using Git / GitHub | ~45 min |
| ⭐ **Extra credit** | Combine Workshop 1's reconnaissance tool with today's tool for a multipurpose tool | – |

---

## 🧭 Choose your route

Every step that differs is labelled with one of these two routes. **Pick one and only follow the steps for your route.** Steps with no label are for everyone.

| | 🌐 **Browser route** | 💻 **Command line route** |
|---|---|---|
| **Best for** | Beginners, school / locked-down PCs, nothing to install | People comfortable with a terminal who want to work on their own machine |
| **You need** | A GitHub account and a web browser | A GitHub account, Git and Python 3 installed |
| **Where you code** | GitHub Codespaces (VS Code in the browser) | Your own editor (e.g. VS Code) |
| **How you share work** | Buttons in GitHub / Codespaces | `git add`, `git commit`, `git push` |

> Not sure? **Pick the browser route.** You can switch to the command line later; the code is the same either way.

---

## Part 1 – Set up (≈ 1 hr)

### Step 1: Know what's in the project

The `pcap-workshop` folder contains:

```text
pcap-workshop/
├── ready_made/      reader.py + server.py – already working (nobody edits these)
├── your_code/       the 5 detectors + analyzer – decide with your group who does which file
├── web/             index.html – the web page the group finishes (feel free to make it your own)
├── samples/         two test captures (one with attacks, one clean)
├── start.py         runs the website:     python start.py
├── check.py         tests everyone's work: python check.py
└── README.md        setup and Git instructions for the group
```

The `your_code` folder is where you work. Each file has its own rules written at the top:

```text
your_code/
├── detect_portscan.py     D1  port scans
├── detect_bruteforce.py   D2  password guessing
├── detect_dns.py          D3  suspicious DNS
├── detect_cleartext.py    D4  unencrypted passwords
├── detect_ports.py        D5  malware ports
└── analyzer.py            A   joins all the detectors into one report
```

> Ignore `__init__.py` – it just tells Python the folder is a package.

### Step 2: Create a GitHub account (everyone)

Sign up or log in at [github.com](https://github.com). Using your **school email** gives you access to the [GitHub Student Developer Pack](https://education.github.com/pack), which includes free Codespaces hours.

### Step 3: Set up your tools

<details open>
<summary><b>🌐 Browser route</b> – nothing to install</summary>

<br>

Nothing to do here! Codespaces already has Git and Python. Skip to **Step 4**.

</details>

<details>
<summary><b>💻 Command line route</b> – install Git and connect it to GitHub (once per computer)</summary>

<br>

**a) Install Git and Python**

1. Open PowerShell and check whether Git is installed:
   ```powershell
   git --version
   ```
   If you see `git version X.XX.X`, skip to step 3.
2. Install Git, either from [git-scm.com/download/win](https://git-scm.com/download/win) (accept the default options) or with:
   ```powershell
   winget install --id Git.Git -e
   ```
3. Install **Python 3** from [python.org](https://www.python.org/downloads/). On Windows, tick **"Add Python to PATH"**.

**b) Tell Git who you are**

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
git config --global init.defaultBranch main
```

**c) Create an SSH key so GitHub knows a push really came from you**

A key comes in two halves: a **private** half that stays on your computer, and a **public** half you give to GitHub.

1. Make the key (press Enter to accept the defaults):
   ```powershell
   ssh-keygen -t ed25519 -C "you@example.com"
   ```
2. Show the public half and copy the whole line (it starts with `ssh-ed25519` and ends with your email):
   ```powershell
   Get-Content $HOME\.ssh\id_ed25519.pub
   ```
3. Add it to GitHub: profile picture → **Settings** → **SSH and GPG keys** → **New SSH key** → give it a name → paste the line into **Key** → **Add SSH key**.
4. Test it:
   ```powershell
   ssh -T git@github.com
   ```
   Type `yes` if asked. You should see: `Hi your-username! You've successfully authenticated...`

> 🔒 **Never share the private half** (the file *without* `.pub`). Anyone with it can push as you.

If your group gets stuck with Git, a technical coordinator will help.

</details>

### Step 4: Create the group repository (one person – the organiser)

The organiser creates the repo and uploads the `pcap-workshop` files so everyone can work from the same copy.

1. On GitHub, click **+** (top right) → **New repository**.
2. Give it a name (no spaces – use hyphens, e.g. `pcap-group-3`).
3. Choose **Public** (anyone can see it) or **Private** (only you and people you invite).
4. Tick **Add a README**, then click **Create repository**.

Then add the workshop files:

<details open>
<summary><b>🌐 Browser route</b></summary>

<br>

1. Open your new repo → **Add file** → **Upload files**.
2. Drag in the **contents** of the `pcap-workshop` folder.
3. Write a short commit message (e.g. `Add workshop files`) → **Commit changes**.

</details>

<details>
<summary><b>💻 Command line route</b></summary>

<br>

1. On the repo page, click the green **Code** button → **SSH** tab → copy the address.
2. Clone it, copy the workshop files in, and push:
   ```powershell
   git clone git@github.com:your-username/your-repo.git
   cd your-repo
   # copy the contents of pcap-workshop into this folder, then:
   git add .
   git commit -m "Add workshop files"
   git push
   ```

</details>

### Step 5: Invite your team

**The organiser** does this once for each teammate:

1. Open the repo → **Settings** tab → **Collaborators** (under *Access*). GitHub may ask for your password.
2. Click **Add people**, type your teammate's username, and send the invite.

**Each teammate** accepts the invite from their email or GitHub notifications, then gets their own copy:

<details open>
<summary><b>🌐 Browser route</b></summary>

<br>

1. Open the repo → green **Code** button → **Codespaces** tab → **Create codespace on main**.
2. Wait for VS Code to load in your browser. You now have the project, a terminal and Python.
3. In the terminal at the bottom, install the requirements:
   ```bash
   pip install -r requirements.txt
   ```

> 💡 To come back later, go to [github.com/codespaces](https://github.com/codespaces) and reopen the same codespace – don't create a new one each time.

</details>

<details>
<summary><b>💻 Command line route</b></summary>

<br>

1. Open the repo → green **Code** button → **SSH** tab → copy the address.
2. In PowerShell, go to where you want the project (e.g. Documents) and run:
   ```powershell
   git clone git@github.com:owner-name/group-project.git
   cd group-project
   pip install -r requirements.txt
   ```

</details>

---

## Part 2 – Develop! (get coding… and leave some pizza for me 🍕)

### Run and test your code

These commands work the same in both routes – in Codespaces, type them in the terminal at the bottom of the screen.

| What | Command |
|---|---|
| Check the reader works (should say `11071 packets`) | `python check.py reader` |
| Test **your** detector | `python check.py portscan` *(or `bruteforce`, `dns`, `cleartext`, `ports`, `analyzer`)* |
| See the whole group's progress | `python check.py` |
| Run the website | `python start.py` |

When you run the website:
- 🌐 **Browser route:** Codespaces shows a pop-up – click **Open in Browser** (or use the **Ports** tab next to the terminal).
- 💻 **Command line route:** open [http://127.0.0.1:8000](http://127.0.0.1:8000).

`OK` = working, `--` = not started, `X` = needs fixing (it tells you why).

### Share your work and get everyone else's

> ✋ **Only edit your own file.** If two people never change the same file, Git never has a conflict.

<details open>
<summary><b>🌐 Browser route</b> (in Codespaces)</summary>

<br>

**To share your work:**
1. Click the **Source Control** icon in the left sidebar (the branching-lines icon).
2. Type a short message, e.g. `DNS detector working`.
3. Click **Commit**, then **Sync Changes**.

**To get everyone else's work:** in Source Control, click **Sync Changes** (or the `↻` icon in the bottom bar).

*Quick fix without Codespaces:* open your file on github.com → ✏️ pencil icon → edit → **Commit changes**.

</details>

<details>
<summary><b>💻 Command line route</b></summary>

<br>

**To share your work:**
```powershell
git status                              # see what you changed
git add your_code/detect_dns.py         # mark your file to be saved
git commit -m "DNS detector working"    # save it with a message
git push                                # send it to GitHub
```

**To get everyone else's work:**
```powershell
git pull
```

> Tip: always `git pull` before you start working and before you push.

</details>

### ✅ Finished when

`python check.py` shows `OK` on every line, and uploading `samples/attack-demo.pcap` on the web page shows **8 alerts, risk score 100**.

<img width="633" height="629" alt="Screenshot of the finished PCAP tool" src="https://github.com/user-attachments/assets/cc1231f2-07d7-4311-8dc9-0611baecb4b7" />

---

## FYI

### Websites and applications

**Websites**
- [GitHub](https://github.com) – stores repositories (the cool kids call them *repos*) online so people can share them.
- [GitHub Codespaces](https://github.com/codespaces) – a coding workspace with Git and Python that runs in your browser.

**Applications** (command line route only)
- [Git](https://git-scm.com) – tracks changes to your files. Works the same on every OS; check with `git --version`.
- [Python 3](https://www.python.org/downloads/) – runs the tool.

### What are Git and GitHub?

**Git** is an open-source version control system that tracks the entire history of changes made to files.

**GitHub** is a cloud platform built on top of Git. It's a central hub where projects are stored, so lots of people can work on the same project at once without overwriting each other's work.

![Git version control guide](https://user-images.githubusercontent.com/14274827/91470661-9d5a8780-e8b2-11ea-9ccb-0d813d2e35d1.png)

### Project keywords

`automation` · `tool development` · `digital forensics` · `networks` · `threat detection` · `GitHub`
