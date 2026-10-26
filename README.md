# PCAP Sentinel --- Workshop 3

## From Network Evidence to Security Findings

**BCU Computing Society \| Cybersecurity Workshop \| 2 hours**

PCAP Sentinel is a learning project in which we design and build a small
network-traffic analysis tool. It reads a packet capture (PCAP),
extracts useful information, looks for suspicious patterns, and produces
a report that an analyst can investigate.

The goal is not to build a perfect intrusion-detection system in two
hours. The goal is to understand how a tool like this is designed, how
its parts work together, how detection logic turns network evidence into
a finding, and how to use AI responsibly while engineering it.

------------------------------------------------------------------------

## 1. The problem we are solving

Networks generate a large amount of traffic. When something suspicious
happens, an analyst may receive a PCAP file containing hundreds,
thousands, or millions of packets. Opening packets one by one is slow,
and important patterns can be easy to miss.

A PCAP contains evidence, not conclusions. It may show repeated
connection attempts, unusual traffic volumes, repeated login requests,
or protocol details that deserve investigation. The challenge is to turn
that raw evidence into useful, explainable findings.

### Our problem statement

> How can we build a small, modular tool that examines a PCAP file,
> summarises its traffic, identifies common suspicious patterns using
> transparent rules, and explains the evidence behind each finding?

### Our proposed solution

We will build **PCAP Sentinel**, a Python application that:

1.  Accepts a PCAP file.
2.  Reads packets and extracts relevant fields.
3.  Calculates traffic statistics and groups related activity.
4.  Runs detection rules against those observations.
5.  Produces structured findings with evidence and context.
6.  Displays the results in a simple web interface.

The tool is intended for **defensive analysis and education**. It does
not prove that a system has been compromised, and it should not label
every unusual event as an attack. It highlights patterns that an analyst
can verify.

------------------------------------------------------------------------

## 2. What is in scope?

We need a realistic scope. We cannot detect every attack from every
capture, and a two-hour workshop is not enough to create a
production-grade IDS.

### In scope

-   Reading packet captures and handling invalid or empty input
    sensibly.
-   Extracting useful packet fields such as timestamps, source and
    destination addresses, ports, protocols, TCP flags, packet lengths,
    and selected application-layer indicators where available.
-   Producing general traffic summaries.
-   Identifying suspicious patterns with understandable heuristic rules.
-   Including evidence with each finding: what was observed, how much,
    over what period, and why it matters.
-   Keeping detection logic modular so additional rules can be added
    without rewriting the web application.
-   Testing against more than one capture, including a capture that was
    not used while writing a rule.
-   Using AI to help write and explain code, while checking that the
    code is correct and understood.

### Example patterns we may investigate

Depending on the protocols and evidence available in a capture, the tool
may look for:

-   **Possible SYN flood:** unusually high rates of TCP SYN packets,
    especially where connection completion appears low.
-   **Possible UDP or ICMP flood:** unusually high packet rates or
    traffic volumes involving these protocols.
-   **Port scanning:** one source contacting many destination ports or
    hosts within a short interval.
-   **Repeated login attempts:** repeated authentication attempts or
    failures, where the protocol and capture expose that information.
-   **Cleartext credentials or authentication:** protocols or requests
    that appear to transmit sensitive information without transport
    encryption.
-   **Web attack indicators:** suspicious request patterns such as
    SQL-injection-like strings, path traversal attempts, or broad path
    enumeration.
-   **File-transfer activity:** observable uploads or downloads that may
    be relevant to an incident.
-   **General anomalies:** unusually high traffic rates, concentration
    of traffic from one source, or other patterns worth reviewing.

These are **indicators, not automatic proof of an attack**. For example,
a busy server can legitimately receive many SYN packets, a vulnerability
scanner can resemble an attacker, and encrypted traffic hides
application details. A rule must explain its evidence and limitations.

### Out of scope

-   Guaranteeing detection of every attack or every zero-day.
-   Replacing professional tools such as Wireshark, Zeek, Suricata, or a
    full network IDS.
-   Treating a heuristic threshold as universal truth.
-   Automatically blocking traffic or interacting with live systems.
-   Claiming that encrypted application content can be inspected when it
    is not visible in the capture.
-   Training a machine-learning model. This workshop focuses on
    transparent, explainable rule-based detection.

------------------------------------------------------------------------

## 3. Understand the data: what is a PCAP?

A **packet capture** records network packets observed at a capture
point. Depending on where and how the capture was made, it may contain
only part of a conversation, miss packets, or omit application data.

A packet can provide information such as:

-   When it was observed.
-   Which addresses communicated.
-   Which protocol was used.
-   Which ports were involved.
-   How large the packet was.
-   TCP flags, such as SYN, ACK, FIN, and RST.
-   Application-layer data, if it was captured and is not encrypted.

A single packet rarely tells the whole story. Detection often comes from
**aggregating many packets over time**.

For example, one SYN packet is normal. Thousands of SYN packets from one
source in a short interval, sent to a target with few completed
connections, may be worth investigating. The finding becomes more useful
when the tool reports the time window, packet count, source, target, and
the rule that triggered.

------------------------------------------------------------------------

## 4. The analysis process

PCAP Sentinel follows a simple analysis pipeline:

``` text
PCAP file
   |
   v
1. Read packets
   |
   v
2. Extract and normalise fields
   |
   v
3. Calculate traffic statistics
   |
   v
4. Run detection rules
   |
   v
5. Build structured findings
   |
   v
6. Display results and evidence
   |
   v
Analyst reviews and validates findings
```

Each stage has one responsibility. Separating the stages makes the
project easier to understand, test, debug, and extend.

### Stage 1 --- Read the PCAP

The reader opens the capture and iterates over its packets. It should
handle malformed input and unsupported packet details without crashing
the whole application unnecessarily.

**Design question:** What should the rest of our program receive from
the reader: raw packet objects, or a consistent representation of the
fields the rest of the system needs?

### Stage 2 --- Extract and normalise fields

Packets use different protocols and may not contain the same fields. A
normalisation step gives the rest of the program a predictable
structure.

For example, a normalised packet record might contain:

-   `timestamp`
-   `src_ip` and `dst_ip`
-   `protocol`
-   `src_port` and `dst_port`, when available
-   `tcp_flags`, when available
-   `packet_length`
-   selected application-layer indicators, when available

Fields that do not apply should be represented consistently, rather than
causing errors. The design should also distinguish **missing
information** from a meaningful zero value.

### Stage 3 --- Analyse the traffic

The analyzer calculates summaries that rules can reuse, such as:

-   Total packets and bytes.
-   Protocol distribution.
-   Top source and destination addresses.
-   Traffic over time windows.
-   Number of unique destination ports contacted by each source.
-   TCP flag counts.
-   Counts of relevant requests or authentication outcomes, where
    observable.

This layer describes what happened. It should not make every security
judgement itself.

### Stage 4 --- Run detection rules

A detection rule receives the packet data or shared statistics, looks
for a defined pattern, and returns a finding when its conditions are
met.

A good rule should answer:

1.  What pattern are we looking for?
2.  What evidence supports the finding?
3.  What threshold or conditions triggered it?
4.  What could cause a false positive?
5.  What should an analyst inspect next?

Rules should be independent modules. Adding a new rule should not
require rewriting the Flask controller, report builder, or HTML page.

### Stage 5 --- Build a report

The report builder converts the analysis into a consistent result
structure. Each finding should use a shared schema, so the interface can
display findings from different rules without knowing their internal
implementation.

A useful finding can include:

-   Rule or finding name.
-   Severity or priority.
-   Short summary.
-   Source and destination, if relevant.
-   Time range.
-   Observed counts and thresholds.
-   Evidence supporting the finding.
-   Explanation of why it matters.
-   Limitations or suggested next steps.

Severity should reflect the strength and impact of the evidence---not
just how alarming the rule name sounds.

### Stage 6 --- Present and validate the findings

The web interface lets a user upload or select a capture, run the
analysis, and inspect the results. It presents the findings; it should
not contain the detection logic itself.

The analyst then validates the results. They may inspect the relevant
packets in Wireshark, compare the finding with surrounding traffic, and
decide whether the activity is malicious, benign, or inconclusive.

------------------------------------------------------------------------

## 5. Project architecture

The workshop uses a deliberately small structure. **Only four files are
student implementation tasks.** The web interface and supporting
framework are supplied so we can focus on the analysis engine and how it
is designed.

``` text
PCAP_Sentinel/
├── app.py                       # Prebuilt: application/controller
├── README.md                    # Project and workshop guide
├── requirements.txt             # Prebuilt: dependencies
├── engine/
│   ├── pcap_reader.py           # STUDENT TASK
│   ├── traffic_analyzer.py      # STUDENT TASK
│   ├── report_builder.py        # STUDENT TASK
│   ├── ddos_rule.py             # STUDENT TASK
│   └── default_rules/           # Prebuilt supporting rules/helpers
├── samples/                     # Practice PCAP files
└── templates/
    └── index.html               # Prebuilt: web interface
```

The exact contents of the supplied starter files are the source of
truth. Do not create extra folders or move components unless the
workshop lead explicitly asks you to.

### Responsibility of each component

  ------------------------------------------------------------------------
  Component                Responsibility          Workshop status
  ------------------------ ----------------------- -----------------------
  `app.py`                 Connects the web        Prebuilt
                           request to the analysis 
                           workflow and returns    
                           results to the          
                           interface.              

  `pcap_reader.py`         Reads a PCAP and        Student task
                           exposes packet data in  
                           the agreed format.      

  `traffic_analyzer.py`    Calculates reusable     Student task
                           statistics and groups   
                           traffic for analysis.   

  `report_builder.py`      Converts results into a Student task
                           consistent report and   
                           finding structure.      

  `ddos_rule.py`           Implements a rule for   Student task
                           detecting possible      
                           DDoS/flood-like         
                           behaviour using         
                           observable evidence.    

  `default_rules/`         Supplies the shared     Prebuilt
                           rule conventions and    
                           supporting              
                           detections/helpers.     

  `templates/index.html`   Displays the analysis   Prebuilt
                           and findings to the     
                           user.                   
  ------------------------------------------------------------------------

### Why use this architecture?

-   **Separation of concerns:** each module has a clear job.
-   **Reusability:** multiple rules can use the same traffic statistics.
-   **Extensibility:** new rules can be added without rebuilding the
    interface.
-   **Testability:** components can be checked independently before the
    full app is run.
-   **Consistency:** every rule reports findings in a shared format.
-   **Maintainability:** bugs are easier to locate when responsibilities
    are not mixed together.

The design is intentionally not a large framework. A small project with
clear boundaries is easier to learn from than a complicated architecture
with many layers.

------------------------------------------------------------------------

## 6. How the components work together

Think of `app.py` as the coordinator, not the analyst.

1.  The user submits a PCAP through the interface.
2.  The controller passes the file to the reader.
3.  The reader returns packet data in the expected format.
4.  The analyzer calculates shared statistics.
5.  The controller makes the analysis available to the detection rules.
6.  Each rule evaluates its own conditions and returns zero or more
    findings.
7.  The report builder combines the results into the agreed report
    format.
8.  The controller sends the report to the interface.
9.  The user opens a finding, checks its evidence, and validates it.

The key principle is **one direction of responsibility**. The HTML page
should not parse packets. A detection rule should not render HTML. The
report builder should not secretly perform packet capture parsing. Each
component should do its own job and communicate through a documented
data structure.

### The rule interface

A rule system needs a predictable contract. Before implementing or
adding a rule, inspect the supplied default rules and identify:

-   How a rule is represented.
-   How the application discovers or calls rules.
-   What inputs a rule receives.
-   What it returns when it finds something.
-   How errors and missing fields are handled.
-   Which fields are required in a finding.

Follow the **existing interface in the starter project** rather than
inventing a competing one. If the rule interface changes, every caller
and test that depends on it may need to change as well.

------------------------------------------------------------------------

## 7. Designing a detection rule: example of a possible SYN flood

A rule is not simply "if packet count is high, call it an attack." It
should turn an observable pattern into a cautious, evidence-based
finding.

### Step 1 --- Define the behaviour

A possible SYN flood involves a high volume of TCP connection-initiation
packets directed at a target. The capture may show many SYN packets and
relatively few signs of completed handshakes, but a PCAP can be
incomplete and the pattern is not conclusive by itself.

### Step 2 --- Decide what evidence is needed

Possible inputs include:

-   TCP packets with the SYN flag set and ACK flag not set.
-   Target address and destination port.
-   Number of qualifying packets in a time window.
-   Number of distinct sources, if relevant.
-   ACK or other handshake-related observations, where reliable.

### Step 3 --- Choose a time window and threshold

A threshold is a configurable heuristic, not a universal boundary
between normal traffic and an attack. A threshold that works for a small
lab capture may be inappropriate for a busy production network.

The rule should document its assumptions and avoid hard-coding a claim
that every high count is malicious.

### Step 4 --- Return evidence, not just a label

A useful result might say:

> A high rate of TCP SYN packets was observed toward the same
> destination during the selected time window. The count exceeded the
> configured threshold. This pattern may be consistent with a SYN flood,
> but legitimate bursts, incomplete captures, or scanning activity can
> produce similar observations.

It should include the observed count, time window, target, configured
threshold, and any supporting measurements available.

### Step 5 --- Test normal and suspicious traffic

A good rule needs both positive and negative tests:

-   A synthetic capture or test dataset that should trigger the rule.
-   A normal or low-volume case that should not trigger it.
-   A boundary case close to the threshold.
-   A case with missing or incomplete fields.

If the rule triggers on everything, it is not useful. If it never
triggers, it is not useful either. Testing helps establish what the rule
actually does.

------------------------------------------------------------------------

## 8. AI-assisted development: use it as a pair programmer

**Using AI to help write code is allowed in this workshop. Understanding
and verifying the code is part of the task.**

Professional developers use documentation, debugging tools, code review,
and AI assistants. The important skill is not typing every line from
memory; it is being able to reason about the design, ask useful
questions, evaluate suggestions, test behaviour, and explain the result.

AI can generate code that looks plausible but has incorrect assumptions,
misses edge cases, invents APIs, or fits one sample PCAP without working
on other captures. Do not treat generated code as correct simply because
it runs once.

### A recommended AI workflow

1.  **Understand the task first.** In your own words, describe what the
    file must do and what it receives and returns.
2.  **Inspect the existing project.** Read the relevant interfaces,
    helper functions, tests, and neighbouring modules before asking for
    code.
3.  **Ask for a design before implementation.** Request a short
    explanation of the proposed approach, data structures, edge cases,
    and trade-offs.
4.  **Implement one component at a time.** Avoid asking AI to rewrite
    the whole repository in one enormous change.
5.  **Ask for an explanation.** For each important function, ask what it
    does, why it is needed, and how data moves through it.
6.  **Review the diff.** Check what changed, whether unrelated files
    were modified, and whether the implementation follows the existing
    architecture.
7.  **Run tests.** Test normal input, suspicious input, empty input,
    malformed input, and cases near thresholds where applicable.
8.  **Investigate failures.** Give AI the specific error and relevant
    code, then verify the suggested fix instead of blindly applying it.
9.  **Test on a different capture.** A detector should look for a
    general pattern, not a filename, a fixed IP address, or a known
    packet number from one example.
10. **Explain your result.** Be ready to describe what your code does,
    what evidence supports its findings, and where it might be wrong.

### Example prompts you can use

**Before coding**

> Explain the responsibility of this module and how it fits into the
> existing PCAP Sentinel architecture. Inspect the existing interfaces
> first. Do not change any code yet. Identify the inputs, outputs,
> assumptions, and edge cases.

**When designing a function**

> Help me design this function in small steps. Explain the algorithm and
> data structures first, then propose an implementation that follows the
> existing project conventions. Do not introduce new folders or
> unrelated dependencies.

**When reviewing code**

> Review this implementation for correctness, edge cases, false
> positives, false negatives, performance, and compatibility with the
> existing rule/report interface. Explain each issue and suggest focused
> fixes.

**When writing tests**

> Propose tests for normal, suspicious, empty, malformed, and
> boundary-case input. Include cases that should not trigger the rule.
> Explain what each test proves.

**When you do not understand something**

> Explain this function line by line for a first- or second-year
> cybersecurity student. Trace one example input through the code and
> show how it affects the output.

### The understanding check

Before committing your work, you should be able to answer:

-   What does this module receive?
-   What does it return?
-   Which other component calls it?
-   Why was this approach chosen?
-   What happens when a field is missing or the input is malformed?
-   What evidence causes a detection to trigger?
-   What normal activity might cause a false positive?
-   How did you test that the rule works---and that it does not trigger
    incorrectly?

If you cannot explain a section, that is not a reason to feel
embarrassed. It is a sign to pause, ask questions, and work through it.
The purpose of the workshop is to learn.

------------------------------------------------------------------------

## 9. Workshop workflow and checkpoints

The workshop is designed for mostly first- and second-year cybersecurity
students. You do not need to be an expert in Python, networking, or
packet analysis before arriving. We will build the understanding step by
step.

  -----------------------------------------------------------------------
  Time                    Activity                Checkpoint
  ----------------------- ----------------------- -----------------------
  00--15 min              Problem, PCAP basics,   Explain why raw packets
                          project goal, and       need to be summarised
                          architecture            before detection.

  15--30 min              Inspect the starter     Identify the four
                          project and trace the   student files and
                          data flow               describe each
                                                  responsibility.

  30--45 min              Build and test the PCAP Show how one packet
                          reader with AI          becomes a normalised
                          assistance              record.

  45--65 min              Build traffic           Explain how a statistic
                          statistics and the      or finding moves
                          report structure        through the system.

  65--85 min              Implement or complete   Explain the rule's
                          the DDoS/flood rule     evidence, threshold,
                                                  and limitations.

  85--105 min             Run the app and         Validate a finding and
                          investigate capture     identify at least one
                          results                 possible false positive
                                                  or limitation.

  105--120 min            Review, Git commit, and Commit the work and
                          discussion              explain one design
                                                  decision.
  -----------------------------------------------------------------------

The timings are a guide. If a concept needs more explanation, prioritise
understanding and a working vertical slice over rushing to implement
every feature. Work in pairs where helpful, and ask for assistance when
blocked.

### Checkpoints matter more than typing speed

At each checkpoint, pause and ask:

-   Does the module work in isolation?
-   Does its output match the interface expected by the next module?
-   Have we tested more than one case?
-   Can we explain the code without relying on the AI response?

Do not wait until the end to run the application for the first time.

------------------------------------------------------------------------

## 10. Testing and validating the findings

A successful run is not the same as a correct detector.

### Test at several levels

**Component tests:** Does the reader handle packets correctly? Does the
analyzer calculate the expected counts? Does the report builder produce
the required structure?

**Rule tests:** Does the rule trigger when its defined conditions are
present? Does it avoid triggering on normal or insufficient evidence?

**Integration tests:** Can the application pass data from the reader
through analysis and rules into a report without breaking the interface?

**Capture validation:** Does the tool behave sensibly on different
PCAPs? Do its claims match what the packets actually show?

### Avoid overfitting to the samples

The supplied captures are practice material, not the definition of what
an attack looks like. Avoid logic such as:

-   Checking for one specific filename.
-   Matching a fixed IP address from a sample.
-   Looking for a known packet or frame number.
-   Triggering because a sample contains a particular string without
    checking its context.
-   Assuming every capture uses the same ports, protocols, packet rates,
    or ordering.

Instead, identify the underlying behaviour and test it against varied
examples. A generic rule may still have limits: some attacks are not
identifiable from a PCAP alone, and different capture points can produce
different evidence.

### A useful finding must be explainable

For every finding, ask: "Could another analyst verify this from the
evidence we provide?" If the report only says "DDoS detected," it is too
vague. The report should state what was observed, where and when it
happened, which conditions were met, and why the conclusion is cautious
rather than absolute.

------------------------------------------------------------------------

## 11. Safe and responsible use

-   Analyse only PCAPs you are authorised to use.
-   Treat packet captures as potentially sensitive. They can contain IP
    addresses, usernames, session tokens, personal data, or plaintext
    credentials.
-   Do not paste sensitive packet contents, passwords, tokens, or
    private captures into an AI tool.
-   Use the provided workshop samples or approved test data.
-   Keep analysis local where required by the workshop rules.
-   Do not use the tool to attack, disrupt, or access systems. This is a
    defensive analysis exercise.
-   Report findings accurately. A heuristic alert is a lead for
    investigation, not proof of malicious intent.

------------------------------------------------------------------------

## 12. Git and project deliverable

Use Git to record progress in small, meaningful steps. Do not wait until
the final five minutes to make your first commit.

A useful sequence is:

1.  Commit after understanding the starter architecture.
2.  Commit the working reader.
3.  Commit the traffic analysis and report structure.
4.  Commit the detection rule and tests.
5.  Commit final fixes and documentation.

Use meaningful commit messages, for example:

-   `Implement normalised PCAP packet records`
-   `Add reusable traffic statistics`
-   `Build structured finding reports`
-   `Add SYN flood heuristic and tests`
-   `Document detection limitations`

Before finishing, confirm that:

-   The application starts using the supplied instructions.
-   The required student modules are implemented.
-   Tests or manual checks have been run and their results are honestly
    described.
-   At least one finding has evidence that you can explain.
-   You have tested a capture or case beyond the exact example used
    while writing the rule.
-   Your repository does not contain secrets or sensitive capture data
    that should not be shared.

------------------------------------------------------------------------

## 13. What you should leave with

By the end of the workshop, you should have:

-   A working understanding of how PCAP analysis tools are structured.
-   Experience turning packet-level data into traffic statistics.
-   An understanding of how a heuristic rule turns evidence into a
    finding.
-   A clearer picture of modular design, interfaces, and data flow.
-   Experience using AI to assist with implementation, review, and
    testing.
-   A project you can explain and develop further for your cybersecurity
    portfolio.

You are **not** expected to leave as an expert in intrusion detection.
You should leave knowing how to approach a problem, divide it into
components, test each component, question suspicious results, and keep
learning.

------------------------------------------------------------------------

## Final principle

**The objective is not to make AI write the most code. The objective is
to use the tools available to build something understandable, testable,
and defensible.**

A security tool is only useful when its findings are supported by
evidence---and an engineer grows by understanding how that evidence
became a result.
