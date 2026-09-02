# 02 — Windows Endpoint + Sysmon

**Course topic: 9.1 SIEM Tools & Security Monitoring** (completes the lesson)
**Where:** the `win-victim` VM (Windows 10/11, `10.10.10.20`), plus one step on the `siem` VM.

**Goal:** turn the Windows VM into a fully instrumented victim. By the end, three log sources flow into Wazuh:

1. **Windows Event Viewer** (Security, System, Application, PowerShell)
2. **Sysmon** (`Microsoft-Windows-Sysmon/Operational`)
3. **Wazuh agent** shipping both to the manager

This is the telemetry backbone for every attack in later docs.

---

## Step 1 — Install the Wazuh agent

On the Windows VM (temporarily enable NAT for the download).

### Option A: from the dashboard (easiest)
1. In the Wazuh dashboard, open **Deploy new agent** from the left navigation pane:
   **Server management → Endpoint Summary → Deploy New Agent**
2. Choose **Windows**, set **Server address** = `10.10.10.10`, agent name = `win-victim`.
3. Copy the generated PowerShell command and run it in an **Administrator PowerShell**. It downloads the MSI, installs, and enrolls in one shot. Example shape:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0.msi -OutFile $env:tmp\wazuh-agent.msi
msiexec.exe /i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER='10.10.10.10' WAZUH_AGENT_NAME='win-victim'
NET START WazuhSvc
```

### Option B: manual MSI
Download the Windows agent MSI from Wazuh, install with defaults, then open **Wazuh Agent Manager**, set Manager IP `10.10.10.10`, name `win-victim`, **Save**, **Restart**.

### Verify enrollment
Wazuh dashboard → **Server management → Endpoint Summary** → `win-victim` shows **Active** (green).

---

## Step 2 — Install Sysmon with a good config

Sysmon (System Monitor) is a Microsoft Sysinternals driver that writes **high-fidelity** events (process creation with command line + hashes, network connections, image loads, registry changes, WMI, named pipes) to its own Event Log channel. This is what makes real detection possible.

Run in **Administrator PowerShell** on the Windows VM:

```powershell
mkdir C:\sysmon; cd C:\sysmon

# Sysmon binary
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive .\Sysmon.zip -DestinationPath . -Force

# A strong community config. SwiftOnSecurity is a solid baseline:
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install and load the config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

> **Config choice for the lecture:** SwiftOnSecurity is beginner-friendly and low-noise. [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) is more comprehensive and is **pre-tagged with MITRE technique IDs** in the `RuleName` — great for Doc 05. You can swap configs later with `Sysmon64.exe -c newconfig.xml`.

### Verify Sysmon locally
Open **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**. You should see Event ID **1** (process create), **3** (network), etc. Also:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Step 3 — Turn on richer Windows auditing (optional but recommended)

Real detections need the Security log to actually record things. Enable command-line auditing and PowerShell logging.

**Process command line in Event ID 4688** (Admin PowerShell):

```powershell
# Audit process creation
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
# Include the full command line in 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**PowerShell Script Block Logging** (captures actual script content — key for detecting obfuscated PowerShell):

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

---

## Step 4 — Tell the Wazuh agent to forward these channels

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` as Administrator. Inside `<ossec_config>`, add the log sources:

```xml
<!-- Sysmon -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- PowerShell operational (script block logging) -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Core Windows logs (usually present by default, confirm they exist) -->
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Optionally enable **File Integrity Monitoring** by adding a watched folder inside the `<syscheck>` block:

```xml
<directories realtime="yes">C:\Users\Public\Downloads</directories>
```

Restart the agent so changes apply:

```powershell
Restart-Service WazuhSvc
```

---

## Step 5 — Confirm telemetry reaches Wazuh

Generate a test event on the Windows VM:

```powershell
whoami
ipconfig /all
```

In the Wazuh dashboard → **Threat Hunting / Discover**, filter:

```
agent.name: "win-victim" and data.win.system.providerName: "Microsoft-Windows-Sysmon"
```

You should see Sysmon Event ID 1 for `whoami.exe` / `ipconfig.exe`, including the full command line and hashes.

---

## Understanding the three log sources (teach this)

| Source | Channel / where | Strengths | Example event |
|--------|-----------------|-----------|---------------|
| **Event Viewer – Security** | `Security` | Logons, priv use, account changes | 4624 logon, 4688 process, 4720 user created |
| **Sysmon** | `Microsoft-Windows-Sysmon/Operational` | Process lineage, hashes, network, registry | 1 process, 3 network, 11 file, 13 registry |
| **Wazuh** | manager | Correlates + alerts + MITRE + hunting | rule fired, technique tagged |

The same action (e.g. running `whoami`) appears in **all three** — that redundancy is the point: Sysmon gives detail, the Security log gives the OS view, Wazuh unifies and alerts.

---

## Verify

- [ ] `win-victim` agent is **Active** in Wazuh.
- [ ] Sysmon service running; Operational log has events.
- [ ] `whoami`/`ipconfig` from the VM appear in Wazuh Discover within seconds.
- [ ] PowerShell and Security channels appear in Wazuh (run a quick PowerShell command to test).
- [ ] Snapshot the Windows VM as `agent-installed`.

---

> [!NOTE]
> **Recording checkpoint (completes 9.1):** You can now record the **full Lesson 9.1 — SIEM Tools & Security Monitoring**: SIEM concepts (Doc 01) + onboarding an endpoint, Sysmon, Event Viewer vs Sysmon vs Wazuh, and watching live telemetry (this doc). This is your first end-to-end recordable lecture.

Next: [03 — Linux Endpoint (optional)](03-linux-endpoint-optional.md) or skip to [04 — Kali Attacker Setup](04-kali-attacker-setup.md).
