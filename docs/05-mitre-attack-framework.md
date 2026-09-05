# 05 — MITRE ATT&CK Framework Deep Dive

**Course topic: 9.2 MITRE ATT&CK Framework Deep Dive**
**Where:** mostly the Wazuh dashboard (`siem`), with a quick attack from Kali to produce a mapped alert.

**Goal:** understand ATT&CK, see how Wazuh maps your telemetry to techniques, and build a **detection coverage map** you'll expand across the module.

---

## 1. ATT&CK in one page (teach this)

MITRE ATT&CK is a knowledge base of real adversary behavior, organized as:

- **Tactics** — the *why* (the attacker's goal). Columns of the matrix. E.g. Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.
- **Techniques / Sub-techniques** — the *how*. E.g. **T1059.001** PowerShell, **T1003.001** LSASS Memory dumping, **T1053.005** Scheduled Task.
- **Procedures** — the specific implementation an actor/tool uses.

Why it matters for this module: it gives you a **shared language** to describe attacks (9.2), organize hunts (9.4), tag detection rules (9.5), and structure an APT case study (9.6).

Reference to keep open while teaching: the ATT&CK Navigator (matrix you can color by coverage).

---

## 2. How Wazuh uses ATT&CK

Two mechanisms:

1. **Rules carry `<mitre><id>` tags.** Many built-in rules are already mapped. When a rule fires, the alert is tagged with its technique(s).
2. **The Sysmon config tags events.** Configs like `olafhartong/sysmon-modular` put `technique_id=...,technique_name=...` in the Sysmon `RuleName` field, which Wazuh rules can match on (you'll use this pattern in Doc 08).

In the dashboard, open the **MITRE ATT&CK** module. It shows techniques observed in your environment, per agent, over time. Right now it's mostly empty — let's populate it.

---

## 3. Produce your first mapped technique

You'll run **T1033 System Owner/User Discovery** and watch it appear as a tagged technique.

### Option A — straight from the victim
On the Windows victim:

```powershell
whoami
whoami /priv
```

### Option B — with Atomic Red Team (preferred, repeatable)
Install Atomic Red Team on the Windows victim (NAT on):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

Invoke-AtomicTest T1033 -TestNumbers 1
```

### See it in Wazuh
- **Threat Hunting / Discover** → filter `rule.mitre.id: "T1033"` (or search `whoami`).
- **MITRE ATT&CK** module → **Discovery** tactic now shows **T1033**.

> If nothing maps yet, that's expected for some raw events — Doc 08 is where you write the rule that *guarantees* the mapping. For now, use a technique that has built-in coverage (T1033, T1059.001 PowerShell) to demonstrate the concept.

---

## 4. Run a small spread across tactics (for the lecture visual)

To make the MITRE module light up across several columns, run a handful of Atomic tests (each maps to a technique):

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1   # Execution: PowerShell
Invoke-AtomicTest T1547.001 -TestNumbers 1   # Persistence: Registry Run Key
Invoke-AtomicTest T1053.005 -TestNumbers 1   # Persistence/PrivEsc: Scheduled Task
Invoke-AtomicTest T1218.010 -TestNumbers 1   # Defense Evasion: Regsvr32
Invoke-AtomicTest T1082 -TestNumbers 1       # Discovery: System Information
```

> Always `Invoke-AtomicTest <T#> -CheckPrereqs` first, and clean up with `-Cleanup` afterward. Snapshot before running a batch.

Refresh the **MITRE ATT&CK** dashboard — you now have a spread across Execution, Persistence, Defense Evasion, and Discovery. This is your live matrix for the lecture.

---

## 5. Build a coverage map

Create a simple tracking table (keep it in your course notes / a spreadsheet). You'll extend it in Docs 08 and 10.

| Technique | Name | Telemetry source | Wazuh rule id | Coverage |
|-----------|------|------------------|---------------|----------|
| T1033 | System Owner/User Discovery | Sysmon EID 1 | built-in / custom 100010 | ✅ |
| T1059.001 | PowerShell | PowerShell Operational / Sysmon | built-in | ✅ |
| T1053.005 | Scheduled Task | Sysmon EID 1 / Security 4698 | built-in | ⚠️ tune |
| T1003.001 | LSASS Memory | Sysmon EID 10 | **custom (Doc 08)** | ❌ → build |
| T1110 | Brute Force | auth.log / Security 4625 | 5710 / built-in | ✅ |

The goal of ATT&CK-driven defense: turn ❌ and ⚠️ into ✅ by writing/tuning rules (Doc 08), and prove it with attacks (Docs 09–10).

---

## Verify

- [ ] The MITRE ATT&CK dashboard shows at least T1033 and a few others.
- [ ] You can filter Discover by `rule.mitre.id`.
- [ ] You started a coverage map table.
- [ ] Atomic Red Team is installed on the victim (you'll reuse it constantly).

---

> [!NOTE]
> **Recording checkpoint (9.2):** Record **Lesson 9.2 — MITRE ATT&CK Framework Deep Dive** now. Structure: tactics vs techniques vs procedures → how Wazuh maps telemetry → run Atomic tests live → watch the matrix populate → introduce the coverage map. Great visual lecture because the dashboard fills in as you talk.

Next: [06 — Threat Intelligence Basics](06-threat-intelligence.md)
