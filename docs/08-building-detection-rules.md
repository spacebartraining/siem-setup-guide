# 08 — Building Detection Rules

**Course topic: 9.5 Building Detection Rules**
**Where:** Wazuh dashboard to write/test rules; Windows victim + Kali to trigger them.

**Goal:** turn the hunts from Doc 07 into **automated detections**. Learn Wazuh's decoder→rule pipeline, write custom rules mapped to MITRE from the dashboard, test them in **Ruleset Test**, and verify they fire on real attacks.

---

## 1. How Wazuh analyzes a log (teach this)

```
Agent log ──▶ Decoder (extracts fields) ──▶ Rules engine (matches) ──▶ Alert (+ MITRE tag, level)
```

- **Decoders** parse raw logs into fields (Windows eventchannel is decoded for you into `data.win.*`).
- **Rules** are XML conditions over those fields. Each rule has an `id`, a `level` (0–15 severity), a `description`, optional `<mitre>` tags, and group membership.
- **Levels:** 0 = ignore/log-only, 5 = notable, 10 = important, 12+ = critical. Alerts show up at/above the manager's alert threshold.

The dashboard is a web editor for that XML. There is no point-and-click “if field = X then alert” wizard — you still write the same rule language, just without SSH.

### Where rules live (the UI writes these files)
- Custom rules: **`/var/ossec/etc/rules/local_rules.xml`** (or any new file you create under `/var/ossec/etc/rules/`).
- Built-in rules (read-only in the UI): `/var/ossec/ruleset/rules/`.
- Custom CDB lists: **Server management → CDB lists** (files under `/var/ossec/etc/lists/`).

> Loading order matters. Wazuh loads rule files in order; keep custom IDs in the **100000+** range to avoid clashing with built-ins.

---

## 2. Anatomy of a rule

```xml
<group name="local,sysmon,">
  <rule id="100010" level="10">
    <if_group>sysmon_event1</if_group>                              <!-- parent context: Sysmon process-create -->
    <field name="win.eventdata.image" type="pcre2">(?i)\\whoami\.exe</field>
    <description>Discovery: whoami.exe executed (T1033)</description>
    <mitre>
      <id>T1033</id>
    </mitre>
  </rule>
</group>
```

Key elements:
- `<if_group>` / `<if_sid>` — chain to a parent so your rule only evaluates relevant events. Prefer `<if_group>` (e.g. `sysmon_event1`, `sysmon_event3`, `windows`).
- `<field name="..." type="pcre2">` — match a decoded field with regex.
- `<mitre><id>` — the ATT&CK mapping that lights up the dashboard.
- `level` — severity.

---

## 3. Create and edit rules in the dashboard (do this)

Use the Wazuh UI for every rule in this lesson.

1. Open the Wazuh dashboard (`https://10.10.10.10`).
2. Go to **Server management → Rules**.
3. Switch the filter to **Custom rules** (built-in rules stay read-only).
4. Open **`local_rules.xml`**, or click **Add new rules file** and name it something like `module9_rules.xml`.
5. Paste one `<group>...</group>` block from section 5 below. Do not delete any sample rule already in `local_rules.xml` — add yours after it.
6. **Save**. Confirm the reload if the UI asks. That writes the file on the manager and reloads the analysis engine.

If Save fails with a syntax error, the XML is incomplete (missing `</rule>` / `</group>`). Fix it in the same editor and save again.

### Optional fallback — SSH only if the UI is down

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

---

## 4. Test before you trust it: Ruleset Test

Never guess. Feed a sample log to the analysis engine and see which rule fires.

1. In the dashboard, go to **Tools → Ruleset Test**.
2. Paste a raw event (Discover → open the event → copy the original log / `full_log`, or grab it from Event Viewer / Sysmon on the victim).
3. Run the test. The panel shows the decoder, extracted fields, and the matching rule id/level.
4. Iterate the regex in **Server management → Rules** until Ruleset Test hits your custom id.

Saving the rule is enough for Ruleset Test. Live alerts need the manager reload from the Save step above.

CLI equivalent on `siem` (same engine, if you prefer a terminal):

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---

## 5. Build the core detections (do these)

For each rule: **Server management → Rules → Custom rules** → edit your file → paste the block → **Save** → confirm in **Tools → Ruleset Test**.

### Rule 1 — LSASS credential dumping (T1003.001)
Promotes Hunt D. Fires when a non-system process opens LSASS with dump-like access.

```xml
<group name="local,sysmon,credaccess,">
  <rule id="100301" level="12">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)0x1010|0x1410|0x1438|0x143a|0x1fffff</field>
    <description>Credential Access: LSASS memory access - possible dumping (T1003.001)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>
```

### Rule 2 — Office spawning a shell (T1059 / phishing execution)
Promotes Hunt C.

```xml
<group name="local,sysmon,execution,">
  <rule id="100310" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(winword|excel|powerpnt|outlook)\.exe</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(cmd|powershell|wscript|cscript|mshta)\.exe</field>
    <description>Execution: Office app spawned a shell/script interpreter (suspicious macro)</description>
    <mitre>
      <id>T1059</id>
      <id>T1566.001</id>
    </mitre>
  </rule>
</group>
```

This VM has Edge, not Office. The rule still belongs in the lecture (classic phishing path). It will stay quiet until Word/Excel exists; Hunt C's Edge→shell query from Doc 07 is the live substitute.

### Rule 3 — Suspicious PowerShell (T1059.001)
Promotes Hunt A.

```xml
<group name="local,sysmon,execution,">
  <rule id="100320" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc |-encodedcommand|downloadstring|downloadfile|-w hidden|-nop |iex\()</field>
    <description>Execution: Suspicious PowerShell (encoded/hidden/download cradle) (T1059.001)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

### Rule 4 — LOLBin abuse (T1218)
Promotes Hunt B.

```xml
<group name="local,sysmon,defense-evasion,">
  <rule id="100330" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(regsvr32|rundll32|mshta|certutil)\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(http|scrobj|javascript:|-urlcache|/i:)</field>
    <description>Defense Evasion: signed-binary proxy execution / remote payload (T1218)</description>
    <mitre>
      <id>T1218</id>
    </mitre>
  </rule>
</group>
```

### Rule 5 — Reverse-shell / C2 beacon by port (T1071/T1571)
Promotes Hunt E. Catches the Meterpreter / Kali listener on 4444 from Doc 04 / Doc 07.

```xml
<group name="local,sysmon,command-and-control,">
  <rule id="100340" level="12">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.destinationPort" type="pcre2">^4444$</field>
    <description>C2: outbound connection to common reverse-shell port 4444 (T1571)</description>
    <mitre>
      <id>T1571</id>
      <id>T1071</id>
    </mitre>
  </rule>
</group>
```

### Rule 6 (Linux) — SSH brute force is already covered
Built-in rule **5710** detects failed SSH logins (T1110). You can *tune* it (raise level, add correlation) to demonstrate overriding a built-in. Add this the same way: **Custom rules** editor, not by changing the built-in 5710 file.

```xml
<group name="local,syslog,sshd,">
  <rule id="100350" level="12" frequency="6" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <description>Credential Access: SSH brute force - 6+ failed logins in 2 min (T1110)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

This is a **correlation rule**: it fires only when the child event (5710) happens 6+ times in 120s — a much stronger signal than a single failure.

---

## 6. Reducing false positives (teach this)

- **Chain to context** with `<if_group>`/`<if_sid>` so rules don't scan everything.
- **Whitelist** known-good with `<field negate="yes">` or a `<list>` of allowed values.
- **Tune levels** — noisy-but-useful → level 3–5 (log, no page); high-confidence → 10–12.
- **Use frequency/timeframe** for brute-force / beacon patterns instead of single events.

Example: exclude a legitimate admin tool from Rule 3. Add this extra `<field>` inside the same `<rule>` in the dashboard editor:

```xml
<field name="win.eventdata.commandLine" negate="yes" type="pcre2">(?i)\\Trusted\\deploy\.ps1</field>
```

---

## 7. Sigma (portable rules — mention/optional)

Sigma is a vendor-neutral detection format. You write once and convert to Wazuh/Splunk/Elastic. Good to show students so their skills transfer:

```bash
pip install sigma-cli
sigma convert -t wazuh path/to/rule.yml
```

Paste the converted XML into **Server management → Rules** the same way. Point them at the SigmaHQ rule repository as a source of community detections they can translate into this lab.

---

## 8. Prove every rule with an attack

For each rule, run the matching attack (from Doc 09) and confirm the alert:

| Rule | Trigger | Expected |
|------|---------|----------|
| 100301 LSASS | `Invoke-AtomicTest T1003.001` or mimikatz | level-12 alert, T1003.001 |
| 100310 Office→shell | Atomic T1566 macro / spawn cmd from Word | level-12 alert |
| 100320 PowerShell | download cradle one-liner | level-10 alert |
| 100330 LOLBin | `Invoke-AtomicTest T1218.010` | level-10 alert |
| 100340 C2:4444 | run `invoice.exe` (Doc 04) or Hunt E's Kali:4444 download | level-12 alert |
| 100350 SSH brute | `hydra` from Kali (Doc 09) | level-12 correlation alert |

Update your **coverage map**: each proven rule flips a technique to ✅.

---

## Verify

- [ ] Custom rules appear under **Server management → Rules → Custom rules**.
- [ ] **Tools → Ruleset Test** matches your rules against sample events.
- [ ] Save/reload completes without XML errors.
- [ ] Each attack in the table above produces its alert with the correct MITRE tag.
- [ ] At least one rule includes a false-positive control (negate/list/frequency).

---

> [!NOTE]
> **Recording checkpoint (9.5):** Record **Lesson 9.5 — Building Detection Rules** here. Flow: decoder→rule pipeline → anatomy of a rule → **Server management → Rules** → write Rule 1 (LSASS) live → **Tools → Ruleset Test** → trigger the attack → alert fires with MITRE tag → discuss false-positive tuning and correlation (Rule 6). This is the payoff of 9.4 → 9.5.

Next: [09 — Attack Simulation Catalog](09-attack-simulation-catalog.md)
