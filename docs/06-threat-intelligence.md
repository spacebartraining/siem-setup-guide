# 06 — Threat Intelligence Basics

**Course topic: 9.3 Threat Intelligence Basics**
**Where:** Wazuh manager (`siem`) for CDB lists + integrations; Windows victim to generate IoC hits; optional MISP VM.

**Goal:** understand what threat intelligence (TI) is, work with **indicators of compromise (IoCs)**, and wire TI into Wazuh so alerts get **enriched** automatically. Two levels: a simple local approach (CDB lists + VirusTotal) and a fuller platform approach (MISP).

---

## 1. Threat intelligence in one page (teach this)

- **What it is:** knowledge about adversaries — their infrastructure, tools, and behavior — used to make better detection and response decisions.
- **IoC vs IoA:** *Indicators of Compromise* are artifacts (IPs, domains, file hashes, URLs). *Indicators of Attack* are behaviors (ATT&CK techniques). IoCs are easy but brittle; behavior (ATT&CK) is durable. A mature SOC uses both.
- **The Pyramid of Pain:** hashes are trivial for attackers to change; TTPs (behaviors) are the hardest. This is why 9.3 (IoCs) and 9.2 (ATT&CK) complement each other.
- **Feeds/sources:** open-source (abuse.ch, AlienVault OTX, MISP communities), commercial, and internal (your own past incidents).

---

## 2. Level 1 — Local IoC matching with CDB lists

Wazuh can match events against a **CDB list** (a simple key:value file of bad indicators). Great for teaching without extra infrastructure.

**On the Wazuh manager:**

Create a list of "known-bad" IPs/domains (use your Kali IP so you get guaranteed hits in the lab):

```bash
sudo tee /var/ossec/etc/lists/malicious-ioc <<'EOF'
10.10.10.100:attacker_infra
evil-c2.example:known_c2_domain
EOF
```

Reference the list and add a rule in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="threatintel,">
  <!-- Alert when a Sysmon network connection destination is in our IoC list -->
  <rule id="100200" level="12">
    <if_group>sysmon_event3</if_group>
    <list field="win.eventdata.destinationIp" lookup="address_match_key">etc/lists/malicious-ioc</list>
    <description>Threat Intel: connection to known-bad IP $(win.eventdata.destinationIp)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
  </rule>
</group>
```

Enable the list in `/var/ossec/etc/ossec.conf` under `<ruleset>`:

```xml
<list>etc/lists/malicious-ioc</list>
```

Restart and test:

```bash
sudo systemctl restart wazuh-manager
```

From the Windows victim, connect to the "bad" IP (your Kali) — e.g. browse `http://10.10.10.100:8080`. Sysmon EID 3 fires, matches the list, and rule **100200** raises a level-12 alert. That's TI-driven detection.

---

## 3. Level 1.5 — VirusTotal enrichment

Wazuh ships a VirusTotal integration that checks file hashes from **FIM** events against VirusTotal.

**On the manager**, in `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VT_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

- Get a free API key from virustotal.com (rate-limited but fine for a lab).
- Requires internet on the manager, so this is a "NAT-on" demo, or explain it conceptually if you keep the SIEM fully isolated.
- Trigger: drop a test file (e.g. the EICAR test string) into a FIM-monitored folder on the victim; Wazuh sends the hash to VirusTotal and raises an alert if flagged.

> Teaching note: VirusTotal on **hashes** is the bottom of the Pyramid of Pain — cheap and useful, but attackers evade it by recompiling. Contrast with the behavior-based detections you build in Doc 08.

---

## 4. Level 2 — MISP integration (optional, fuller platform)

MISP (Malware Information Sharing Platform) is a real TI platform: it stores IoCs, correlates them, and exposes an API. Wazuh queries MISP for each relevant event and raises a high-severity alert on a hit.

### Deploy MISP
Easiest is the official Docker image on a small VM (or on the Linux victim if resources allow):

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env   # edit BASE_URL etc.
sudo docker compose up -d
```

Log in, create a **read-only API key** (Administration → Auth keys), and add a few events/attributes (or pull an OSINT feed) so there's data to match — include your Kali IP `10.10.10.100` and the domain `evil-c2.example` for guaranteed lab hits.

### Wire Wazuh → MISP
1. Place the integration script at `/var/ossec/integrations/custom-misp` on the manager and make it executable (`chmod 750`, `chown root:wazuh`). Reference implementations: [luckykumar19/MISP-Wazuh-Integration](https://github.com/luckykumar19/MISP-Wazuh-Integration) and [juaromu/wazuh-misp](https://github.com/juaromu/wazuh-misp).
2. Set your MISP URL + API key inside the script.
3. In `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-misp</name>
  <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

4. Add matching rules in a `misp.xml` rule file:

```xml
<group name="misp,">
  <rule id="100620" level="10">
    <field name="integration">misp</field>
    <description>MISP Events</description>
    <options>no_full_log</options>
  </rule>
  <rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP - Error connecting to API</description>
    <options>no_full_log</options>
  </rule>
  <rule id="100622" level="12">
    <field name="misp.category">\.+</field>
    <description>MISP - IoC found in Threat Intel - Category: $(misp.category), Value: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,</group>
  </rule>
</group>
```

Restart the manager. Now, when the victim makes a DNS query (Sysmon EID 22) or network connection to something in MISP, Wazuh calls MISP, gets a positive hit, and fires **rule 100622 (level 12)** — an enriched, TI-backed alert.

### Demo
From the Windows victim: `nslookup evil-c2.example` (add it to your hosts/MISP first) or connect to `10.10.10.100`. Watch the enriched MISP alert appear in Wazuh.

---

## 5. Bringing it together

| Approach | Effort | What it teaches |
|----------|--------|-----------------|
| CDB list | Low | How IoC matching works mechanically |
| VirusTotal | Low | Hash reputation, Pyramid of Pain |
| MISP | Higher | Real TI platform, API enrichment, sharing |

For a first course run, **CDB list + VirusTotal** is plenty to teach 9.3. Add MISP if you want a standout, portfolio-grade demo.

---

## Verify

- [ ] A connection from the victim to your "bad" IP raises the CDB-list alert (rule 100200).
- [ ] (If used) VirusTotal integration produces an alert on a flagged file hash.
- [ ] (If used) MISP returns a hit and rule 100622 fires.
- [ ] You can explain IoC vs IoA and the Pyramid of Pain.

---

> [!NOTE]
> **Recording checkpoint (9.3):** Record **Lesson 9.3 — Threat Intelligence Basics** here. Suggested flow: TI concepts + Pyramid of Pain → CDB list live demo (guaranteed hit via Kali IP) → VirusTotal hash enrichment → (optional) MISP integration and an enriched alert. End by tying IoCs back to the ATT&CK behavior view from 9.2.

Next: [07 — Proactive Threat Hunting](07-threat-hunting.md)
