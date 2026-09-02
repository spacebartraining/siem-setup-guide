# 01 — SIEM & Wazuh Manager Setup

**Course topic: 9.1 SIEM Tools & Security Monitoring**
**Where:** the `siem` VM (Ubuntu Server 22.04, `10.10.10.10`).

**Goal:** deploy the Wazuh manager, indexer, and dashboard (your SIEM), and log in to the web UI. This is the brain that receives, analyzes, and visualizes all endpoint telemetry.

---

## What Wazuh is (teach this in the lecture)

Wazuh is an open-source **SIEM + XDR**. Three core components, all installed together in this lab:


| Component           | Role                                                                      |
| ------------------- | ------------------------------------------------------------------------- |
| **Wazuh Manager**   | Receives agent logs, runs them through decoders + rules, generates alerts |
| **Wazuh Indexer**   | OpenSearch-based store that makes events searchable                       |
| **Wazuh Dashboard** | Web UI (OpenSearch Dashboards) for search, alerts, MITRE view, hunting    |


> Modern Wazuh uses **OpenSearch Dashboards**, which looks and behaves like Kibana. Everywhere these docs say "dashboard", that is your Kibana-equivalent UI.

Agents on the Windows/Linux victims ship logs to the manager on **TCP 1514**; enrollment happens on **TCP 1515**.

---



## Path A — Scripted all-in-one install (recommended)

Temporarily enable NAT so the VM has internet, then run these on the `siem` VM.

```bash
sudo apt update && sudo apt -y upgrade

# Add Wazuh GPG key
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

# Download and run the official all-in-one installer
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

- `-a` installs **all** components (manager + indexer + dashboard) on this one host.
- The install takes ~15–30 minutes.
- At the end it prints the **admin password**. Copy it. You can also recover credentials later:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

> If the installer complains the hostname/resources are too small, confirm the VM has **4 vCPU and 8 GB RAM** as specced in Doc 00.

---



## Path B — Import the Wazuh OVA (fastest, no install)

If you would rather not run the installer:

1. Download the official **Wazuh OVA** from the Wazuh site (Amazon Linux 2023, manager + dashboard preinstalled).
2. VirtualBox → **File → Import Appliance** → select the `.ova`.
3. Set its network adapter to your host-only `vboxnet0`, give it `10.10.10.10`.
4. Start it, log in at the console, and continue to **Verify** below.

Default OVA credentials are shown on the Wazuh VM download page; change the dashboard admin password after first login.

---



## Access the dashboard

From your **host browser** (the host can reach the host-only network):

```
https://10.10.10.10
```

- Accept the self-signed certificate warning.
- Log in as `admin` with the password from the installer.

You should see the Wazuh overview with **0 agents** (we add them next).

---



## Baseline hardening / housekeeping

- Change the `admin` password if you used the OVA defaults.
- Confirm the manager service is healthy:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

- Confirm listening ports:

```bash
sudo ss -lntp | grep -E '1514|1515|443'
```

You should see `1514`/`1515` (manager) and `443` (dashboard).

---



## Tour the dashboard (for the lecture)

Point out these modules — you'll return to them throughout the module:


| Dashboard area                | Used for                            | Course topic |
| ----------------------------- | ----------------------------------- | ------------ |
| **Endpoints / Agents**        | Which machines are reporting        | 9.1          |
| **Threat Hunting / Discover** | Raw searchable events               | 9.4          |
| **MITRE ATT&CK**              | Techniques seen in your environment | 9.2          |
| **Vulnerability Detection**   | CVE inventory per agent             | 9.1          |
| **Security events / Rules**   | Alerts and the rules that fired     | 9.5          |


---



## Verify

- [ ] `https://10.10.10.10` loads the Wazuh dashboard and you can log in.
- [ ] `systemctl status wazuh-manager` is **active (running)**.
- [ ] Ports 1514 and 1515 are listening.
- [ ] The **Agents** page shows 0 agents (expected — none enrolled yet).
- [ ] Snapshot the `siem` VM as `wazuh-installed`.

---

> [!NOTE]
> **Recording checkpoint (partial 9.1):** You can now record the **first half of Lesson 9.1** — "What a SIEM is, Wazuh architecture, deploying the manager, touring the dashboard." Finish the **second half of 9.1** after [Doc 02](02-windows-endpoint-sysmon.md), when real endpoint telemetry is flowing.

Next: [02 — Windows Endpoint + Sysmon](02-windows-endpoint-sysmon.md)