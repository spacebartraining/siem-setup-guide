# 03 — Linux Endpoint (Optional)

**Course topic: 9.1 SIEM Tools & Security Monitoring** (breadth — multi-OS monitoring)
**Where:** the `linux-victim` VM (Ubuntu 22.04, `10.10.10.30`).

**Goal:** add a Linux victim so you can demonstrate that a SIEM monitors **heterogeneous** environments, and so 9.6's APT story can include an SSH brute-force / Linux pivot. Skip this if you're tight on RAM — the module works with just the Windows victim.

---

## Step 1 — Install the Wazuh agent (from the dashboard)

Temporarily enable **NAT** on the Linux VM so it can download the `.deb`. Use the **same agent version as your Wazuh manager** (the wizard prints a command for that version).

### On the Wazuh dashboard

1. Left navigation pane: **Server management → Endpoint Summary → Deploy New Agent**.
2. Choose **Linux** (DEB / Ubuntu / Debian).
3. Set **Server address** = `10.10.10.10`.
4. Set **Agent name** = `linux-victim` (or leave the generated name — you will hunt on whatever you type here).
5. Copy the install command the dashboard shows. It looks like this (version numbers will match **your** manager):

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb && sudo WAZUH_MANAGER='10.10.10.10' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='linux-victim' dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb
```

> Paste **exactly** the command from your dashboard. Do not mix a 4.9 `.deb` onto a machine that already has a **newer** agent (for example 4.14.x). That downgrade leaves an incompatible `ossec.conf` (`No such tag 'users' at module 'syscollector'`).

### On the Linux victim (run the copied command)

If `dpkg` asks about `/etc/systemd/system/wazuh-agent.service` and says the file was deleted, choose **`Y`** (install the package maintainer’s version). **`N`** leaves you with no service file.

If `apt`/`dpkg` waits on a lock (`Could not get lock /var/lib/dpkg/lock-frontend` / `unattended-upgr`), **wait** until that process finishes. Do not kill it or delete the lock.

Then start the agent:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

Use **`sudo`** for `systemctl`. Confirm the manager address is not still a placeholder:

```bash
sudo grep "<address>" /var/ossec/etc/ossec.conf
```

If you see `<address>MANAGER_IP</address>`, the env vars did not rewrite the config (common on reinstall of the same package). Fix it:

```bash
sudo sed -i "s/<address>MANAGER_IP<\/address>/<address>10.10.10.10<\/address>/" /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

### Verify enrollment

Wazuh dashboard → **Server management → Endpoint Summary** → your agent (`linux-victim` or the name you set) shows **Active** (green).

---

## Step 2 — Add auditd for syscall-level telemetry

`auditd` is the Linux equivalent of Sysmon-style depth: it records execve (commands run), file access, and more.

```bash
sudo apt -y install auditd audispd-plugins
sudo systemctl enable --now auditd
```

Add a couple of high-value audit rules (command execution + sensitive file access):

```bash
sudo tee /etc/audit/rules.d/lab.rules >/dev/null <<'EOF'
## Log every command execution (execve) with a key we can hunt on
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

## Watch sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_config
EOF

sudo augenrules --load
sudo systemctl restart auditd
```

---

## Step 3 — Forward auditd + auth logs to Wazuh

Edit `/var/ossec/etc/ossec.conf` on the Linux victim and confirm/add these `<localfile>` blocks inside `<ossec_config>`:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

Restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

---

## Step 4 — Verify telemetry

Generate activity:

```bash
whoami
sudo cat /etc/shadow >/dev/null
id root
```

In Wazuh **Discover**, filter (use the agent name you set in the wizard):

```
agent.name: "linux-victim"
```

You should see auditd `execve` events (key `exec`) and, if you failed an `su`/SSH login, authentication events. SSH failed logins map to built-in Wazuh rule **5710** (tagged MITRE **T1110 Brute Force**) — you'll use this in Doc 10.

---

## Verify

- [ ] The Linux agent is **Active** under **Server management → Endpoint Summary**.
- [ ] `auditctl -l` shows your rules loaded.
- [ ] Running a command on the victim shows up as an auditd event in Wazuh.
- [ ] Snapshot the Linux VM as `agent-installed`.

---

> [!NOTE]
> **Recording checkpoint:** Optional add-on to **Lesson 9.1**. If your course emphasizes multi-OS monitoring, record a short segment here showing the same SIEM ingesting Linux telemetry. Otherwise this is background prep for the APT case study in Doc 10.

Next: [04 — Kali Attacker Setup](04-kali-attacker-setup.md)
