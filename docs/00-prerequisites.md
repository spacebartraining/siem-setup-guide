# 00 — Prerequisites & Lab Design

**Goal:** prepare the host, hypervisor, network, and VMs so the rest of the lab installs cleanly and stays isolated.

---

## 1. Host machine requirements


| Resource       | Minimum                      | Recommended |
| -------------- | ---------------------------- | ----------- |
| CPU            | 4 cores                      | 8+ cores    |
| RAM            | 16 GB                        | 32 GB       |
| Disk (free)    | 200 GB SSD                   | 300+ GB SSD |
| Virtualization | VT-x / AMD-V enabled in BIOS | same        |


You can use **VirtualBox** (free) or **VMware Workstation/Player**. These docs use VirtualBox terminology but the equivalents in VMware are noted where relevant.

---

## 2. Software to download (on the host)

- Hypervisor: [VirtualBox](https://www.virtualbox.org/) or VMware Workstation.
- **Ubuntu Server 22.04 LTS** ISO — Wazuh manager.
- **Windows 10 or 11 Evaluation** ISO (free 90-day eval from Microsoft) — victim.
- **Kali Linux** ISO or prebuilt VM (you said this is already configured — good).
- *(Optional)* **Ubuntu Server/Desktop 22.04** ISO — Linux victim.

> Alternative for the SIEM: instead of installing Wazuh on Ubuntu yourself, you can import the official **Wazuh OVA** (Amazon Linux 2023, manager + dashboard preinstalled). Doc 01 covers both paths.

---



## 3. Network design (this is the most important part)

Create **one isolated network** that all lab VMs share, with **no bridge** to your real LAN.

### VirtualBox

1. **File → Tools → Network Manager → Host-only Networks → Create.**
2. Name it e.g. `vboxnet0`, set the adapter IPv4 to `10.10.10.1/24`.
3. **Disable the DHCP server** for this network (we assign static IPs manually).
4. Each VM: **Settings → Network → Adapter 1 → Host-only Adapter →** `vboxnet0`**.**

> A **Host-only** network lets the VMs talk to each other and to your host, but not to the internet. That is exactly what we want during attacks.



### Temporary internet for installs

You will need internet a few times (install Wazuh, Sysmon, Atomic Red Team, apt updates). Two clean options:

- **Option A (recommended):** give each VM a **second adapter** set to **NAT**, enabled only while installing, then disable it before running attacks.
- **Option B:** temporarily switch Adapter 1 to NAT, install, then switch back to Host-only.

> [!WARNING]
> Never run attack steps while a NAT/bridged adapter is active. Malware/emulation traffic must stay in the lab.



### IP plan


| VM                 | IP           | Gateway | Notes  |
| ------------------ | ------------ | ------- | ------ |
| Wazuh manager      | 10.10.10.10  | —       | static |
| Windows victim     | 10.10.10.20  | —       | static |
| Linux victim (opt) | 10.10.10.30  | —       | static |
| Kali attacker      | 10.10.10.100 | —       | static |


---



## 4. Create the VMs (shells only for now)

Create each VM with the resources from the [VM inventory](../README.md#vm-inventory). Do **not** install software beyond the OS yet — the later docs handle that.


| VM             | OS to install       | Doc that configures it               |
| -------------- | ------------------- | ------------------------------------ |
| `siem`         | Ubuntu Server 22.04 | [01](01-siem-wazuh-manager-setup.md) |
| `win-victim`   | Windows 10/11       | [02](02-windows-endpoint-sysmon.md)  |
| `linux-victim` | Ubuntu 22.04        | [03](03-linux-endpoint-optional.md)  |
| `kali`         | Kali Linux          | [04](04-kali-attacker-setup.md)      |




### Set static IPs

- **Ubuntu (netplan)** — edit `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [10.10.10.10/24]
```

Apply with `sudo netplan apply`. (Use `.30` for the Linux victim.)

- **Windows** — Settings → Network → Ethernet → IP assignment → Manual → IPv4 on, address `10.10.10.20`, mask `255.255.255.0`.
- **Kali** — set `10.10.10.100` via the NetworkManager GUI or `/etc/network/interfaces`.

---



## 5. Snapshot discipline

After each VM's OS is installed and networked, take a snapshot named `clean-os`. You will take more snapshots as you go:


| Snapshot name        | When to take it                                 |
| -------------------- | ----------------------------------------------- |
| `clean-os`           | Fresh OS, static IP set                         |
| `agent-installed`    | After Wazuh agent + Sysmon are working (Doc 02) |
| `pre-attack`         | Right before any attack doc                     |
| `post-attack-<name>` | After an interesting attack, to re-demo later   |


---



## Verify

- [ ] All four VMs boot and have their static IPs (`ip a` / `ipconfig`).
- [ ] From Kali, you can `ping 10.10.10.10` and `ping 10.10.10.20`.
- [ ] From the Windows victim, you can `ping 10.10.10.10`.
- [ ] With NAT disabled, none of the VMs can reach the internet (`ping 8.8.8.8` fails). This proves isolation.
- [ ] `clean-os` snapshot exists for every VM.

---

> [!NOTE]
> **Recording checkpoint:** Nothing to record yet. This doc is infrastructure. The first recordable lecture (**9.1**) comes after [Doc 01](01-siem-wazuh-manager-setup.md) and [Doc 02](02-windows-endpoint-sysmon.md).

Next: [01 — SIEM & Wazuh Manager Setup](01-siem-wazuh-manager-setup.md)