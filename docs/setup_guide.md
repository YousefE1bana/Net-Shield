> **Retired V1 university documentation.** Historical context only. Do not follow legacy root/firewall/attack instructions. Use the current [V2 installation](INSTALL.md) and [security model](THREAT-MODEL.md).

# NetShield IDS — Lab Setup Guide

## Prerequisites

| Machine | OS | Role | Required Software |
|---|---|---|---|
| **Attacker** | Kali Linux | Launch attacks | Python 3, Scapy, Paramiko |
| **IDS Server** | Ubuntu Server | Monitor + Dashboard | Python 3, Scapy, Flask |
| **Victim** | Windows 7 | Target machine | HTTP server, SSH (optional) |

---

## Step 1: Network Configuration

All three machines must be on the same network. Use static IPs:

```
┌─────────────────────────────────────────┐
│           Network: 192.168.1.0/24       │
│                                         │
│  Kali:    192.168.1.200                 │
│  Ubuntu:  192.168.1.150                 │
│  Win7:    192.168.1.100                 │
│  Gateway: 192.168.1.1                   │
└─────────────────────────────────────────┘
```

### Ubuntu Server
```bash
# Edit network config
sudo nano /etc/netplan/01-netcfg.yaml
```
```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses: [192.168.1.150/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8]
```
```bash
sudo netplan apply
```

### Kali Linux
```bash
sudo ifconfig eth0 192.168.1.200 netmask 255.255.255.0
sudo route add default gw 192.168.1.1
```

### Windows 7
1. Control Panel → Network → Change adapter settings
2. Right-click adapter → Properties → IPv4
3. Set: IP `192.168.1.100`, Mask `255.255.255.0`, Gateway `192.168.1.1`

### Verify connectivity
```bash
# From each machine, ping the others
ping 192.168.1.100   # Windows 7
ping 192.168.1.150   # Ubuntu
ping 192.168.1.200   # Kali
```

---

## Step 2: Ubuntu Server Setup (IDS)

```bash
# 1. Copy NetShield project to Ubuntu
scp -r NetShield/ user@192.168.1.150:~/

# 2. SSH into Ubuntu
ssh user@192.168.1.150

# 3. Run setup
cd ~/NetShield
sudo bash setup.sh

# 4. Edit config
nano config.py
# Set VICTIM_IP, ATTACKER_IP, IDS_IP, NETWORK_INTERFACE

# 5. Start the IDS
source venv/bin/activate
sudo python3 -m dashboard.app
```

---

## Step 3: Windows 7 Setup (Victim)

### Enable HTTP Server (Simple Python server for testing)
```cmd
# If Python is installed:
python -m http.server 80

# Or install XAMPP/IIS for a real web server
```

### Enable Remote Desktop (optional, for RDP testing)
1. Right-click Computer → Properties → Remote Settings
2. Allow Remote Desktop connections

---

## Step 4: Kali Linux Setup (Attacker)

```bash
# 1. Copy attack scripts
scp -r NetShield/attack_scripts/ kali@192.168.1.200:~/

# 2. Install dependencies
cd ~/attack_scripts
pip3 install scapy paramiko requests colorama

# 3. Run attacks (see README for commands)
sudo python3 ddos_sim.py --target 192.168.1.100 --type syn --duration 10
```

---

## Step 5: Verify Everything Works

1. Open browser: `http://192.168.1.150:8080`
2. Dashboard should show "Online" status
3. Click **Attack Simulation** buttons on dashboard
4. Verify alerts appear in real-time
5. From Kali, run actual attack scripts
6. Watch the IDS detect and respond!

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Scapy permission error | Run with `sudo` |
| Dashboard not loading | Check port 8080 is not blocked by firewall |
| Packets not captured | Verify `NETWORK_INTERFACE` in config.py matches `ifconfig` |
| Machines can't ping | Check they're on the same subnet and firewalls allow ICMP |
| WebSocket disconnects | Try `http://` not `https://`, check browser console |
