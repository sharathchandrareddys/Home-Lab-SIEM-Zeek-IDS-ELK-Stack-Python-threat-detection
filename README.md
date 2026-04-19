# Network Monitor — Home Lab SIEM

> A production-style network traffic analysis pipeline built with **Zeek IDS**, **Elasticsearch**, **Kibana**, and **Python** threat detection. Captures live traffic, ships structured logs into a searchable stack, and alerts on port scans and DNS anomalies in real time.

![Architecture](docs/screenshots/kibana-dashboard.png)

---

## Architecture

```
Windows Host (WSL2 Ubuntu)
│
├── Zeek 8.x  ──────────────────► /opt/zeek/logs/current/
│   Captures live traffic              conn.log  dns.log
│   on eth0 / any interface            ssl.log   http.log
│
├── Filebeat  ──────────────────► Elasticsearch :9200
│   Ships JSON logs                    Index: zeek-logs-*
│
├── Kibana :5601 ◄───────────── Elasticsearch
│   Dashboards + Visualizations
│
└── alert.py  ──────────────────► alerts.log
    Runs every 5 min via cron          Port scan detection
                                       DNS tunneling detection
```

---

## Features

- Live packet capture and structured log generation with Zeek IDS
- Full ELK pipeline: Filebeat → Elasticsearch → Kibana
- Real-time dashboards: top talkers, protocol breakdown, connection timeline, DNS queries
- Python-based threat detection — port scans and DNS tunneling alerts
- Automated alerting via cron job every 5 minutes
- Runs entirely on free tools — no paid services required

---

## Tech Stack

| Tool | Version | Purpose |
|------|---------|---------|
| Zeek | 8.x | Network IDS — packet capture + log generation |
| Elasticsearch | 8.11.0 | Log storage and indexing |
| Kibana | 8.11.0 | Dashboards and visualization |
| Filebeat | 8.11.0 | Log shipping agent |
| Docker + Compose | Latest | Container orchestration |
| Python 3 | 3.x | Threat detection alerting |
| WSL2 / Ubuntu 22.04 | — | Linux environment on Windows |

---

## Prerequisites

- Windows 10/11 with WSL2 enabled
- Ubuntu 22.04 installed in WSL2
- Docker Desktop installed (or docker.io in WSL2)
- At least 4GB RAM available for the ELK stack

---

## Setup Guide

### Step 1 — Enable WSL2 and install Ubuntu

Open PowerShell as Administrator:

```powershell
wsl --install
```

Restart when prompted. Open Ubuntu from Start menu, create your username and password, then update:

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2 — Install Docker inside WSL2

```bash
sudo apt install docker.io docker-compose -y
sudo usermod -aG docker $USER
```

Close and reopen your terminal for the group change to take effect.

### Step 3 — Install Zeek

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update && sudo apt install zeek -y
```

Add Zeek to your PATH:

```bash
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc
source ~/.bashrc
```

> **Important:** `sudo` uses a different PATH than your user. Always use the full path with sudo:
> `sudo /opt/zeek/bin/zeek` and `sudo /opt/zeek/bin/zeekctl`

Fix sudo PATH permanently:

```bash
sudo visudo
```

Find `Defaults secure_path` and add `:/opt/zeek/bin` to the end:

```
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/zeek/bin"
```

Verify installation:

```bash
zeek --version
```

### Step 4 — Enable JSON logging in Zeek

```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Add this line at the very bottom:

```
@load policy/tuning/json-logs
```

Save with `Ctrl+O`, `Enter`, `Ctrl+X`.

### Step 5 — Clone this repo and start the stack

```bash
git clone https://github.com/sharathchandrareddys/Home-Lab-SIEM-Zeek-IDS-ELK-Stack-Python-threat-detection.git
cd Home-Lab-SIEM-Zeek-IDS-ELK-Stack-Python-threat-detection
sudo chown root:root filebeat.yml
docker-compose up -d
```

Wait 60 seconds for Elasticsearch and Kibana to initialize.

### Step 6 — Deploy Zeek

Find your network interface:

```bash
ip link show
```

Fix the logs symlink (required on first run):

```bash
sudo rm -rf /opt/zeek/logs/current
```

Edit the Zeek node config:

```bash
sudo nano /opt/zeek/etc/node.cfg
```

Set `interface=eth0` or `interface=any` to capture all interfaces.

Deploy Zeek:

```bash
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

Verify JSON logs are being written:

```bash
sudo cat /opt/zeek/logs/current/conn.log | head -3
```

### Step 7 — Verify data is flowing into Elasticsearch

```bash
curl http://localhost:9200/_cat/indices?v
```

If `docs.count` stays at 0, check Filebeat logs:

```bash
docker-compose logs --tail=30 filebeat
```

If you see mapping errors, reset and restart:

```bash
curl -X DELETE "http://localhost:9200/zeek"
curl -X DELETE "http://localhost:9200/_data_stream/zeek-logs-$(date +%Y.%m.%d)."
docker-compose stop filebeat
docker-compose rm -f filebeat
docker-compose up -d filebeat
```

### Step 8 — Set up Kibana dashboards

Open `http://localhost:5601` in your browser.

1. Go to **Hamburger menu → Stack Management → Index Patterns**
2. Click **Create index pattern**
3. Name: `zeek-logs-*`
4. Time field: `@timestamp`
5. Click **Create index pattern**

Create these visualizations under **Dashboard → Create visualization**:

| Visualization | Type | Field |
|---------------|------|-------|
| Top Source IPs | Bar horizontal | `id.orig_h` |
| Protocol Breakdown | Pie | `proto` |
| Connections Over Time | Date histogram | `@timestamp` |
| Top DNS Queries | Bar horizontal | `query` |

### Step 9 — Run the threat detection script

```bash
sudo apt install python3-pip -y
pip3 install requests
python3 alert.py
```

Set up automated alerting every 5 minutes:

```bash
crontab -e
```

Add this line:

```
*/5 * * * * python3 /home/YOUR_USERNAME/Home-Lab-SIEM-Zeek-IDS-ELK-Stack-Python-threat-detection/alert.py >> /home/YOUR_USERNAME/Home-Lab-SIEM-Zeek-IDS-ELK-Stack-Python-threat-detection/alerts.log 2>&1
```

---

## Detections Implemented

| Threat | Detection Logic | Log Source | Threshold |
|--------|----------------|-----------|-----------|
| Port scan | Unique destination ports per source IP | conn.log | ≥ 20 ports / 5 min |
| DNS tunneling | Unusually long DNS query strings | dns.log | Query length > 50 chars |
| High volume traffic | Connection count per source IP | conn.log | ≥ 500 connections / 5 min |

### Testing detections

Temporarily lower the threshold in `alert.py` for testing:

```python
PORT_SCAN_THRESHOLD = 5   # change from 20
```

Also change the time window:

```python
PORT_SCAN_WINDOW = "now-24h"   # change from now-5m
```

Run the script — alerts should fire. Change values back after testing.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `sudo zeek: command not found` | Use full path: `sudo /opt/zeek/bin/zeek` |
| `sudo zeekctl: command not found` | Use full path: `sudo /opt/zeek/bin/zeekctl` |
| Zeekctl deploy fails — symlink error | Run: `sudo rm -rf /opt/zeek/logs/current` then redeploy |
| Filebeat exits with uid error | Run: `sudo chown root:root filebeat.yml` |
| Elasticsearch `docs.count` stays 0 | Delete old indices, restart Filebeat |
| Logs not in JSON format | Add `@load policy/tuning/json-logs` to local.zeek |
| Permission denied on log files | Use `sudo cat` or `sudo ls` for Zeek log directories |
| Alert script shows no threats | Change time window to `now-24h` and threshold to `>= 5` for testing |

---

## What I Learned

Building this project taught me how raw network packets become structured security events, and what a real SIEM ingestion pipeline looks like end to end. I learned that Zeek operates in promiscuous mode to see all traffic on an interface. Setting up the ELK stack showed me how log shipping, indexing, and visualization work together — the same pattern used in enterprise SOCs with tools like Splunk. The Python alerting script made me understand how port scan detection actually works: counting unique destination ports per source IP within a time window. Debugging the pipeline — from Filebeat ownership errors to Elasticsearch mapping conflicts — gave me real hands-on experience that documentation alone never could.

---

## License

MIT License — free to use, modify, and build on.

---

## Author
#Sharath
