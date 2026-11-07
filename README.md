# 📋 SOC Incident Response Playbooks & DFIR Triage

![Blue Team](https://img.shields.io/badge/Focus-Blue_Team_%26_DFIR-005571?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-C8102E?style=for-the-badge&logo=target&logoColor=white)
![Linux](https://img.shields.io/badge/Platform-Linux_IR-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![NIST](https://img.shields.io/badge/Standard-NIST_SP_800--61-2496ED?style=for-the-badge)

## 📌 Overview

This repository contains standardized **Standard Operating Procedures (SOPs)**, **SOC Tier 1/2 Alert Triage Playbooks**, and **Live Forensics (DFIR) collection scripts** developed during my **Blue Team Specialization** studies and home lab operations.

Each playbook follows the **NIST SP 800-61 (Incident Handling Guide)** lifecycle:
1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication & Recovery**
4. **Post-Incident Activity (Lessons Learned)**

---

## 🛡️ Playbook 01: Compromised Linux Endpoint / Suspicious Shell Activity
- **MITRE ATT&CK:** `T1059.004` (Command and Scripting Interpreter: Unix Shell) & `T1053.003` (Scheduled Task/Job: Cron)
- **Trigger:** Wazuh SIEM High-Severity Alert (FIM alert on `/etc/crontab` or anomalous outbound connection from `/tmp` or `/dev/shm`).

### 🔍 Triage & Investigation Steps (SOC Tier 1/2)
1. **Validate the Alert:** Inspect the raw Wazuh event JSON and correlate with Suricata `eve.json` network flows for the target host IP.
2. **Live Volatile Triage:** Execute `linux-ir-triage.sh` on the affected endpoint to capture volatile state before isolation:
   - Active network connections (`ss -tulnp` / `netstat`)
   - Running processes and parent-child hierarchies (`ps auxf`)
   - Unauthorized persistence in `crontab`, `systemd`, and `~/.ssh/authorized_keys`
   - Recent authentication and sudo execution logs (`/var/log/auth.log`)
3. **Containment:** Trigger **Wazuh Active Response** or isolate the VM/host interface at the firewall level while preserving memory/disk snapshots.

---

## 🛡️ Playbook 02: Phishing & Malicious Payload Triage
- **MITRE ATT&CK:** `T1566` (Phishing)
- **Triage Workflow:**
  1. Extract email headers (`SPF`, `DKIM`, `DMARC`, `Return-Path`, and originating SMTP IP).
  2. Defang all URLs and IPv4 indicators using `py-ioc-enricher`.
  3. Compute SHA-256 hashes of attachments (`sha256sum`) and query Threat Intelligence feeds (VirusTotal / MalwareBazaar) without executing the sample directly.

---

## 🚀 Usage: Automated Linux Live IR Triage Script

To collect volatile forensic artifacts from a suspected Linux server into a timestamped report:

```bash
git clone https://github.com/rcybershield/soc-incident-playbooks.git
cd soc-incident-playbooks
chmod +x linux-ir-triage.sh
sudo ./linux-ir-triage.sh
```

---
*Developed by **Rafael Laporte** – [LinkedIn](https://www.linkedin.com/in/rafaellaporte)*
