#!/usr/bin/env bash
# ==============================================================================
# Script Name: linux-ir-triage.sh
# Description: Automated Live DFIR & SOC Triage Artifact Collector for Linux
# Author:      Rafael Laporte (github.com/rcybershield)
# ==============================================================================

set -uo pipefail

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname)
OUT_DIR="./ir_triage_${HOSTNAME}_${TIMESTAMP}"

mkdir -p "$OUT_DIR"

echo "============================================================="
echo " 🛡️  LINUX DFIR TRIAGE COLLECTOR | SOC Incident Response"
echo "============================================================="
echo "[*] Collecting volatile artifacts from host: $HOSTNAME"
echo "[*] Output directory: $OUT_DIR"

# 1. System Date, Uptime & Logged-in Users
echo "[+] Capturing active sessions and system uptime..."
{
    echo "=== DATE & UPTIME ==="
    date -u
    uptime
    echo -e "\n=== CURRENTLY LOGGED USERS (w / who) ==="
    w
    echo -e "\n=== RECENT LOGINS (last -n 20) ==="
    last -n 20
} > "$OUT_DIR/01_users_and_sessions.txt" 2>&1

# 2. Running Processes Tree
echo "[+] Capturing process tree and execution paths..."
ps auxf > "$OUT_DIR/02_process_tree.txt" 2>&1

# 3. Network Connections & Listening Ports
echo "[+] Capturing active network sockets and listening ports..."
{
    echo "=== LISTENING & ESTABLISHED SOCKETS (ss -tulnp) ==="
    ss -tulnp
    echo -e "\n=== ARP CACHE ==="
    ip neigh
} > "$OUT_DIR/03_network_connections.txt" 2>&1

# 4. Persistence Mechanisms (Cron & SSH Keys)
echo "[+] Auditing persistence mechanisms (Crontabs & SSH keys)..."
{
    echo "=== /etc/crontab ==="
    cat /etc/crontab
    echo -e "\n=== /etc/cron.* directories ==="
    ls -la /etc/cron* 
} > "$OUT_DIR/04_persistence_cron.txt" 2>&1

# 5. Suspicious World-Writable / Temp Executables (/tmp, /dev/shm)
echo "[+] Scanning /tmp and /dev/shm for dropped artifacts..."
ls -laR /tmp /dev/shm > "$OUT_DIR/05_temp_directories.txt" 2>&1

# 6. Generate SHA-256 Manifest for Chain of Custody
echo "[+] Generating SHA-256 integrity hashes for collected evidence..."
sha256sum "$OUT_DIR"/*.txt > "$OUT_DIR/evidence_manifest.sha256"

echo "============================================================="
echo " [+] Triage complete! Artifacts saved to: $OUT_DIR"
echo "============================================================="
