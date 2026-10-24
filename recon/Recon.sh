#!/usr/bin/env bash

# OSCP Recon Script
# Usage: ./oscp-recon.sh <target-ip>

set -u

TARGET="$1"
BASE_DIR="recon_${TARGET}"
NMAP_DIR="${BASE_DIR}/nmap"
WEB_DIR="${BASE_DIR}/web"
EXPLOIT_DIR="${BASE_DIR}/searchsploit"
NOTE_DIR="${BASE_DIR}/notes"

if [ -z "${TARGET:-}" ]; then
    echo "[!] Usage: $0 <target-ip>"
    exit 1
fi

mkdir -p "$NMAP_DIR" "$WEB_DIR" "$EXPLOIT_DIR" "$NOTE_DIR"

echo "[*] Target: $TARGET"
echo "[*] Output dir: $BASE_DIR"

# ----------------------------
# 1. Fast full TCP scan
# ----------------------------
echo "[*] Running full TCP port scan..."
nmap -Pn -p- --min-rate 5000 -T4 -oN "$NMAP_DIR/all_ports.nmap" "$TARGET"

PORTS=$(grep '^[0-9]' "$NMAP_DIR/all_ports.nmap" | cut -d'/' -f1 | paste -sd, -)

if [ -z "$PORTS" ]; then
    echo "[!] No open TCP ports found."
    exit 1
fi

echo "[+] Open ports: $PORTS"

# ----------------------------
# 2. Service/version scan
# ----------------------------
echo "[*] Running service and default script scan..."
nmap -Pn -sC -sV -p"$PORTS" -oN "$NMAP_DIR/service_scan.nmap" "$TARGET"

# ----------------------------
# 3. Searchsploit
# ----------------------------
echo "[*] Running Searchsploit against discovered service names..."
grep ' open ' "$NMAP_DIR/service_scan.nmap" | awk '{print $3}' | sort -u > "$EXPLOIT_DIR/services.txt"

if [ -s "$EXPLOIT_DIR/services.txt" ]; then
    xargs searchsploit < "$EXPLOIT_DIR/services.txt" > "$EXPLOIT_DIR/searchsploit_by_service.txt"
    echo "[+] Saved Searchsploit results to $EXPLOIT_DIR/searchsploit_by_service.txt"
else
    echo "[!] No services found to search."
fi

echo "[*] Extracting version strings for manual Searchsploit follow-up..."
grep ' open ' "$NMAP_DIR/service_scan.nmap" > "$EXPLOIT_DIR/open_ports_full.txt"

# ----------------------------
# 4. Identify web ports
# ----------------------------
WEB_PORTS=$(grep ' open ' "$NMAP_DIR/service_scan.nmap" | egrep 'http|https|ssl/http|http-proxy' | cut -d'/' -f1)

if [ -n "$WEB_PORTS" ]; then
    echo "[+] Web ports found: $WEB_PORTS"
else
    echo "[!] No web ports found."
fi

# ----------------------------
# 5. Web recon
# ----------------------------
for PORT in $WEB_PORTS; do
    if [[ "$PORT" == "443" ]] || grep "^$PORT/tcp" "$NMAP_DIR/service_scan.nmap" | grep -qiE 'https|ssl'; then
        SCHEME="https"
    else
        SCHEME="http"
    fi

    URL="${SCHEME}://${TARGET}:${PORT}"

    echo "[*] Running WhatWeb on $URL"
    whatweb "$URL" > "$WEB_DIR/whatweb_${PORT}.txt" 2>&1

    echo "[*] Running Gobuster on $URL"
    gobuster dir \
        -u "$URL" \
        -w /usr/share/wordlists/dirb/common.txt \
        -k \
        -t 30 \
        -o "$WEB_DIR/gobuster_${PORT}.txt" 2>/dev/null

    echo "[*] Saving FFUF commands for $URL"
    cat > "$WEB_DIR/ffuf_${PORT}.txt" <<EOF
# Basic content discovery
ffuf -u ${URL}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fc 404

# Common extensions
ffuf -u ${URL}/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak,.html -mc all -fc 404

# Vhost fuzzing (edit domain/header if needed)
ffuf -u ${SCHEME}://${TARGET}:${PORT}/ -H "Host: FUZZ" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0
EOF
done

# ----------------------------
# 6. Notes / quick checklist
# ----------------------------
cat > "$NOTE_DIR/manual-checks.txt" <<EOF
Manual checks:
- Login pages / default creds / weak creds
- robots.txt
- File uploads
- Admin panels
- Directory traversal / LFI / RFI
- Command injection
- Password reset / registration flaws
- Virtual hosts
- SMB shares if 139/445 open
- Anonymous FTP if 21 open
- SNMP public/private if 161 open
- NFS if 2049 open
- Redis if 6379 open
- WinRM if 5985/5986 open
- MSSQL if 1433 open
- Jenkins / Tomcat / Git / phpMyAdmin if present
EOF

# ----------------------------
# 7. Final summary
# ----------------------------
echo
echo "[+] Recon complete."
echo "[+] Review these first:"
echo "    $NMAP_DIR/service_scan.nmap"
echo "    $EXPLOIT_DIR/searchsploit_by_service.txt"
echo "    $EXPLOIT_DIR/open_ports_full.txt"
echo "    $WEB_DIR/"
echo "    $NOTE_DIR/manual-checks.txt"
