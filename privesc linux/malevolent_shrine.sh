#!/usr/bin/env bash
# ==============================================================================
#   SUKUNA RECON: Malevolent Shrine Enumeration
#   "Know your place. A script this grand deserves absolute subservience."
# ==============================================================================
set -u

HOSTNAME="$(hostname 2>/dev/null || echo "pathetic-mortal-host")"
TS="$(date +"%Y%m%d-%H%M%S")"
OUTFILE="shrine_recon_${HOSTNAME}_${TS}.txt"

# Sukuna's aesthetic printers
hr() { 
    printf '\n%s\n\n' "◆━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◆"
}

execute_technique() {
    local technique_name="$1"
    shift
    local command_string="$*"
    
    hr | tee -a "$OUTFILE"
    printf '⚔️  [TECHNIQUE]: %s\n' "$technique_name" | tee -a "$OUTFILE"
    printf '📜  [INCANTATION]: %s\n\n' "$command_string" | tee -a "$OUTFILE"
    
    eval "$command_string" 2>&1 | tee -a "$OUTFILE"
}

# --- Open the Domain ---
hr | tee "$OUTFILE"
printf '⛩️  DOMAIN EXPANSION: MALEVOLENT SHRINE  ⛩️\n' | tee -a "$OUTFILE"
printf 'Subject: %s | Time: %s (UTC)\n' "$HOSTNAME" "$(date -u +"%Y-%m-%d %H:%M:%S")" | tee -a "$OUTFILE"
printf '"Turn everything to ash. Let us peel back the layers of this world."\n' | tee -a "$OUTFILE"
hr | tee -a "$OUTFILE"

# --- 1. Identity & Soul (User Identity) ---
execute_technique "SOUL INSPECTION (Identity)" 'id && echo && whoami'

# --- 2. Dominance & Authority (Sudo Privileges) ---
if sudo -n true 2>/dev/null; then
    execute_technique "ABSOLUTE AUTHORITY (Sudo -l)" 'sudo -n -l'
else
    execute_technique "STRUGGLING FOR POWER (Sudo -l - May Prompt)" 'sudo -l'
fi

# --- 3. Cleave & Dismantle (SUID Binaries) ---
execute_technique "CLEAVE (SUID Root Binaries)" 'find / -user root -perm /4000 2>/dev/null'

# --- 4. Flaying the Flesh (OS Details) ---
execute_technique "DISMANTLE THE FLESH (Kernel Info)" 'uname -a'
execute_technique "PEELING THE SKIN (/etc/issue & /etc/os-release)" 'cat /etc/issue /etc/os-release 2>/dev/null || echo "The system resists my gaze."'

# --- 5. Binding Vows (Cron & Scheduled Tasks) ---
execute_technique "BINDING VOWS (User Crontab)" 'crontab -l 2>/dev/null || echo "No personal vows found."'
execute_technique "CURSED TIME RITUALS (System Cron Directories)" 'ls -la /etc/cron* 2>/dev/null'
execute_technique "DISTORTED SECRETS (/var/log/syslog CRON logs)" 'grep -i "cron" /var/log/syslog 2>/dev/null || echo "Logs are silent."'

# --- 6. Cursed Energy Flow (Network Listeners) ---
# Note: Replaced outdated netstat with ss, falling back to netstat if missing
execute_technique "CURSED ENERGY FLOW (Network Sockets)" 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "Network visibility blocked."'

# --- 7. Looting the Vault (/opt inspection) ---
execute_technique "TREASURE VAULT INSPECTION (/opt)" 'ls -la /opt 2>/dev/null'

# --- 8. Retainers & Puppets (Root Processes) ---
execute_technique "MALEVOLENT PUPPETS (Root Processes)" 'ps aux 2>/dev/null | grep "^root" || echo "No puppets found."'

# --- Close the Domain ---
hr | tee -a "$OUTFILE"
printf '💀  The Shrine closes. Your secrets are mine.  💀\n' | tee -a "$OUTFILE"
printf 'Scroll saved to: %s\n' "$OUTFILE" | tee -a "$OUTFILE"
hr | tee -a "$OUTFILE"
