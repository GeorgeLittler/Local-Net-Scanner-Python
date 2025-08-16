#!/usr/bin/env python3
"""
Local Network Scanner
Fast async TCP port scanner for a given CIDR, with:
- Auto CIDR detection (--auto)
- Port presets (--preset)
- HTML report (--html)
- Text progress bar
- Light retry/backoff on connect
- Optional service guessing (--guess)
- CSV export (host, port, service_guess)

Usage examples:
  python scanner.py --auto --preset common --guess --csv scan.csv --html scan.html
  python scanner.py --cidr 192.168.1.0/24 --ports 1-1024 --concurrency 1024 --timeout 0.3
"""

import argparse
import asyncio
import csv
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

DEFAULT_PORTS = [22, 80, 443, 3389, 8080, 53, 445, 139, 3306, 5432, 8000]

PORT_PRESETS = {
    "common": sorted(set(DEFAULT_PORTS + [25,110,143,993,995,8443,5900,5985,5986])),
    "web": [80, 443, 8080, 8000, 8443],
    "db": [3306, 5432, 1433, 1521, 27017, 6379, 6380, 11211, 9200],
    "remote": [22, 3389, 5900, 5985, 5986],
    "smb": [139, 445],
    "all-1-1024": list(range(1, 1025)),
}

PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 27017: "mongodb", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5672: "amqp", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    5985: "winrm", 5986: "winrm-https", 11211: "memcached", 9200: "elasticsearch",
}

HTTP_PORTS = {80, 8000, 8080, 8443}
TLS_LIKE = {443, 465, 993, 995, 8443, 5986}

# ---------- Utilities ----------

def parse_ports(arg: str, preset: Optional[str]) -> List[int]:
    if preset:
        if preset not in PORT_PRESETS:
            raise SystemExit(f"Unknown preset '{preset}'. Choose from: {', '.join(PORT_PRESETS)}")
        return PORT_PRESETS[preset]
    if not arg:
        return DEFAULT_PORTS
    items: List[int] = []
    for chunk in arg.split(","):
        c = chunk.strip()
        if not c:
            continue
        if "-" in c:
            a, b = c.split("-", 1)
            a, b = int(a), int(b)
            if a > b: a, b = b, a
            items.extend(range(a, b + 1))
        else:
            items.append(int(c))
    seen, out = set(), []
    for p in items:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p); out.append(p)
    return out

def progress_bar(done: int, total: int, width: int = 30) -> str:
    if total <= 0:
        return ""
    ratio = done / total
    filled = int(ratio * width)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {done}/{total}"

def write_csv(path: str, findings: Dict[str, List[Tuple[int, Optional[str]]]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "service_guess"])
        for host in sorted(findings):
            for port, guess in findings[host]:
                w.writerow([host, port, (guess or "")])
    print(f"[i] CSV written to {path}")

def write_html(path: str, findings: Dict[str, List[Tuple[int, Optional[str]]]], cidr: str, ports_len: int, scanned: int, duration_s: float) -> None:
    rows = []
    total_open = 0
    for host in sorted(findings):
        for port, guess in findings[host]:
            total_open += 1
            rows.append(f"<tr><td>{host}</td><td>{port}</td><td>{(guess or '').replace('&','&amp;')}</td></tr>")
    table = "\n".join(rows) or '<tr><td colspan="3">No open ports found.</td></tr>'
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Local Network Scanner Report</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body {{ font-family: system-ui,-apple-system,Segoe UI,Roboto,Ubuntu; margin: 2rem; }}
h1 {{ margin: 0 0 .25rem 0; }}
.small {{ color: #555; margin: 0 0 1rem 0; }}
.summary {{ display:flex; gap:1rem; margin:.5rem 0 1rem 0; flex-wrap:wrap }}
.card {{ padding:.5rem .75rem; border:1px solid #ddd; border-radius:.5rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #e5e5e5; padding: .5rem .6rem; text-align: left; }}
th {{ background:#fafafa; }}
code {{ background:#f6f6f6; padding:.1rem .3rem; border-radius:.25rem; }}
</style></head><body>
<h1>Local Network Scanner — Report</h1>
<p class="small">CIDR: <code>{cidr}</code> · Ports scanned: <code>{ports_len}</code> · Hosts scanned: <code>{scanned}</code> · Duration: <code>{duration_s:.2f}s</code> · Total open: <code>{total_open}</code></p>
<div class="summary">
  <div class="card">Unique hosts with findings: <strong>{len(findings)}</strong></div>
  <div class="card">Open port entries: <strong>{total_open}</strong></div>
</div>
<table>
  <thead><tr><th>Host</th><th>Port</th><th>Service (guess)</th></tr></thead>
  <tbody>
    {table}
  </tbody>
</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[i] HTML written to {path}")

# CIDR detection (best-effort, stdlib only)

def auto_detect_cidr() -> Optional[str]:
    """
    Best-effort cross-platform CIDR detection by parsing ipconfig/ifconfig output.
    Falls back to None if not found.
    """
    try_cmds = []
    if sys.platform.startswith("win"):
        try_cmds.append(("ipconfig", ["ipconfig"]))
    else:
        # Most Unix-likes
        for cmd in (("ip", ["ip", "addr"]), ("ifconfig", ["ifconfig"])):
            try_cmds.append(cmd)

    text = ""
    for name, cmd in try_cmds:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=2)
            text = out
            break
        except Exception:
            continue
    if not text:
        return None

    # Windows parsing
    if sys.platform.startswith("win"):
        # Find first non-APIPA private v4 with mask
        blocks = re.split(r"\r?\n\r?\n", text)
        for b in blocks:
            ipm = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", b)
            nmm = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", b)
            if ipm and nmm:
                ip = ipm.group(1)
                mask = nmm.group(1)
                if ip.startswith(("10.", "172.", "192.168.")):
                    try:
                        iface = ipaddress.ip_interface(f"{ip}/{mask}")
                        return str(iface.network)
                    except Exception:
                        pass
        return None

    # Linux/macOS parsing from `ip addr` or `ifconfig`
    # Look for 'inet X/Y' where X is private
    for ip_cidr in re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", text):
        try:
            iface = ipaddress.ip_interface(ip_cidr)
            ip = str(iface.ip)
            if ip.startswith(("10.", "172.", "192.168.")):
                return str(iface.network)
        except Exception:
            continue
    return None

# Async scanning

async def try_connect(host: str, port: int, timeout: float) -> bool:
    # One quick retry on timeout-like failures
    for attempt in (1, 2):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            if attempt == 1:
                await asyncio.sleep(0.03)
            else:
                return False
    return False

async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None
    try:
        if port in HTTP_PORTS:
            try:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(200), timeout=timeout)
                if data:
                    text = data.decode(errors="replace")
                    head = text.split("\r\n")[0][:120]
                    server = ""
                    for line in text.split("\r\n"):
                        if line.lower().startswith("server:"):
                            server = " " + line[:80]
                            break
                    return (head + server).strip()
            except Exception:
                pass
        elif port in TLS_LIKE:
            return f"{PORT_NAMES.get(port, 'service')} (tls?)"

        # Passive read
        try:
            await asyncio.sleep(0.05)
            data = await asyncio.wait_for(reader.read(200), timeout=timeout)
            if data:
                text = data.decode(errors="replace").strip().splitlines()[0][:120]
                return text if text else PORT_NAMES.get(port)
        except Exception:
            pass
        return PORT_NAMES.get(port)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def scan_host(host: str, ports: List[int], timeout: float, host_sem: asyncio.Semaphore, guess: bool) -> Tuple[str, List[Tuple[int, Optional[str]]]]:
    results: List[Tuple[int, Optional[str]]] = []
    async with host_sem:
        checks = [try_connect(host, p, timeout) for p in ports]
        open_bools = await asyncio.gather(*checks, return_exceptions=False)

    open_ports = [p for p, is_open in zip(ports, open_bools) if is_open]
    if not open_ports:
        return host, results

    if guess:
        gsem = asyncio.Semaphore(min(32, len(open_ports)))
        async def one(p: int):
            async with gsem:
                b = await grab_banner(host, p, timeout)
                return (p, b)
        guesses = await asyncio.gather(*(one(p) for p in open_ports))
        results.extend(guesses)
    else:
        results.extend((p, None) for p in open_ports)
    return host, results

async def scan_cidr(cidr: str, ports: List[int], timeout: float, concurrency: int, guess: bool) -> Dict[str, List[Tuple[int, Optional[str]]]]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    host_sem = asyncio.Semaphore(concurrency)
    tasks = [scan_host(h, ports, timeout, host_sem, guess) for h in hosts]

    found: Dict[str, List[Tuple[int, Optional[str]]]] = {}
    done, total = 0, len(tasks)
    last_drawn = ""

    start = time.time()
    try:
        for coro in asyncio.as_completed(tasks):
            host, items = await coro
            done += 1
            if items:
                found[host] = items
            # Draw progress bar every ~N hosts
            if done == total or done % 20 == 0:
                bar = progress_bar(done, total)
                msg = f"\r{bar}"
                if msg != last_drawn:
                    print(msg, end="", flush=True)
                    last_drawn = msg
    except KeyboardInterrupt:
        print("\n[!] Interrupted — returning partial results...")
    finally:
        if total:
            print("\r" + " " * 80 + "\r", end="")
    duration = time.time() - start
    return found

# CLI

def main():
    ap = argparse.ArgumentParser(description="Local Network Scanner (Round 2)")
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("--cidr", help="CIDR to scan, e.g. 192.168.1.0/24")
    g.add_argument("--auto", action="store_true", help="Auto-detect local CIDR")

    ap.add_argument("--ports", default="", help="Ports list (e.g. 22,80,443 or 1-1024)")
    ap.add_argument("--preset", choices=sorted(PORT_PRESETS.keys()), help="Port preset (e.g. common, web, db, remote, smb, all-1-1024)")
    ap.add_argument("--timeout", type=float, default=0.5, help="TCP connect timeout seconds (default 0.5)")
    ap.add_argument("--concurrency", type=int, default=512, help="Concurrent host scans (default 512)")
    ap.add_argument("--csv", default="", help="Output CSV path (optional)")
    ap.add_argument("--html", default="", help="Output HTML report path (optional)")
    ap.add_argument("--guess", action="store_true", help="Attempt simple service guessing")
    args = ap.parse_args()

    cidr = args.cidr
    if args.auto:
        cidr = auto_detect_cidr()
        if not cidr:
            raise SystemExit("Could not auto-detect a private IPv4 CIDR. Specify --cidr explicitly.")
        print(f"[i] Auto-detected CIDR: {cidr}")
    if not cidr:
        ap.error("Specify --cidr or use --auto")

    ports = parse_ports(args.ports, args.preset)
    print(f"[i] Scanning {cidr} on {len(ports)} ports "
          f"(timeout={args.timeout}s, concurrency={args.concurrency}, guess={'on' if args.guess else 'off'})")

    start = time.time()
    findings = asyncio.run(scan_cidr(cidr, ports, args.timeout, args.concurrency, args.guess))
    duration = time.time() - start

    print("\n=== Summary ===")
    if not findings:
        print("No open ports found.")
    else:
        for host in sorted(findings):
            line = ", ".join(
                f"{p}{' ('+g+')' if g else ''}"
                for p, g in findings[host]
            )
            print(f"{host}: {line}")

    if args.csv:
        write_csv(args.csv, findings)
    if args.html:
        # Number of hosts scanned = size of network minus network/broadcast
        scanned_hosts = ipaddress.ip_network(cidr, strict=False).num_addresses - 2
        write_html(args.html, findings, cidr, len(ports), scanned_hosts, duration)

if __name__ == "__main__":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
    except Exception:
        pass
    main()
