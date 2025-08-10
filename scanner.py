#!/usr/bin/env python3
"""
Local Network Scanner — Round 1
Fast async TCP port scanner for a given CIDR.
Finds live hosts (any open port) + lists open common ports, exports CSV.

Usage:
  python scanner.py --cidr 192.168.1.0/24 --ports 22,80,443,3389 --csv results.csv
"""

import argparse
import asyncio
import ipaddress
import csv
from typing import List, Tuple, Dict

DEFAULT_PORTS = [22, 80, 443, 3389, 8080, 53, 445, 139, 3306, 5432, 8000]

async def check_port(host: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def scan_host(host: str, ports: List[int], timeout: float, sem: asyncio.Semaphore) -> Tuple[str, List[int]]:
    open_ports: List[int] = []
    async with sem:
        # schedule all port checks concurrently per host
        checks = [check_port(host, p, timeout) for p in ports]
        results = await asyncio.gather(*checks, return_exceptions=False)
        for p, is_open in zip(ports, results):
            if is_open:
                open_ports.append(p)
    return host, open_ports

async def scan_cidr(cidr: str, ports: List[int], timeout: float, concurrency: int) -> Dict[str, List[int]]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_host(h, ports, timeout, sem) for h in hosts]
    results = {}
    for coro in asyncio.as_completed(tasks):
        host, open_ports = await coro
        if open_ports:
            results[host] = open_ports
            print(f"[+] {host} open: {','.join(map(str, open_ports))}")
    return results

def parse_ports(arg: str) -> List[int]:
    if not arg:
        return DEFAULT_PORTS
    items: List[int] = []
    for chunk in arg.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            items.extend(range(a, b + 1))
        else:
            items.append(int(chunk))
    # dedupe while preserving order
    seen = set()
    out = []
    for p in items:
        if p not in seen:
            out.append(p); seen.add(p)
    return out

def write_csv(path: str, findings: Dict[str, List[int]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "open_ports"])
        for host, ports in sorted(findings.items()):
            w.writerow([host, " ".join(map(str, ports))])
    print(f"[i] CSV written to {path}")

def main():
    ap = argparse.ArgumentParser(
        description="Local Network Scanner (Round 1): async TCP scan for a CIDR range."
    )
    ap.add_argument("--cidr", required=True, help="CIDR to scan, e.g. 192.168.1.0/24")
    ap.add_argument("--ports", default="", help="Ports list (e.g. 22,80,443 or 1-1024). Blank = common ports.")
    ap.add_argument("--timeout", type=float, default=0.5, help="TCP connect timeout seconds (default 0.5)")
    ap.add_argument("--concurrency", type=int, default=512, help="Concurrent host scans (default 512)")
    ap.add_argument("--csv", default="", help="Output CSV path (optional)")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"[i] Scanning {args.cidr} on {len(ports)} ports "
          f"(timeout={args.timeout}s, concurrency={args.concurrency})")
    findings = asyncio.run(scan_cidr(args.cidr, ports, args.timeout, args.concurrency))

    print("\n=== Summary ===")
    if not findings:
        print("No open ports found.")
    else:
        for host, ports in sorted(findings.items()):
            print(f"{host}: {', '.join(map(str, ports))}")
        if args.csv:
            write_csv(args.csv, findings)

if __name__ == "__main__":
    main()
