# Local Network Scanner

A lightweight Python tool that scans a local subnet for active devices and open ports using fast asynchronous TCP connections.  
It can auto-dtect your local CIDR, guess common services from banners, and export results to both CSV and HTML reports.  
There are noo external dependencies and it's built with the Python standard library.

> **Use responsibly.** Only scan networks you own or have explicit permission to test.

## Features

- **CIDR scan** (e.g. `192.168.1.0/24`)
- **Auto CIDR detection**: `--auto` (Windows/macOS/Linux via system tooling)
- **Fast async** TCP connect scans with configurable **concurrency** & **timeout**
- **Port presets**: `--preset common|web|db|remote|smb|all-1-1024` or custom `--ports`
- **Optional service guessing**: `--guess` (HTTP `HEAD` / tiny passive banners)
- **Reports**: CSV (`host,port,service_guess`) and pretty **HTML**
- **Progress bar** and **retry/backoff** for borderline timeouts
- **Stdlib only** (no external dependencies)

## Quick start

```bash
# Auto-detect your local CIDR and scan common ports, with guesses, CSV and HTML outputs:
python scanner.py --auto --preset common --guess --csv scan.csv --html scan.html

# Manual CIDR with a custom port range:
python scanner.py --cidr 192.168.1.0/24 --ports 1-1024 --concurrency 1024 --timeout 0.3
```

## Example output

```bash
$ python3 scanner.py --cidr 127.0.0.1/32 --ports 8080 --guess
[i] Scanning 127.0.0.1/32 on 1 ports (timeout=0.5s, concurrency=512, guess=on)

=== Summary ===
127.0.0.1: 8080 (HTTP/1.0 200 OK Server: SimpleHTTP/0.6 Python/3.12.3)
```

## Notes

- Auto-detection is best-effort; if it fails, pass --cidr explicitly.
- Service guessing is heuristic. TLS services are labelled tls? (no TLS handshake).
- Press Ctrl-C any time; partial findings are retained for reporting.