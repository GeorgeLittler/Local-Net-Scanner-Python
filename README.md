# Local Network Scanner

A lightweight, **async TCP port scanner** for local networks.

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

## Notes

- Auto-detection is best-effort; if it fails, pass --cidr explicitly.
- Service guessing is heuristic. TLS services are labelled tls? (no TLS handshake).
- Press Ctrl-C any time; partial findings are retained for reporting.