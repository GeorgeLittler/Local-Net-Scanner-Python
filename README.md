# Local Network Scanner

A lightweight, **async TCP port scanner** for your local network.  
Scans a CIDR (e.g. `192.168.1.0/24`), identifies **live hosts** (any open port), lists open **common ports**, and can export results to CSV.

> **Use responsibly.** Only scan networks you own or have explicit permission to test.

**Round 1 delivers**
- CIDR scan (e.g. `/24`)
- Async TCP connect scans (fast)
- Common ports by default (`22, 80, 443, 3389, 8080, 53, 445, 139, 3306, 5432, 8000`)
- CSV export

**Planned for Round 2**
- Banner grabbing (simple service guess)
- Auto-detect local CIDR (e.g. via `netifaces`)
- Larger default port sets / presets
- Pretty HTML report
- Retry/backoff and progress bar

---

## Run Locally + Examples
```bash
# 1) Create and activate venv (optional)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) No extra deps (stdlib only)

# 3) Run a quick scan over a /24 (common ports)
python scanner.py --cidr 192.168.1.0/24

# 4) Custom ports and CSV export
python scanner.py --cidr 192.168.1.0/24 --ports 22,80,443,8080 --csv results.csv

# 5) Port ranges and higher concurrency
python scanner.py --cidr 10.0.0.0/24 --ports 1-1024 --concurrency 1024 --timeout 0.3
