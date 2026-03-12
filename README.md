# AbuseCLI

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI/CD](https://github.com/LouisDecourtis/AbuseCLI/actions/workflows/ci.yml/badge.svg)](https://github.com/LouisDecourtis/AbuseCLI/actions)

A powerful CLI tool to query [AbuseIPDB](https://www.abuseipdb.com/), analyze log files, report abusive IPs, and manipulate IP-based Indicators of Compromise (IoCs) — with Shodan enrichment and async bulk checking.

## Features

- **Check IPs** — Query AbuseIPDB for abuse confidence scores on one or more IP addresses
- **Analyze logs** — Automatically extract and check IPs from log files (auth.log, access.log, syslog, etc.)
- **Report abuse** — Report abusive IPs directly to AbuseIPDB with category and comment
- **Shodan enrichment** — Enrich results with open ports, CVEs, and hostnames via Shodan InternetDB (free, no API key)
- **Async bulk checking** — Parallel API requests for fast bulk IP analysis
- **Load & filter** — Reload previously exported results and apply filters without re-querying the API
- **Rich terminal output** — Color-coded tables, score bars, and summary panels
- **Flexible input** — IPs from arguments, files, or stdin pipes
- **Multiple export formats** — CSV, JSON, Excel, HTML, Parquet
- **Local cache** — SQLite cache to avoid redundant API calls (4h TTL)
- **Advanced filtering** — By risk level, score, country, TOR status, private/public, whitelist

## Installation

```bash
git clone https://github.com/LouisDecourtis/AbuseCLI.git
cd AbuseCLI
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

AbuseCLI needs an [AbuseIPDB API key](https://www.abuseipdb.com/account/api). You can provide it in three ways:

| Method | Example |
|--------|---------|
| `.env` file | `ABUSEIPDB_API_KEY=your_key_here` |
| CLI argument | `--token your_key_here` |
| Interactive prompt | The tool will ask on first run and offer to save it |

## Usage

### Check IP addresses

```bash
# Check one or more IPs
python3 abusecli.py check --ips 1.1.1.1 8.8.8.8

# Check IPs from a file (one per line)
python3 abusecli.py check --file ips.txt

# Read IPs from stdin (pipe-friendly)
cat ips.txt | python3 abusecli.py check --ips -

# Check with filters
python3 abusecli.py check --ips 1.1.1.1 8.8.8.8 --risk-level critical --score 75

# Check and export results
python3 abusecli.py check --ips 1.1.1.1 --export csv json

# Check with Shodan enrichment (open ports, CVEs, hostnames)
python3 abusecli.py check --ips 1.1.1.1 8.8.8.8 --enrich
```

### Report abusive IPs

Report an IP address directly to AbuseIPDB with abuse categories and an optional comment.

```bash
# Report an IP for SSH brute force
python3 abusecli.py report --ip 1.2.3.4 --categories 18,22 --comment "SSH brute force"

# Report with just categories
python3 abusecli.py report --ip 5.6.7.8 --categories 14
```

See [AbuseIPDB categories](https://www.abuseipdb.com/categories) for the full list of category IDs.

### Analyze log files

Automatically extract IP addresses from any log file, deduplicate them, filter out private/loopback addresses, and check them against AbuseIPDB.

```bash
# Analyze an auth log
python3 abusecli.py analyze /var/log/auth.log

# Analyze with a minimum score filter and export
python3 abusecli.py analyze /var/log/nginx/access.log --score 50 --export csv

# Analyze with verbose output
python3 abusecli.py analyze /var/log/syslog -v
```

Supported log formats: any text file containing IP addresses (auth.log, access.log, syslog, firewall logs, etc.).

### Load previously exported data

```bash
# Load and display
python3 abusecli.py load --source ip_analysis_20250101.csv

# Load, filter, and re-export
python3 abusecli.py load --source results.json --risk-level high --export csv
```

## Filtering options

All commands (`check`, `analyze`, `load`) support the same filters:

| Flag | Description |
|------|-------------|
| `--risk-level`, `-r` | Filter by risk level: `critical`, `high`, `medium`, `low` |
| `--score`, `-s` | Minimum abuse confidence score (0-100) |
| `--country-code` | Filter by country code (e.g. `CN`, `US`, `FR`) |
| `--is-tor` | Keep only TOR exit nodes |
| `--is-not-tor` | Exclude TOR exit nodes |
| `--remove-private` | Keep only public IP addresses |
| `--remove-whitelisted` | Remove whitelisted IP addresses |
| `--enrich` | Enrich with Shodan InternetDB (ports, CVEs, hostnames) |

## Risk levels

| Level | Score range | Color |
|-------|-----------|-------|
| Critical | 75 - 100 | Red |
| High | 50 - 74 | Orange |
| Medium | 25 - 49 | Yellow |
| Low | 0 - 24 | Green |

## Export formats

| Format | Extension | Flag |
|--------|-----------|------|
| CSV | `.csv` | `--export csv` |
| JSON | `.json` | `--export json` |
| Excel | `.excel` | `--export excel` |
| HTML | `.html` | `--export html` |
| Parquet | `.parquet` | `--export parquet` |

Multiple formats can be specified at once: `--export csv json excel`

## Output example

```
                        IP Analysis Results
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━┳━━━━━━━━┓
┃ IP Address ┃   Risk   ┃        Score         ┃ Country ┃ Whitelisted ┃ TOR ┃ Public ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━╇━━━━━━━━┩
│ 1.2.3.4    │ CRITICAL │ ██████████████░ 95%  │   CN    │     No      │ Yes │  Yes   │
├────────────┼──────────┼──────────────────────┼─────────┼─────────────┼─────┼────────┤
│ 8.8.8.8    │   LOW    │  ░░░░░░░░░░░░░░░ 0%  │   US    │     Yes     │ No  │  Yes   │
├────────────┼──────────┼──────────────────────┼─────────┼─────────────┼─────┼────────┤
│ 5.5.5.5    │   HIGH   │ ██████████░░░░░ 65%  │   RU    │     No      │ No  │  Yes   │
└────────────┴──────────┴──────────────────────┴─────────┴─────────────┴─────┴────────┘

╭──────────── Summary ────────────╮
│ Total IPs:  3                   │
│ Critical      1  █████░░░░░░░░░ │
│ High          1  █████░░░░░░░░░ │
│ Low           1  █████░░░░░░░░░ │
│ Countries:  3                   │
│ TOR nodes: 1                    │
╰─────────────────────────────────╯
```

## DevSecOps

This project includes a full CI/CD pipeline and security tooling.

### CI/CD Pipeline (GitHub Actions)

The pipeline runs on every push and PR to `main`:

| Stage | Tool | Description |
|-------|------|-------------|
| Lint & Format | [Ruff](https://github.com/astral-sh/ruff) | Python linting and code formatting |
| SAST | [Bandit](https://github.com/PyCQA/bandit) | Static Application Security Testing |
| Dependency Check | [Safety](https://github.com/pyupio/safety) | Known vulnerability scanning on dependencies |
| Tests | [Pytest](https://pytest.org/) | Unit tests with coverage (Python 3.10, 3.11, 3.12) |
| Docker | Docker Build | Validates the container image builds and runs |

### Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

Hooks run automatically before each commit:
- **Ruff** lint + format
- **Bandit** security scan
- **Trailing whitespace** / **end-of-file** fixes
- **Private key detection**
- **Large file check** (max 500KB)

### Docker

```bash
# Build
docker build -t abusecli .

# Run
docker run --rm -e ABUSEIPDB_API_KEY=your_key abusecli check --ips 8.8.8.8

# Analyze a log file (mount it as volume)
docker run --rm -e ABUSEIPDB_API_KEY=your_key -v /var/log:/logs:ro abusecli analyze /logs/auth.log
```

### Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=. --cov-report=term-missing
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
