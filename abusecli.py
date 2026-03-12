#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import asyncio
import sqlite3
import getpass
import argparse
import requests

import aiohttp
import pandas as pd

from tqdm import tqdm
from pathlib import Path
from dotenv import load_dotenv, set_key

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


__version__ = "1.1.0"

###########################################################################
## CONSTANTS ##############################################################
###########################################################################

API_URL = "https://api.abuseipdb.com/api/v2/check"
API_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"

BANNER = """
[bold red] █████╗ ██████╗ ██╗   ██╗███████╗███████╗ ██████╗██╗     ██╗
██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝██╔════╝██║     ██║
███████║██████╔╝██║   ██║███████╗█████╗  ██║     ██║     ██║
██╔══██║██╔══██╗██║   ██║╚════██║██╔══╝  ██║     ██║     ██║
██║  ██║██████╔╝╚██████╔╝███████║███████╗╚██████╗███████╗██║
╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝[/bold red]
[dim]v{version} — AbuseIPDB CLI Tool[/dim]
"""
ENV_FILE = ".env"

# Cache constants
CACHE_DIR = os.path.join(str(Path.home()), ".abusecli")
CACHE_DB = os.path.join(CACHE_DIR, "cache.db")
DEFAULT_CACHE_TTL = 14400  # 4 hours in seconds

# Risk level constants
RISK_CRITICAL_MIN = 75
RISK_HIGH_MIN = 50
RISK_MEDIUM_MIN = 25
RISK_LOW_MIN = 0

RISK_LEVELS = {
    "critical": (RISK_CRITICAL_MIN, 100),
    "high": (RISK_HIGH_MIN, RISK_CRITICAL_MIN - 1),
    "medium": (RISK_MEDIUM_MIN, RISK_HIGH_MIN - 1),
    "low": (RISK_LOW_MIN, RISK_MEDIUM_MIN - 1),
}

###########################################################################
## PARSER #################################################################
###########################################################################


def create_parser():
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        description="AbuseIPDB CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  abusecli.py check --ips 1.1.1.1 8.8.8.8
  abusecli.py check --ips 1.1.1.1 8.8.8.8 --enrich
  abusecli.py check --file ips.txt
  cat ips.txt | abusecli.py check --ips -
  abusecli.py analyze /var/log/auth.log
  abusecli.py report --ip 1.2.3.4 --categories 18,22 --comment "SSH brute force"
  """,
    )

    # Global arguments (optional)
    parser.add_argument("--token", help="AbuseIP API Token")
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass cache and force fresh API calls",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_CACHE_TTL,
        metavar="SECONDS",
        help=f"Cache time-to-live in seconds (default: {DEFAULT_CACHE_TTL} = 4h)",
    )

    # Subparsers
    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands",
        description="Available commands",
        help="Use <command> --help for command-specific help",
    )

    # CHECK command
    check_parser = subparsers.add_parser(
        "check", help="Check connectivity to IP addresses"
    )
    check_input = check_parser.add_mutually_exclusive_group(required=True)
    check_input.add_argument(
        "--ips",
        nargs="+",
        metavar="IP",
        help="List of IP addresses to check (use '-' to read from stdin)",
    )
    check_input.add_argument(
        "--file",
        metavar="FILE",
        help="Read IP addresses from a file (one per line)",
    )
    check_parser.add_argument(
        "--risk-level",
        "-r",
        choices=["critical", "high", "medium", "low"],
        help="Filter by risk level (critical, high, medium, low)",
    )
    check_parser.add_argument(
        "--score",
        "-s",
        type=int,
        help="Only keep IPs with a score above this value (between 0 and 100)",
    )
    check_parser.add_argument(
        "--country-code",
        type=str,
        help="Only keep IPs with the corresponding country code",
    )

    check_parser.add_argument(
        "--is-tor", action="store_true", help="Only keep TOR IP addresses"
    )
    check_parser.add_argument(
        "--is-not-tor", action="store_true", help="Only keep non-TOR IP addresses"
    )

    check_parser.add_argument(
        "--remove-private", action="store_true", help="Only keep public IP addresses"
    )

    check_parser.add_argument(
        "--remove-whitelisted",
        action="store_true",
        help="Only keep non-whitelisted IP addresses",
    )

    check_parser.add_argument(
        "--export",
        "-e",
        nargs="+",
        choices=["csv", "json", "excel", "html", "parquet"],
        metavar="FORMAT",
        help="Export results to file(s). Formats: csv, json, excel, html, parquet. Can specify multiple formats.",
    )

    check_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output, strongly recommanded for debugging.",
    )

    # LOAD command
    load_parser = subparsers.add_parser(
        "load", help="Load IP data from file and apply filters"
    )
    load_parser.add_argument(
        "--source",
        "-s",
        required=True,
        metavar="FILE",
        help="Source file to load (CSV, JSON, Excel, Parquet)",
    )
    load_parser.add_argument(
        "--format",
        "-f",
        choices=["csv", "json", "excel", "parquet", "auto"],
        default="auto",
        help="File format (default: auto-detect from extension)",
    )

    # Add all the same filtering arguments as check command
    load_parser.add_argument(
        "--risk-level",
        "-r",
        choices=["critical", "high", "medium", "low"],
        help="Filter by risk level (critical, high, medium, low)",
    )
    load_parser.add_argument(
        "--score",
        type=int,
        help="Only keep IPs with a score above this value (between 0 and 100)",
    )
    load_parser.add_argument(
        "--country-code",
        type=str,
        help="Only keep IPs with the corresponding country code",
    )
    load_parser.add_argument(
        "--is-tor", action="store_true", help="Only keep TOR IP addresses"
    )
    load_parser.add_argument(
        "--is-not-tor", action="store_true", help="Only keep non-TOR IP addresses"
    )
    load_parser.add_argument(
        "--remove-private", action="store_true", help="Only keep public IP addresses"
    )
    load_parser.add_argument(
        "--remove-whitelisted",
        action="store_true",
        help="Only keep non-whitelisted IP addresses",
    )
    load_parser.add_argument(
        "--export",
        "-e",
        nargs="+",
        choices=["csv", "json", "excel", "html", "parquet"],
        metavar="FORMAT",
        help="Export results to file(s). Formats: csv, json, excel, html, parquet. Can specify multiple formats.",
    )
    load_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output, strongly recommended for debugging.",
    )

    # ANALYZE command
    analyze_parser = subparsers.add_parser(
        "analyze", help="Extract and analyze IP addresses from log files"
    )
    analyze_parser.add_argument(
        "log_file",
        metavar="LOG_FILE",
        help="Path to the log file to analyze (auth.log, access.log, syslog, etc.)",
    )
    analyze_parser.add_argument(
        "--risk-level",
        "-r",
        choices=["critical", "high", "medium", "low"],
        help="Filter by risk level (critical, high, medium, low)",
    )
    analyze_parser.add_argument(
        "--score",
        "-s",
        type=int,
        help="Only keep IPs with a score above this value (between 0 and 100)",
    )
    analyze_parser.add_argument(
        "--country-code",
        type=str,
        help="Only keep IPs with the corresponding country code",
    )
    analyze_parser.add_argument(
        "--is-tor", action="store_true", help="Only keep TOR IP addresses"
    )
    analyze_parser.add_argument(
        "--is-not-tor", action="store_true", help="Only keep non-TOR IP addresses"
    )
    analyze_parser.add_argument(
        "--remove-private", action="store_true", help="Only keep public IP addresses"
    )
    analyze_parser.add_argument(
        "--remove-whitelisted",
        action="store_true",
        help="Only keep non-whitelisted IP addresses",
    )
    analyze_parser.add_argument(
        "--export",
        "-e",
        nargs="+",
        choices=["csv", "json", "excel", "html", "parquet"],
        metavar="FORMAT",
        help="Export results to file(s). Formats: csv, json, excel, html, parquet.",
    )
    analyze_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output, strongly recommended for debugging.",
    )

    # QUOTA command
    quota_parser = subparsers.add_parser(
        "quota",
        help="Display current API usage and remaining quota",
    )
    quota_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output.",
    )

    # CACHE command
    cache_parser = subparsers.add_parser(
        "cache",
        help="Manage the local response cache",
    )
    cache_sub = cache_parser.add_subparsers(
        dest="cache_action",
        title="Cache actions",
        description="Available cache actions",
    )
    cache_sub.add_parser("stats", help="Show cache statistics")
    cache_clear_parser = cache_sub.add_parser("clear", help="Clear the cache")
    cache_clear_parser.add_argument(
        "--older-than",
        metavar="DURATION",
        help="Only clear entries older than duration (e.g. 7d, 12h, 30m)",
    )

    # REPORT command
    report_parser = subparsers.add_parser(
        "report",
        help="Report an abusive IP address to AbuseIPDB",
    )
    report_parser.add_argument(
        "--ip",
        required=True,
        metavar="IP",
        help="IP address to report",
    )
    report_parser.add_argument(
        "--categories",
        "-c",
        required=True,
        metavar="CAT",
        help="Comma-separated abuse category IDs (e.g. 18,22). See https://www.abuseipdb.com/categories",
    )
    report_parser.add_argument(
        "--comment",
        "-m",
        metavar="TEXT",
        help="Description of the abusive activity",
    )
    report_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output.",
    )

    # Add --enrich flag to check, analyze, and load commands
    for sub_parser in [check_parser, analyze_parser, load_parser]:
        sub_parser.add_argument(
            "--enrich",
            action="store_true",
            help="Enrich results with Shodan InternetDB data (open ports, CVEs, hostnames). Free, no API key needed.",
        )

    return parser


###########################################################################
## DISPLAY ################################################################
###########################################################################


def print_banner():
    """Print the AbuseCLI ASCII banner"""
    console.print(BANNER.format(version=__version__))


def print_success(message):
    """Print success message with green [+] prefix"""
    print(f"\033[92m[+]\033[0m {message}")


def print_error(message):
    """Print error message with red [!] prefix"""
    print(f"\033[91m[!]\033[0m {message}")


def print_info(message):
    """Print info message with blue [i] prefix"""
    print(f"\033[94m[i]\033[0m {message}")


def print_warning(message):
    """Print warning message with yellow [!] prefix"""
    print(f"\033[93m[!]\033[0m {message}")


RISK_COLORS = {
    "critical": "red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "green",
}


def build_score_bar(score, width=15):
    """Build a colored progress bar string for an abuse confidence score"""
    filled = round(score / 100 * width)
    empty = width - filled

    if score >= RISK_CRITICAL_MIN:
        color = "red"
    elif score >= RISK_HIGH_MIN:
        color = "dark_orange"
    elif score >= RISK_MEDIUM_MIN:
        color = "yellow"
    else:
        color = "green"

    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim")
    bar.append(f" {score}%", style=f"bold {color}")
    return bar


def display_results(df):
    """Display results as a rich colored table with a summary panel"""
    table = Table(
        title="IP Analysis Results",
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
    )

    table.add_column("IP Address", style="bold white", no_wrap=True)
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="center", min_width=20)
    table.add_column("Country", justify="center")
    table.add_column("Whitelisted", justify="center")
    table.add_column("TOR", justify="center")
    table.add_column("Public", justify="center")

    has_enrichment = "open_ports" in df.columns
    if has_enrichment:
        table.add_column("Ports", style="cyan", max_width=30)
        table.add_column("CVEs", style="red", max_width=40)
        table.add_column("Hostnames", style="blue", max_width=30)

    for _, row in df.iterrows():
        risk = str(row.get("risk_level", "N/A"))
        risk_color = RISK_COLORS.get(risk, "white")
        score = int(row.get("abuseConfidenceScore", 0))

        row_data = [
            str(row.get("ipAddress", "N/A")),
            Text(risk.upper(), style=f"bold {risk_color}"),
            build_score_bar(score),
            str(row.get("countryCode", "N/A")),
            "Yes" if row.get("isWhitelisted") else "No",
            Text("Yes", style="bold red") if row.get("isTor") else Text("No"),
            "Yes" if row.get("isPublic") else Text("No", style="dim"),
        ]

        if has_enrichment:
            row_data.extend(
                [
                    str(row.get("open_ports", "-")),
                    str(row.get("cves", "-")),
                    str(row.get("hostnames", "-")),
                ]
            )

        table.add_row(*row_data)

    console.print()
    console.print(table)

    # Summary panel
    total = len(df)
    risk_counts = (
        df["risk_level"].value_counts() if "risk_level" in df.columns else pd.Series()
    )

    summary_lines = [f"[bold]Total IPs:[/bold]  {total}"]

    for level in ["critical", "high", "medium", "low"]:
        count = risk_counts.get(level, 0)
        color = RISK_COLORS.get(level, "white")
        bar_width = round(count / total * 20) if total > 0 else 0
        bar = "█" * bar_width + "░" * (20 - bar_width)
        summary_lines.append(
            f"[{color}]{level.capitalize():10s}[/{color}]  {count:>3d}  [{color}]{bar}[/{color}]"
        )

    if "countryCode" in df.columns:
        unique_countries = df["countryCode"].nunique()
        summary_lines.append(f"[bold]Countries:[/bold]  {unique_countries}")

    if "isTor" in df.columns:
        tor_count = df["isTor"].sum()
        if tor_count > 0:
            summary_lines.append(f"[bold red]TOR nodes:[/bold red] {tor_count}")

    console.print()
    console.print(
        Panel(
            "\n".join(summary_lines), title="Summary", border_style="cyan", expand=False
        )
    )
    console.print()


def fetch_quota(api_key):
    """Fetch API quota by making a lightweight check and reading rate limit headers"""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": "127.0.0.1", "maxAgeInDays": 1}

    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        return {
            "limit": int(response.headers.get("X-RateLimit-Limit", 0)),
            "remaining": int(response.headers.get("X-RateLimit-Remaining", 0)),
            "reset": int(response.headers.get("X-RateLimit-Reset", 0)),
        }
    except requests.exceptions.RequestException as e:
        print_error(f"Failed to fetch quota: {e}")
        return None


def display_quota(quota):
    """Display API quota with a rich panel and progress bars"""
    limit = quota["limit"]
    remaining = quota["remaining"]
    used = limit - remaining
    reset_seconds = quota["reset"]

    # Usage percentage
    usage_pct = round(used / limit * 100) if limit > 0 else 0
    remaining_pct = 100 - usage_pct

    # Color based on remaining quota
    if remaining_pct > 50:
        bar_color = "green"
        status_color = "green"
        status_text = "Healthy"
    elif remaining_pct > 20:
        bar_color = "yellow"
        status_color = "yellow"
        status_text = "Moderate"
    elif remaining_pct > 5:
        bar_color = "dark_orange"
        status_color = "dark_orange"
        status_text = "Low"
    else:
        bar_color = "red"
        status_color = "red"
        status_text = "Critical"

    # Build usage bar
    bar_width = 30
    filled = round(used / limit * bar_width) if limit > 0 else 0
    empty = bar_width - filled
    usage_bar = Text()
    usage_bar.append("█" * filled, style=bar_color)
    usage_bar.append("░" * empty, style="dim")

    # Build remaining bar
    rem_filled = bar_width - filled
    rem_empty = bar_width - rem_filled
    remaining_bar = Text()
    remaining_bar.append("█" * rem_filled, style="green")
    remaining_bar.append("░" * rem_empty, style="dim")

    # Reset time
    hours = reset_seconds // 3600
    minutes = (reset_seconds % 3600) // 60

    # Build table
    table = Table(
        title="API Quota",
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
    )

    table.add_column("Metric", style="bold white", min_width=15)
    table.add_column("Value", justify="right", min_width=10)
    table.add_column("Visual", min_width=35)

    table.add_row(
        "Status",
        Text(status_text, style=f"bold {status_color}"),
        Text(f"● {status_text}", style=f"bold {status_color}"),
    )
    table.add_row(
        "Daily Limit", str(limit), Text(f"max {limit} requests/day", style="dim")
    )
    table.add_row(
        "Used",
        Text(f"{used}", style=bar_color),
        usage_bar,
    )
    table.add_row(
        "Remaining",
        Text(
            f"{remaining}",
            style="bold green" if remaining_pct > 20 else f"bold {bar_color}",
        ),
        remaining_bar,
    )
    table.add_row(
        "Usage",
        Text(f"{usage_pct}%", style=f"bold {bar_color}"),
        Text(f"{used}/{limit} requests used today", style="dim"),
    )
    table.add_row(
        "Resets in",
        f"{hours}h {minutes}m",
        Text(f"{reset_seconds}s until quota reset", style="dim"),
    )

    console.print()
    console.print(table)
    console.print()


###########################################################################
## CACHE ##################################################################
###########################################################################


def init_cache_db():
    """Initialize the cache database and return a connection"""
    os.makedirs(CACHE_DIR, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS ip_cache (
            ip_address TEXT PRIMARY KEY,
            response_data TEXT NOT NULL,
            cached_at REAL NOT NULL
        )"""
    )
    conn.commit()
    return conn


def cache_get(conn, ip_address, ttl):
    """Get a cached response if it exists and hasn't expired"""
    row = conn.execute(
        "SELECT response_data, cached_at FROM ip_cache WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()

    if row is None:
        return None

    response_data, cached_at = row
    if time.time() - cached_at > ttl:
        return None

    return json.loads(response_data)


def cache_set(conn, ip_address, response_data):
    """Store an API response in the cache"""
    conn.execute(
        "INSERT OR REPLACE INTO ip_cache (ip_address, response_data, cached_at) VALUES (?, ?, ?)",
        (ip_address, json.dumps(response_data), time.time()),
    )
    conn.commit()


def cache_stats():
    """Return cache statistics"""
    if not os.path.exists(CACHE_DB):
        return {"entries": 0, "size_bytes": 0, "oldest": None, "newest": None}

    conn = sqlite3.connect(CACHE_DB)
    row = conn.execute(
        "SELECT COUNT(*), MIN(cached_at), MAX(cached_at) FROM ip_cache"
    ).fetchone()
    conn.close()

    size = os.path.getsize(CACHE_DB)
    count, oldest, newest = row

    return {
        "entries": count,
        "size_bytes": size,
        "oldest": oldest,
        "newest": newest,
    }


def cache_clear(older_than=None):
    """Clear cache entries. If older_than is set (seconds), only purge old entries."""
    if not os.path.exists(CACHE_DB):
        return 0

    conn = sqlite3.connect(CACHE_DB)
    if older_than is not None:
        cutoff = time.time() - older_than
        deleted = conn.execute(
            "DELETE FROM ip_cache WHERE cached_at < ?", (cutoff,)
        ).rowcount
    else:
        deleted = conn.execute("DELETE FROM ip_cache").rowcount

    conn.commit()
    conn.close()
    return deleted


def display_cache_stats():
    """Display cache statistics with a rich panel"""
    stats = cache_stats()

    if stats["entries"] == 0:
        console.print(
            Panel("Cache is empty.", title="Cache Stats", border_style="cyan")
        )
        return

    size_kb = stats["size_bytes"] / 1024
    oldest_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats["oldest"]))
    newest_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats["newest"]))

    lines = [
        f"[bold]Entries:[/bold]    {stats['entries']}",
        f"[bold]Size:[/bold]       {size_kb:.1f} KB",
        f"[bold]Oldest:[/bold]     {oldest_str}",
        f"[bold]Newest:[/bold]     {newest_str}",
        f"[bold]Location:[/bold]   {CACHE_DB}",
    ]

    console.print()
    console.print(
        Panel("\n".join(lines), title="Cache Stats", border_style="cyan", expand=False)
    )
    console.print()


def parse_duration(duration_str):
    """Parse a duration string like '7d', '12h', '30m' into seconds"""
    match = re.match(r"^(\d+)([dhm])$", duration_str)
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    multipliers = {"d": 86400, "h": 3600, "m": 60}
    return value * multipliers[unit]


###########################################################################
## API RESPONSE HANDLING ##################################################
###########################################################################


def handle_api_response(
    response, success_message="Operation completed successfully", verbose: bool = False
):
    """Handle API response with proper error management"""
    try:
        response.raise_for_status()
        if verbose:
            print_success(success_message)
        return response.json() if response.content else {"status": "success"}
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401:
            print_error("Authentication failed. Please check your API token.")
        elif response.status_code == 403:
            print_error(
                "Access forbidden. You don't have permission to perform this action."
            )
        elif response.status_code == 404:
            print_error("Resource not found. Please check the UUID provided.")
        elif response.status_code == 400:
            print_error("Bad request. Please check your input parameters.")
        else:
            print_error(f"HTTP Error {response.status_code}: {http_err}")

        try:
            error_details = response.json()
            print_error(f"API Error Details: {json.dumps(error_details, indent=2)}")
        except (ValueError, json.JSONDecodeError):
            print_error(f"Response content: {response.text}")
        return None
    except requests.exceptions.RequestException as err:
        print_error(f"Request failed: {err}")
        return None


###########################################################################
## SECRET MANAGEMENT ######################################################
###########################################################################


def load_api_key(args):
    """Load API key from .env, arguments, or ask user"""
    env_path = Path(ENV_FILE)
    if env_path.exists():
        load_dotenv(env_path)

    api_key = None

    # Check argument
    if args.token:
        api_key = args.token
        if args.verbose:
            print_info("API key provided via --token argument")

    # Check environment variable
    elif os.getenv("ABUSEIPDB_API_KEY"):
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if args.verbose:
            print_info("API key loaded from .env")

    # Ask and save
    else:
        print_warning("AbuseIPDB API key not found.")
        print_info("You can get your API key at: https://www.abuseipdb.com/api")

        api_key = getpass.getpass("Enter your AbuseIPDB API key: ").strip()

        if not api_key:
            print_error("API key required to continue.")
            sys.exit(1)

        # Save to .env
        save_choice = input("Do you want to save this key in .env? (y/N): ").lower()
        if save_choice in ["y", "yes"]:
            save_api_key_to_env(api_key=api_key, verbose=args.verbose)
            print_info("API key saved to .env")

    if not api_key:
        print_error("API key required to use AbuseIPDB, aborting...")
        sys.exit(1)

    return api_key


def save_api_key_to_env(api_key, verbose: bool = False):
    """Save API key to .env file"""
    try:
        env_path = Path(ENV_FILE)

        # Create .env file if it doesn't exist
        if not env_path.exists():
            env_path.touch()
            if verbose:
                print_info(f"File {ENV_FILE} created")

        # Add or update API key
        set_key(env_path, "ABUSEIPDB_API_KEY", api_key)

        # Add comment if file is new
        with open(env_path, "r") as f:
            content = f.read()

        if "AbuseIPDB API Key" not in content:
            with open(env_path, "a") as f:
                f.write("\n# AbuseIPDB API Key\n")

    except Exception as e:
        print_error(f"Error saving to file: {e}")


def validate_api_key(api_key):
    """Validate API key format (basic validation)"""
    if not api_key:
        return False

    # AbuseIPDB keys are typically 80 characters
    if len(api_key) < 50:
        print_error("API key seems too short")
        return False

    return True


###########################################################################
## ABUSE API METHODS  #####################################################
###########################################################################


def check_ip_abuse(
    ip_address,
    api_key,
    verbose: bool = False,
    cache_conn=None,
    cache_ttl=DEFAULT_CACHE_TTL,
):
    """Check IP abuse score on AbuseIPDB, with optional cache"""
    # Try cache first
    if cache_conn is not None:
        cached = cache_get(cache_conn, ip_address, cache_ttl)
        if cached is not None:
            if verbose:
                print_info(f"{ip_address} served from cache")
            return cached

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""}

    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=30)
        result = handle_api_response(
            response=response,
            success_message=f"{ip_address} successfully verified on AbuseIPDB",
            verbose=verbose,
        )

        # Store in cache on success
        if result is not None and cache_conn is not None:
            cache_set(cache_conn, ip_address, result)

        return result
    except requests.exceptions.RequestException as e:
        print(f"Error querying {ip_address}: {e}")
        return None


###########################################################################
## SHODAN INTERNETDB ENRICHMENT ###########################################
###########################################################################


async def fetch_shodan_ip(session, ip_address):
    """Fetch enrichment data from Shodan InternetDB for a single IP"""
    try:
        async with session.get(
            f"{SHODAN_INTERNETDB_URL}/{ip_address}",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                return ip_address, await resp.json()
            return ip_address, None
    except Exception:
        return ip_address, None


async def fetch_shodan_bulk(ip_list):
    """Fetch Shodan InternetDB data for multiple IPs concurrently"""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_shodan_ip(session, ip) for ip in ip_list]
        return dict(await asyncio.gather(*tasks))


def enrich_dataframe_with_shodan(df, verbose=False):
    """Enrich a DataFrame with Shodan InternetDB data (ports, CVEs, hostnames)"""
    ip_list = df["ipAddress"].tolist()

    if verbose:
        print_info(f"Enriching {len(ip_list)} IPs with Shodan InternetDB...")

    shodan_data = asyncio.run(fetch_shodan_bulk(ip_list))

    ports_list = []
    cves_list = []
    hostnames_list = []

    for ip in ip_list:
        data = shodan_data.get(ip)
        if data:
            ports_list.append(", ".join(str(p) for p in data.get("ports", [])) or "-")
            cves_list.append(", ".join(data.get("vulns", [])) or "-")
            hostnames_list.append(", ".join(data.get("hostnames", [])) or "-")
        else:
            ports_list.append("-")
            cves_list.append("-")
            hostnames_list.append("-")

    df = df.copy()
    df["open_ports"] = ports_list
    df["cves"] = cves_list
    df["hostnames"] = hostnames_list

    if verbose:
        enriched_count = sum(1 for d in shodan_data.values() if d is not None)
        print_success(
            f"Shodan enrichment complete: {enriched_count}/{len(ip_list)} IPs enriched"
        )

    return df


###########################################################################
## REPORT IP ##############################################################
###########################################################################


def report_ip_abuse(ip_address, categories, comment, api_key, verbose=False):
    """Report an abusive IP address to AbuseIPDB"""
    headers = {"Key": api_key, "Accept": "application/json"}
    data = {
        "ip": ip_address,
        "categories": categories,
    }
    if comment:
        data["comment"] = comment

    try:
        response = requests.post(API_REPORT_URL, headers=headers, data=data, timeout=30)
        result = handle_api_response(
            response=response,
            success_message=f"Successfully reported {ip_address} to AbuseIPDB",
            verbose=verbose,
        )

        if result and "data" in result:
            report_data = result["data"]
            table = Table(
                title="Report Submitted",
                show_lines=True,
                header_style="bold cyan",
                border_style="dim",
                expand=False,
            )
            table.add_column("Field", style="bold white")
            table.add_column("Value", justify="left")

            table.add_row("IP Address", str(report_data.get("ipAddress", ip_address)))
            table.add_row(
                "Abuse Score",
                str(report_data.get("abuseConfidenceScore", "N/A")) + "%",
            )
            table.add_row("Categories", categories)
            if comment:
                table.add_row("Comment", comment)

            console.print()
            console.print(table)
            console.print()
            print_success(f"IP {ip_address} reported successfully")
        return result
    except requests.exceptions.RequestException as e:
        print_error(f"Failed to report {ip_address}: {e}")
        return None


###########################################################################
## ASYNC BULK CHECKING ####################################################
###########################################################################


async def check_ip_abuse_async(
    session,
    ip_address,
    api_key,
    semaphore,
    cache_conn=None,
    cache_ttl=DEFAULT_CACHE_TTL,
):
    """Check a single IP via AbuseIPDB asynchronously"""
    # Try cache first
    if cache_conn is not None:
        cached = cache_get(cache_conn, ip_address, cache_ttl)
        if cached is not None:
            return ip_address, cached, True

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""}

    async with semaphore:
        try:
            async with session.get(
                API_URL,
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    if cache_conn is not None:
                        cache_set(cache_conn, ip_address, result)
                    return ip_address, result, False
                elif resp.status == 429:
                    # Rate limited — wait and retry once
                    retry_after = int(resp.headers.get("Retry-After", 2))
                    await asyncio.sleep(retry_after)
                    async with session.get(
                        API_URL,
                        headers=headers,
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as retry_resp:
                        if retry_resp.status == 200:
                            result = await retry_resp.json()
                            if cache_conn is not None:
                                cache_set(cache_conn, ip_address, result)
                            return ip_address, result, False
                return ip_address, None, False
        except Exception:
            return ip_address, None, False


async def check_ips_bulk_async(
    ip_list, api_key, cache_conn=None, cache_ttl=DEFAULT_CACHE_TTL, max_concurrent=10
):
    """Check multiple IPs concurrently with rate limiting"""
    semaphore = asyncio.Semaphore(max_concurrent)
    async with aiohttp.ClientSession() as session:
        tasks = [
            check_ip_abuse_async(session, ip, api_key, semaphore, cache_conn, cache_ttl)
            for ip in ip_list
        ]
        return await asyncio.gather(*tasks)


###########################################################################
## DATA MANIPULATION ######################################################
###########################################################################


def add_risk_level_column(df, verbose: bool = False):
    """Add risk_level column based on abuseConfidenceScore"""

    def get_risk_level(score):
        if score >= RISK_CRITICAL_MIN:
            return "critical"
        elif score >= RISK_HIGH_MIN:
            return "high"
        elif score >= RISK_MEDIUM_MIN:
            return "medium"
        else:
            return "low"

    df["risk_level"] = df["abuseConfidenceScore"].apply(get_risk_level)

    if verbose:
        print_info("Added risk_level column based on abuseConfidenceScore")

    return df


def filter_by_risk_level(df, risk_level, verbose: bool = False):
    """Filter DataFrame by risk level"""
    if risk_level is None:
        if verbose:
            print_info("No risk level filter applied")
        return df

    if verbose:
        print_info(f"Applying risk level filter: {risk_level}")

    min_score, max_score = RISK_LEVELS[risk_level]
    filtered_df = df[
        (df["abuseConfidenceScore"] >= min_score)
        & (df["abuseConfidenceScore"] <= max_score)
    ]

    if filtered_df.empty:
        print_warning(f"No IPs found with risk level: {risk_level}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs with risk level: {risk_level}")

    return filtered_df


def filter_by_score(df, min_score, verbose: bool = False):
    """Filter DataFrame by minimum abuse confidence score"""
    if min_score is None:
        if verbose:
            print_info("No score filter applied")
        return df

    if verbose:
        print_info(f"Applying score filter: >= {min_score}")

    if not (0 <= min_score <= 100):
        print_error("Score must be between 0 and 100")
        return df

    filtered_df = df[df["abuseConfidenceScore"] >= min_score]

    if filtered_df.empty:
        print_warning(f"No IPs found with score >= {min_score}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs with score >= {min_score}")

    return filtered_df


def filter_by_country_code(df, country_code, verbose: bool = False):
    """Filter DataFrame by country code"""
    if country_code is None:
        if verbose:
            print_info("No country code filter applied")
        return df

    country_code = country_code.upper()  # Normalize to uppercase

    if verbose:
        print_info(f"Applying country code filter: {country_code}")

    filtered_df = df[df["countryCode"] == country_code]

    if filtered_df.empty:
        print_warning(f"No IPs found for country code: {country_code}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs for country code: {country_code}")

    return filtered_df


def filter_tor_addresses(df, is_tor, is_not_tor, verbose: bool = False):
    """Filter DataFrame by TOR status"""
    if is_tor and is_not_tor:
        print_error("Cannot use both --is-tor and --is-not-tor flags")
        return df

    if is_tor:
        if verbose:
            print_info("Applying TOR filter: keeping only TOR addresses")
        filtered_df = df[df["isTor"].eq(True)]
        if filtered_df.empty:
            print_warning("No TOR IP addresses found")
        elif verbose:
            print_success(f"Found {len(filtered_df)} TOR IP addresses")
        return filtered_df

    if is_not_tor:
        if verbose:
            print_info("Applying TOR filter: removing TOR addresses")
        filtered_df = df[df["isTor"].eq(False)]
        if filtered_df.empty:
            print_warning("No non-TOR IP addresses found")
        elif verbose:
            print_success(f"Found {len(filtered_df)} non-TOR IP addresses")
        return filtered_df

    if verbose:
        print_info("No TOR filter applied")
    return df


def filter_remove_private(df, remove_private, verbose: bool = False):
    """Filter to keep only public IP addresses"""
    if not remove_private:
        if verbose:
            print_info("No private IP filter applied")
        return df

    if verbose:
        print_info("Applying private IP filter: keeping only public addresses")

    filtered_df = df[df["isPublic"].eq(True)]

    if filtered_df.empty:
        print_warning("No public IP addresses found")
    elif verbose:
        print_success(f"Found {len(filtered_df)} public IP addresses")

    return filtered_df


def filter_remove_whitelisted(df, remove_whitelisted, verbose: bool = False):
    """Filter to keep only non-whitelisted IP addresses"""
    if not remove_whitelisted:
        if verbose:
            print_info("No whitelist filter applied")
        return df

    if verbose:
        print_info("Applying whitelist filter: removing whitelisted addresses")

    filtered_df = df[df["isWhitelisted"].eq(False)]

    if filtered_df.empty:
        print_warning("No non-whitelisted IP addresses found")
    elif verbose:
        print_success(f"Found {len(filtered_df)} non-whitelisted IP addresses")

    return filtered_df


def apply_all_filters(df, args):
    """Apply all filtering operations based on command line arguments"""
    if df.empty:
        return df

    original_count = len(df)

    if args.verbose:
        print_info(f"Starting with {original_count} IP addresses")

    # Add risk level column first
    df = add_risk_level_column(df, verbose=args.verbose)

    # Apply filters in sequence
    df = filter_by_risk_level(df, args.risk_level, verbose=args.verbose)
    if args.verbose:
        print_info(f"After risk level filter: {len(df)} IPs remaining")

    df = filter_by_score(df, args.score, verbose=args.verbose)
    if args.verbose:
        print_info(f"After score filter: {len(df)} IPs remaining")

    df = filter_by_country_code(df, args.country_code, verbose=args.verbose)
    if args.verbose:
        print_info(f"After country filter: {len(df)} IPs remaining")

    df = filter_tor_addresses(df, args.is_tor, args.is_not_tor, verbose=args.verbose)
    if args.verbose:
        print_info(f"After TOR filter: {len(df)} IPs remaining")

    df = filter_remove_private(df, args.remove_private, verbose=args.verbose)
    if args.verbose:
        print_info(f"After private IP filter: {len(df)} IPs remaining")

    df = filter_remove_whitelisted(df, args.remove_whitelisted, verbose=args.verbose)
    if args.verbose:
        print_info(f"After whitelist filter: {len(df)} IPs remaining")

    if args.verbose:
        print_success(f"Final result: {len(df)} IP addresses after filtering")
        if not df.empty:
            print_info("Final risk level distribution:")
            print(df["risk_level"].value_counts().to_string())

    return df


###########################################################################
## IMPORT / EXPORT METHODS ################################################
###########################################################################


def export_dataframe(df, formats, base_filename="ip_analysis", verbose: bool = False):
    """
    Export DataFrame to multiple formats using pandas default methods

    Args:
        df: pandas DataFrame to export
        formats: list of format strings ['csv', 'json', 'excel', 'html', 'parquet']
        base_filename: base name for output files (without extension)
        verbose: whether to show detailed output
    """
    if not formats:
        return

    exported_files = []

    for format_type in formats:
        try:
            filename = f"{base_filename}.{format_type}"

            if format_type == "csv":
                df.to_csv(filename, index=False)
                if verbose:
                    print_info(f"Exported to CSV: {filename}")

            elif format_type == "json":
                df.to_json(filename, orient="records", indent=2, date_format="iso")
                if verbose:
                    print_info(f"Exported to JSON: {filename}")

            elif format_type == "excel":
                df.to_excel(filename, index=False, engine="openpyxl")
                if verbose:
                    print_info(f"Exported to Excel: {filename}")

            elif format_type == "html":
                df.to_html(
                    filename,
                    index=False,
                    classes="table table-striped table-bordered",
                    table_id="ip-analysis-table",
                    escape=False,
                )
                if verbose:
                    print_info(f"Exported to HTML: {filename}")

            elif format_type == "parquet":
                df.to_parquet(filename, index=False)
                if verbose:
                    print_info(f"Exported to Parquet: {filename}")

            exported_files.append(filename)

        except Exception as e:
            print_error(f"Failed to export to {format_type}: {str(e)}")

    if exported_files:
        print_success(
            f"Successfully exported to {len(exported_files)} format(s): {', '.join(exported_files)}"
        )

    return exported_files


def load_dataframe_from_file(file_path, file_format="auto", verbose: bool = False):
    """
    Load DataFrame from various file formats

    Args:
        file_path: Path to the source file
        file_format: Format of the file ('csv', 'json', 'excel', 'parquet', 'auto')
        verbose: Whether to show detailed output

    Returns:
        pandas.DataFrame or None if loading failed
    """
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return None

    # Auto-detect format from file extension
    if file_format == "auto":
        extension = Path(file_path).suffix.lower()
        format_mapping = {
            ".csv": "csv",
            ".json": "json",
            ".xlsx": "excel",
            ".xls": "excel",
            ".parquet": "parquet",
            ".pq": "parquet",
        }
        file_format = format_mapping.get(extension)

        if not file_format:
            print_error(f"Cannot auto-detect format for file: {file_path}")
            print_info("Supported extensions: .csv, .json, .xlsx, .xls, .parquet, .pq")
            return None

        if verbose:
            print_info(f"Auto-detected format: {file_format}")

    try:
        if verbose:
            print_info(f"Loading data from {file_path} as {file_format.upper()}")

        if file_format == "csv":
            df = pd.read_csv(file_path)

        elif file_format == "json":
            df = pd.read_json(file_path)

        elif file_format == "excel":
            df = pd.read_excel(file_path)

        elif file_format == "parquet":
            df = pd.read_parquet(file_path)

        else:
            print_error(f"Unsupported file format: {file_format}")
            return None

        if df.empty:
            print_warning("Loaded file is empty")
            return None

        if verbose:
            print_success(f"Successfully loaded {len(df)} records from {file_path}")
            print_info(f"Columns: {', '.join(df.columns.tolist())}")

        return df

    except Exception as e:
        print_error(f"Failed to load file {file_path}: {str(e)}")
        return None


def validate_loaded_dataframe(df, verbose: bool = False):
    """
    Validate that the loaded DataFrame has the required columns for IP analysis

    Args:
        df: pandas DataFrame to validate
        verbose: Whether to show detailed output

    Returns:
        bool: True if valid, False otherwise
    """
    required_columns = ["ipAddress", "abuseConfidenceScore"]
    optional_columns = [
        "countryCode",
        "isWhitelisted",
        "isTor",
        "isPublic",
        "risk_level",
    ]

    missing_required = [col for col in required_columns if col not in df.columns]

    if missing_required:
        print_error(f"Missing required columns: {', '.join(missing_required)}")
        print_info(f"Available columns: {', '.join(df.columns.tolist())}")
        return False

    missing_optional = [col for col in optional_columns if col not in df.columns]

    if verbose:
        print_success("Required columns found")
        if missing_optional:
            print_warning(f"Missing optional columns: {', '.join(missing_optional)}")
            print_info("Missing columns will be handled automatically")

    return True


###########################################################################
## IP EXTRACTION ##########################################################
###########################################################################

# Regex matching IPv4 and IPv6 addresses
IP_REGEX = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![\d.])"
    r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
)

# Private/loopback ranges to exclude from log analysis
PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "0.",
    "169.254.",
)


def extract_ips_from_text(text):
    """Extract unique IP addresses from raw text"""
    return list(set(IP_REGEX.findall(text)))


def extract_ips_from_file(file_path, skip_private=True, verbose=False):
    """Extract unique IP addresses from a log file"""
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return []

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print_error(f"Failed to read file {file_path}: {e}")
        return []

    all_ips = extract_ips_from_text(content)

    if skip_private:
        public_ips = [ip for ip in all_ips if not ip.startswith(PRIVATE_IP_PREFIXES)]
    else:
        public_ips = all_ips

    if verbose:
        print_info(f"Total IPs found in file: {len(all_ips)}")
        if skip_private:
            print_info(f"After removing private/loopback: {len(public_ips)}")
        print_info(f"Unique public IPs to check: {len(public_ips)}")

    return public_ips


def resolve_ip_list(args):
    """Resolve the final list of unique IPs from --ips (including stdin via '-') or --file"""
    if args.file:
        file_path = args.file
        if not os.path.exists(file_path):
            print_error(f"File not found: {file_path}")
            return []
        with open(file_path, "r") as f:
            ips = [line.strip() for line in f if line.strip()]
    elif args.ips:
        if args.ips == ["-"]:
            if sys.stdin.isatty():
                print_error("No input from stdin. Pipe data or use --file/--ips.")
                return []
            raw = sys.stdin.read()
            ips = [line.strip() for line in raw.splitlines() if line.strip()]
        else:
            ips = args.ips
    else:
        return []

    # Deduplicate while preserving order
    unique_ips = list(dict.fromkeys(ips))

    if len(unique_ips) < len(ips) and args.verbose:
        print_info(
            f"Removed {len(ips) - len(unique_ips)} duplicate IPs "
            f"({len(ips)} -> {len(unique_ips)})"
        )

    if args.verbose:
        print_info(f"Loaded {len(unique_ips)} unique IPs")

    return unique_ips


###########################################################################
## PROCESSING METHODS #####################################################
###########################################################################


def process_ip_addresses(args, api_key):
    ip_list = resolve_ip_list(args)
    if not ip_list:
        print_error("No IP addresses provided")
        return None

    # Initialize cache unless disabled
    cache_conn = None
    if not args.no_cache:
        cache_conn = init_cache_db()

    ip_array = []
    success_count = 0
    cache_hit_count = 0
    error_count = 0

    # Use async bulk checking for better performance
    if len(ip_list) > 1:
        print_info(f"Checking {len(ip_list)} IPs asynchronously...")
        results = asyncio.run(
            check_ips_bulk_async(
                ip_list, api_key, cache_conn=cache_conn, cache_ttl=args.cache_ttl
            )
        )

        for ip, result, from_cache in results:
            if from_cache:
                cache_hit_count += 1
            if result and "data" in result:
                ip_data = result["data"]
                if "reports" in ip_data:
                    del ip_data["reports"]
                ip_array.append(ip_data)
                success_count += 1
            else:
                error_count += 1
    else:
        # Single IP — use synchronous call with progress
        with tqdm(ip_list, desc="Analyzing IPs", unit="IP", colour="green") as pbar:
            for ip in pbar:
                try:
                    pbar.set_description(f"Checking {ip}")
                    ip_data = check_ip_abuse(
                        ip_address=ip,
                        api_key=api_key,
                        verbose=args.verbose,
                        cache_conn=cache_conn,
                        cache_ttl=args.cache_ttl,
                    ).get("data")

                    if ip_data and "reports" in ip_data:
                        del ip_data["reports"]
                        ip_array.append(ip_data)
                        success_count += 1
                    else:
                        error_count += 1

                except Exception as e:
                    error_count += 1
                    if args.verbose:
                        print_error(f"Error checking {ip}: {str(e)}")

    if cache_conn is not None:
        cache_conn.close()

    if args.verbose:
        print_info(
            f"API calls completed: {success_count} successful, {error_count} failed"
        )
        if cache_hit_count > 0:
            print_info(f"Cache hits: {cache_hit_count}/{len(ip_list)}")

    # Data processing
    if not ip_array:
        print_error("No valid IP data retrieved")
        return None

    df = pd.DataFrame(ip_array)
    filtered_df = apply_all_filters(df, args)

    # Shodan enrichment if requested
    if hasattr(args, "enrich") and args.enrich and not filtered_df.empty:
        filtered_df = enrich_dataframe_with_shodan(filtered_df, verbose=args.verbose)

    if filtered_df.empty:
        print_error("No IP addresses match the specified criteria")
        return None

    # Display results
    columns_order = [
        "ipAddress",
        "risk_level",
        "abuseConfidenceScore",
        "countryCode",
        "isWhitelisted",
        "isTor",
        "isPublic",
    ] + [
        col
        for col in filtered_df.columns
        if col
        not in [
            "ipAddress",
            "risk_level",
            "abuseConfidenceScore",
            "countryCode",
            "isWhitelisted",
            "isTor",
            "isPublic",
        ]
    ]

    display_df = filtered_df[columns_order]

    # Export if requested
    if args.export:
        if args.verbose:
            print_info(f"Exporting to formats: {', '.join(args.export)}")

        # Generate base filename with timestamp
        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"ip_analysis_{timestamp}"

        export_dataframe(
            df=display_df,
            formats=args.export,
            base_filename=base_filename,
            verbose=args.verbose,
        )

    return display_df


def process_loaded_data(args):
    """
    Process data loaded from file with the same filtering capabilities as check command

    Args:
        args: Command line arguments from argparse

    Returns:
        pandas.DataFrame or None
    """
    # Load the data
    df = load_dataframe_from_file(args.source, args.format, verbose=args.verbose)

    if df is None:
        return None

    # Validate the DataFrame structure
    if not validate_loaded_dataframe(df, verbose=args.verbose):
        return None

    # Add missing columns with default values if needed
    if "countryCode" not in df.columns:
        df["countryCode"] = "Unknown"
        if args.verbose:
            print_info(
                "Added missing 'countryCode' column with default value 'Unknown'"
            )

    if "isWhitelisted" not in df.columns:
        df["isWhitelisted"] = False
        if args.verbose:
            print_info("Added missing 'isWhitelisted' column with default value False")

    if "isTor" not in df.columns:
        df["isTor"] = False
        if args.verbose:
            print_info("Added missing 'isTor' column with default value False")

    if "isPublic" not in df.columns:
        df["isPublic"] = True
        if args.verbose:
            print_info("Added missing 'isPublic' column with default value True")

    # Apply all filters (same as check command)
    filtered_df = apply_all_filters(df, args)

    if filtered_df.empty:
        print_error("No IP addresses match the specified criteria")
        return None

    # Shodan enrichment if requested
    if hasattr(args, "enrich") and args.enrich and not filtered_df.empty:
        filtered_df = enrich_dataframe_with_shodan(filtered_df, verbose=args.verbose)

    # Display results
    columns_order = [
        "ipAddress",
        "risk_level",
        "abuseConfidenceScore",
        "countryCode",
        "isWhitelisted",
        "isTor",
        "isPublic",
    ] + [
        col
        for col in filtered_df.columns
        if col
        not in [
            "ipAddress",
            "risk_level",
            "abuseConfidenceScore",
            "countryCode",
            "isWhitelisted",
            "isTor",
            "isPublic",
        ]
    ]

    # Only include columns that exist in the DataFrame
    available_columns = [col for col in columns_order if col in filtered_df.columns]
    display_df = filtered_df[available_columns]

    # Export if requested
    if args.export:
        if args.verbose:
            print_info(f"Exporting to formats: {', '.join(args.export)}")

        # Generate base filename with timestamp
        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        source_name = Path(args.source).stem
        base_filename = f"{source_name}_filtered_{timestamp}"

        export_dataframe(
            df=display_df,
            formats=args.export,
            base_filename=base_filename,
            verbose=args.verbose,
        )

    return display_df


def process_analyze(args, api_key):
    """
    Extract IPs from a log file, check them via the API, and display results.
    """
    ips = extract_ips_from_file(args.log_file, skip_private=True, verbose=args.verbose)

    if not ips:
        print_error("No public IP addresses found in the log file")
        return None

    print_success(f"Found {len(ips)} unique public IPs in {args.log_file}")

    # Reuse process_ip_addresses by injecting the IP list
    args.ips = ips
    args.file = None
    return process_ip_addresses(args, api_key)


###########################################################################
## MAIN ###################################################################
###########################################################################


def main():
    print_banner()

    parser = create_parser()

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    if args.command in ("check", "analyze", "quota", "report"):
        try:
            api_key = load_api_key(args=args)
        except KeyboardInterrupt:
            print_error("\nOperation aborted by user...")
            return
        except Exception as e:
            print_error(f"Error occured while loading API key: {e}")
            return

        if args.command == "quota":
            quota = fetch_quota(api_key)
            if quota:
                display_quota(quota)
        elif args.command == "report":
            report_ip_abuse(
                ip_address=args.ip,
                categories=args.categories,
                comment=args.comment,
                api_key=api_key,
                verbose=args.verbose,
            )
        elif args.command == "check":
            ip_df = process_ip_addresses(args=args, api_key=api_key)
            if ip_df is not None and not ip_df.empty:
                display_results(ip_df)
        else:
            ip_df = process_analyze(args=args, api_key=api_key)
            if ip_df is not None and not ip_df.empty:
                display_results(ip_df)

    elif args.command == "load":
        ip_df = process_loaded_data(args)
        if ip_df is not None and not ip_df.empty:
            display_results(ip_df)

    elif args.command == "cache":
        if not hasattr(args, "cache_action") or args.cache_action is None:
            print_error("Please specify a cache action: stats or clear")
            print_info(
                "Usage: abusecli.py cache stats | abusecli.py cache clear [--older-than 7d]"
            )
            return

        if args.cache_action == "stats":
            display_cache_stats()
        elif args.cache_action == "clear":
            older_than = None
            if args.older_than:
                older_than = parse_duration(args.older_than)
                if older_than is None:
                    print_error(
                        f"Invalid duration: {args.older_than}. Use format like 7d, 12h, 30m"
                    )
                    return
            deleted = cache_clear(older_than)
            if older_than:
                print_success(
                    f"Cleared {deleted} cache entries older than {args.older_than}"
                )
            else:
                print_success(f"Cleared {deleted} cache entries")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
