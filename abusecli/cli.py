import argparse

from abusecli.constants import DEFAULT_CACHE_TTL


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
        help="Show detailed output, strongly recommended for debugging.",
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
