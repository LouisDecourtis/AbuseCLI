import sys

from abusecli.cli import create_parser
from abusecli.api import fetch_quota, report_ip_abuse
from abusecli.cache import cache_clear, display_cache_stats
from abusecli.display import print_banner, display_results, display_quota
from abusecli.processing import (
    process_ip_addresses,
    process_loaded_data,
    process_analyze,
)
from abusecli.utils import (
    load_api_key,
    parse_duration,
    print_error,
    print_info,
    print_success,
)


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
