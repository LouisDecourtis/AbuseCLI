import asyncio

import pandas as pd

from pathlib import Path
from tqdm import tqdm

from abusecli.api import check_ip_abuse, check_ips_bulk_async
from abusecli.cache import init_cache_db
from abusecli.enrichment import enrich_dataframe_with_shodan
from abusecli.extraction import resolve_ip_list, extract_ips_from_file
from abusecli.filters import apply_all_filters
from abusecli.io import (
    export_dataframe,
    load_dataframe_from_file,
    validate_loaded_dataframe,
)
from abusecli.utils import print_error, print_info, print_success


def process_ip_addresses(args, api_key):
    """Check IPs via AbuseIPDB API and return filtered DataFrame"""
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
                    result = check_ip_abuse(
                        ip_address=ip,
                        api_key=api_key,
                        verbose=args.verbose,
                        cache_conn=cache_conn,
                        cache_ttl=args.cache_ttl,
                    )

                    if result and "data" in result:
                        ip_data = result["data"]
                        if "reports" in ip_data:
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
    """Process data loaded from file with the same filtering capabilities as check command"""
    df = load_dataframe_from_file(args.source, args.format, verbose=args.verbose)

    if df is None:
        return None

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

    # Apply all filters
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

    available_columns = [col for col in columns_order if col in filtered_df.columns]
    display_df = filtered_df[available_columns]

    # Export if requested
    if args.export:
        if args.verbose:
            print_info(f"Exporting to formats: {', '.join(args.export)}")

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
    """Extract IPs from a log file, check them via the API, and display results."""
    ips = extract_ips_from_file(args.log_file, skip_private=True, verbose=args.verbose)

    if not ips:
        print_error("No public IP addresses found in the log file")
        return None

    print_success(f"Found {len(ips)} unique public IPs in {args.log_file}")

    # Reuse process_ip_addresses by injecting the IP list
    args.ips = ips
    args.file = None
    return process_ip_addresses(args, api_key)
