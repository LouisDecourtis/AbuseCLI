from abusecli.constants import (
    RISK_LEVELS,
    RISK_CRITICAL_MIN,
    RISK_HIGH_MIN,
    RISK_MEDIUM_MIN,
)
from abusecli.utils import print_error, print_info, print_success, print_warning


def add_risk_level_column(df, verbose=False):
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


def filter_by_risk_level(df, risk_level, verbose=False):
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


def filter_by_score(df, min_score, verbose=False):
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


def filter_by_country_code(df, country_code, verbose=False):
    """Filter DataFrame by country code"""
    if country_code is None:
        if verbose:
            print_info("No country code filter applied")
        return df

    country_code = country_code.upper()

    if verbose:
        print_info(f"Applying country code filter: {country_code}")

    filtered_df = df[df["countryCode"] == country_code]

    if filtered_df.empty:
        print_warning(f"No IPs found for country code: {country_code}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs for country code: {country_code}")

    return filtered_df


def filter_tor_addresses(df, is_tor, is_not_tor, verbose=False):
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


def filter_remove_private(df, remove_private, verbose=False):
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


def filter_remove_whitelisted(df, remove_whitelisted, verbose=False):
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

    df = add_risk_level_column(df, verbose=args.verbose)

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
