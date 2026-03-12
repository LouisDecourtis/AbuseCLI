import os
import sys

from abusecli.constants import IP_REGEX, PRIVATE_IP_PREFIXES
from abusecli.utils import print_error, print_info


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
