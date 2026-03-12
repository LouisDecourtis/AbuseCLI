import os
import sys
import getpass
import json
import re
import requests

from pathlib import Path
from dotenv import load_dotenv, set_key

from abusecli.constants import ENV_FILE


###########################################################################
## PRINT HELPERS ##########################################################
###########################################################################


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


###########################################################################
## API RESPONSE HANDLING ##################################################
###########################################################################


def handle_api_response(
    response, success_message="Operation completed successfully", verbose=False
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


def save_api_key_to_env(api_key, verbose=False):
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
## DURATION PARSING #######################################################
###########################################################################


def parse_duration(duration_str):
    """Parse a duration string like '7d', '12h', '30m' into seconds"""
    match = re.match(r"^(\d+)([dhm])$", duration_str)
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    multipliers = {"d": 86400, "h": 3600, "m": 60}
    return value * multipliers[unit]
