import asyncio

import aiohttp
import requests

from rich.console import Console
from rich.table import Table

from abusecli.constants import API_URL, API_REPORT_URL, DEFAULT_CACHE_TTL
from abusecli.cache import cache_get, cache_set
from abusecli.utils import handle_api_response, print_error, print_info, print_success

console = Console()


###########################################################################
## SYNCHRONOUS API ########################################################
###########################################################################


def check_ip_abuse(
    ip_address, api_key, verbose=False, cache_conn=None, cache_ttl=DEFAULT_CACHE_TTL
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
