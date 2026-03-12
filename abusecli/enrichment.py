import asyncio

import aiohttp

from abusecli.constants import SHODAN_INTERNETDB_URL
from abusecli.utils import print_info, print_success


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
