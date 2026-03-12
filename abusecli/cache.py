import os
import json
import time
import sqlite3

from rich.console import Console
from rich.panel import Panel

from abusecli.constants import CACHE_DIR, CACHE_DB

console = Console()


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
