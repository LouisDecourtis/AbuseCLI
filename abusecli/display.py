import pandas as pd

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from abusecli import __version__
from abusecli.constants import (
    BANNER,
    RISK_CRITICAL_MIN,
    RISK_HIGH_MIN,
    RISK_MEDIUM_MIN,
    RISK_COLORS,
)

console = Console()


def print_banner():
    """Print the AbuseCLI ASCII banner"""
    console.print(BANNER.format(version=__version__))


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
