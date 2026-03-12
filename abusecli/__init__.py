"""AbuseCLI — AbuseIPDB CLI Tool"""

__version__ = "1.1.0"

# Re-export public API for backwards compatibility (tests import from `abusecli`)
from abusecli.constants import PRIVATE_IP_PREFIXES  # noqa: F401
from abusecli.extraction import extract_ips_from_text, extract_ips_from_file  # noqa: F401
from abusecli.filters import (  # noqa: F401
    add_risk_level_column,
    filter_by_risk_level,
    filter_by_score,
    filter_by_country_code,
    filter_tor_addresses,
    filter_remove_private,
    filter_remove_whitelisted,
)
