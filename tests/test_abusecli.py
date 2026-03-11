import pandas as pd
import pytest

from abusecli import (
    add_risk_level_column,
    extract_ips_from_text,
    extract_ips_from_file,
    filter_by_risk_level,
    filter_by_score,
    filter_by_country_code,
    filter_tor_addresses,
    filter_remove_private,
    filter_remove_whitelisted,
    PRIVATE_IP_PREFIXES,
)


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def sample_df():
    """Sample DataFrame mimicking AbuseIPDB API response"""
    return pd.DataFrame(
        [
            {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 95,
                "countryCode": "CN",
                "isWhitelisted": False,
                "isTor": True,
                "isPublic": True,
            },
            {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isWhitelisted": True,
                "isTor": False,
                "isPublic": True,
            },
            {
                "ipAddress": "5.5.5.5",
                "abuseConfidenceScore": 65,
                "countryCode": "RU",
                "isWhitelisted": False,
                "isTor": False,
                "isPublic": True,
            },
            {
                "ipAddress": "10.0.0.1",
                "abuseConfidenceScore": 35,
                "countryCode": "FR",
                "isWhitelisted": False,
                "isTor": False,
                "isPublic": False,
            },
        ]
    )


# ── IP Extraction ────────────────────────────────────────────────────


class TestIPExtraction:
    def test_extract_ipv4_from_text(self):
        text = "Failed login from 192.168.1.1 and 10.0.0.5 on port 22"
        ips = extract_ips_from_text(text)
        assert "192.168.1.1" in ips
        assert "10.0.0.5" in ips

    def test_extract_deduplicates(self):
        text = "8.8.8.8 tried again 8.8.8.8 and 1.1.1.1"
        ips = extract_ips_from_text(text)
        assert ips.count("8.8.8.8") == 1

    def test_extract_no_ips(self):
        text = "No IP addresses in this log line"
        ips = extract_ips_from_text(text)
        assert ips == []

    def test_extract_from_auth_log(self):
        log = (
            "Mar 11 08:23:01 server sshd[1234]: Failed password for root from 185.220.101.34 port 43210\n"
            "Mar 11 08:23:05 server sshd[1235]: Failed password for admin from 45.33.32.156 port 12345\n"
            "Mar 11 08:24:00 server sshd[1236]: Accepted from 127.0.0.1 port 55555\n"
        )
        ips = extract_ips_from_text(log)
        assert "185.220.101.34" in ips
        assert "45.33.32.156" in ips
        assert "127.0.0.1" in ips

    def test_extract_from_file_not_found(self):
        ips = extract_ips_from_file("/nonexistent/path.log")
        assert ips == []

    def test_extract_from_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "Connection from 8.8.8.8\n"
            "Connection from 192.168.1.1\n"
            "Connection from 1.1.1.1\n"
        )
        ips = extract_ips_from_file(str(log_file), skip_private=True)
        assert "8.8.8.8" in ips
        assert "1.1.1.1" in ips
        assert "192.168.1.1" not in ips

    def test_extract_from_file_keep_private(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("Connection from 192.168.1.1\n")
        ips = extract_ips_from_file(str(log_file), skip_private=False)
        assert "192.168.1.1" in ips


# ── Private IP Prefixes ──────────────────────────────────────────────


class TestPrivateIPPrefixes:
    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
        ],
    )
    def test_private_ips_detected(self, ip):
        assert ip.startswith(PRIVATE_IP_PREFIXES)

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "185.220.101.34",
            "45.33.32.156",
        ],
    )
    def test_public_ips_not_filtered(self, ip):
        assert not ip.startswith(PRIVATE_IP_PREFIXES)


# ── Risk Level ────────────────────────────────────────────────────────


class TestRiskLevel:
    def test_add_risk_level_column(self, sample_df):
        df = add_risk_level_column(sample_df)
        assert "risk_level" in df.columns
        assert (
            df.loc[df["ipAddress"] == "1.2.3.4", "risk_level"].values[0] == "critical"
        )
        assert df.loc[df["ipAddress"] == "8.8.8.8", "risk_level"].values[0] == "low"
        assert df.loc[df["ipAddress"] == "5.5.5.5", "risk_level"].values[0] == "high"
        assert df.loc[df["ipAddress"] == "10.0.0.1", "risk_level"].values[0] == "medium"

    def test_risk_level_boundaries(self):
        df = pd.DataFrame({"abuseConfidenceScore": [0, 24, 25, 49, 50, 74, 75, 100]})
        df = add_risk_level_column(df)
        levels = df["risk_level"].tolist()
        assert levels == [
            "low",
            "low",
            "medium",
            "medium",
            "high",
            "high",
            "critical",
            "critical",
        ]


# ── Filters ───────────────────────────────────────────────────────────


class TestFilters:
    def test_filter_by_risk_level(self, sample_df):
        df = add_risk_level_column(sample_df)
        result = filter_by_risk_level(df, "critical")
        assert len(result) == 1
        assert result.iloc[0]["ipAddress"] == "1.2.3.4"

    def test_filter_by_risk_level_none(self, sample_df):
        result = filter_by_risk_level(sample_df, None)
        assert len(result) == len(sample_df)

    def test_filter_by_score(self, sample_df):
        result = filter_by_score(sample_df, 50)
        assert len(result) == 2
        assert all(result["abuseConfidenceScore"] >= 50)

    def test_filter_by_score_none(self, sample_df):
        result = filter_by_score(sample_df, None)
        assert len(result) == len(sample_df)

    def test_filter_by_score_invalid(self, sample_df):
        result = filter_by_score(sample_df, 150)
        assert len(result) == len(sample_df)

    def test_filter_by_country_code(self, sample_df):
        result = filter_by_country_code(sample_df, "CN")
        assert len(result) == 1
        assert result.iloc[0]["ipAddress"] == "1.2.3.4"

    def test_filter_by_country_code_case_insensitive(self, sample_df):
        result = filter_by_country_code(sample_df, "cn")
        assert len(result) == 1

    def test_filter_by_country_code_none(self, sample_df):
        result = filter_by_country_code(sample_df, None)
        assert len(result) == len(sample_df)

    def test_filter_tor_only(self, sample_df):
        result = filter_tor_addresses(sample_df, is_tor=True, is_not_tor=False)
        assert len(result) == 1
        assert result.iloc[0]["ipAddress"] == "1.2.3.4"

    def test_filter_not_tor(self, sample_df):
        result = filter_tor_addresses(sample_df, is_tor=False, is_not_tor=True)
        assert len(result) == 3

    def test_filter_tor_both_flags(self, sample_df):
        result = filter_tor_addresses(sample_df, is_tor=True, is_not_tor=True)
        assert len(result) == len(sample_df)

    def test_filter_remove_private(self, sample_df):
        result = filter_remove_private(sample_df, remove_private=True)
        assert len(result) == 3
        assert all(result["isPublic"])

    def test_filter_remove_private_false(self, sample_df):
        result = filter_remove_private(sample_df, remove_private=False)
        assert len(result) == len(sample_df)

    def test_filter_remove_whitelisted(self, sample_df):
        result = filter_remove_whitelisted(sample_df, remove_whitelisted=True)
        assert len(result) == 3
        assert not any(result["isWhitelisted"])

    def test_filter_remove_whitelisted_false(self, sample_df):
        result = filter_remove_whitelisted(sample_df, remove_whitelisted=False)
        assert len(result) == len(sample_df)

    def test_filter_empty_df(self):
        df = pd.DataFrame(
            columns=[
                "abuseConfidenceScore",
                "countryCode",
                "isTor",
                "isPublic",
                "isWhitelisted",
            ]
        )
        result = filter_by_score(df, 50)
        assert result.empty
