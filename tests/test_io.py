import pandas as pd
import pytest

from abusecli.io import (
    export_dataframe,
    load_dataframe_from_file,
    validate_loaded_dataframe,
)


@pytest.fixture
def sample_df():
    return pd.DataFrame(
        [
            {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95, "countryCode": "CN"},
            {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0, "countryCode": "US"},
        ]
    )


class TestExport:
    def test_export_csv(self, sample_df, tmp_path):
        base = str(tmp_path / "test")
        files = export_dataframe(sample_df, ["csv"], base_filename=base)
        assert len(files) == 1
        assert files[0].endswith(".csv")

        loaded = pd.read_csv(files[0])
        assert len(loaded) == 2

    def test_export_json(self, sample_df, tmp_path):
        base = str(tmp_path / "test")
        files = export_dataframe(sample_df, ["json"], base_filename=base)
        assert len(files) == 1

        loaded = pd.read_json(files[0])
        assert len(loaded) == 2

    def test_export_multiple(self, sample_df, tmp_path):
        base = str(tmp_path / "test")
        files = export_dataframe(sample_df, ["csv", "json"], base_filename=base)
        assert len(files) == 2

    def test_export_empty_formats(self, sample_df):
        result = export_dataframe(sample_df, [])
        assert result is None


class TestLoad:
    def test_load_csv(self, sample_df, tmp_path):
        path = str(tmp_path / "test.csv")
        sample_df.to_csv(path, index=False)
        loaded = load_dataframe_from_file(path)
        assert len(loaded) == 2

    def test_load_json(self, sample_df, tmp_path):
        path = str(tmp_path / "test.json")
        sample_df.to_json(path, orient="records")
        loaded = load_dataframe_from_file(path)
        assert len(loaded) == 2

    def test_load_not_found(self):
        result = load_dataframe_from_file("/nonexistent/file.csv")
        assert result is None

    def test_load_unknown_extension(self, tmp_path):
        path = str(tmp_path / "test.xyz")
        with open(path, "w") as f:
            f.write("data")
        result = load_dataframe_from_file(path)
        assert result is None


class TestValidate:
    def test_valid(self, sample_df):
        assert validate_loaded_dataframe(sample_df) is True

    def test_missing_required(self):
        df = pd.DataFrame([{"foo": "bar"}])
        assert validate_loaded_dataframe(df) is False
