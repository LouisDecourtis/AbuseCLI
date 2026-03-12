import os

import pandas as pd

from pathlib import Path

from abusecli.utils import print_error, print_info, print_success, print_warning


def export_dataframe(df, formats, base_filename="ip_analysis", verbose=False):
    """Export DataFrame to multiple formats using pandas default methods"""
    if not formats:
        return

    exported_files = []

    for format_type in formats:
        try:
            filename = f"{base_filename}.{format_type}"

            if format_type == "csv":
                df.to_csv(filename, index=False)
            elif format_type == "json":
                df.to_json(filename, orient="records", indent=2, date_format="iso")
            elif format_type == "excel":
                df.to_excel(filename, index=False, engine="openpyxl")
            elif format_type == "html":
                df.to_html(
                    filename,
                    index=False,
                    classes="table table-striped table-bordered",
                    table_id="ip-analysis-table",
                    escape=False,
                )
            elif format_type == "parquet":
                df.to_parquet(filename, index=False)

            if verbose:
                print_info(f"Exported to {format_type.upper()}: {filename}")

            exported_files.append(filename)

        except Exception as e:
            print_error(f"Failed to export to {format_type}: {str(e)}")

    if exported_files:
        print_success(
            f"Successfully exported to {len(exported_files)} format(s): {', '.join(exported_files)}"
        )

    return exported_files


def load_dataframe_from_file(file_path, file_format="auto", verbose=False):
    """Load DataFrame from various file formats"""
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return None

    # Auto-detect format from file extension
    if file_format == "auto":
        extension = Path(file_path).suffix.lower()
        format_mapping = {
            ".csv": "csv",
            ".json": "json",
            ".xlsx": "excel",
            ".xls": "excel",
            ".parquet": "parquet",
            ".pq": "parquet",
        }
        file_format = format_mapping.get(extension)

        if not file_format:
            print_error(f"Cannot auto-detect format for file: {file_path}")
            print_info("Supported extensions: .csv, .json, .xlsx, .xls, .parquet, .pq")
            return None

        if verbose:
            print_info(f"Auto-detected format: {file_format}")

    try:
        if verbose:
            print_info(f"Loading data from {file_path} as {file_format.upper()}")

        if file_format == "csv":
            df = pd.read_csv(file_path)
        elif file_format == "json":
            df = pd.read_json(file_path)
        elif file_format == "excel":
            df = pd.read_excel(file_path)
        elif file_format == "parquet":
            df = pd.read_parquet(file_path)
        else:
            print_error(f"Unsupported file format: {file_format}")
            return None

        if df.empty:
            print_warning("Loaded file is empty")
            return None

        if verbose:
            print_success(f"Successfully loaded {len(df)} records from {file_path}")
            print_info(f"Columns: {', '.join(df.columns.tolist())}")

        return df

    except Exception as e:
        print_error(f"Failed to load file {file_path}: {str(e)}")
        return None


def validate_loaded_dataframe(df, verbose=False):
    """Validate that the loaded DataFrame has the required columns for IP analysis"""
    required_columns = ["ipAddress", "abuseConfidenceScore"]
    optional_columns = [
        "countryCode",
        "isWhitelisted",
        "isTor",
        "isPublic",
        "risk_level",
    ]

    missing_required = [col for col in required_columns if col not in df.columns]

    if missing_required:
        print_error(f"Missing required columns: {', '.join(missing_required)}")
        print_info(f"Available columns: {', '.join(df.columns.tolist())}")
        return False

    missing_optional = [col for col in optional_columns if col not in df.columns]

    if verbose:
        print_success("Required columns found")
        if missing_optional:
            print_warning(f"Missing optional columns: {', '.join(missing_optional)}")
            print_info("Missing columns will be handled automatically")

    return True
