from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Dict, List


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from backend.services.feature_engineering import (  # noqa: E402
    REQUIRED_FEATURE_NAMES,
    extract_email_features,
    validate_feature_dictionary,
)


# ============================================================
# FILE PATHS
# ============================================================

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed_phishing_email_dataset.csv"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "feature_engineered_dataset.csv"
)


# ============================================================
# CSV HELPERS
# ============================================================

def load_csv(
    file_path: Path,
) -> List[Dict[str, str]]:
    """
    Load a CSV file into dictionaries.
    """

    if not file_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {file_path}"
        )

    with file_path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as csv_file:

        reader = csv.DictReader(
            csv_file
        )

        if reader.fieldnames is None:
            raise ValueError(
                "CSV file does not contain a header."
            )

        return list(
            reader
        )


def save_csv(
    records: List[Dict[str, object]],
    file_path: Path,
) -> None:
    """
    Save records to CSV.
    """

    if not records:
        raise ValueError(
            "Cannot save an empty feature dataset."
        )

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = list(
        records[0].keys()
    )

    with file_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(
            records
        )


# ============================================================
# BOOLEAN SERIALIZATION
# ============================================================

def csv_value(
    value: object,
) -> object:
    """
    Convert booleans to CSV-friendly TRUE/FALSE strings.

    Other values are returned unchanged.
    """

    if isinstance(
        value,
        bool,
    ):
        return "TRUE" if value else "FALSE"

    return value


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def build_feature_records(
    records: List[Dict[str, str]],
) -> List[Dict[str, object]]:
    """
    Add all required project features to every email record.
    """

    feature_records: List[
        Dict[str, object]
    ] = []

    for record in records:
        features = extract_email_features(
            record
        )

        validate_feature_dictionary(
            features
        )

        enriched = dict(
            record
        )

        for name in REQUIRED_FEATURE_NAMES:
            enriched[name] = csv_value(
                features[name]
            )

        feature_records.append(
            enriched
        )

    return feature_records


# ============================================================
# STATISTICS
# ============================================================

def calculate_feature_statistics(
    records: List[Dict[str, object]],
) -> None:
    """
    Print basic statistics for important features.
    """

    def count_true(
        feature_name: str,
    ) -> int:
        return sum(
            str(
                record.get(
                    feature_name,
                    "",
                )
            ).upper()
            == "TRUE"
            for record in records
        )

    print()
    print("=" * 72)
    print("FEATURE ENGINEERING SUMMARY")
    print("=" * 72)

    print(
        f"Total feature records       : {len(records)}"
    )

    print(
        f"Required features generated : "
        f"{len(REQUIRED_FEATURE_NAMES)}"
    )

    print()
    print("Boolean feature counts:")
    print(
        "  has_ip_url                : "
        f"{count_true('has_ip_url')}"
    )
    print(
        "  has_shortened_url_pattern : "
        f"{count_true('has_shortened_url_pattern')}"
    )
    print(
        "  suspicious_attachment     : "
        f"{count_true('suspicious_attachment')}"
    )
    print(
        "  generic_greeting          : "
        f"{count_true('generic_greeting')}"
    )
    print(
        "  contains_password_request : "
        f"{count_true('contains_password_request')}"
    )
    print(
        "  contains_personal_info_request: "
        f"{count_true('contains_personal_info_request')}"
    )

    print()
    print(
        "Feature engineering completed successfully."
    )

    print("=" * 72)


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Main feature-engineering workflow.
    """

    print(
        "Loading processed phishing email dataset..."
    )

    records = load_csv(
        INPUT_PATH
    )

    if not records:
        raise RuntimeError(
            "Input dataset is empty."
        )

    print(
        f"Loaded {len(records)} records."
    )

    print(
        "Extracting structured phishing features..."
    )

    feature_records = build_feature_records(
        records
    )

    save_csv(
        feature_records,
        OUTPUT_PATH,
    )

    calculate_feature_statistics(
        feature_records
    )

    print()
    print(
        f"Feature-engineered dataset saved to:\n"
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()