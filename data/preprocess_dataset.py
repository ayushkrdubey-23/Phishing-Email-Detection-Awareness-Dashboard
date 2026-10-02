from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Dict, List


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from backend.services.preprocessor import (  # noqa: E402
    REQUIRED_COLUMNS,
    preprocess_records,
)


# ============================================================
# FILE PATHS
# ============================================================

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "phishing_email_dataset.csv"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed_phishing_email_dataset.csv"
)


# ============================================================
# LOAD CSV
# ============================================================

def load_csv(
    file_path: Path,
) -> List[Dict[str, str]]:
    """
    Load a CSV file into a list of dictionaries.
    """

    if not file_path.exists():
        raise FileNotFoundError(
            f"Input dataset not found: {file_path}"
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
                "CSV file does not contain a header row."
            )

        missing_columns = [
            column
            for column in REQUIRED_COLUMNS
            if column not in reader.fieldnames
        ]

        if missing_columns:
            raise ValueError(
                "Input dataset is missing required columns: "
                f"{missing_columns}"
            )

        return list(reader)


# ============================================================
# SAVE CSV
# ============================================================

def save_csv(
    records: List[Dict[str, str]],
    file_path: Path,
) -> None:
    """
    Save processed records to a CSV file.
    """

    if not records:
        raise ValueError(
            "Cannot save an empty processed dataset."
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
        writer.writerows(records)


# ============================================================
# DATASET SUMMARY
# ============================================================

def calculate_label_counts(
    records: List[Dict[str, str]],
) -> Dict[str, int]:
    """
    Count records by label.
    """

    counts: Dict[str, int] = {}

    for record in records:
        label = record.get(
            "label",
            "",
        )

        counts[label] = (
            counts.get(label, 0) + 1
        )

    return counts


def print_summary(
    original_count: int,
    processed_records: List[Dict[str, str]],
    duplicate_count: int,
) -> None:
    """
    Print preprocessing summary.
    """

    label_counts = calculate_label_counts(
        processed_records
    )

    with_url_data = sum(
        int(
            record.get(
                "url_count_preprocessed",
                "0",
            )
        ) > 0
        for record in processed_records
    )

    with_attachment = sum(
        bool(
            record.get(
                "attachment_extension",
                "",
            )
        )
        for record in processed_records
    )

    suspicious_attachment = sum(
        record.get(
            "suspicious_attachment",
            "False",
        ).lower()
        == "true"
        for record in processed_records
    )

    keyword_matches = sum(
        record.get(
            "has_keyword_match",
            "False",
        ).lower()
        == "true"
        for record in processed_records
    )

    print()
    print("=" * 70)
    print("DATA PREPROCESSING COMPLETED")
    print("=" * 70)

    print(
        f"Original records          : {original_count}"
    )

    print(
        f"Duplicates removed       : {duplicate_count}"
    )

    print(
        f"Processed records        : {len(processed_records)}"
    )

    print(
        f"LEGITIMATE               : "
        f"{label_counts.get('LEGITIMATE', 0)}"
    )

    print(
        f"PHISHING                 : "
        f"{label_counts.get('PHISHING', 0)}"
    )

    print(
        f"Records with extracted URL: "
        f"{with_url_data}"
    )

    print(
        f"Records with attachment  : "
        f"{with_attachment}"
    )

    print(
        f"Suspicious attachments   : "
        f"{suspicious_attachment}"
    )

    print(
        f"Records with keywords    : "
        f"{keyword_matches}"
    )

    print()
    print(
        f"Processed dataset saved to:\n{OUTPUT_PATH}"
    )

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Main preprocessing workflow.
    """

    print(
        "Loading synthetic email dataset..."
    )

    records = load_csv(
        INPUT_PATH
    )

    print(
        f"Loaded {len(records)} records."
    )

    processed_records, duplicate_count = (
        preprocess_records(records)
    )

    if len(processed_records) == 0:
        raise RuntimeError(
            "Preprocessing produced zero records."
        )

    save_csv(
        processed_records,
        OUTPUT_PATH,
    )

    print_summary(
        original_count=len(records),
        processed_records=processed_records,
        duplicate_count=duplicate_count,
    )


if __name__ == "__main__":
    main()
    