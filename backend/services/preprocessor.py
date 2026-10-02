from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


# ============================================================
# REQUIRED DATASET COLUMNS
# ============================================================

REQUIRED_COLUMNS = [
    "email_id",
    "sender",
    "sender_domain",
    "subject",
    "body",
    "urls",
    "attachment_name",
    "label",
]


# ============================================================
# SAFE EMAIL / URL PATTERNS
# ============================================================

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
)

URL_PATTERN = re.compile(
    r"(?i)\b(?:https?://|ftp://|www\.)[^\s<>\"]+"
)


# ============================================================
# SECURITY-SENSITIVE KEYWORD CATEGORIES
# ============================================================

KEYWORD_PATTERNS: Dict[str, List[str]] = {
    "urgency": [
        "urgent",
        "immediately",
        "immediate",
        "act now",
        "right away",
        "as soon as possible",
        "today",
        "within 24 hours",
        "do not delay",
        "deadline",
    ],
    "credential": [
        "password",
        "passcode",
        "login",
        "log in",
        "sign in",
        "credentials",
        "one-time password",
        "otp",
        "verification code",
        "security code",
        "authenticate",
    ],
    "financial": [
        "payment",
        "invoice",
        "billing",
        "bank",
        "account number",
        "card number",
        "outstanding",
        "refund",
        "transaction",
        "money",
        "financial",
    ],
    "threat": [
        "suspended",
        "suspension",
        "blocked",
        "restrict",
        "restricted",
        "penalty",
        "terminate",
        "termination",
        "locked",
        "lockout",
    ],
    "personal_information": [
        "personal details",
        "personal information",
        "identity",
        "date of birth",
        "address",
        "phone number",
        "contact details",
        "employee details",
    ],
    "reward": [
        "won",
        "winner",
        "prize",
        "reward",
        "gift",
        "bonus",
        "claim",
        "congratulations",
    ],
    "verification": [
        "verify",
        "verification",
        "confirm",
        "confirmation",
        "validate",
        "validation",
        "review your details",
    ],
}


# ============================================================
# ATTACHMENT EXTENSIONS
# ============================================================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".msi",
    ".com",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".psm1",
}

SUSPICIOUS_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
}

ALL_SUSPICIOUS_EXTENSIONS = (
    EXECUTABLE_EXTENSIONS
    | SCRIPT_EXTENSIONS
    | SUSPICIOUS_ARCHIVE_EXTENSIONS
)


# ============================================================
# TEXT CLEANING
# ============================================================

def safe_text(value: object) -> str:
    """
    Convert any incoming value into a safe string.

    Missing values such as None are converted to an empty string.
    """

    if value is None:
        return ""

    return str(value).strip()


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode characters while preserving meaningful text.

    This does NOT remove punctuation or cybersecurity indicators.
    """

    text = safe_text(text)

    return unicodedata.normalize(
        "NFKC",
        text,
    )


def normalize_whitespace(text: str) -> str:
    """
    Normalize repeated whitespace without removing punctuation.
    """

    text = normalize_unicode(text)

    # Replace tabs and repeated spaces while preserving line meaning.
    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    # Normalize excessive blank lines.
    text = re.sub(
        r"\n{3,}",
        "\n\n",
        text,
    )

    return text.strip()


def normalize_text_for_matching(text: str) -> str:
    """
    Prepare text for keyword matching.

    Important:
    - Original text is preserved separately.
    - Lowercasing is used only for analysis/matching.
    - Punctuation is intentionally preserved.
    """

    text = normalize_whitespace(text)

    return text.lower()


# ============================================================
# MISSING VALUE HANDLING
# ============================================================

def fill_missing_values(
    record: Dict[str, object],
) -> Dict[str, str]:
    """
    Fill missing required fields with safe empty strings.

    The function creates a fresh dictionary and does not mutate
    the caller's original record.
    """

    cleaned: Dict[str, str] = {}

    for column in REQUIRED_COLUMNS:
        cleaned[column] = safe_text(
            record.get(column, "")
        )

    return cleaned


# ============================================================
# DUPLICATE DETECTION
# ============================================================

def build_duplicate_key(
    record: Dict[str, str],
) -> Tuple[str, ...]:
    """
    Build a deterministic key used for duplicate removal.

    Email ID is intentionally excluded because a duplicated email
    with a different synthetic ID should still be recognized as a
    duplicate based on its actual content.
    """

    return tuple(
        record.get(column, "").strip().lower()
        for column in REQUIRED_COLUMNS
        if column != "email_id"
    )


def remove_duplicates(
    records: Iterable[Dict[str, object]],
) -> Tuple[List[Dict[str, str]], int]:
    """
    Remove exact duplicate email records.

    Returns:
        (unique_records, duplicate_count)
    """

    unique_records: List[Dict[str, str]] = []
    seen_keys = set()
    duplicate_count = 0

    for record in records:
        cleaned = fill_missing_values(record)

        duplicate_key = build_duplicate_key(
            cleaned
        )

        if duplicate_key in seen_keys:
            duplicate_count += 1
            continue

        seen_keys.add(duplicate_key)
        unique_records.append(cleaned)

    return unique_records, duplicate_count


# ============================================================
# SENDER DOMAIN EXTRACTION
# ============================================================

def extract_email_address(
    sender: str,
) -> str:
    """
    Extract an email address from a sender value.

    Supports simple forms such as:
        user@example.org

    and display-name forms such as:
        Security Team <user@example.org>
    """

    sender = safe_text(sender)

    match = EMAIL_PATTERN.search(sender)

    if match:
        return match.group(0).lower()

    return sender.lower()


def extract_sender_domain(
    sender: str,
) -> str:
    """
    Extract the domain from a sender email address.
    """

    email_address = extract_email_address(
        sender
    )

    if "@" not in email_address:
        return ""

    domain = email_address.split(
        "@",
        1,
    )[1]

    return domain.lower().strip()


def extract_sender_local_part(
    sender: str,
) -> str:
    """
    Extract the part before @ from a sender address.
    """

    email_address = extract_email_address(
        sender
    )

    if "@" not in email_address:
        return ""

    return email_address.split(
        "@",
        1,
    )[0].lower().strip()


# ============================================================
# URL EXTRACTION
# ============================================================

def clean_extracted_url(url: str) -> str:
    """
    Remove common sentence punctuation from the end of a URL.

    This performs string cleanup only and never opens the URL.
    """

    url = safe_text(url)

    return url.rstrip(
        ".,;:!?)]}>\"'"
    )


def extract_urls_from_text(
    text: str,
) -> List[str]:
    """
    Extract URLs from a text string using static pattern matching.

    No network request is performed.
    """

    text = safe_text(text)

    matches = URL_PATTERN.findall(text)

    cleaned_urls = [
        clean_extracted_url(url)
        for url in matches
    ]

    # Remove empty values while preserving order.
    result: List[str] = []
    seen = set()

    for url in cleaned_urls:
        if not url:
            continue

        normalized = url.lower()

        if normalized not in seen:
            seen.add(normalized)
            result.append(url)

    return result


def parse_existing_urls(
    urls_field: str,
) -> List[str]:
    """
    Parse URLs already present in the CSV urls field.

    The project dataset uses semicolon-separated URLs.
    """

    urls_field = safe_text(urls_field)

    if not urls_field:
        return []

    candidates = re.split(
        r"[;\n]+",
        urls_field,
    )

    result: List[str] = []
    seen = set()

    for candidate in candidates:
        candidate = clean_extracted_url(
            candidate.strip()
        )

        if not candidate:
            continue

        normalized = candidate.lower()

        if normalized not in seen:
            seen.add(normalized)
            result.append(candidate)

    return result


def extract_all_urls(
    subject: str,
    body: str,
    urls_field: str,
) -> List[str]:
    """
    Combine URLs from:
    - Subject
    - Body
    - Existing URL field

    Duplicate URLs are removed.
    """

    candidates: List[str] = []

    candidates.extend(
        parse_existing_urls(urls_field)
    )

    candidates.extend(
        extract_urls_from_text(subject)
    )

    candidates.extend(
        extract_urls_from_text(body)
    )

    result: List[str] = []
    seen = set()

    for url in candidates:
        normalized = url.lower()

        if normalized not in seen:
            seen.add(normalized)
            result.append(url)

    return result


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

def extract_attachment_extensions(
    attachment_name: str,
) -> List[str]:
    """
    Extract all filename extensions.

    Example:
        invoice.pdf.exe
        -> [".pdf", ".exe"]

    This is filename analysis only.
    """

    attachment_name = safe_text(
        attachment_name
    )

    if not attachment_name:
        return []

    # Only analyze the basename.
    filename = Path(
        attachment_name
    ).name.lower()

    parts = filename.split(".")

    # No extension.
    if len(parts) <= 1:
        return []

    extensions: List[str] = []

    for part in parts[1:]:
        if part:
            extensions.append(
                f".{part}"
            )

    return extensions


def get_primary_attachment_extension(
    attachment_name: str,
) -> str:
    """
    Return the final/primary extension.

    Example:
        invoice.pdf.exe -> .exe
    """

    extensions = extract_attachment_extensions(
        attachment_name
    )

    if not extensions:
        return ""

    return extensions[-1]


def has_double_extension(
    attachment_name: str,
) -> bool:
    """
    Determine whether a filename contains two or more extensions.
    """

    return len(
        extract_attachment_extensions(
            attachment_name
        )
    ) >= 2


def is_suspicious_attachment(
    attachment_name: str,
) -> bool:
    """
    Perform safe static filename analysis.

    Returns True when the filename contains an executable,
    script, or suspicious archive extension, or uses a double
    extension pattern.
    """

    extensions = extract_attachment_extensions(
        attachment_name
    )

    if not extensions:
        return False

    if any(
        extension in ALL_SUSPICIOUS_EXTENSIONS
        for extension in extensions
    ):
        return True

    return has_double_extension(
        attachment_name
    )


# ============================================================
# KEYWORD DETECTION
# ============================================================

def find_keyword_matches(
    text: str,
) -> Dict[str, List[str]]:
    """
    Detect cybersecurity-relevant keyword patterns.

    Matching is case-insensitive.

    The function returns the actual matched phrases so later
    explainability features can tell the user why a message
    received a finding.
    """

    normalized_text = normalize_text_for_matching(
        text
    )

    findings: Dict[str, List[str]] = {}

    for category, keywords in KEYWORD_PATTERNS.items():
        matches: List[str] = []

        for keyword in keywords:
            pattern = re.escape(
                keyword.lower()
            )

            # Word boundaries are used for simple terms.
            # Longer phrases are matched safely as literal text.
            if re.search(
                rf"\b{pattern}\b",
                normalized_text,
            ):
                matches.append(keyword)

        if matches:
            findings[category] = matches

    return findings


def serialize_keyword_matches(
    matches: Dict[str, List[str]],
) -> str:
    """
    Convert keyword findings to JSON for storage in CSV.

    JSON is used so the structured information can be parsed
    again later by the backend or ML pipeline.
    """

    return json.dumps(
        matches,
        ensure_ascii=False,
        sort_keys=True,
    )


# ============================================================
# EMAIL RECORD PREPROCESSING
# ============================================================

def preprocess_record(
    record: Dict[str, object],
) -> Dict[str, str]:
    """
    Preprocess one email record while preserving original evidence.

    Original values remain available.
    Additional analysis columns are appended.
    """

    cleaned = fill_missing_values(
        record
    )

    # Preserve raw-looking values while preparing normalized copies.
    normalized_subject = normalize_whitespace(
        cleaned["subject"]
    )

    normalized_body = normalize_whitespace(
        cleaned["body"]
    )

    matching_text = (
        f"{normalized_subject}\n{normalized_body}"
    )

    # Sender analysis.
    extracted_email = extract_email_address(
        cleaned["sender"]
    )

    extracted_domain = extract_sender_domain(
        cleaned["sender"]
    )

    local_part = extract_sender_local_part(
        cleaned["sender"]
    )

    # URL extraction.
    extracted_urls = extract_all_urls(
        normalized_subject,
        normalized_body,
        cleaned["urls"],
    )

    # Attachment extraction.
    attachment_extensions = (
        extract_attachment_extensions(
            cleaned["attachment_name"]
        )
    )

    primary_extension = (
        get_primary_attachment_extension(
            cleaned["attachment_name"]
        )
    )

    double_extension = has_double_extension(
        cleaned["attachment_name"]
    )

    suspicious_attachment = (
        is_suspicious_attachment(
            cleaned["attachment_name"]
        )
    )

    # Keyword detection.
    keyword_matches = find_keyword_matches(
        matching_text
    )

    # Create output record.
    processed = dict(cleaned)

    processed.update(
        {
            "normalized_subject": normalized_subject,
            "normalized_body": normalized_body,
            "sender_email_extracted": extracted_email,
            "sender_domain_extracted": extracted_domain,
            "sender_local_part": local_part,
            "extracted_urls": json.dumps(
                extracted_urls,
                ensure_ascii=False,
            ),
            "url_count_preprocessed": str(
                len(extracted_urls)
            ),
            "attachment_extension": primary_extension,
            "attachment_extensions": ",".join(
                attachment_extensions
            ),
            "double_extension": str(
                double_extension
            ),
            "suspicious_attachment": str(
                suspicious_attachment
            ),
            "keyword_hits_json": serialize_keyword_matches(
                keyword_matches
            ),
            "keyword_category_count": str(
                len(keyword_matches)
            ),
            "has_keyword_match": str(
                bool(keyword_matches)
            ),
        }
    )

    return processed


def preprocess_records(
    records: Iterable[Dict[str, object]],
) -> Tuple[List[Dict[str, str]], int]:
    """
    Preprocess a collection of email records.

    Processing order:
        1. Missing values
        2. Duplicate removal
        3. Record preprocessing

    Returns:
        (processed_records, duplicate_count)
    """

    unique_records, duplicate_count = (
        remove_duplicates(records)
    )

    processed_records = [
        preprocess_record(record)
        for record in unique_records
    ]

    return (
        processed_records,
        duplicate_count,
    )
