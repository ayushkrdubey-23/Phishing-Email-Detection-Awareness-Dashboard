from __future__ import annotations

import ipaddress
import json
import re
from typing import Dict, List
from urllib.parse import urlsplit

from backend.services.preprocessor import (
    KEYWORD_PATTERNS,
    extract_all_urls,
    extract_sender_domain,
    is_suspicious_attachment,
    normalize_whitespace,
    safe_text,
)


# ============================================================
# URL ANALYSIS CONSTANTS
# ============================================================

# Common URL-shortening hostnames.
# These are checked statically; no network request is made.
SHORTENER_HOSTNAMES = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "tiny.cc",
    "shorturl.at",
    "lnkd.in",
}


# URL terms that can be associated with social-engineering
# or account/financial actions.
SUSPICIOUS_URL_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "confirm",
    "account",
    "password",
    "reset",
    "billing",
    "payment",
    "invoice",
    "reward",
    "prize",
    "security",
}


# ============================================================
# GENERIC GREETING PATTERNS
# ============================================================

GENERIC_GREETING_PATTERNS = [
    r"\bdear\s+customer\b",
    r"\bdear\s+user\b",
    r"\bdear\s+valued\s+customer\b",
    r"\bdear\s+valued\s+user\b",
    r"\bhello\s+customer\b",
    r"\bhello\s+user\b",
    r"\bhi\s+customer\b",
    r"\bhi\s+user\b",
    r"\bdear\s+account\s+holder\b",
]


# ============================================================
# REQUEST PATTERNS
# ============================================================

PASSWORD_REQUEST_PATTERNS = [
    r"\b(?:verify|confirm|provide|share|send|enter|submit|update|type)\b"
    r".{0,80}"
    r"\b(?:password|passcode|otp|one[- ]time password|verification code|credentials)\b",

    r"\b(?:password|passcode|otp|one[- ]time password|verification code|credentials)\b"
    r".{0,80}"
    r"\b(?:verify|confirm|provide|share|send|enter|submit|update|type)\b",
]


PERSONAL_INFO_REQUEST_PATTERNS = [
    r"\b(?:verify|confirm|provide|share|send|enter|submit|update)\b"
    r".{0,80}"
    r"\b(?:personal information|personal details|identity|address|phone number|contact details|date of birth)\b",

    r"\b(?:personal information|personal details|identity|address|phone number|contact details|date of birth)\b"
    r".{0,80}"
    r"\b(?:verify|confirm|provide|share|send|enter|submit|update)\b",
]


# ============================================================
# LOW-LEVEL URL HELPERS
# ============================================================

def prepare_url(url: str) -> str:
    """
    Prepare a URL for static parsing.

    No network connection is made.

    www.example.org/path
        -> http://www.example.org/path

    https://example.org/path
        -> unchanged
    """

    url = safe_text(url)

    if not url:
        return ""

    if url.lower().startswith("www."):
        return f"http://{url}"

    return url


def get_hostname(url: str) -> str:
    """
    Extract hostname from a URL safely.
    """

    prepared_url = prepare_url(url)

    if not prepared_url:
        return ""

    try:
        parsed = urlsplit(
            prepared_url
        )

        return (
            parsed.hostname
            or ""
        ).lower()

    except ValueError:
        return ""


def is_raw_ip_hostname(
    hostname: str,
) -> bool:
    """
    Determine whether a hostname is a raw IPv4/IPv6 address.
    """

    hostname = safe_text(
        hostname
    )

    if not hostname:
        return False

    try:
        ipaddress.ip_address(
            hostname
        )
        return True

    except ValueError:
        return False


def has_shortener_hostname(
    hostname: str,
) -> bool:
    """
    Detect known URL-shortening domains by static hostname comparison.
    """

    hostname = hostname.lower().strip()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return (
        hostname in SHORTENER_HOSTNAMES
    )


def count_subdomains_from_domain(
    domain: str,
) -> int:
    """
    Estimate the number of subdomains.

    This project uses a lightweight heuristic:
        labels - 2

    Examples:
        example.org
            -> 0

        mail.example.org
            -> 1

        secure.mail.example.org
            -> 2

    This is a heuristic rather than a full public-suffix database.
    """

    domain = safe_text(
        domain
    ).lower().strip(
        "."
    )

    if not domain:
        return 0

    labels = [
        label
        for label in domain.split(".")
        if label
    ]

    return max(
        0,
        len(labels) - 2,
    )


def has_unusual_url_characters(
    url: str,
) -> bool:
    """
    Detect a small set of unusual URL characters.

    This is only a feature signal, not a maliciousness verdict.
    """

    url = safe_text(
        url
    )

    if not url:
        return False

    return bool(
        re.search(
            r"[\s<>\"'`\\|{}]",
            url,
        )
    )


def url_has_suspicious_keyword(
    url: str,
) -> bool:
    """
    Detect security-related keywords inside the URL.
    """

    normalized_url = safe_text(
        url
    ).lower()

    return any(
        keyword in normalized_url
        for keyword in SUSPICIOUS_URL_KEYWORDS
    )


def is_suspicious_url_basic(
    url: str,
) -> bool:
    """
    Perform lightweight static URL feature analysis.

    The URL is never opened.

    The URL is considered suspicious for feature-engineering
    purposes when one or more lightweight indicators are present:
        - raw IP hostname
        - non-HTTPS scheme
        - known shortener
        - excessive subdomains
        - suspicious keywords
        - unusual characters
        - unusually long URL
    """

    prepared_url = prepare_url(
        url
    )

    if not prepared_url:
        return False

    try:
        parsed = urlsplit(
            prepared_url
        )

    except ValueError:
        return True

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    if not hostname:
        return True

    indicators = 0

    # Raw IP address.
    if is_raw_ip_hostname(
        hostname
    ):
        indicators += 1

    # Non-HTTPS scheme.
    if parsed.scheme.lower() != "https":
        indicators += 1

    # Known shortening service.
    if has_shortener_hostname(
        hostname
    ):
        indicators += 1

    # Excessive subdomain heuristic.
    if count_subdomains_from_domain(
        hostname
    ) >= 3:
        indicators += 1

    # Security/social-engineering keywords.
    if url_has_suspicious_keyword(
        prepared_url
    ):
        indicators += 1

    # Unusual characters.
    if has_unusual_url_characters(
        prepared_url
    ):
        indicators += 1

    # Long URLs can be a contextual signal.
    if len(prepared_url) > 120:
        indicators += 1

    return indicators > 0


# ============================================================
# KEYWORD COUNTING
# ============================================================

def count_keyword_occurrences(
    text: str,
    keywords: List[str],
) -> int:
    """
    Count case-insensitive occurrences of keyword/phrase patterns.

    Punctuation is not removed because it can itself be useful
    security evidence.

    Returns the total number of keyword occurrences.
    """

    normalized_text = (
        normalize_whitespace(
            text
        ).lower()
    )

    total = 0

    for keyword in keywords:
        escaped_keyword = re.escape(
            keyword.lower()
        )

        matches = re.findall(
            rf"\b{escaped_keyword}\b",
            normalized_text,
        )

        total += len(
            matches
        )

    return total


def count_category_keywords(
    text: str,
    category: str,
) -> int:
    """
    Count occurrences belonging to one security keyword category.
    """

    keywords = KEYWORD_PATTERNS.get(
        category,
        [],
    )

    return count_keyword_occurrences(
        text,
        keywords,
    )


# ============================================================
# BOOLEAN FEATURE HELPERS
# ============================================================

def contains_pattern(
    text: str,
    patterns: List[str],
) -> bool:
    """
    Return True when any supplied regular-expression pattern matches.
    """

    normalized_text = (
        normalize_whitespace(
            text
        ).lower()
    )

    return any(
        re.search(
            pattern,
            normalized_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        for pattern in patterns
    )


def contains_generic_greeting(
    text: str,
) -> bool:
    """
    Detect common generic greetings.
    """

    normalized_text = (
        normalize_whitespace(
            text
        )
    )

    # Only inspect an initial section because greetings normally
    # occur near the beginning of the message.
    first_section = normalized_text[
        :300
    ]

    return contains_pattern(
        first_section,
        GENERIC_GREETING_PATTERNS,
    )


def calculate_uppercase_ratio(
    text: str,
) -> float:
    """
    Calculate the ratio of uppercase alphabetic characters.

    Formula:
        uppercase letters / total alphabetic letters

    Returns a value from 0.0 to 1.0.
    """

    text = safe_text(
        text
    )

    alphabetic_characters = [
        character
        for character in text
        if character.isalpha()
    ]

    if not alphabetic_characters:
        return 0.0

    uppercase_characters = [
        character
        for character in alphabetic_characters
        if character.isupper()
    ]

    return round(
        len(uppercase_characters)
        / len(alphabetic_characters),
        4,
    )


def contains_raw_ip_url(
    urls: List[str],
) -> bool:
    """
    Return True when at least one extracted URL uses a raw IP address.
    """

    for url in urls:
        hostname = get_hostname(
            url
        )

        if is_raw_ip_hostname(
            hostname
        ):
            return True

    return False


def contains_shortened_url(
    urls: List[str],
) -> bool:
    """
    Return True when at least one URL uses a known shortener.
    """

    for url in urls:
        hostname = get_hostname(
            url
        )

        if has_shortener_hostname(
            hostname
        ):
            return True

    return False


def count_suspicious_urls(
    urls: List[str],
) -> int:
    """
    Count URLs that trigger at least one lightweight
    suspicious-URL feature.
    """

    return sum(
        is_suspicious_url_basic(
            url
        )
        for url in urls
    )


# ============================================================
# MAIN FEATURE EXTRACTION FUNCTION
# ============================================================

def extract_email_features(
    email: Dict[str, object],
) -> Dict[str, object]:
    """
    Extract structured phishing-related features from one email.

    Required features from the project prompt are included.

    Returns:
        A feature dictionary suitable for:
        - rule-based scoring
        - ML input preparation
        - dashboard analytics
        - explainable findings
    """

    sender = safe_text(
        email.get(
            "sender",
            "",
        )
    )

    sender_domain = safe_text(
        email.get(
            "sender_domain",
            "",
        )
    )

    subject = normalize_whitespace(
        safe_text(
            email.get(
                "subject",
                "",
            )
        )
    )

    body = normalize_whitespace(
        safe_text(
            email.get(
                "body",
                "",
            )
        )
    )

    urls_field = safe_text(
        email.get(
            "urls",
            "",
        )
    )

    attachment_name = safe_text(
        email.get(
            "attachment_name",
            "",
        )
    )

    # Combine subject + body for language-related analysis.
    analysis_text = (
        f"{subject}\n{body}"
    )

    # Prefer an existing sender-domain value when available;
    # otherwise derive it from the sender address.
    extracted_domain = (
        sender_domain.lower().strip()
        if sender_domain
        else extract_sender_domain(
            sender
        )
    )

    # Extract URLs without visiting them.
    urls = extract_all_urls(
        subject,
        body,
        urls_field,
    )

    # Keyword counts.
    urgent_keyword_count = (
        count_category_keywords(
            analysis_text,
            "urgency",
        )
    )

    credential_keyword_count = (
        count_category_keywords(
            analysis_text,
            "credential",
        )
    )

    financial_keyword_count = (
        count_category_keywords(
            analysis_text,
            "financial",
        )
    )

    threat_keyword_count = (
        count_category_keywords(
            analysis_text,
            "threat",
        )
    )

    # URL-related features.
    url_count = len(
        urls
    )

    suspicious_url_count = (
        count_suspicious_urls(
            urls
        )
    )

    has_ip_url = contains_raw_ip_url(
        urls
    )

    has_shortened_url_pattern = (
        contains_shortened_url(
            urls
        )
    )

    # Sender features.
    sender_domain_length = len(
        extracted_domain
    )

    subdomain_count = (
        count_subdomains_from_domain(
            extracted_domain
        )
    )

    # Attachment feature.
    suspicious_attachment = (
        is_suspicious_attachment(
            attachment_name
        )
    )

    # Language/formatting features.
    generic_greeting = (
        contains_generic_greeting(
            body
        )
    )

    contains_password_request = (
        contains_pattern(
            analysis_text,
            PASSWORD_REQUEST_PATTERNS,
        )
    )

    contains_personal_info_request = (
        contains_pattern(
            analysis_text,
            PERSONAL_INFO_REQUEST_PATTERNS,
        )
    )

    exclamation_count = (
        analysis_text.count("!")
    )

    uppercase_ratio = (
        calculate_uppercase_ratio(
            subject + "\n" + body
        )
    )

    body_length = len(
        body
    )

    subject_length = len(
        subject
    )

    # Required structured feature dictionary.
    features: Dict[str, object] = {
        "urgent_keyword_count": urgent_keyword_count,
        "credential_keyword_count": credential_keyword_count,
        "financial_keyword_count": financial_keyword_count,
        "threat_keyword_count": threat_keyword_count,
        "url_count": url_count,
        "suspicious_url_count": suspicious_url_count,
        "has_ip_url": has_ip_url,
        "has_shortened_url_pattern": has_shortened_url_pattern,
        "sender_domain_length": sender_domain_length,
        "subdomain_count": subdomain_count,
        "suspicious_attachment": suspicious_attachment,
        "generic_greeting": generic_greeting,
        "contains_password_request": contains_password_request,
        "contains_personal_info_request": contains_personal_info_request,
        "exclamation_count": exclamation_count,
        "uppercase_ratio": uppercase_ratio,
        "body_length": body_length,
        "subject_length": subject_length,
    }

    return features


# ============================================================
# SERIALIZATION HELPER
# ============================================================

def serialize_features(
    features: Dict[str, object],
) -> str:
    """
    Convert feature dictionary to readable JSON.

    This is useful when storing all features in one dataset column
    or exposing them in an API response.
    """

    return json.dumps(
        features,
        ensure_ascii=False,
        sort_keys=True,
    )


# ============================================================
# FEATURE VALIDATION
# ============================================================

REQUIRED_FEATURE_NAMES = [
    "urgent_keyword_count",
    "credential_keyword_count",
    "financial_keyword_count",
    "threat_keyword_count",
    "url_count",
    "suspicious_url_count",
    "has_ip_url",
    "has_shortened_url_pattern",
    "sender_domain_length",
    "subdomain_count",
    "suspicious_attachment",
    "generic_greeting",
    "contains_password_request",
    "contains_personal_info_request",
    "exclamation_count",
    "uppercase_ratio",
    "body_length",
    "subject_length",
]


def validate_feature_dictionary(
    features: Dict[str, object],
) -> None:
    """
    Verify that every required project feature exists.
    """

    missing = [
        feature
        for feature in REQUIRED_FEATURE_NAMES
        if feature not in features
    ]

    if missing:
        raise ValueError(
            "Missing required features: "
            f"{missing}"
        )

    # Basic numerical sanity checks.
    non_negative_features = [
        "urgent_keyword_count",
        "credential_keyword_count",
        "financial_keyword_count",
        "threat_keyword_count",
        "url_count",
        "suspicious_url_count",
        "sender_domain_length",
        "subdomain_count",
        "exclamation_count",
        "body_length",
        "subject_length",
    ]

    for feature in non_negative_features:
        value = features[
            feature
        ]

        if not isinstance(
            value,
            int,
        ):
            raise TypeError(
                f"{feature} must be an integer."
            )

        if value < 0:
            raise ValueError(
                f"{feature} cannot be negative."
            )

    uppercase_ratio = features[
        "uppercase_ratio"
    ]

    if not isinstance(
        uppercase_ratio,
        float,
    ):
        raise TypeError(
            "uppercase_ratio must be a float."
        )

    if not 0.0 <= uppercase_ratio <= 1.0:
        raise ValueError(
            "uppercase_ratio must be between 0.0 and 1.0."
        )