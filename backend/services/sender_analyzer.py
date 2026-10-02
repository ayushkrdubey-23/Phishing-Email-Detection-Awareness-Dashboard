from __future__ import annotations

import re
from typing import Dict, List, Optional

from backend.services.preprocessor import (
    EMAIL_PATTERN,
    extract_email_address,
    extract_sender_domain,
    extract_sender_local_part,
)


# ============================================================
# CONSTANTS
# ============================================================

# Maximum score returned by this module.
MAX_SENDER_RISK_SCORE = 100


# Characters that are unusual enough to deserve a finding
# during static sender analysis.
UNUSUAL_LOCAL_PART_PATTERN = re.compile(
    r"[^A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]"
)

UNUSUAL_DOMAIN_PATTERN = re.compile(
    r"[^A-Za-z0-9.-]"
)


# Common words frequently used in generic display names.
# These are deliberately treated as neutral words so that
# "Security Team", "Account Support", etc. do not automatically
# create a mismatch finding.
GENERIC_DISPLAY_WORDS = {
    "account",
    "accounts",
    "admin",
    "administrator",
    "alert",
    "alerts",
    "billing",
    "desk",
    "delivery",
    "department",
    "email",
    "finance",
    "help",
    "human",
    "hr",
    "info",
    "information",
    "mail",
    "notification",
    "notifications",
    "office",
    "request",
    "security",
    "service",
    "services",
    "support",
    "system",
    "systems",
    "team",
    "user",
    "users",
}


# Common top-level domains used by the project's safe
# synthetic examples.
COMMON_SAFE_TLDS = {
    "com",
    "org",
    "net",
    "test",
}


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_text(value: object) -> str:
    """
    Convert an incoming value into a stripped string.
    """

    if value is None:
        return ""

    return str(value).strip()


def clamp_score(
    score: int,
) -> int:
    """
    Keep the sender risk score within 0-100.
    """

    return max(
        0,
        min(
            MAX_SENDER_RISK_SCORE,
            score,
        ),
    )


def add_finding(
    findings: List[Dict[str, object]],
    indicator_type: str,
    description: str,
    severity: str,
    score: int,
) -> None:
    """
    Append one explainable sender finding.
    """

    findings.append(
        {
            "indicator_type": indicator_type,
            "description": description,
            "severity": severity,
            "score_contribution": score,
        }
    )


# ============================================================
# EMAIL FORMAT ANALYSIS
# ============================================================

def is_valid_email_format(
    sender: str,
) -> bool:
    """
    Validate a simple email address format.

    This is format validation only. It does not verify whether
    the mailbox actually exists.
    """

    sender = clean_text(
        sender
    )

    address = extract_email_address(
        sender
    )

    if not address:
        return False

    return bool(
        EMAIL_PATTERN.fullmatch(
            address
        )
    )


# ============================================================
# DOMAIN ANALYSIS
# ============================================================

def split_domain_labels(
    domain: str,
) -> List[str]:
    """
    Split a domain into non-empty labels.
    """

    domain = clean_text(
        domain
    ).lower().strip(
        "."
    )

    if not domain:
        return []

    return [
        label
        for label in domain.split(".")
        if label
    ]


def count_subdomains(
    domain: str,
) -> int:
    """
    Estimate subdomain count using a simple label-count heuristic.

    Example:

        example.org
        -> 0

        mail.example.org
        -> 1

        secure.mail.example.org
        -> 2

    This is intentionally a lightweight heuristic and does not
    use external DNS or public-suffix services.
    """

    labels = split_domain_labels(
        domain
    )

    return max(
        0,
        len(labels) - 2,
    )


def domain_length(
    domain: str,
) -> int:
    """
    Return the number of characters in the sender domain.
    """

    return len(
        clean_text(
            domain
        )
    )


def has_unusual_domain_characters(
    domain: str,
) -> bool:
    """
    Detect characters that are unusual in a normal domain.
    """

    domain = clean_text(
        domain
    )

    if not domain:
        return False

    return bool(
        UNUSUAL_DOMAIN_PATTERN.search(
            domain
        )
    )


def has_unusual_local_part_characters(
    local_part: str,
) -> bool:
    """
    Detect unusual characters in the sender's local part.

    Normal email special characters are allowed by design.
    """

    local_part = clean_text(
        local_part
    )

    if not local_part:
        return False

    return bool(
        UNUSUAL_LOCAL_PART_PATTERN.search(
            local_part
        )
    )


# ============================================================
# LOOKALIKE CHARACTERISTICS
# ============================================================

def is_mixed_alpha_numeric_label(
    label: str,
) -> bool:
    """
    Determine whether a domain label mixes letters and digits.

    A mixed label is not automatically malicious. It becomes a
    useful signal when it looks like a synthetic lookalike pattern.
    """

    label = clean_text(
        label
    ).lower()

    has_letter = bool(
        re.search(
            r"[a-z]",
            label,
        )
    )

    has_digit = bool(
        re.search(
            r"\d",
            label,
        )
    )

    return has_letter and has_digit


def contains_possible_lookalike_pattern(
    domain: str,
) -> bool:
    """
    Detect obvious synthetic lookalike characteristics.

    Examples of characteristics:
    - alphabetic labels containing digits
    - repeated hyphens
    - labels beginning or ending with a hyphen

    This does not attempt to identify real organizations or
    determine whether a domain is malicious.
    """

    labels = split_domain_labels(
        domain
    )

    if not labels:
        return False

    # Skip the final TLD where appropriate.
    candidate_labels = labels[:-1]

    for label in candidate_labels:
        if is_mixed_alpha_numeric_label(
            label
        ):
            return True

        if "--" in label:
            return True

        if label.startswith("-") or label.endswith("-"):
            return True

    return False


# ============================================================
# DISPLAY-NAME ANALYSIS
# ============================================================

def normalize_display_tokens(
    display_name: str,
) -> List[str]:
    """
    Convert a display name into meaningful lowercase tokens.
    """

    display_name = clean_text(
        display_name
    ).lower()

    tokens = re.findall(
        r"[a-z0-9]+",
        display_name,
    )

    return [
        token
        for token in tokens
        if token
        and token not in GENERIC_DISPLAY_WORDS
    ]


def domain_tokens(
    domain: str,
) -> List[str]:
    """
    Extract useful textual tokens from a domain.

    The top-level domain is excluded.
    """

    labels = split_domain_labels(
        domain
    )

    if len(labels) <= 1:
        return labels

    return [
        label
        for label in labels[:-1]
        if label
        and label not in COMMON_SAFE_TLDS
    ]


def display_name_domain_mismatch(
    display_name: Optional[str],
    domain: str,
) -> bool:
    """
    Determine whether a supplied display name has no meaningful
    overlap with the sender domain.

    This check only runs when:
    - display_name is supplied, and
    - meaningful display-name tokens exist.

    Generic role names alone do not trigger the finding.
    """

    if not display_name:
        return False

    display_tokens = normalize_display_tokens(
        display_name
    )

    if not display_tokens:
        return False

    domain_parts = domain_tokens(
        domain
    )

    if not domain_parts:
        return False

    domain_text = " ".join(
        domain_parts
    )

    # A direct token match is considered consistent.
    for token in display_tokens:
        if token in domain_text:
            return False

    return True


# ============================================================
# SENDER ANALYSIS ENGINE
# ============================================================

def analyze_sender(
    sender: str,
    display_name: Optional[str] = None,
) -> Dict[str, object]:
    """
    Analyze a sender email address using static heuristics.

    Parameters
    ----------
    sender:
        Sender email address or a simple display-name/address
        representation.

    display_name:
        Optional display name supplied separately.

    Returns
    -------
    dict
        {
            "sender_risk_score": int,
            "sender_findings": list,
            "sender_email": str,
            "sender_local_part": str,
            "sender_domain": str,
            "domain_length": int,
            "subdomain_count": int,
            "is_valid_format": bool
        }

    Security note:
        This function performs static string analysis only.
        It does not:
        - connect to the domain,
        - perform DNS lookups,
        - send email,
        - check mailbox existence,
        - visit websites.
    """

    sender = clean_text(
        sender
    )

    sender_email = extract_email_address(
        sender
    )

    sender_local_part = (
        extract_sender_local_part(
            sender
        )
    )

    sender_domain = (
        extract_sender_domain(
            sender
        )
    )

    findings: List[
        Dict[str, object]
    ] = []

    risk_score = 0

    # --------------------------------------------------------
    # 1. Sender format
    # --------------------------------------------------------

    valid_format = is_valid_email_format(
        sender
    )

    if not valid_format:
        add_finding(
            findings,
            indicator_type="invalid_sender_format",
            description=(
                "The supplied sender value does not match a "
                "basic email-address format."
            ),
            severity="high",
            score=25,
        )

        risk_score += 25

    # --------------------------------------------------------
    # 2. Missing domain
    # --------------------------------------------------------

    if not sender_domain:
        add_finding(
            findings,
            indicator_type="missing_sender_domain",
            description=(
                "A sender domain could not be extracted from "
                "the supplied sender address."
            ),
            severity="high",
            score=20,
        )

        risk_score += 20

    # --------------------------------------------------------
    # 3. Domain length
    # --------------------------------------------------------

    current_domain_length = domain_length(
        sender_domain
    )

    if current_domain_length >= 40:
        add_finding(
            findings,
            indicator_type="long_sender_domain",
            description=(
                "The sender domain is unusually long and may "
                "deserve additional contextual review."
            ),
            severity="low",
            score=5,
        )

        risk_score += 5

    # --------------------------------------------------------
    # 4. Excessive subdomains
    # --------------------------------------------------------

    current_subdomain_count = count_subdomains(
        sender_domain
    )

    if current_subdomain_count >= 3:
        add_finding(
            findings,
            indicator_type="excessive_subdomains",
            description=(
                "The sender domain contains several nested "
                "subdomains, which is a contextual review signal."
            ),
            severity="medium",
            score=10,
        )

        risk_score += 10

    # --------------------------------------------------------
    # 5. Unusual domain characters
    # --------------------------------------------------------

    if has_unusual_domain_characters(
        sender_domain
    ):
        add_finding(
            findings,
            indicator_type="unusual_domain_characters",
            description=(
                "The sender domain contains characters that are "
                "unusual for a normal domain name."
            ),
            severity="medium",
            score=10,
        )

        risk_score += 10

    # --------------------------------------------------------
    # 6. Unusual local-part characters
    # --------------------------------------------------------

    if has_unusual_local_part_characters(
        sender_local_part
    ):
        add_finding(
            findings,
            indicator_type="unusual_sender_characters",
            description=(
                "The local part of the sender address contains "
                "unusual characters."
            ),
            severity="low",
            score=5,
        )

        risk_score += 5

    # --------------------------------------------------------
    # 7. Possible synthetic lookalike pattern
    # --------------------------------------------------------

    if contains_possible_lookalike_pattern(
        sender_domain
    ):
        add_finding(
            findings,
            indicator_type="possible_lookalike_pattern",
            description=(
                "The sender domain shows an obvious synthetic "
                "lookalike characteristic, such as mixed "
                "letters and digits or repeated separators."
            ),
            severity="medium",
            score=12,
        )

        risk_score += 12

    # --------------------------------------------------------
    # 8. Display-name/domain mismatch
    # --------------------------------------------------------

    if display_name_domain_mismatch(
        display_name,
        sender_domain,
    ):
        add_finding(
            findings,
            indicator_type="display_name_domain_mismatch",
            description=(
                "The supplied display name has no meaningful "
                "textual relationship with the sender domain. "
                "This is a contextual signal and is not proof "
                "of impersonation."
            ),
            severity="medium",
            score=15,
        )

        risk_score += 15

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    risk_score = clamp_score(
        risk_score
    )

    return {
        "sender_risk_score": risk_score,
        "sender_findings": findings,
        "sender_email": sender_email,
        "sender_local_part": sender_local_part,
        "sender_domain": sender_domain,
        "domain_length": current_domain_length,
        "subdomain_count": current_subdomain_count,
        "is_valid_format": valid_format,
    }


# ============================================================
# HUMAN-READABLE FINDINGS
# ============================================================

def format_sender_findings(
    analysis: Dict[str, object],
) -> List[str]:
    """
    Convert structured findings into simple strings suitable
    for a beginner-friendly UI.
    """

    raw_findings = analysis.get(
        "sender_findings",
        [],
    )

    formatted: List[str] = []

    if not isinstance(
        raw_findings,
        list,
    ):
        return formatted

    for finding in raw_findings:
        if not isinstance(
            finding,
            dict,
        ):
            continue

        description = finding.get(
            "description",
            "",
        )

        if description:
            formatted.append(
                str(description)
            )

    return formatted


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Perform basic built-in checks without external dependencies.
    """

    # --------------------------------------------------------
    # Test 1: normal safe sender
    # --------------------------------------------------------

    safe_result = analyze_sender(
        "training@example.org"
    )

    assert (
        safe_result["is_valid_format"] is True
    )

    assert (
        safe_result["sender_domain"]
        == "example.org"
    )

    assert (
        safe_result["sender_risk_score"] == 0
    )

    # --------------------------------------------------------
    # Test 2: excessive subdomains
    # --------------------------------------------------------

    subdomain_result = analyze_sender(
        "alerts@secure.mail.team.example.org"
    )

    assert (
        subdomain_result["subdomain_count"]
        == 3
    )

    assert (
        subdomain_result["sender_risk_score"]
        >= 10
    )

    # --------------------------------------------------------
    # Test 3: mixed alpha-numeric lookalike pattern
    # --------------------------------------------------------

    lookalike_result = analyze_sender(
        "support@examp1e.com"
    )

    assert (
        lookalike_result["sender_risk_score"]
        >= 12
    )

    finding_types = {
        finding["indicator_type"]
        for finding in lookalike_result[
            "sender_findings"
        ]
    }

    assert (
        "possible_lookalike_pattern"
        in finding_types
    )

    # --------------------------------------------------------
    # Test 4: invalid sender
    # --------------------------------------------------------

    invalid_result = analyze_sender(
        "not-a-valid-sender"
    )

    assert (
        invalid_result["is_valid_format"] is False
    )

    assert (
        invalid_result["sender_risk_score"]
        >= 25
    )

    print(
        "Sender analyzer self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()
    