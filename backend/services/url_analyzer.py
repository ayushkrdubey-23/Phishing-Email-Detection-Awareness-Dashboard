from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlsplit


# ============================================================
# CONSTANTS
# ============================================================

MAX_URL_RISK_SCORE = 100

COMMON_URL_SHORTENERS = {
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

SUSPICIOUS_URL_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "confirm",
    "confirmation",
    "account",
    "password",
    "reset",
    "billing",
    "payment",
    "invoice",
    "reward",
    "prize",
    "security",
    "unlock",
    "suspended",
}

SUSPICIOUS_SCHEMES = {
    "http",
    "ftp",
}

ALLOWED_COMMON_SCHEMES = {
    "http",
    "https",
    "ftp",
}

# Characters that deserve static review.
UNUSUAL_CHARACTER_PATTERN = re.compile(
    r"[\s<>\"'`\\|{}]"
)

# Detect strings that look like an email-style userinfo
# component before @ in a URL.
USERINFO_PATTERN = re.compile(
    r"^[^/@]+@"
)


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_url(url: object) -> str:
    """
    Convert an incoming URL into a clean string.

    This does not contact the URL.
    """

    if url is None:
        return ""

    value = str(url).strip()

    # Remove common punctuation accidentally captured
    # from surrounding email sentences.
    value = value.rstrip(
        ".,;:!?)]}>\"'"
    )

    return value


def prepare_url(url: str) -> str:
    """
    Prepare a URL for safe parsing.

    www.example.org/path
        becomes
    http://www.example.org/path

    A URL without a scheme is still parsed as text,
    but the original scheme behavior is tracked separately.
    """

    url = clean_url(url)

    if not url:
        return ""

    if url.lower().startswith("www."):
        return f"http://{url}"

    if "://" not in url:
        return f"http://{url}"

    return url


def clamp_score(score: int) -> int:
    """
    Keep the risk score within 0-100.
    """

    return max(
        0,
        min(
            MAX_URL_RISK_SCORE,
            score,
        ),
    )


def add_finding(
    findings: List[Dict[str, object]],
    indicator_type: str,
    description: str,
    severity: str,
    score_contribution: int,
) -> None:
    """
    Add one structured, explainable URL finding.
    """

    findings.append(
        {
            "indicator_type": indicator_type,
            "description": description,
            "severity": severity,
            "score_contribution": score_contribution,
        }
    )


# ============================================================
# HOSTNAME / IP HELPERS
# ============================================================

def is_raw_ip(hostname: str) -> bool:
    """
    Determine whether a hostname is a raw IPv4 or IPv6 address.
    """

    hostname = str(
        hostname or ""
    ).strip(
        "[]"
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


def split_hostname_labels(
    hostname: str,
) -> List[str]:
    """
    Split hostname into non-empty labels.
    """

    hostname = str(
        hostname or ""
    ).strip(
        "."
    ).lower()

    if not hostname:
        return []

    return [
        label
        for label in hostname.split(".")
        if label
    ]


def count_subdomains(
    hostname: str,
) -> int:
    """
    Estimate subdomain count using:
        number of labels - 2

    Examples:
        example.org
            -> 0

        mail.example.org
            -> 1

        secure.mail.example.org
            -> 2

    This is a lightweight project heuristic, not a full
    public-suffix implementation.
    """

    labels = split_hostname_labels(
        hostname
    )

    if is_raw_ip(hostname):
        return 0

    return max(
        0,
        len(labels) - 2,
    )


# ============================================================
# URL COMPONENT HELPERS
# ============================================================

def extract_url_components(
    url: str,
) -> Dict[str, object]:
    """
    Parse URL components without making a network request.
    """

    original_url = clean_url(
        url
    )

    prepared = prepare_url(
        original_url
    )

    if not prepared:
        return {
            "scheme": "",
            "hostname": "",
            "path": "",
            "query": "",
            "fragment": "",
            "username": "",
            "port": None,
            "query_parameter_count": 0,
        }

    try:
        parsed = urlsplit(
            prepared
        )

        query_parameters = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        return {
            "scheme": parsed.scheme.lower(),
            "hostname": (
                parsed.hostname or ""
            ).lower(),
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "username": parsed.username or "",
            "port": parsed.port,
            "query_parameter_count": len(
                query_parameters
            ),
        }

    except ValueError:
        return {
            "scheme": "",
            "hostname": "",
            "path": "",
            "query": "",
            "fragment": "",
            "username": "",
            "port": None,
            "query_parameter_count": 0,
        }


# ============================================================
# STATIC INDICATOR HELPERS
# ============================================================

def find_suspicious_keywords(
    url: str,
) -> List[str]:
    """
    Find security/social-engineering keywords in the URL.
    """

    normalized = clean_url(
        url
    ).lower()

    matches = []

    for keyword in sorted(
        SUSPICIOUS_URL_KEYWORDS
    ):
        if keyword in normalized:
            matches.append(
                keyword
            )

    return matches


def is_shortened_url(
    hostname: str,
) -> bool:
    """
    Detect known URL-shortening hostnames.

    This is a static hostname comparison only.
    """

    hostname = str(
        hostname or ""
    ).lower().strip(
        "."
    )

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname in COMMON_URL_SHORTENERS


def find_unusual_characters(
    url: str,
) -> List[str]:
    """
    Detect unusual URL characters.

    The returned values are for explanation only.
    """

    url = clean_url(
        url
    )

    matches = sorted(
        set(
            UNUSUAL_CHARACTER_PATTERN.findall(
                url
            )
        )
    )

    return matches


def find_deceptive_structure_indicators(
    url: str,
    hostname: str,
    username: str,
) -> List[str]:
    """
    Detect obvious deceptive URL structures.

    Signals include:
    - userinfo before the hostname
    - hostname labels mixing letters and digits
    - repeated hyphens
    - punycode prefix
    - excessive nested subdomains
    """

    indicators: List[str] = []

    if username:
        indicators.append(
            "userinfo component before hostname"
        )

    # Look for text before the final top-level domain.
    labels = split_hostname_labels(
        hostname
    )

    for label in labels[:-1]:
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

        if (
            has_letter
            and has_digit
        ):
            indicators.append(
                "hostname label mixes letters and digits"
            )
            break

    if any(
        "--" in label
        for label in labels
    ):
        indicators.append(
            "repeated hyphen pattern"
        )

    if any(
        label.startswith("xn--")
        for label in labels
    ):
        indicators.append(
            "punycode-style hostname label"
        )

    if count_subdomains(
        hostname
    ) >= 3:
        indicators.append(
            "excessive nested subdomains"
        )

    return indicators


def displayed_text_mismatch(
    displayed_text: Optional[str],
    hostname: str,
) -> bool:
    """
    Compare optional displayed link text with destination hostname.

    This is only a simple text comparison and should not be
    interpreted as full HTML/email rendering analysis.

    Example:
        displayed_text = "example.org"
        hostname = "account-check.example.net"

    -> True
    """

    if not displayed_text:
        return False

    displayed = str(
        displayed_text
    ).strip().lower()

    hostname = str(
        hostname or ""
    ).strip().lower()

    if not displayed or not hostname:
        return False

    # Remove common prefixes from displayed text.
    displayed = re.sub(
        r"^https?://",
        "",
        displayed,
    )

    displayed = displayed.strip(
        "/"
    )

    # Exact hostname relationship.
    if displayed == hostname:
        return False

    # If the displayed text contains the destination hostname,
    # treat it as consistent.
    if hostname in displayed:
        return False

    return True


def suspicious_scheme(
    scheme: str,
) -> bool:
    """
    Return True for schemes that are less suitable for ordinary
    secure email-link use in this project.
    """

    return (
        scheme.lower()
        in SUSPICIOUS_SCHEMES
    )


# ============================================================
# MAIN URL ANALYSIS ENGINE
# ============================================================

def analyze_url(
    url: str,
    displayed_text: Optional[str] = None,
) -> Dict[str, object]:
    """
    Perform complete static URL risk analysis.

    Parameters
    ----------
    url:
        URL string to analyze.

    displayed_text:
        Optional text that was displayed to the recipient.

    Returns
    -------
    dict
        Structured static URL analysis.

    Security guarantees
    -------------------
    This function NEVER:
    - opens the URL
    - sends an HTTP request
    - performs DNS resolution
    - follows redirects
    - downloads content
    - executes JavaScript
    """

    original_url = clean_url(
        url
    )

    components = extract_url_components(
        original_url
    )

    scheme = str(
        components["scheme"]
    )

    hostname = str(
        components["hostname"]
    )

    path = str(
        components["path"]
    )

    query = str(
        components["query"]
    )

    fragment = str(
        components["fragment"]
    )

    username = str(
        components["username"]
    )

    port = components["port"]

    query_parameter_count = int(
        components["query_parameter_count"]
    )

    url_length = len(
        original_url
    )

    hostname_length = len(
        hostname
    )

    subdomain_count = count_subdomains(
        hostname
    )

    raw_ip = is_raw_ip(
        hostname
    )

    https_present = (
        scheme.lower() == "https"
    )

    keyword_matches = (
        find_suspicious_keywords(
            original_url
        )
    )

    shortener_pattern = (
        is_shortened_url(
            hostname
        )
    )

    unusual_characters = (
        find_unusual_characters(
            original_url
        )
    )

    deceptive_indicators = (
        find_deceptive_structure_indicators(
            original_url,
            hostname,
            username,
        )
    )

    display_mismatch = (
        displayed_text_mismatch(
            displayed_text,
            hostname,
        )
    )

    findings: List[
        Dict[str, object]
    ] = []

    risk_score = 0

    # --------------------------------------------------------
    # 1. Empty / malformed URL
    # --------------------------------------------------------

    if not original_url:
        add_finding(
            findings,
            indicator_type="empty_url",
            description=(
                "No URL value was supplied for analysis."
            ),
            severity="low",
            score_contribution=0,
        )

    elif not hostname:
        add_finding(
            findings,
            indicator_type="invalid_url_structure",
            description=(
                "The URL could not be parsed into a valid hostname "
                "using static URL parsing."
            ),
            severity="high",
            score_contribution=25,
        )

        risk_score += 25

    # --------------------------------------------------------
    # 2. Raw IP
    # --------------------------------------------------------

    if raw_ip:
        add_finding(
            findings,
            indicator_type="raw_ip_address",
            description=(
                "The URL uses a raw IP address instead of a domain name."
            ),
            severity="high",
            score_contribution=20,
        )

        risk_score += 20

    # --------------------------------------------------------
    # 3. Non-HTTPS scheme
    # --------------------------------------------------------

    if scheme and suspicious_scheme(
        scheme
    ):
        add_finding(
            findings,
            indicator_type="non_https_scheme",
            description=(
                f"The URL uses the '{scheme}' scheme rather than HTTPS. "
                "This is a risk signal, but HTTP alone does not prove "
                "that a URL is malicious."
            ),
            severity="medium",
            score_contribution=10,
        )

        risk_score += 10

    elif scheme and scheme not in ALLOWED_COMMON_SCHEMES:
        add_finding(
            findings,
            indicator_type="unusual_scheme",
            description=(
                "The URL uses a scheme outside the common schemes "
                "supported by this project."
            ),
            severity="medium",
            score_contribution=15,
        )

        risk_score += 15

    # --------------------------------------------------------
    # 4. Suspicious keywords
    # --------------------------------------------------------

    if keyword_matches:
        add_finding(
            findings,
            indicator_type="suspicious_url_keywords",
            description=(
                "Security or social-engineering related keywords "
                "were found in the URL."
            ),
            severity="medium",
            score_contribution=min(
                15,
                5 * len(
                    keyword_matches
                ),
            ),
        )

        risk_score += min(
            15,
            5 * len(
                keyword_matches
            ),
        )

    # --------------------------------------------------------
    # 5. URL shortening service
    # --------------------------------------------------------

    if shortener_pattern:
        add_finding(
            findings,
            indicator_type="url_shortener_pattern",
            description=(
                "The hostname matches a known URL-shortening "
                "service. Shortened links can hide the final "
                "destination and should be reviewed carefully."
            ),
            severity="medium",
            score_contribution=10,
        )

        risk_score += 10

    # --------------------------------------------------------
    # 6. Excessive subdomains
    # --------------------------------------------------------

    if subdomain_count >= 3:
        add_finding(
            findings,
            indicator_type="excessive_subdomains",
            description=(
                "The hostname contains several nested subdomains."
            ),
            severity="medium",
            score_contribution=10,
        )

        risk_score += 10

    # --------------------------------------------------------
    # 7. Long URL
    # --------------------------------------------------------

    if url_length > 120:
        add_finding(
            findings,
            indicator_type="long_url",
            description=(
                "The URL is unusually long and may contain "
                "additional path or query structures that deserve review."
            ),
            severity="low",
            score_contribution=5,
        )

        risk_score += 5

    # --------------------------------------------------------
    # 8. Long hostname
    # --------------------------------------------------------

    if hostname_length > 60:
        add_finding(
            findings,
            indicator_type="long_hostname",
            description=(
                "The hostname is unusually long and should be "
                "reviewed in context."
            ),
            severity="low",
            score_contribution=5,
        )

        risk_score += 5

    # --------------------------------------------------------
    # 9. Unusual characters
    # --------------------------------------------------------

    if unusual_characters:
        add_finding(
            findings,
            indicator_type="unusual_characters",
            description=(
                "The URL contains unusual characters that may "
                "warrant additional review."
            ),
            severity="medium",
            score_contribution=10,
        )

        risk_score += 10

    # --------------------------------------------------------
    # 10. Deceptive-looking structure
    # --------------------------------------------------------

    if deceptive_indicators:
        # Avoid double-counting excessive subdomains because
        # that already has a dedicated risk contribution.
        structure_count = sum(
            1
            for item in deceptive_indicators
            if item != "excessive nested subdomains"
        )

        contribution = min(
            15,
            structure_count * 8,
        )

        if contribution:
            add_finding(
                findings,
                indicator_type="deceptive_structure",
                description=(
                    "The URL shows one or more structural "
                    "characteristics that can be associated with "
                    "deceptive link construction."
                ),
                severity="medium",
                score_contribution=contribution,
            )

            risk_score += contribution

    # --------------------------------------------------------
    # 11. Displayed text mismatch
    # --------------------------------------------------------

    if display_mismatch:
        add_finding(
            findings,
            indicator_type="displayed_text_destination_mismatch",
            description=(
                "The supplied displayed link text does not match "
                "the parsed destination hostname. This can be a "
                "useful warning signal when analyzing email links."
            ),
            severity="high",
            score_contribution=15,
        )

        risk_score += 15

    # --------------------------------------------------------
    # 12. Userinfo component
    # --------------------------------------------------------

    if username:
        add_finding(
            findings,
            indicator_type="userinfo_in_url",
            description=(
                "The URL contains a user-information component "
                "before the destination hostname, which can make "
                "the destination harder to recognize."
            ),
            severity="medium",
            score_contribution=10,
        )

        risk_score += 10

    # --------------------------------------------------------
    # HTTPS explanation
    # --------------------------------------------------------

    https_explanation = (
        "HTTPS is present. HTTPS protects the connection in "
        "transit, but HTTPS does NOT mean that the destination "
        "website is trustworthy."
        if https_present
        else
        "HTTPS is not present. This is a contextual risk signal. "
        "The absence of HTTPS does not by itself prove phishing."
    )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    risk_score = clamp_score(
        risk_score
    )

    return {
        "url": original_url,
        "scheme": scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "fragment": fragment,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "subdomain_count": subdomain_count,
        "has_ip_address": raw_ip,
        "https_present": https_present,
        "suspicious_keywords": keyword_matches,
        "shortened_url_pattern": shortener_pattern,
        "unusual_characters": unusual_characters,
        "deceptive_structure_indicators": deceptive_indicators,
        "displayed_text_mismatch": display_mismatch,
        "query_parameter_count": query_parameter_count,
        "port": port,
        "url_risk_score": risk_score,
        "url_findings": findings,
        "https_explanation": https_explanation,
        "static_analysis_only": True,
    }


# ============================================================
# HUMAN-READABLE FINDINGS
# ============================================================

def format_url_findings(
    analysis: Dict[str, object],
) -> List[str]:
    """
    Convert structured URL findings into simple UI-ready text.
    """

    findings = analysis.get(
        "url_findings",
        [],
    )

    formatted: List[str] = []

    if not isinstance(
        findings,
        list,
    ):
        return formatted

    for finding in findings:
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

    https_explanation = analysis.get(
        "https_explanation",
        "",
    )

    if https_explanation:
        formatted.append(
            str(https_explanation)
        )

    return formatted


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Run deterministic static URL-analysis tests.
    """

    # --------------------------------------------------------
    # Test 1: Safe fictional HTTPS URL
    # --------------------------------------------------------

    safe_result = analyze_url(
        "https://example.org/training"
    )

    assert (
        safe_result["hostname"]
        == "example.org"
    )

    assert (
        safe_result["https_present"] is True
    )

    assert (
        safe_result["has_ip_address"] is False
    )

    assert (
        safe_result["url_risk_score"] == 0
    )

    assert (
        safe_result["static_analysis_only"] is True
    )

    # --------------------------------------------------------
    # Test 2: Raw IP and HTTP
    # --------------------------------------------------------

    ip_result = analyze_url(
        "http://198.51.100.10/verify-account"
    )

    assert (
        ip_result["has_ip_address"] is True
    )

    assert (
        ip_result["https_present"] is False
    )

    assert (
        ip_result["url_risk_score"] > 0
    )

    # --------------------------------------------------------
    # Test 3: Known shortening pattern
    # --------------------------------------------------------

    shortener_result = analyze_url(
        "https://bit.ly/ExampleTraining"
    )

    assert (
        shortener_result[
            "shortened_url_pattern"
        ] is True
    )

    # --------------------------------------------------------
    # Test 4: Suspicious keywords
    # --------------------------------------------------------

    keyword_result = analyze_url(
        "https://example.org/account/verify-password"
    )

    assert (
        len(
            keyword_result[
                "suspicious_keywords"
            ]
        ) >= 2
    )

    # --------------------------------------------------------
    # Test 5: Excessive subdomains
    # --------------------------------------------------------

    subdomain_result = analyze_url(
        "https://a.b.c.example.org/verify"
    )

    assert (
        subdomain_result[
            "subdomain_count"
        ] == 3
    )

    # --------------------------------------------------------
    # Test 6: Display mismatch
    # --------------------------------------------------------

    mismatch_result = analyze_url(
        "https://account.example.net/verify",
        displayed_text="example.org",
    )

    assert (
        mismatch_result[
            "displayed_text_mismatch"
        ] is True
    )

    # --------------------------------------------------------
    # Test 7: Userinfo / deceptive structure
    # --------------------------------------------------------

    deceptive_result = analyze_url(
        "http://login@example.org/verify"
    )

    assert (
        deceptive_result["url_findings"]
    )

    finding_types = {
        finding["indicator_type"]
        for finding in deceptive_result[
            "url_findings"
        ]
    }

    assert (
        "userinfo_in_url"
        in finding_types
    )

    # --------------------------------------------------------
    # Test 8: Long URL
    # --------------------------------------------------------

    long_path = "a" * 130

    long_result = analyze_url(
        f"https://example.org/{long_path}"
    )

    assert (
        long_result["url_length"] > 120
    )

    long_types = {
        finding["indicator_type"]
        for finding in long_result[
            "url_findings"
        ]
    }

    assert (
        "long_url"
        in long_types
    )

    # --------------------------------------------------------
    # Test 9: HTTPS does not mean trusted
    # --------------------------------------------------------

    https_result = analyze_url(
        "https://example.org/account/verify"
    )

    assert (
        "does NOT mean"
        in https_result[
            "https_explanation"
        ]
    )

    # --------------------------------------------------------
    # Test 10: Empty input
    # --------------------------------------------------------

    empty_result = analyze_url(
        ""
    )

    assert (
        empty_result["url_risk_score"] == 0
    )

    assert (
        empty_result["static_analysis_only"]
        is True
    )

    print(
        "URL analyzer self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()

