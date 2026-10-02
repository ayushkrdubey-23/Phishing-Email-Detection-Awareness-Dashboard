from __future__ import annotations

import re
from typing import Dict, List


# ============================================================
# CATEGORY PATTERNS
# ============================================================

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bimmediate\b",
    r"\bact now\b",
    r"\bact immediately\b",
    r"\bright away\b",
    r"\bas soon as possible\b",
    r"\bdo not delay\b",
    r"\brespond today\b",
    r"\bwithin 24 hours\b",
    r"\bdeadline\b",
]


FEAR_PATTERNS = [
    r"\bwill be suspended\b",
    r"\bwill be blocked\b",
    r"\bwill be locked\b",
    r"\baccount suspension\b",
    r"\baccount will be suspended\b",
    r"\byour access will be\b",
    r"\byou will lose access\b",
    r"\baccess may be restricted\b",
    r"\bavoid termination\b",
    r"\bavoid penalty\b",
    r"\bpenalty\b",
    r"\bconsequences\b",
    r"\bsecurity threat\b",
]


FINANCIAL_PRESSURE_PATTERNS = [
    r"\boutstanding payment\b",
    r"\binvoice\b",
    r"\binvoice due\b",
    r"\bpayment required\b",
    r"\bpayment due\b",
    r"\bfinancial request\b",
    r"\bconfirm payment\b",
    r"\bpayment information\b",
    r"\bbilling information\b",
    r"\bbank details\b",
    r"\bcard number\b",
    r"\baccount number\b",
    r"\bsmall payment\b",
    r"\btransaction\b",
    r"\brefund\b",
]


CREDENTIAL_REQUEST_PATTERNS = [
    r"\bverify your password\b",
    r"\bconfirm your password\b",
    r"\bprovide your password\b",
    r"\bshare your password\b",
    r"\benter your password\b",
    r"\bsubmit your password\b",
    r"\bcurrent password\b",
    r"\bverify your credentials\b",
    r"\bconfirm your credentials\b",
    r"\bprovide your credentials\b",
    r"\benter your credentials\b",
    r"\bverify your login\b",
    r"\bconfirm your login\b",
    r"\benter your login\b",
    r"\bverification code\b",
    r"\bsecurity code\b",
    r"\bone[- ]time password\b",
    r"\botp\b",
    r"\bpasscode\b",
]


REWARD_PATTERNS = [
    r"\byou have won\b",
    r"\byou won\b",
    r"\bcongratulations\b",
    r"\bprize\b",
    r"\breward\b",
    r"\bspecial reward\b",
    r"\bgift\b",
    r"\bbonus\b",
    r"\bwinner\b",
    r"\bclaim your prize\b",
    r"\bclaim the reward\b",
]


PERSONAL_INFORMATION_PATTERNS = [
    r"\bpersonal information\b",
    r"\bpersonal details\b",
    r"\bconfirm your address\b",
    r"\bprovide your address\b",
    r"\bphone number\b",
    r"\bcontact details\b",
    r"\bdate of birth\b",
    r"\bidentity\b",
    r"\bidentity information\b",
    r"\bemployee information\b",
    r"\bemployee details\b",
    r"\bconfirm your personal\b",
]


SUSPICIOUS_CTA_PATTERNS = [
    r"\bclick (?:the )?(?:link|button)\b",
    r"\bclick here\b",
    r"\bverify now\b",
    r"\bverify immediately\b",
    r"\bconfirm now\b",
    r"\bconfirm immediately\b",
    r"\bsubmit now\b",
    r"\benter your\b",
    r"\bprovide your\b",
    r"\bshare your\b",
    r"\bdownload now\b",
    r"\bopen the attachment\b",
    r"\bcomplete the verification\b",
    r"\bcomplete the request\b",
]


GENERIC_GREETING_PATTERNS = [
    r"^\s*dear\s+customer\b",
    r"^\s*dear\s+user\b",
    r"^\s*dear\s+valued\s+customer\b",
    r"^\s*dear\s+valued\s+user\b",
    r"^\s*hello\s+customer\b",
    r"^\s*hello\s+user\b",
    r"^\s*hi\s+customer\b",
    r"^\s*hi\s+user\b",
    r"^\s*dear\s+account\s+holder\b",
]


# ============================================================
# FINDING DESCRIPTIONS
# ============================================================

CATEGORY_DETAILS = {
    "urgency": {
        "severity": "medium",
        "description": (
            "Urgency language was detected. Pressure to act quickly "
            "can reduce the time a recipient has to verify a request."
        ),
    },
    "fear": {
        "severity": "medium",
        "description": (
            "Fear or consequence language was detected. Threats of "
            "suspension, blocking, penalties, or loss of access can "
            "be used as social-engineering pressure."
        ),
    },
    "financial_pressure": {
        "severity": "medium",
        "description": (
            "Financial-pressure language was detected. Payment, invoice, "
            "billing, refund, or transaction requests should be verified "
            "through a trusted channel."
        ),
    },
    "credential_request": {
        "severity": "high",
        "description": (
            "A request involving passwords, credentials, passcodes, "
            "OTP values, or verification codes was detected. Sensitive "
            "authentication information should not be disclosed through "
            "an unexpected email request."
        ),
    },
    "reward": {
        "severity": "medium",
        "description": (
            "Reward or prize language was detected. Unexpected rewards "
            "can be used to create emotional pressure and encourage "
            "unsafe actions."
        ),
    },
    "personal_information": {
        "severity": "medium",
        "description": (
            "A request for personal or identity-related information "
            "was detected. The request should be independently verified."
        ),
    },
    "suspicious_call_to_action": {
        "severity": "medium",
        "description": (
            "A direct call to action was detected. Requests to click, "
            "verify, submit, provide, or download should be reviewed "
            "carefully when received unexpectedly."
        ),
    },
    "generic_greeting": {
        "severity": "low",
        "description": (
            "The message uses a generic greeting rather than addressing "
            "the recipient specifically. This can occur in legitimate "
            "bulk communications, so it is only a contextual signal."
        ),
    },
    "unusual_formatting": {
        "severity": "low",
        "description": (
            "Unusual formatting or punctuation patterns were detected. "
            "Formatting anomalies can provide context but do not prove "
            "that an email is malicious."
        ),
    },
    "possible_language_anomaly": {
        "severity": "low",
        "description": (
            "The message contains a possible language or writing anomaly. "
            "Spelling and grammar differences can occur in legitimate "
            "messages as well, so this should be reviewed in context."
        ),
    },
}


# ============================================================
# BASIC TEXT HELPERS
# ============================================================

def normalize_text(
    text: str,
) -> str:
    """
    Normalize whitespace without removing useful punctuation.
    """

    text = str(
        text or ""
    )

    text = text.replace(
        "\r\n",
        "\n",
    ).replace(
        "\r",
        "\n",
    )

    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    text = re.sub(
        r"\n{3,}",
        "\n\n",
        text,
    )

    return text.strip()


def add_finding(
    findings: List[Dict[str, object]],
    category: str,
    matched_terms: List[str],
) -> None:
    """
    Add one explainable content finding.
    """

    if not matched_terms:
        return

    details = CATEGORY_DETAILS[
        category
    ]

    findings.append(
        {
            "indicator_type": category,
            "severity": details["severity"],
            "matched_terms": matched_terms,
            "description": details["description"],
        }
    )


# ============================================================
# PATTERN MATCHING
# ============================================================

def find_pattern_matches(
    text: str,
    patterns: List[str],
) -> List[str]:
    """
    Return readable matched terms from a list of regex patterns.

    Matches are determined using case-insensitive static text analysis.
    """

    normalized = normalize_text(
        text
    )

    matches: List[str] = []
    seen = set()

    for pattern in patterns:
        found = re.findall(
            pattern,
            normalized,
            flags=re.IGNORECASE,
        )

        for item in found:
            if isinstance(
                item,
                tuple,
            ):
                match_text = (
                    " ".join(
                        part
                        for part in item
                        if part
                    )
                ).strip()
            else:
                match_text = str(
                    item
                ).strip()

            if not match_text:
                continue

            key = match_text.lower()

            if key not in seen:
                seen.add(key)
                matches.append(
                    match_text
                )

    return matches


# ============================================================
# GENERIC GREETING
# ============================================================

def detect_generic_greeting(
    body: str,
) -> bool:
    """
    Check the beginning of the email body for a generic greeting.
    """

    body = normalize_text(
        body
    )

    if not body:
        return False

    first_section = body[
        :250
    ]

    return bool(
        find_pattern_matches(
            first_section,
            GENERIC_GREETING_PATTERNS,
        )
    )


# ============================================================
# FORMATTING ANALYSIS
# ============================================================

def detect_unusual_formatting(
    subject: str,
    body: str,
) -> List[str]:
    """
    Detect concrete formatting patterns that may warrant review.

    This is deliberately conservative and does not claim that a
    formatting pattern is malicious.
    """

    text = (
        f"{normalize_text(subject)}\n"
        f"{normalize_text(body)}"
    )

    findings: List[str] = []

    # Three or more consecutive exclamation marks.
    if re.search(
        r"!{3,}",
        text,
    ):
        findings.append(
            "multiple consecutive exclamation marks"
        )

    # Three or more question marks.
    if re.search(
        r"\?{3,}",
        text,
    ):
        findings.append(
            "multiple consecutive question marks"
        )

    # Repeated punctuation combinations.
    if re.search(
        r"[!?]{3,}",
        text,
    ):
        findings.append(
            "repeated mixed punctuation"
        )

    # Long runs of uppercase words.
    uppercase_words = re.findall(
        r"\b[A-Z]{5,}\b",
        text,
    )

    if len(
        uppercase_words
    ) >= 3:

        findings.append(
            "several fully uppercase words"
        )

    # Very long lines can indicate unusual formatting.
    if any(
        len(line) > 160
        for line in text.splitlines()
    ):
        findings.append(
            "unusually long text line"
        )

    return findings


# ============================================================
# POSSIBLE LANGUAGE ANOMALIES
# ============================================================

def detect_language_anomalies(
    subject: str,
    body: str,
) -> List[str]:
    """
    Detect simple, explainable language/writing anomalies.

    This function intentionally avoids claiming to perform
    full grammar checking.

    Signals include:
    - repeated words directly beside each other
    - a word immediately followed by another word without spacing
    - repeated punctuation
    """

    text = (
        f"{normalize_text(subject)}\n"
        f"{normalize_text(body)}"
    )

    findings: List[str] = []

    # Repeated word:
    # "verify verify your account"
    if re.search(
        r"\b([A-Za-z]{3,})\s+\1\b",
        text,
        flags=re.IGNORECASE,
    ):
        findings.append(
            "repeated word pattern"
        )

    # Adjacent alphabetic and digit content can sometimes
    # indicate formatting irregularity.
    if re.search(
        r"\b[A-Za-z]{2,}\d{2,}\b|\b\d{2,}[A-Za-z]{2,}\b",
        text,
    ):
        findings.append(
            "mixed alphabetic and numeric token"
        )

    return findings


# ============================================================
# CONTENT SCORE
# ============================================================

CATEGORY_WEIGHTS = {
    "urgency": 10,
    "fear": 10,
    "financial_pressure": 10,
    "credential_request": 20,
    "reward": 8,
    "personal_information": 15,
    "suspicious_call_to_action": 10,
    "generic_greeting": 5,
    "unusual_formatting": 5,
    "possible_language_anomaly": 5,
}


def clamp_score(
    score: int,
) -> int:
    """
    Restrict content risk to 0-100.
    """

    return max(
        0,
        min(
            100,
            score,
        ),
    )


# ============================================================
# MAIN CONTENT ANALYSIS FUNCTION
# ============================================================

def analyze_email_content(
    subject: str,
    body: str,
) -> Dict[str, object]:
    """
    Analyze email subject and body using static text heuristics.

    Parameters
    ----------
    subject:
        Email subject.

    body:
        Email body.

    Returns
    -------
    dict
        {
            "content_risk_score": int,
            "content_findings": list,
            "categories_detected": list,
            "normalized_subject": str,
            "normalized_body": str
        }

    Notes
    -----
    This is contextual detection.

    No single indicator proves phishing.

    The function does not:
    - visit URLs
    - execute files
    - contact external services
    - send email
    """

    subject = normalize_text(
        subject
    )

    body = normalize_text(
        body
    )

    combined_text = (
        f"{subject}\n{body}"
    )

    findings: List[
        Dict[str, object]
    ] = []

    # --------------------------------------------------------
    # 1. Urgency
    # --------------------------------------------------------

    urgency_matches = find_pattern_matches(
        combined_text,
        URGENCY_PATTERNS,
    )

    add_finding(
        findings,
        "urgency",
        urgency_matches,
    )

    # --------------------------------------------------------
    # 2. Fear / threats
    # --------------------------------------------------------

    fear_matches = find_pattern_matches(
        combined_text,
        FEAR_PATTERNS,
    )

    add_finding(
        findings,
        "fear",
        fear_matches,
    )

    # --------------------------------------------------------
    # 3. Financial pressure
    # --------------------------------------------------------

    financial_matches = find_pattern_matches(
        combined_text,
        FINANCIAL_PRESSURE_PATTERNS,
    )

    add_finding(
        findings,
        "financial_pressure",
        financial_matches,
    )

    # --------------------------------------------------------
    # 4. Credential request
    # --------------------------------------------------------

    credential_matches = find_pattern_matches(
        combined_text,
        CREDENTIAL_REQUEST_PATTERNS,
    )

    add_finding(
        findings,
        "credential_request",
        credential_matches,
    )

    # --------------------------------------------------------
    # 5. Reward
    # --------------------------------------------------------

    reward_matches = find_pattern_matches(
        combined_text,
        REWARD_PATTERNS,
    )

    add_finding(
        findings,
        "reward",
        reward_matches,
    )

    # --------------------------------------------------------
    # 6. Personal information
    # --------------------------------------------------------

    personal_info_matches = find_pattern_matches(
        combined_text,
        PERSONAL_INFORMATION_PATTERNS,
    )

    add_finding(
        findings,
        "personal_information",
        personal_info_matches,
    )

    # --------------------------------------------------------
    # 7. Suspicious CTA
    # --------------------------------------------------------

    cta_matches = find_pattern_matches(
        combined_text,
        SUSPICIOUS_CTA_PATTERNS,
    )

    add_finding(
        findings,
        "suspicious_call_to_action",
        cta_matches,
    )

    # --------------------------------------------------------
    # 8. Generic greeting
    # --------------------------------------------------------

    if detect_generic_greeting(
        body
    ):
        add_finding(
            findings,
            "generic_greeting",
            [
                "generic greeting"
            ],
        )

    # --------------------------------------------------------
    # 9. Formatting anomalies
    # --------------------------------------------------------

    formatting_matches = (
        detect_unusual_formatting(
            subject,
            body,
        )
    )

    add_finding(
        findings,
        "unusual_formatting",
        formatting_matches,
    )

    # --------------------------------------------------------
    # 10. Possible language anomalies
    # --------------------------------------------------------

    language_matches = (
        detect_language_anomalies(
            subject,
            body,
        )
    )

    add_finding(
        findings,
        "possible_language_anomaly",
        language_matches,
    )

    # --------------------------------------------------------
    # Calculate contextual content score
    # --------------------------------------------------------

    detected_categories = {
        str(
            finding["indicator_type"]
        )
        for finding in findings
    }

    content_risk_score = 0

    for category in detected_categories:
        content_risk_score += (
            CATEGORY_WEIGHTS.get(
                category,
                0,
            )
        )

    content_risk_score = clamp_score(
        content_risk_score
    )

    return {
        "content_risk_score": content_risk_score,
        "content_findings": findings,
        "categories_detected": sorted(
            detected_categories
        ),
        "normalized_subject": subject,
        "normalized_body": body,
    }


# ============================================================
# HUMAN-READABLE OUTPUT
# ============================================================

def format_content_findings(
    analysis: Dict[str, object],
) -> List[str]:
    """
    Convert structured content findings into simple UI-ready text.
    """

    findings = analysis.get(
        "content_findings",
        [],
    )

    result: List[str] = []

    if not isinstance(
        findings,
        list,
    ):
        return result

    for finding in findings:
        if not isinstance(
            finding,
            dict,
        ):
            continue

        category = finding.get(
            "indicator_type",
            "unknown",
        )

        description = finding.get(
            "description",
            "",
        )

        matched_terms = finding.get(
            "matched_terms",
            [],
        )

        if matched_terms:
            result.append(
                f"{category}: "
                f"{description} "
                f"Matched: {', '.join(map(str, matched_terms))}"
            )
        else:
            result.append(
                f"{category}: {description}"
            )

    return result


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Run deterministic checks for the content analyzer.
    """

    phishing_result = analyze_email_content(
        subject=(
            "URGENT: Verify Your Account Immediately!"
        ),
        body=(
            "Dear Customer, "
            "verify your password immediately or your account "
            "will be suspended. "
            "Confirm your personal details and payment information."
        ),
    )

    categories = set(
        phishing_result[
            "categories_detected"
        ]
    )

    assert (
        "urgency" in categories
    )

    assert (
        "credential_request" in categories
    )

    assert (
        "fear" in categories
    )

    assert (
        "financial_pressure" in categories
    )

    assert (
        "personal_information" in categories
    )

    assert (
        "generic_greeting" in categories
    )

    assert (
        phishing_result[
            "content_risk_score"
        ] > 0
    )

    legitimate_result = analyze_email_content(
        subject=(
            "Cybersecurity Workshop Reminder"
        ),
        body=(
            "Hello Ayush,\n\n"
            "This is a reminder for the scheduled workshop. "
            "The agenda is available through the normal university portal. "
            "No password or payment information is requested.\n\n"
            "Regards,\n"
            "Training Team"
        ),
    )

    assert isinstance(
        legitimate_result[
            "content_findings"
        ],
        list,
    )

    # A generic greeting should NOT be triggered by a specific name.
    assert (
        "generic_greeting"
        not in set(
            legitimate_result[
                "categories_detected"
            ]
        )
    )

    # Direct formatting test.
    formatting_result = analyze_email_content(
        subject="URGENT!!!",
        body="ACT NOW!!! VERIFY!!!",
    )

    assert (
        "unusual_formatting"
        in set(
            formatting_result[
                "categories_detected"
            ]
        )
    )

    print(
        "Content analyzer self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()

