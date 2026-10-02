from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


# ============================================================
# PROJECT SCORING WEIGHTS
# ============================================================

MAX_RISK_SCORE = 100

WEIGHTS = {
    "suspicious_sender": 15,
    "urgency": 10,
    "credential_request": 20,
    "suspicious_url": 20,
    "suspicious_attachment": 25,
    "generic_greeting": 5,
    "threat_or_fear": 10,
}


# ============================================================
# PROJECT CLASSIFICATION THRESHOLDS
# ============================================================

CLASSIFICATION_THRESHOLDS = {
    "low_risk_max": 20,
    "moderate_risk_max": 40,
    "suspicious_max": 70,
    "high_risk_max": 100,
}


# ============================================================
# BASIC HELPERS
# ============================================================

def clamp_score(
    score: int,
) -> int:
    """
    Keep a score between 0 and 100.
    """

    return max(
        0,
        min(
            MAX_RISK_SCORE,
            int(score),
        ),
    )


def safe_int(
    value: Any,
    default: int = 0,
) -> int:
    """
    Convert a value safely to int.
    """

    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def safe_bool(
    value: Any,
) -> bool:
    """
    Convert common Python/string representations to bool.
    """

    if isinstance(
        value,
        bool,
    ):
        return value

    if value is None:
        return False

    if isinstance(
        value,
        str,
    ):
        return value.strip().lower() in {
            "true",
            "1",
            "yes",
            "y",
        }

    if isinstance(
        value,
        (int, float),
    ):
        return value != 0

    return bool(value)


def normalize_findings(
    findings: Any,
) -> List[Dict[str, Any]]:
    """
    Safely normalize a findings collection into a list of dictionaries.
    """

    if findings is None:
        return []

    if isinstance(
        findings,
        dict,
    ):
        return [findings]

    if not isinstance(
        findings,
        (list, tuple),
    ):
        return []

    result: List[
        Dict[str, Any]
    ] = []

    for finding in findings:
        if isinstance(
            finding,
            dict,
        ):
            result.append(
                finding
            )

    return result


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_risk(
    score: int,
) -> str:
    """
    Convert a 0-100 phishing score into the project's
    documented classification.

    Thresholds:
        0-20    LOW RISK
        21-40   MODERATE RISK
        41-70   SUSPICIOUS
        71-100  HIGH RISK / LIKELY PHISHING
    """

    score = clamp_score(
        score
    )

    if score <= CLASSIFICATION_THRESHOLDS[
        "low_risk_max"
    ]:
        return "LOW RISK"

    if score <= CLASSIFICATION_THRESHOLDS[
        "moderate_risk_max"
    ]:
        return "MODERATE RISK"

    if score <= CLASSIFICATION_THRESHOLDS[
        "suspicious_max"
    ]:
        return "SUSPICIOUS"

    return "HIGH RISK / LIKELY PHISHING"


# ============================================================
# SCORE CONTRIBUTION BUILDER
# ============================================================

def build_contribution(
    signal: str,
    triggered: bool,
    description: str,
) -> Dict[str, Any]:
    """
    Create one explainable scoring contribution.
    """

    weight = WEIGHTS[
        signal
    ]

    return {
        "signal": signal,
        "triggered": triggered,
        "weight": weight,
        "contribution": (
            weight if triggered else 0
        ),
        "description": description,
    }


# ============================================================
# ANALYSIS-SIGNAL EXTRACTION
# ============================================================

def sender_signal_triggered(
    sender_analysis: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Determine whether the sender should contribute the
    'suspicious sender' weight.

    A sender contributes when:
    - sender risk score reaches 10+, or
    - at least one sender finding has a positive score contribution.

    This avoids treating an unfamiliar domain as automatically
    suspicious when no actual configured finding exists.
    """

    if not sender_analysis:
        return False

    sender_score = safe_int(
        sender_analysis.get(
            "sender_risk_score",
            0,
        )
    )

    if sender_score >= 10:
        return True

    findings = normalize_findings(
        sender_analysis.get(
            "sender_findings",
            [],
        )
    )

    return any(
        safe_int(
            finding.get(
                "score_contribution",
                0,
            )
        ) > 0
        for finding in findings
    )


def content_categories(
    content_analysis: Optional[
        Dict[str, Any]
    ],
) -> set[str]:
    """
    Extract detected content categories.
    """

    if not content_analysis:
        return set()

    categories = content_analysis.get(
        "categories_detected",
        [],
    )

    if not isinstance(
        categories,
        (list, tuple, set),
    ):
        return set()

    return {
        str(category).lower()
        for category in categories
    }


def urgency_signal_triggered(
    content_analysis: Optional[
        Dict[str, Any]
    ],
    feature_data: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Detect urgency using either the content analyzer or
    feature-engineering output.
    """

    categories = content_categories(
        content_analysis
    )

    if "urgency" in categories:
        return True

    if feature_data:
        return safe_int(
            feature_data.get(
                "urgent_keyword_count",
                0,
            )
        ) > 0

    return False


def credential_signal_triggered(
    content_analysis: Optional[
        Dict[str, Any]
    ],
    feature_data: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Detect credential requests from content analysis or
    structured features.
    """

    categories = content_categories(
        content_analysis
    )

    if "credential_request" in categories:
        return True

    if feature_data:
        return safe_bool(
            feature_data.get(
                "contains_password_request",
                False,
            )
        )

    return False


def threat_signal_triggered(
    content_analysis: Optional[
        Dict[str, Any]
    ],
    feature_data: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Detect threat/fear language.
    """

    categories = content_categories(
        content_analysis
    )

    if "fear" in categories:
        return True

    if feature_data:
        return safe_int(
            feature_data.get(
                "threat_keyword_count",
                0,
            )
        ) > 0

    return False


def generic_greeting_triggered(
    content_analysis: Optional[
        Dict[str, Any]
    ],
    feature_data: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Detect generic greetings.
    """

    categories = content_categories(
        content_analysis
    )

    if "generic_greeting" in categories:
        return True

    if feature_data:
        return safe_bool(
            feature_data.get(
                "generic_greeting",
                False,
            )
        )

    return False


def url_signal_triggered(
    url_analyses: Optional[
        Iterable[Dict[str, Any]]
    ],
    feature_data: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Determine whether at least one suspicious URL exists.

    URL analyzer evidence takes priority when available.
    """

    if url_analyses:
        for analysis in url_analyses:
            if not isinstance(
                analysis,
                dict,
            ):
                continue

            if safe_int(
                analysis.get(
                    "url_risk_score",
                    0,
                )
            ) > 0:

                return True

            findings = normalize_findings(
                analysis.get(
                    "url_findings",
                    [],
                )
            )

            if findings:
                # Ignore informational-only findings when
                # deciding whether a suspicious URL exists.
                if any(
                    finding.get(
                        "indicator_type"
                    )
                    != "empty_url"
                    and safe_int(
                        finding.get(
                            "score_contribution",
                            0,
                        )
                    ) > 0
                    for finding in findings
                ):
                    return True

    if feature_data:
        return (
            safe_int(
                feature_data.get(
                    "suspicious_url_count",
                    0,
                )
            )
            > 0
            or safe_bool(
                feature_data.get(
                    "has_ip_url",
                    False,
                )
            )
            or safe_bool(
                feature_data.get(
                    "has_shortened_url_pattern",
                    False,
                )
            )
        )

    return False


def attachment_signal_triggered(
    attachment_analysis: Optional[
        Dict[str, Any]
    ],
    feature_data: Optional[
        Dict[str, Any]
    ],
) -> bool:
    """
    Determine whether an attachment should contribute the
    suspicious-attachment weight.
    """

    if attachment_analysis:
        if safe_int(
            attachment_analysis.get(
                "attachment_risk_score",
                0,
            )
        ) > 0:
            return True

        findings = normalize_findings(
            attachment_analysis.get(
                "findings",
                [],
            )
        )

        if any(
            safe_int(
                finding.get(
                    "score_contribution",
                    0,
                )
            ) > 0
            for finding in findings
        ):
            return True

    if feature_data:
        return safe_bool(
            feature_data.get(
                "suspicious_attachment",
                False,
            )
        )

    return False


# ============================================================
# RECOMMENDATION GENERATION
# ============================================================

def build_recommendations(
    triggered_signals: Dict[str, bool],
    score: int,
) -> List[str]:
    """
    Generate defensive security recommendations based on
    detected risk signals.
    """

    recommendations: List[str] = []

    if triggered_signals.get(
        "suspicious_url",
        False,
    ):
        recommendations.append(
            "Do not click suspicious or unexpected links."
        )

    if triggered_signals.get(
        "suspicious_attachment",
        False,
    ):
        recommendations.append(
            "Do not open unexpected attachments."
        )

    if triggered_signals.get(
        "credential_request",
        False,
    ):
        recommendations.append(
            "Do not provide passwords, OTPs, or other credentials "
            "through an unexpected email request."
        )

    if triggered_signals.get(
        "suspicious_sender",
        False,
    ):
        recommendations.append(
            "Verify the sender through a trusted communication channel."
        )

    if triggered_signals.get(
        "financial_pressure",
        False,
    ):
        recommendations.append(
            "Verify payment or financial requests independently "
            "before taking action."
        )

    # Always useful for elevated results.
    if score >= 41:
        recommendations.append(
            "Report the message to the organization's security team "
            "according to local policy."
        )

    # Direct users to trusted services instead of email links.
    if (
        triggered_signals.get(
            "credential_request",
            False,
        )
        or triggered_signals.get(
            "suspicious_url",
            False,
        )
    ):
        recommendations.append(
            "Use the organization's official website or application "
            "directly instead of following an unexpected email link."
        )

    # If nothing suspicious was detected.
    if not recommendations:
        recommendations.append(
            "Continue normal email-safety checks and verify unexpected "
            "requests through trusted channels."
        )

    # Remove accidental duplicates while preserving order.
    unique_recommendations: List[str] = []
    seen = set()

    for recommendation in recommendations:
        if recommendation not in seen:
            seen.add(
                recommendation
            )
            unique_recommendations.append(
                recommendation
            )

    return unique_recommendations


# ============================================================
# MAIN RISK ENGINE
# ============================================================

def calculate_phishing_score(
    sender_analysis: Optional[
        Dict[str, Any]
    ] = None,
    content_analysis: Optional[
        Dict[str, Any]
    ] = None,
    url_analyses: Optional[
        Iterable[Dict[str, Any]]
    ] = None,
    attachment_analysis: Optional[
        Dict[str, Any]
    ] = None,
    feature_data: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    """
    Calculate the rule-based phishing risk score.

    Scoring weights from the project specification:

        Suspicious Sender       +15
        Urgency                 +10
        Credential Request      +20
        Suspicious URL          +20
        Suspicious Attachment   +25
        Generic Greeting         +5
        Threat/Fear Language    +10

    Final score is capped at 100.

    Parameters
    ----------
    sender_analysis:
        Output from analyze_sender().

    content_analysis:
        Output from analyze_email_content().

    url_analyses:
        One or more outputs from analyze_url().

    attachment_analysis:
        Output from analyze_attachment().

    feature_data:
        Optional Step 5 feature dictionary. It provides a
        useful fallback when the dedicated analyzers are not
        available.

    Returns
    -------
    dict
        Structured explainable risk assessment.
    """

    # Determine each of the seven primary signals.
    suspicious_sender = sender_signal_triggered(
        sender_analysis
    )

    urgency = urgency_signal_triggered(
        content_analysis,
        feature_data,
    )

    credential_request = credential_signal_triggered(
        content_analysis,
        feature_data,
    )

    suspicious_url = url_signal_triggered(
        url_analyses,
        feature_data,
    )

    suspicious_attachment = attachment_signal_triggered(
        attachment_analysis,
        feature_data,
    )

    generic_greeting = generic_greeting_triggered(
        content_analysis,
        feature_data,
    )

    threat_or_fear = threat_signal_triggered(
        content_analysis,
        feature_data,
    )

    # Financial pressure is not an independent scoring weight
    # in the prompt's seven-weight rule engine, but it is kept
    # for recommendations and explainability.
    categories = content_categories(
        content_analysis
    )

    financial_pressure = (
        "financial_pressure"
        in categories
    )

    # --------------------------------------------------------
    # Score contributions
    # --------------------------------------------------------

    contributions = [
        build_contribution(
            "suspicious_sender",
            suspicious_sender,
            (
                "Sender analysis identified one or more "
                "sender characteristics requiring additional review."
            ),
        ),
        build_contribution(
            "urgency",
            urgency,
            (
                "Urgent or pressure-based language was detected."
            ),
        ),
        build_contribution(
            "credential_request",
            credential_request,
            (
                "A request involving credentials or "
                "authentication information was detected."
            ),
        ),
        build_contribution(
            "suspicious_url",
            suspicious_url,
            (
                "One or more URLs triggered static "
                "risk indicators."
            ),
        ),
        build_contribution(
            "suspicious_attachment",
            suspicious_attachment,
            (
                "The attachment filename triggered "
                "one or more risk indicators."
            ),
        ),
        build_contribution(
            "generic_greeting",
            generic_greeting,
            (
                "A generic greeting was detected. "
                "This is only a contextual signal."
            ),
        ),
        build_contribution(
            "threat_or_fear",
            threat_or_fear,
            (
                "Threat or fear-based language was detected."
            ),
        ),
    ]

    raw_score = sum(
        safe_int(
            item.get(
                "contribution",
                0,
            )
        )
        for item in contributions
    )

    risk_score = clamp_score(
        raw_score
    )

    classification = classify_risk(
        risk_score
    )

    triggered_signals = {
        "suspicious_sender": suspicious_sender,
        "urgency": urgency,
        "credential_request": credential_request,
        "suspicious_url": suspicious_url,
        "suspicious_attachment": suspicious_attachment,
        "generic_greeting": generic_greeting,
        "threat_or_fear": threat_or_fear,
        "financial_pressure": financial_pressure,
    }

    recommendations = build_recommendations(
        triggered_signals,
        risk_score,
    )

    # --------------------------------------------------------
    # Explainable summary
    # --------------------------------------------------------

    detected_indicators: List[str] = []

    for contribution in contributions:
        if contribution[
            "triggered"
        ]:
            detected_indicators.append(
                str(
                    contribution[
                        "signal"
                    ]
                )
            )

    return {
        "phishing_risk_score": risk_score,
        "raw_score_before_cap": raw_score,
        "classification": classification,
        "score_cap": MAX_RISK_SCORE,
        "score_contributions": contributions,
        "detected_indicators": detected_indicators,
        "triggered_signals": triggered_signals,
        "recommendations": recommendations,
        "scoring_weights": dict(
            WEIGHTS
        ),
        "classification_thresholds": dict(
            CLASSIFICATION_THRESHOLDS
        ),
        "thresholds_are_project_assumptions": True,
        "requires_validation_calibration": True,
        "probability": None,
        "analysis_note": (
            "The rule-based risk score is a project-specific "
            "heuristic. It is not a probability and must be "
            "validated and calibrated using representative data."
        ),
    }


# ============================================================
# EXPLAINABILITY HELPERS
# ============================================================

def get_triggered_contributions(
    risk_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Return only scoring signals that contributed to the final score.
    """

    contributions = risk_result.get(
        "score_contributions",
        [],
    )

    if not isinstance(
        contributions,
        list,
    ):
        return []

    return [
        contribution
        for contribution in contributions
        if isinstance(
            contribution,
            dict,
        )
        and safe_bool(
            contribution.get(
                "triggered",
                False,
            )
        )
    ]


def format_risk_explanation(
    risk_result: Dict[str, Any],
) -> List[str]:
    """
    Convert the scoring result into simple UI-ready explanations.
    """

    triggered = get_triggered_contributions(
        risk_result
    )

    explanations: List[str] = []

    for contribution in triggered:
        signal = str(
            contribution.get(
                "signal",
                "",
            )
        )

        weight = safe_int(
            contribution.get(
                "contribution",
                0,
            )
        )

        description = str(
            contribution.get(
                "description",
                "",
            )
        )

        explanations.append(
            f"{signal}: +{weight} points. "
            f"{description}"
        )

    return explanations


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Run deterministic tests for the rule-based risk engine.
    """

    # --------------------------------------------------------
    # Test 1: Completely clean input
    # --------------------------------------------------------

    clean_result = calculate_phishing_score()

    assert (
        clean_result[
            "phishing_risk_score"
        ]
        == 0
    )

    assert (
        clean_result[
            "classification"
        ]
        == "LOW RISK"
    )

    # --------------------------------------------------------
    # Test 2: Urgency only
    # --------------------------------------------------------

    urgency_result = calculate_phishing_score(
        content_analysis={
            "categories_detected": [
                "urgency"
            ]
        }
    )

    assert (
        urgency_result[
            "phishing_risk_score"
        ]
        == 10
    )

    assert (
        urgency_result[
            "classification"
        ]
        == "LOW RISK"
    )

    # --------------------------------------------------------
    # Test 3: Credential request
    # --------------------------------------------------------

    credential_result = calculate_phishing_score(
        content_analysis={
            "categories_detected": [
                "credential_request"
            ]
        }
    )

    assert (
        credential_result[
            "phishing_risk_score"
        ]
        == 20
    )

    assert (
        credential_result[
            "classification"
        ]
        == "LOW RISK"
    )

    # --------------------------------------------------------
    # Test 4: Suspicious URL
    # --------------------------------------------------------

    url_result = calculate_phishing_score(
        url_analyses=[
            {
                "url_risk_score": 30,
                "url_findings": [
                    {
                        "indicator_type": "raw_ip_address",
                        "score_contribution": 20,
                    }
                ],
            }
        ]
    )

    assert (
        url_result[
            "phishing_risk_score"
        ]
        == 20
    )

    # --------------------------------------------------------
    # Test 5: Suspicious attachment
    # --------------------------------------------------------

    attachment_result = calculate_phishing_score(
        attachment_analysis={
            "attachment_risk_score": 50,
            "findings": [
                {
                    "indicator_type": "executable_extension",
                    "score_contribution": 35,
                }
            ],
        }
    )

    assert (
        attachment_result[
            "phishing_risk_score"
        ]
        == 25
    )

    # --------------------------------------------------------
    # Test 6: Generic greeting
    # --------------------------------------------------------

    greeting_result = calculate_phishing_score(
        content_analysis={
            "categories_detected": [
                "generic_greeting"
            ]
        }
    )

    assert (
        greeting_result[
            "phishing_risk_score"
        ]
        == 5
    )

    # --------------------------------------------------------
    # Test 7: Threat/fear
    # --------------------------------------------------------

    threat_result = calculate_phishing_score(
        content_analysis={
            "categories_detected": [
                "fear"
            ]
        }
    )

    assert (
        threat_result[
            "phishing_risk_score"
        ]
        == 10
    )

    # --------------------------------------------------------
    # Test 8: Suspicious sender
    # --------------------------------------------------------

    sender_result = calculate_phishing_score(
        sender_analysis={
            "sender_risk_score": 25,
            "sender_findings": [
                {
                    "indicator_type": "possible_lookalike_pattern",
                    "score_contribution": 12,
                }
            ],
        }
    )

    assert (
        sender_result[
            "phishing_risk_score"
        ]
        == 15
    )

    # --------------------------------------------------------
    # Test 9: Maximum primary contributions
    # --------------------------------------------------------

    maximum_result = calculate_phishing_score(
        sender_analysis={
            "sender_risk_score": 100
        },
        content_analysis={
            "categories_detected": [
                "urgency",
                "credential_request",
                "fear",
                "generic_greeting",
            ]
        },
        url_analyses=[
            {
                "url_risk_score": 90
            }
        ],
        attachment_analysis={
            "attachment_risk_score": 90
        },
    )

    # 15 + 10 + 20 + 20 + 25 + 5 + 10 = 105,
    # then capped at 100.
    assert (
        maximum_result[
            "raw_score_before_cap"
        ]
        == 105
    )

    assert (
        maximum_result[
            "phishing_risk_score"
        ]
        == 100
    )

    assert (
        maximum_result[
            "classification"
        ]
        == "HIGH RISK / LIKELY PHISHING"
    )

    # --------------------------------------------------------
    # Test 10: Threshold boundaries
    # --------------------------------------------------------

    assert (
        classify_risk(0)
        == "LOW RISK"
    )

    assert (
        classify_risk(20)
        == "LOW RISK"
    )

    assert (
        classify_risk(21)
        == "MODERATE RISK"
    )

    assert (
        classify_risk(40)
        == "MODERATE RISK"
    )

    assert (
        classify_risk(41)
        == "SUSPICIOUS"
    )

    assert (
        classify_risk(70)
        == "SUSPICIOUS"
    )

    assert (
        classify_risk(71)
        == "HIGH RISK / LIKELY PHISHING"
    )

    assert (
        classify_risk(100)
        == "HIGH RISK / LIKELY PHISHING"
    )

    # --------------------------------------------------------
    # Test 11: Feature-data fallback
    # --------------------------------------------------------

    feature_result = calculate_phishing_score(
        feature_data={
            "urgent_keyword_count": 1,
            "contains_password_request": "TRUE",
            "threat_keyword_count": 1,
            "suspicious_url_count": 1,
            "suspicious_attachment": "TRUE",
            "generic_greeting": "TRUE",
        }
    )

    # 10 + 20 + 10 + 20 + 25 + 5 = 90.
    assert (
        feature_result[
            "phishing_risk_score"
        ]
        == 90
    )

    # --------------------------------------------------------
    # Test 12: Recommendations
    # --------------------------------------------------------

    recommendation_result = calculate_phishing_score(
        content_analysis={
            "categories_detected": [
                "credential_request",
                "urgency",
            ]
        },
        url_analyses=[
            {
                "url_risk_score": 20
            }
        ],
    )

    recommendations = recommendation_result[
        "recommendations"
    ]

    assert any(
        "Do not click"
        in recommendation
        for recommendation in recommendations
    )

    assert any(
        "credentials"
        in recommendation.lower()
        for recommendation in recommendations
    )

    # --------------------------------------------------------
    # Test 13: Explainability
    # --------------------------------------------------------

    explanation_result = calculate_phishing_score(
        content_analysis={
            "categories_detected": [
                "credential_request"
            ]
        }
    )

    explanations = format_risk_explanation(
        explanation_result
    )

    assert (
        len(explanations)
        == 1
    )

    assert (
        "+20"
        in explanations[0]
    )

    # --------------------------------------------------------
    # Test 14: Risk-score range
    # --------------------------------------------------------

    assert (
        0
        <= maximum_result[
            "phishing_risk_score"
        ]
        <= 100
    )

    print(
        "Risk engine self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()
    