from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


# ============================================================
# SEVERITY ORDER
# ============================================================

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# ============================================================
# BASIC HELPERS
# ============================================================

def safe_text(value: Any) -> str:
    """
    Convert a value into a safe string for display preparation.
    """

    if value is None:
        return ""

    return str(value).strip()


def safe_int(
    value: Any,
    default: int = 0,
) -> int:
    """
    Convert a value safely to integer.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_bool(value: Any) -> bool:
    """
    Convert common boolean representations into bool.
    """

    if isinstance(value, bool):
        return value

    if value is None:
        return False

    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "1",
            "yes",
            "y",
        }

    if isinstance(value, (int, float)):
        return value != 0

    return bool(value)


def normalize_findings(
    findings: Any,
) -> List[Dict[str, Any]]:
    """
    Normalize a findings collection into a list of dictionaries.
    """

    if findings is None:
        return []

    if isinstance(findings, dict):
        return [findings]

    if not isinstance(findings, (list, tuple)):
        return []

    return [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]


# ============================================================
# SEVERITY HELPERS
# ============================================================

def normalize_severity(
    severity: Any,
) -> str:
    """
    Normalize finding severity to a supported value.
    """

    severity = safe_text(
        severity
    ).lower()

    if severity in SEVERITY_ORDER:
        return severity

    return "info"


def severity_rank(
    severity: Any,
) -> int:
    """
    Return numerical severity ranking for sorting.
    """

    return SEVERITY_ORDER.get(
        normalize_severity(severity),
        0,
    )


# ============================================================
# FINDING CONVERSION
# ============================================================

def make_unified_finding(
    source: str,
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert a sender/content/URL/attachment finding into a
    common explainability structure.
    """

    indicator_type = safe_text(
        finding.get(
            "indicator_type",
            "unknown",
        )
    )

    description = safe_text(
        finding.get(
            "description",
            "",
        )
    )

    severity = normalize_severity(
        finding.get(
            "severity",
            "info",
        )
    )

    score_contribution = safe_int(
        finding.get(
            "score_contribution",
            0,
        )
    )

    matched_terms = finding.get(
        "matched_terms",
        [],
    )

    if isinstance(
        matched_terms,
        (list, tuple),
    ):
        matched_terms = [
            safe_text(term)
            for term in matched_terms
            if safe_text(term)
        ]
    else:
        matched_terms = []

    return {
        "source": source,
        "indicator_type": indicator_type,
        "severity": severity,
        "severity_rank": severity_rank(
            severity
        ),
        "description": description,
        "matched_terms": matched_terms,
        "score_contribution": score_contribution,
    }


# ============================================================
# COLLECT FINDINGS FROM ALL ANALYZERS
# ============================================================

def collect_all_findings(
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
) -> List[Dict[str, Any]]:
    """
    Collect findings from all analysis engines into one list.
    """

    unified: List[
        Dict[str, Any]
    ] = []

    # --------------------------------------------------------
    # Sender findings
    # --------------------------------------------------------

    if sender_analysis:
        for finding in normalize_findings(
            sender_analysis.get(
                "sender_findings",
                [],
            )
        ):
            unified.append(
                make_unified_finding(
                    "sender",
                    finding,
                )
            )

    # --------------------------------------------------------
    # Content findings
    # --------------------------------------------------------

    if content_analysis:
        for finding in normalize_findings(
            content_analysis.get(
                "content_findings",
                [],
            )
        ):
            unified.append(
                make_unified_finding(
                    "content",
                    finding,
                )
            )

    # --------------------------------------------------------
    # URL findings
    # --------------------------------------------------------

    if url_analyses:
        for index, url_analysis in enumerate(
            url_analyses,
            start=1,
        ):
            if not isinstance(
                url_analysis,
                dict,
            ):
                continue

            url_value = safe_text(
                url_analysis.get(
                    "url",
                    "",
                )
            )

            for finding in normalize_findings(
                url_analysis.get(
                    "url_findings",
                    [],
                )
            ):
                converted = make_unified_finding(
                    "url",
                    finding,
                )

                converted[
                    "url_index"
                ] = index

                converted[
                    "url_safe_representation"
                ] = (
                    url_value
                    if url_value
                    else f"URL #{index}"
                )

                unified.append(
                    converted
                )

    # --------------------------------------------------------
    # Attachment findings
    # --------------------------------------------------------

    if attachment_analysis:
        for finding in normalize_findings(
            attachment_analysis.get(
                "findings",
                [],
            )
        ):
            unified.append(
                make_unified_finding(
                    "attachment",
                    finding,
                )
            )

    return unified


# ============================================================
# SCORE CONTRIBUTION FINDINGS
# ============================================================

def build_score_evidence(
    risk_result: Optional[
        Dict[str, Any]
    ],
) -> List[Dict[str, Any]]:
    """
    Convert risk-engine score contributions into evidence records.
    """

    if not risk_result:
        return []

    contributions = risk_result.get(
        "score_contributions",
        [],
    )

    if not isinstance(
        contributions,
        list,
    ):
        return []

    evidence: List[
        Dict[str, Any]
    ] = []

    for item in contributions:
        if not isinstance(
            item,
            dict,
        ):
            continue

        triggered = safe_bool(
            item.get(
                "triggered",
                False,
            )
        )

        if not triggered:
            continue

        evidence.append(
            {
                "signal": safe_text(
                    item.get(
                        "signal",
                        "",
                    )
                ),
                "weight": safe_int(
                    item.get(
                        "weight",
                        0,
                    )
                ),
                "contribution": safe_int(
                    item.get(
                        "contribution",
                        0,
                    )
                ),
                "description": safe_text(
                    item.get(
                        "description",
                        "",
                    )
                ),
            }
        )

    return evidence


# ============================================================
# WHY SUMMARY GENERATION
# ============================================================

def build_why_suspicious(
    findings: List[Dict[str, Any]],
    score_evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Build concise explainable reasons for the dashboard.

    Findings are sorted by:
        1. severity
        2. score contribution
        3. source
    """

    combined: List[
        Dict[str, Any]
    ] = []

    # --------------------------------------------------------
    # Detailed analyzer evidence
    # --------------------------------------------------------

    for finding in findings:
        combined.append(
            {
                "type": "detailed_finding",
                "source": finding.get(
                    "source",
                    "unknown",
                ),
                "indicator_type": finding.get(
                    "indicator_type",
                    "unknown",
                ),
                "severity": finding.get(
                    "severity",
                    "info",
                ),
                "description": finding.get(
                    "description",
                    "",
                ),
                "matched_terms": finding.get(
                    "matched_terms",
                    [],
                ),
                "score_contribution": safe_int(
                    finding.get(
                        "score_contribution",
                        0,
                    )
                ),
            }
        )

    # --------------------------------------------------------
    # Main rule-engine evidence
    # --------------------------------------------------------

    for evidence in score_evidence:
        combined.append(
            {
                "type": "score_signal",
                "source": "risk_engine",
                "indicator_type": evidence.get(
                    "signal",
                    "",
                ),
                "severity": (
                    "medium"
                    if safe_int(
                        evidence.get(
                            "contribution",
                            0,
                        )
                    ) >= 10
                    else "low"
                ),
                "description": evidence.get(
                    "description",
                    "",
                ),
                "matched_terms": [],
                "score_contribution": safe_int(
                    evidence.get(
                        "contribution",
                        0,
                    )
                ),
            }
        )

    # --------------------------------------------------------
    # Sort by importance
    # --------------------------------------------------------

    combined.sort(
        key=lambda item: (
            -severity_rank(
                item.get(
                    "severity",
                    "info",
                )
            ),
            -safe_int(
                item.get(
                    "score_contribution",
                    0,
                )
            ),
            safe_text(
                item.get(
                    "source",
                    "",
                )
            ),
        )
    )

    # --------------------------------------------------------
    # Deduplicate reasons
    # --------------------------------------------------------

    result: List[
        Dict[str, Any]
    ] = []

    seen = set()

    for item in combined:
        key = (
            item.get(
                "source",
                "",
            ),
            item.get(
                "indicator_type",
                "",
            ),
            item.get(
                "description",
                "",
            ),
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


# ============================================================
# RISK MESSAGE
# ============================================================

def build_risk_message(
    score: int,
    classification: str,
) -> str:
    """
    Generate a concise user-facing interpretation.
    """

    score = max(
        0,
        min(
            100,
            score,
        ),
    )

    classification = safe_text(
        classification
    )

    if classification == "HIGH RISK / LIKELY PHISHING":
        return (
            "Multiple risk signals were detected. Treat the message "
            "with caution and verify it through a trusted channel."
        )

    if classification == "SUSPICIOUS":
        return (
            "Several risk signals were detected. Review the evidence "
            "carefully before taking any action."
        )

    if classification == "MODERATE RISK":
        return (
            "Some risk signals were detected. Verify unexpected "
            "requests before responding."
        )

    return (
        "No major configured rule-based risk combination was detected. "
        "This result does not guarantee that the email is safe."
    )


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

def build_security_recommendations(
    risk_result: Optional[
        Dict[str, Any]
    ],
    unified_findings: List[
        Dict[str, Any]
    ],
) -> List[str]:
    """
    Generate a deduplicated list of defensive recommendations.
    """

    recommendations: List[str] = []

    finding_types = {
        safe_text(
            finding.get(
                "indicator_type",
                "",
            )
        ).lower()
        for finding in unified_findings
    }

    sources = {
        safe_text(
            finding.get(
                "source",
                "",
            )
        ).lower()
        for finding in unified_findings
    }

    # --------------------------------------------------------
    # URL-related recommendation
    # --------------------------------------------------------

    if (
        "url" in sources
        or "suspicious_url" in finding_types
        or "raw_ip_address" in finding_types
        or "url_shortener_pattern" in finding_types
    ):
        recommendations.append(
            "Do not click suspicious or unexpected links."
        )

        recommendations.append(
            "Open the organization's official website or application "
            "directly instead of following an unexpected email link."
        )

    # --------------------------------------------------------
    # Attachment-related recommendation
    # --------------------------------------------------------

    if (
        "attachment" in sources
        or any(
            keyword in finding_types
            for keyword in {
                "executable_extension",
                "script_extension",
                "double_extension",
                "suspicious_archive_extension",
                "macro_or_active_content",
            }
        )
    ):
        recommendations.append(
            "Do not open unexpected attachments."
        )

    # --------------------------------------------------------
    # Credential-related recommendation
    # --------------------------------------------------------

    if any(
        keyword in finding_types
        for keyword in {
            "credential_request",
            "contains_password_request",
        }
    ):
        recommendations.append(
            "Do not provide passwords, OTPs, passcodes, or credentials "
            "through an unexpected email request."
        )

    # --------------------------------------------------------
    # Sender-related recommendation
    # --------------------------------------------------------

    if (
        "sender" in sources
        or "suspicious_sender" in finding_types
    ):
        recommendations.append(
            "Verify the sender through a trusted communication channel."
        )

    # --------------------------------------------------------
    # Financial-related recommendation
    # --------------------------------------------------------

    if (
        "financial_pressure" in finding_types
        or "financial_pressure"
        in {
            safe_text(
                finding.get(
                    "indicator_type",
                    "",
                )
            ).lower()
            for finding in unified_findings
        }
    ):
        recommendations.append(
            "Independently verify payment, invoice, or financial requests."
        )

    # --------------------------------------------------------
    # Elevated-risk recommendation
    # --------------------------------------------------------

    score = 0

    if risk_result:
        score = safe_int(
            risk_result.get(
                "phishing_risk_score",
                0,
            )
        )

    if score >= 41:
        recommendations.append(
            "Report the suspicious message to the organization's "
            "security team according to local policy."
        )

    # --------------------------------------------------------
    # Default recommendation
    # --------------------------------------------------------

    if not recommendations:
        recommendations.append(
            "Continue normal email-safety checks and verify unexpected "
            "requests through trusted channels."
        )

    # Deduplicate while preserving order.
    unique: List[str] = []
    seen = set()

    for recommendation in recommendations:
        if recommendation in seen:
            continue

        seen.add(
            recommendation
        )

        unique.append(
            recommendation
        )

    return unique


# ============================================================
# ANALYST REVIEW NOTES
# ============================================================

def build_analyst_notes(
    score: int,
    classification: str,
    unified_findings: List[
        Dict[str, Any]
    ],
) -> List[str]:
    """
    Generate notes useful for an analyst reviewing the result.
    """

    notes: List[str] = []

    score = max(
        0,
        min(
            100,
            score,
        ),
    )

    classification = safe_text(
        classification
    )

    if not unified_findings:
        notes.append(
            "No configured analyzer finding was produced."
        )

    else:
        notes.append(
            f"{len(unified_findings)} explainable finding(s) "
            "were collected from the analysis modules."
        )

    if score >= 71:
        notes.append(
            "The rule engine classified the combined result as "
            "HIGH RISK / LIKELY PHISHING. Analyst review remains required."
        )

    elif score >= 41:
        notes.append(
            "The rule engine classified the result as SUSPICIOUS. "
            "Review the supporting evidence before taking action."
        )

    elif score >= 21:
        notes.append(
            "The result contains moderate risk signals. "
            "Unexpected requests should be independently verified."
        )

    else:
        notes.append(
            "A low rule-based score does not guarantee that an email "
            "is legitimate. Detection should be considered contextual."
        )

    notes.append(
        "Automated scoring supports analyst judgment rather than replacing it."
    )

    return notes


# ============================================================
# SANITIZED EMAIL METADATA
# ============================================================

def build_safe_email_metadata(
    sender: Optional[str] = None,
    sender_domain: Optional[str] = None,
    subject: Optional[str] = None,
) -> Dict[str, str]:
    """
    Store/display only basic email metadata.

    The email body is intentionally excluded.
    """

    metadata: Dict[str, str] = {}

    if sender:
        metadata["sender"] = safe_text(
            sender
        )

    if sender_domain:
        metadata["sender_domain"] = safe_text(
            sender_domain
        )

    if subject:
        metadata["subject"] = safe_text(
            subject
        )

    return metadata


# ============================================================
# MAIN EXPLAINABILITY FUNCTION
# ============================================================

def build_explainable_result(
    risk_result: Optional[
        Dict[str, Any]
    ],
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
    sender: Optional[str] = None,
    sender_domain: Optional[str] = None,
    subject: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build one unified, explainable security result.

    The returned structure is intended for:
    - FastAPI responses
    - frontend dashboard rendering
    - analysis history metadata
    - SOC-style review

    The email body is NOT included in the returned structure.
    """

    risk_result = (
        risk_result
        if isinstance(
            risk_result,
            dict,
        )
        else {}
    )

    score = safe_int(
        risk_result.get(
            "phishing_risk_score",
            0,
        )
    )

    classification = safe_text(
        risk_result.get(
            "classification",
            "LOW RISK",
        )
    )

    unified_findings = (
        collect_all_findings(
            sender_analysis=sender_analysis,
            content_analysis=content_analysis,
            url_analyses=url_analyses,
            attachment_analysis=attachment_analysis,
        )
    )

    score_evidence = (
        build_score_evidence(
            risk_result
        )
    )

    why_suspicious = build_why_suspicious(
        unified_findings,
        score_evidence,
    )

    recommendations = (
        build_security_recommendations(
            risk_result,
            unified_findings,
        )
    )

    analyst_notes = build_analyst_notes(
        score,
        classification,
        unified_findings,
    )

    # --------------------------------------------------------
    # URL summary
    # --------------------------------------------------------

    url_summary: List[
        Dict[str, Any]
    ] = []

    if url_analyses:
        for index, analysis in enumerate(
            url_analyses,
            start=1,
        ):
            if not isinstance(
                analysis,
                dict,
            ):
                continue

            url_summary.append(
                {
                    "url_index": index,
                    "url": safe_text(
                        analysis.get(
                            "url",
                            "",
                        )
                    ),
                    "risk_score": safe_int(
                        analysis.get(
                            "url_risk_score",
                            0,
                        )
                    ),
                    "hostname": safe_text(
                        analysis.get(
                            "hostname",
                            "",
                        )
                    ),
                    "https_present": safe_bool(
                        analysis.get(
                            "https_present",
                            False,
                        )
                    ),
                    "has_ip_address": safe_bool(
                        analysis.get(
                            "has_ip_address",
                            False,
                        )
                    ),
                    "shortened_url_pattern": safe_bool(
                        analysis.get(
                            "shortened_url_pattern",
                            False,
                        )
                    ),
                    "findings_count": len(
                        normalize_findings(
                            analysis.get(
                                "url_findings",
                                [],
                            )
                        )
                    ),
                }
            )

    # --------------------------------------------------------
    # Attachment summary
    # --------------------------------------------------------

    attachment_summary: Dict[str, Any] = {}

    if attachment_analysis:
        attachment_summary = {
            "attachment_name": safe_text(
                attachment_analysis.get(
                    "attachment_name",
                    "",
                )
            ),
            "risk_score": safe_int(
                attachment_analysis.get(
                    "attachment_risk_score",
                    0,
                )
            ),
            "risk_category": safe_text(
                attachment_analysis.get(
                    "attachment_risk",
                    "NO ATTACHMENT",
                )
            ),
            "double_extension": safe_bool(
                attachment_analysis.get(
                    "double_extension",
                    False,
                )
            ),
            "static_analysis_only": safe_bool(
                attachment_analysis.get(
                    "static_analysis_only",
                    True,
                )
            ),
            "execution_performed": safe_bool(
                attachment_analysis.get(
                    "execution_performed",
                    False,
                )
            ),
        }

    # --------------------------------------------------------
    # Sender summary
    # --------------------------------------------------------

    sender_summary: Dict[str, Any] = {}

    if sender_analysis:
        sender_summary = {
            "sender_email": safe_text(
                sender_analysis.get(
                    "sender_email",
                    "",
                )
            ),
            "sender_domain": safe_text(
                sender_analysis.get(
                    "sender_domain",
                    "",
                )
            ),
            "risk_score": safe_int(
                sender_analysis.get(
                    "sender_risk_score",
                    0,
                )
            ),
            "domain_length": safe_int(
                sender_analysis.get(
                    "domain_length",
                    0,
                )
            ),
            "subdomain_count": safe_int(
                sender_analysis.get(
                    "subdomain_count",
                    0,
                )
            ),
            "is_valid_format": safe_bool(
                sender_analysis.get(
                    "is_valid_format",
                    False,
                )
            ),
        }

    # --------------------------------------------------------
    # Content summary
    # --------------------------------------------------------

    content_summary: Dict[str, Any] = {}

    if content_analysis:
        content_summary = {
            "risk_score": safe_int(
                content_analysis.get(
                    "content_risk_score",
                    0,
                )
            ),
            "categories_detected": [
                safe_text(category)
                for category in content_analysis.get(
                    "categories_detected",
                    [],
                )
            ],
            "findings_count": len(
                normalize_findings(
                    content_analysis.get(
                        "content_findings",
                        [],
                    )
                )
            ),
        }

    # --------------------------------------------------------
    # Main result
    # --------------------------------------------------------

    result = {
        "analysis_summary": {
            "phishing_risk_score": score,
            "classification": classification,
            "risk_message": build_risk_message(
                score,
                classification,
            ),
        },
        "email_metadata": build_safe_email_metadata(
            sender=sender,
            sender_domain=sender_domain,
            subject=subject,
        ),
        "why_suspicious": why_suspicious,
        "detected_indicators": [
            {
                "source": finding.get(
                    "source",
                    "unknown",
                ),
                "indicator_type": finding.get(
                    "indicator_type",
                    "unknown",
                ),
                "severity": finding.get(
                    "severity",
                    "info",
                ),
                "description": finding.get(
                    "description",
                    "",
                ),
            }
            for finding in unified_findings
        ],
        "score_evidence": score_evidence,
        "sender_analysis": sender_summary,
        "content_analysis": content_summary,
        "url_analysis": url_summary,
        "attachment_analysis": attachment_summary,
        "recommendations": recommendations,
        "analyst_notes": analyst_notes,
        "privacy": {
            "email_body_included": False,
            "attachment_executed": False,
            "suspicious_urls_visited": False,
            "static_analysis_only": True,
        },
    }

    return result


# ============================================================
# HUMAN-READABLE SUMMARY
# ============================================================

def format_explainable_summary(
    result: Dict[str, Any],
) -> str:
    """
    Create a simple text summary suitable for a terminal
    demonstration or future report.
    """

    summary = result.get(
        "analysis_summary",
        {},
    )

    score = safe_int(
        summary.get(
            "phishing_risk_score",
            0,
        )
    )

    classification = safe_text(
        summary.get(
            "classification",
            "LOW RISK",
        )
    )

    lines = [
        f"PHISHING RISK SCORE: {score}/100",
        f"CLASSIFICATION: {classification}",
        "",
        "WHY?",
    ]

    why = result.get(
        "why_suspicious",
        [],
    )

    if isinstance(
        why,
        list,
    ):
        for index, finding in enumerate(
            why[:10],
            start=1,
        ):
            if not isinstance(
                finding,
                dict,
            ):
                continue

            description = safe_text(
                finding.get(
                    "description",
                    "",
                )
            )

            if description:
                lines.append(
                    f"{index}. {description}"
                )

    lines.append("")
    lines.append(
        "RECOMMENDED ACTIONS:"
    )

    recommendations = result.get(
        "recommendations",
        [],
    )

    if isinstance(
        recommendations,
        list,
    ):
        for recommendation in recommendations:
            lines.append(
                f"- {recommendation}"
            )

    return "\n".join(
        lines
    )


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Run deterministic explainability checks.
    """

    # --------------------------------------------------------
    # Mock outputs representing results from earlier modules.
    # --------------------------------------------------------

    sender_analysis = {
        "sender_risk_score": 25,
        "sender_email": (
            "security-alert@example.org"
        ),
        "sender_domain": "example.org",
        "domain_length": 11,
        "subdomain_count": 0,
        "is_valid_format": True,
        "sender_findings": [
            {
                "indicator_type": "possible_lookalike_pattern",
                "severity": "medium",
                "description": (
                    "The sender domain shows an obvious synthetic "
                    "lookalike characteristic."
                ),
                "score_contribution": 12,
            }
        ],
    }

    content_analysis = {
        "content_risk_score": 55,
        "categories_detected": [
            "urgency",
            "credential_request",
            "fear",
            "generic_greeting",
        ],
        "content_findings": [
            {
                "indicator_type": "urgency",
                "severity": "medium",
                "matched_terms": [
                    "URGENT",
                    "immediately",
                ],
                "description": (
                    "Urgency language was detected."
                ),
            },
            {
                "indicator_type": "credential_request",
                "severity": "high",
                "matched_terms": [
                    "verify your password",
                ],
                "description": (
                    "A credential request was detected."
                ),
            },
        ],
    }

    url_analyses = [
        {
            "url": (
                "http://198.51.100.10/verify-account"
            ),
            "url_risk_score": 30,
            "hostname": "198.51.100.10",
            "https_present": False,
            "has_ip_address": True,
            "shortened_url_pattern": False,
            "url_findings": [
                {
                    "indicator_type": "raw_ip_address",
                    "severity": "high",
                    "description": (
                        "The URL uses a raw IP address."
                    ),
                    "score_contribution": 20,
                }
            ],
        }
    ]

    attachment_analysis = {
        "attachment_name": "invoice.pdf.exe",
        "attachment_risk_score": 60,
        "attachment_risk": "HIGH RISK",
        "double_extension": True,
        "static_analysis_only": True,
        "execution_performed": False,
        "findings": [
            {
                "indicator_type": "executable_extension",
                "severity": "high",
                "description": (
                    "The attachment contains an executable extension."
                ),
                "score_contribution": 35,
            },
            {
                "indicator_type": "double_extension",
                "severity": "high",
                "description": (
                    "The attachment filename contains multiple extensions."
                ),
                "score_contribution": 25,
            },
        ],
    }

    risk_result = {
        "phishing_risk_score": 90,
        "classification": (
            "HIGH RISK / LIKELY PHISHING"
        ),
        "score_contributions": [
            {
                "signal": "suspicious_sender",
                "triggered": True,
                "weight": 15,
                "contribution": 15,
                "description": "Sender risk signal.",
            },
            {
                "signal": "urgency",
                "triggered": True,
                "weight": 10,
                "contribution": 10,
                "description": "Urgency signal.",
            },
            {
                "signal": "credential_request",
                "triggered": True,
                "weight": 20,
                "contribution": 20,
                "description": "Credential request signal.",
            },
            {
                "signal": "suspicious_url",
                "triggered": True,
                "weight": 20,
                "contribution": 20,
                "description": "Suspicious URL signal.",
            },
            {
                "signal": "suspicious_attachment",
                "triggered": True,
                "weight": 25,
                "contribution": 25,
                "description": "Suspicious attachment signal.",
            },
        ],
    }

    result = build_explainable_result(
        risk_result=risk_result,
        sender_analysis=sender_analysis,
        content_analysis=content_analysis,
        url_analyses=url_analyses,
        attachment_analysis=attachment_analysis,
        sender=(
            "security-alert@example.org"
        ),
        sender_domain="example.org",
        subject=(
            "URGENT: Verify Your Account"
        ),
    )

    # --------------------------------------------------------
    # Basic result checks
    # --------------------------------------------------------

    assert (
        result[
            "analysis_summary"
        ][
            "phishing_risk_score"
        ]
        == 90
    )

    assert (
        result[
            "analysis_summary"
        ][
            "classification"
        ]
        == "HIGH RISK / LIKELY PHISHING"
    )

    # --------------------------------------------------------
    # Explainability checks
    # --------------------------------------------------------

    assert (
        len(
            result[
                "why_suspicious"
            ]
        )
        > 0
    )

    assert (
        len(
            result[
                "detected_indicators"
            ]
        )
        > 0
    )

    assert (
        len(
            result[
                "recommendations"
            ]
        )
        > 0
    )

    # --------------------------------------------------------
    # Component summaries
    # --------------------------------------------------------

    assert (
        result[
            "sender_analysis"
        ][
            "risk_score"
        ]
        == 25
    )

    assert (
        result[
            "content_analysis"
        ][
            "risk_score"
        ]
        == 55
    )

    assert (
        len(
            result[
                "url_analysis"
            ]
        )
        == 1
    )

    assert (
        result[
            "attachment_analysis"
        ][
            "double_extension"
        ]
        is True
    )

    # --------------------------------------------------------
    # Privacy checks
    # --------------------------------------------------------

    assert (
        result[
            "privacy"
        ][
            "email_body_included"
        ]
        is False
    )

    assert (
        result[
            "privacy"
        ][
            "attachment_executed"
        ]
        is False
    )

    assert (
        result[
            "privacy"
        ][
            "suspicious_urls_visited"
        ]
        is False
    )

    assert (
        result[
            "privacy"
        ][
            "static_analysis_only"
        ]
        is True
    )

    # --------------------------------------------------------
    # Text summary check
    # --------------------------------------------------------

    summary = format_explainable_summary(
        result
    )

    assert (
        "PHISHING RISK SCORE: 90/100"
        in summary
    )

    assert (
        "HIGH RISK / LIKELY PHISHING"
        in summary
    )

    assert (
        "RECOMMENDED ACTIONS:"
        in summary
    )

    print(
        "Explainability self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()
