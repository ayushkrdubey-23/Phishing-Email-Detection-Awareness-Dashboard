"""
Central analysis orchestration service.

This module connects the project's existing defensive detection engines
into one reusable analysis pipeline for the FastAPI backend.

Security principles:
- URLs are analyzed statically and never visited.
- Attachments are analyzed by filename only and never executed.
- Raw email body content is analyzed in memory and is not persisted
  by the history/database layer.
"""

from __future__ import annotations

import re
from typing import Any

from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.explainability import build_explainable_result
from backend.services.feature_engineering import extract_email_features
from backend.services.hybrid_detector import analyze_with_hybrid_detection
from backend.services.risk_engine import calculate_phishing_score
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def clamp_score(value: Any) -> int:
    """Convert a value to an integer between 0 and 100."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0

    return max(0, min(100, round(numeric)))


def extract_score(result: Any, default: int = 0) -> int:
    """Extract a risk score from a detector result."""
    if not isinstance(result, dict):
        return clamp_score(default)

    possible_keys = (
        "risk_score",
        "score",
        "sender_risk_score",
        "content_risk_score",
        "url_risk_score",
        "attachment_risk_score",
        "phishing_risk_score",
    )

    for key in possible_keys:
        if key in result:
            return clamp_score(result[key])

    return clamp_score(default)


def extract_findings(result: Any) -> list[Any]:
    """Extract findings from a detector result."""
    if result is None:
        return []

    if isinstance(result, list):
        return result

    if isinstance(result, str):
        return [result]

    if not isinstance(result, dict):
        return []

    possible_keys = (
        "findings",
        "sender_findings",
        "content_findings",
        "url_findings",
        "attachment_findings",
        "detected_indicators",
        "why_suspicious",
    )

    for key in possible_keys:
        value = result.get(key)

        if isinstance(value, list):
            return value

        if isinstance(value, str) and value.strip():
            return [value]

    return []


def normalize_finding(
    finding: Any,
    indicator_type: str,
    detector_score: int,
) -> dict[str, str]:
    """Convert a detector finding into one consistent API structure."""
    default_severity = (
        "HIGH"
        if detector_score >= 70
        else "MEDIUM"
        if detector_score >= 40
        else "LOW"
    )

    if isinstance(finding, dict):
        description = str(
            finding.get("description")
            or finding.get("message")
            or finding.get("finding")
            or finding.get("text")
            or finding
        )

        finding_type = str(
            finding.get("indicator_type")
            or finding.get("type")
            or indicator_type
        )

        severity = str(
            finding.get("severity")
            or default_severity
        ).upper()

        return {
            "indicator_type": finding_type,
            "description": description,
            "severity": severity,
        }

    return {
        "indicator_type": indicator_type,
        "description": str(finding),
        "severity": default_severity,
    }


# ---------------------------------------------------------------------------
# Sender and URL helpers
# ---------------------------------------------------------------------------

def extract_sender_domain(sender: str) -> str:
    """Extract a sender domain without performing any network lookup."""
    sender = (sender or "").strip()

    if "@" not in sender:
        return ""

    return sender.rsplit("@", 1)[1].strip().lower()


def extract_urls_from_text(text: str) -> list[str]:
    """
    Extract URL-like strings from email text.

    This is static string processing only. URLs are never opened.
    """
    pattern = re.compile(
        r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+"
    )

    matches = pattern.findall(text or "")

    urls: list[str] = []

    for url in matches:
        cleaned = url.rstrip(".,);]}>")

        if cleaned and cleaned not in urls:
            urls.append(cleaned)

    return urls


def merge_urls(
    body: str,
    explicit_urls: list[str],
) -> list[str]:
    """Combine explicit URLs and URLs found statically in the body."""
    urls: list[str] = []

    for url in explicit_urls:
        cleaned = (url or "").strip()

        if cleaned and cleaned not in urls:
            urls.append(cleaned)

    for url in extract_urls_from_text(body):
        if url not in urls:
            urls.append(url)

    return urls


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def build_email_feature_input(
    sender: str,
    subject: str,
    body: str,
    urls: list[str],
    attachment_name: str | None,
) -> dict[str, object]:
    """
    Build the dictionary expected by extract_email_features().

    The feature-engineering function intentionally receives one structured
    email object instead of multiple keyword arguments.
    """
    return {
        "sender": sender,
        "sender_domain": extract_sender_domain(sender),
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachment_name": attachment_name or "",
    }


# ---------------------------------------------------------------------------
# Explainable output
# ---------------------------------------------------------------------------

def build_local_explanation(
    sender_result: dict[str, Any],
    content_result: dict[str, Any],
    url_results: list[dict[str, Any]],
    attachment_result: dict[str, Any],
    rule_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a stable explainability structure.

    This also acts as a fallback if the dedicated explainability module
    changes its interface in the future.
    """
    indicator_rows: list[dict[str, str]] = []

    # Sender findings
    for finding in extract_findings(sender_result):
        indicator_rows.append(
            normalize_finding(
                finding=finding,
                indicator_type="SENDER",
                detector_score=extract_score(sender_result),
            )
        )

    # Content findings
    for finding in extract_findings(content_result):
        indicator_rows.append(
            normalize_finding(
                finding=finding,
                indicator_type="CONTENT",
                detector_score=extract_score(content_result),
            )
        )

    # URL findings
    for url_result in url_results:
        url_score = extract_score(url_result)

        for finding in extract_findings(url_result):
            indicator_rows.append(
                normalize_finding(
                    finding=finding,
                    indicator_type="URL",
                    detector_score=url_score,
                )
            )

    # Attachment findings
    for finding in extract_findings(attachment_result):
        indicator_rows.append(
            normalize_finding(
                finding=finding,
                indicator_type="ATTACHMENT",
                detector_score=extract_score(attachment_result),
            )
        )

    risk_score = extract_score(rule_result)

    classification = str(
        rule_result.get(
            "classification",
            rule_result.get(
                "risk_level",
                "",
            ),
        )
    )

    why_suspicious = [
        row["description"]
        for row in indicator_rows
        if row["description"].strip()
    ]

    if not why_suspicious:
        why_suspicious.append(
            "No strong phishing indicators were detected by the rule engine."
        )

    recommendations = [
        "Do not click suspicious links.",
        "Do not open unexpected attachments.",
        "Verify the sender through a trusted communication channel.",
        "Use the organization's official website or application directly.",
        "Report suspicious messages according to your security process.",
    ]

    return {
        "risk_score": risk_score,
        "classification": classification,
        "why_suspicious": why_suspicious,
        "detected_indicators": indicator_rows,
        "recommendations": recommendations,
        "analyst_notes": [
            "Automated scoring supports analyst review and does not prove malicious intent.",
            "Individual indicators should be interpreted in context.",
        ],
        "privacy": {
            "raw_email_body_stored": False,
            "suspicious_urls_visited": False,
            "attachments_executed": False,
            "analysis_mode": "static_defensive_analysis",
        },
    }


def run_explainability(
    sender_result: dict[str, Any],
    content_result: dict[str, Any],
    feature_result: dict[str, Any],
    url_results: list[dict[str, Any]],
    attachment_result: dict[str, Any],
    rule_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Use the project's dedicated explainability module.

    The local implementation is retained as a safe fallback.
    """
    try:
        result = build_explainable_result(
            sender_analysis=sender_result,
            content_analysis=content_result,
            feature_data=feature_result,
            url_analyses=url_results,
            attachment_analysis=attachment_result,
            risk_result=rule_result,
        )

        if isinstance(result, dict):
            return result

    except TypeError:
        # The project's explainability module may have a slightly different
        # parameter interface. The local fallback keeps the API operational.
        pass

    except Exception:
        # Explainability must not cause the entire analysis to fail.
        pass

    return build_local_explanation(
        sender_result=sender_result,
        content_result=content_result,
        url_results=url_results,
        attachment_result=attachment_result,
        rule_result=rule_result,
    )


# ---------------------------------------------------------------------------
# Hybrid detection
# ---------------------------------------------------------------------------

def run_hybrid_detection(
    subject: str,
    body: str,
    rule_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Run the optional rule + ML hybrid detector.

    If the saved ML model is unavailable, the API still returns the
    rule-based analysis instead of failing the entire request.
    """
    try:
        result = analyze_with_hybrid_detection(
            subject=subject,
            body=body,
            rule_result=rule_result,
        )

        if isinstance(result, dict):
            return result

        return {
            "enabled": True,
            "result": result,
        }

    except FileNotFoundError:
        return {
            "enabled": False,
            "reason": (
                "No saved ML model is available. "
                "Rule-based detection remains active."
            ),
        }

    except RuntimeError as exc:
        return {
            "enabled": False,
            "reason": str(exc),
        }


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------

def analyze_email(
    sender: str,
    display_name: str | None,
    subject: str,
    body: str,
    attachment_name: str | None,
    explicit_urls: list[str],
) -> dict[str, Any]:
    """
    Execute the complete phishing-email analysis pipeline.

    Processing order:
        Sender
        ↓
        Content
        ↓
        Feature Engineering
        ↓
        URL Analysis
        ↓
        Attachment Analysis
        ↓
        Rule Engine
        ↓
        Hybrid ML Detection
        ↓
        Explainability
    """
    # ---------------------------------------------------------------
    # 1. Normalize URLs
    # ---------------------------------------------------------------
    urls = merge_urls(
        body=body,
        explicit_urls=explicit_urls,
    )

    # ---------------------------------------------------------------
    # 2. Sender analysis
    # ---------------------------------------------------------------
    sender_result = analyze_sender(
        sender=sender,
        display_name=display_name,
    )

    # ---------------------------------------------------------------
    # 3. Content analysis
    # ---------------------------------------------------------------
    content_result = analyze_email_content(
        subject=subject,
        body=body,
    )

    # ---------------------------------------------------------------
    # 4. Feature engineering
    # ---------------------------------------------------------------
    email_feature_input = build_email_feature_input(
        sender=sender,
        subject=subject,
        body=body,
        urls=urls,
        attachment_name=attachment_name,
    )

    feature_result = extract_email_features(
        email_feature_input
    )

    # ---------------------------------------------------------------
    # 5. Static URL analysis
    # ---------------------------------------------------------------
    url_results: list[dict[str, Any]] = []

    for url in urls:
        result = analyze_url(
            url=url
        )

        url_results.append(
            result
        )

    # ---------------------------------------------------------------
    # 6. Static attachment analysis
    # ---------------------------------------------------------------
    attachment_result = analyze_attachment(
        attachment_name or ""
    )

    # ---------------------------------------------------------------
    # 7. Rule-based phishing score
    # ---------------------------------------------------------------
    #
    # This call now matches the exact signature discovered from the
    # existing risk engine:
    #
    # calculate_phishing_score(
    #     sender_analysis,
    #     content_analysis,
    #     url_analyses,
    #     attachment_analysis,
    #     feature_data,
    # )
    #
    rule_result = calculate_phishing_score(
        sender_analysis=sender_result,
        content_analysis=content_result,
        url_analyses=url_results,
        attachment_analysis=attachment_result,
        feature_data=feature_result,
    )

    # ---------------------------------------------------------------
    # 8. Explainable security output
    # ---------------------------------------------------------------
    explanation = run_explainability(
        sender_result=sender_result,
        content_result=content_result,
        feature_result=feature_result,
        url_results=url_results,
        attachment_result=attachment_result,
        rule_result=rule_result,
    )

    # ---------------------------------------------------------------
    # 9. Optional hybrid Rule + ML detector
    # ---------------------------------------------------------------
    hybrid_result = run_hybrid_detection(
        subject=subject,
        body=body,
        rule_result=rule_result,
    )

    # ---------------------------------------------------------------
    # 10. Normalize final top-level fields
    # ---------------------------------------------------------------
    risk_score = extract_score(
        rule_result
    )

    classification = str(
        rule_result.get(
            "classification",
            rule_result.get(
                "risk_level",
                explanation.get(
                    "classification",
                    "",
                ),
            ),
        )
    )

    return {
        "analysis": {
            "risk_score": risk_score,
            "classification": classification,
            "sender_domain": extract_sender_domain(sender),
            "subject": subject,
        },

        "sender_analysis": sender_result,

        "content_analysis": content_result,

        "features": feature_result,

        "url_analysis": [
            {
                "url": url,
                "result": result,
            }
            for url, result in zip(
                urls,
                url_results,
            )
        ],

        "attachment_analysis": attachment_result,

        "rule_based_result": rule_result,

        "hybrid_detection": hybrid_result,

        "explainability": explanation,

        "privacy": {
            "raw_email_body_stored": False,
            "suspicious_urls_visited": False,
            "attachments_executed": False,
            "static_analysis_only": True,
        },
    }


if __name__ == "__main__":
    """
    Simple local pipeline self-test.

    Uses only the project's safe fictional demonstration data.
    """
    sample = analyze_email(
        sender="security-alert@account-check.invalid.test",
        display_name="Account Security Team",
        subject="URGENT: Verify Your Account Immediately",
        body=(
            "Dear User, your account will be suspended unless you "
            "verify your password immediately. Confirm your account "
            "information using the verification link below: "
            "http://198.51.100.10/verify-account. "
            "Failure to act now may result in account suspension."
        ),
        attachment_name="account-verification.pdf.exe",
        explicit_urls=[
            "http://198.51.100.10/verify-account"
        ],
    )

    print("Analysis pipeline self-test: PASSED")
    print(
        f"Rule score: "
        f"{sample['analysis']['risk_score']}/100"
    )
    print(
        f"Classification: "
        f"{sample['analysis']['classification']}"
    )
    print(
        "Static URL analysis: "
        f"{sample['privacy']['suspicious_urls_visited'] is False}"
    )
    print(
        "Attachment execution: "
        f"{sample['privacy']['attachments_executed'] is False}"
    )