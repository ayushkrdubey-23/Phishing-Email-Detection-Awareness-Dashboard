from __future__ import annotations

import sys
import unittest
from pathlib import Path


# ============================================================
# MAKE PROJECT ROOT IMPORTABLE
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from backend.services.explainability import (  # noqa: E402
    build_explainable_result,
    build_risk_message,
    build_safe_email_metadata,
    collect_all_findings,
    format_explainable_summary,
)


# ============================================================
# TEST CLASS
# ============================================================

class ExplainabilityTests(
    unittest.TestCase
):
    """
    Unit tests for the unified explainability layer.
    """

    def _build_sample_inputs(
        self,
    ):
        """
        Create deterministic sample analyzer results.
        """

        sender_analysis = {
            "sender_risk_score": 15,
            "sender_email": (
                "alerts@example.org"
            ),
            "sender_domain": "example.org",
            "domain_length": 11,
            "subdomain_count": 0,
            "is_valid_format": True,
            "sender_findings": [
                {
                    "indicator_type": "possible_lookalike_pattern",
                    "severity": "medium",
                    "description": "Lookalike pattern detected.",
                    "score_contribution": 12,
                }
            ],
        }

        content_analysis = {
            "content_risk_score": 20,
            "categories_detected": [
                "urgency",
                "credential_request",
            ],
            "content_findings": [
                {
                    "indicator_type": "urgency",
                    "severity": "medium",
                    "matched_terms": [
                        "urgent"
                    ],
                    "description": "Urgency detected.",
                },
                {
                    "indicator_type": "credential_request",
                    "severity": "high",
                    "matched_terms": [
                        "password"
                    ],
                    "description": "Credential request detected.",
                },
            ],
        }

        url_analyses = [
            {
                "url": (
                    "http://198.51.100.10/verify"
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
                        "description": "Raw IP detected.",
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
                    "description": "Executable extension detected.",
                    "score_contribution": 35,
                }
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
                    "description": "Sender signal.",
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
                    "description": "Credential signal.",
                },
                {
                    "signal": "suspicious_url",
                    "triggered": True,
                    "weight": 20,
                    "contribution": 20,
                    "description": "URL signal.",
                },
                {
                    "signal": "suspicious_attachment",
                    "triggered": True,
                    "weight": 25,
                    "contribution": 25,
                    "description": "Attachment signal.",
                },
            ],
        }

        return (
            sender_analysis,
            content_analysis,
            url_analyses,
            attachment_analysis,
            risk_result,
        )

    # --------------------------------------------------------
    # 1. Findings collection
    # --------------------------------------------------------

    def test_collect_all_findings(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            _,
        ) = self._build_sample_inputs()

        findings = collect_all_findings(
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        self.assertGreater(
            len(findings),
            0,
        )

    # --------------------------------------------------------
    # 2. Sources are preserved
    # --------------------------------------------------------

    def test_finding_sources(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            _,
        ) = self._build_sample_inputs()

        findings = collect_all_findings(
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        sources = {
            finding["source"]
            for finding in findings
        }

        self.assertIn(
            "sender",
            sources,
        )

        self.assertIn(
            "content",
            sources,
        )

        self.assertIn(
            "url",
            sources,
        )

        self.assertIn(
            "attachment",
            sources,
        )

    # --------------------------------------------------------
    # 3. Main result
    # --------------------------------------------------------

    def test_build_explainable_result(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
            sender="alerts@example.org",
            sender_domain="example.org",
            subject="URGENT: Verify",
        )

        self.assertEqual(
            result[
                "analysis_summary"
            ][
                "phishing_risk_score"
            ],
            90,
        )

    # --------------------------------------------------------
    # 4. Classification preserved
    # --------------------------------------------------------

    def test_classification_preserved(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        self.assertEqual(
            result[
                "analysis_summary"
            ][
                "classification"
            ],
            "HIGH RISK / LIKELY PHISHING",
        )

    # --------------------------------------------------------
    # 5. Why section exists
    # --------------------------------------------------------

    def test_why_section(
        self,
    ) -> None:

        *_, risk = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk
        )

        self.assertGreater(
            len(
                result[
                    "why_suspicious"
                ]
            ),
            0,
        )

    # --------------------------------------------------------
    # 6. Recommendations exist
    # --------------------------------------------------------

    def test_recommendations(
        self,
    ) -> None:

        *_, risk = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk
        )

        self.assertGreater(
            len(
                result[
                    "recommendations"
                ]
            ),
            0,
        )

    # --------------------------------------------------------
    # 7. Email body not returned
    # --------------------------------------------------------

    def test_email_body_not_in_output(
        self,
    ) -> None:

        *_, risk = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender="alerts@example.org",
            subject="Demo Subject",
        )

        serialized = str(
            result
        )

        self.assertNotIn(
            "SECRET_REAL_EMAIL_BODY",
            serialized,
        )

        self.assertFalse(
            result[
                "privacy"
            ][
                "email_body_included"
            ]
        )

    # --------------------------------------------------------
    # 8. Static-only privacy flags
    # --------------------------------------------------------

    def test_static_only_flags(
        self,
    ) -> None:

        *_, risk = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk
        )

        self.assertFalse(
            result[
                "privacy"
            ][
                "attachment_executed"
            ]
        )

        self.assertFalse(
            result[
                "privacy"
            ][
                "suspicious_urls_visited"
            ]
        )

        self.assertTrue(
            result[
                "privacy"
            ][
                "static_analysis_only"
            ]
        )

    # --------------------------------------------------------
    # 9. URL summary
    # --------------------------------------------------------

    def test_url_summary(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        self.assertEqual(
            len(
                result[
                    "url_analysis"
                ]
            ),
            1,
        )

        self.assertTrue(
            result[
                "url_analysis"
            ][0][
                "has_ip_address"
            ]
        )

    # --------------------------------------------------------
    # 10. Attachment summary
    # --------------------------------------------------------

    def test_attachment_summary(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        self.assertTrue(
            result[
                "attachment_analysis"
            ][
                "double_extension"
            ]
        )

    # --------------------------------------------------------
    # 11. Sender summary
    # --------------------------------------------------------

    def test_sender_summary(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        self.assertEqual(
            result[
                "sender_analysis"
            ][
                "risk_score"
            ],
            15,
        )

    # --------------------------------------------------------
    # 12. Content summary
    # --------------------------------------------------------

    def test_content_summary(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        self.assertEqual(
            result[
                "content_analysis"
            ][
                "risk_score"
            ],
            20,
        )

    # --------------------------------------------------------
    # 13. Safe metadata
    # --------------------------------------------------------

    def test_safe_email_metadata(
        self,
    ) -> None:

        metadata = build_safe_email_metadata(
            sender="alerts@example.org",
            sender_domain="example.org",
            subject="Demo",
        )

        self.assertEqual(
            metadata["sender"],
            "alerts@example.org",
        )

        self.assertEqual(
            metadata["sender_domain"],
            "example.org",
        )

        self.assertEqual(
            metadata["subject"],
            "Demo",
        )

        self.assertNotIn(
            "body",
            metadata,
        )

    # --------------------------------------------------------
    # 14. Risk message high
    # --------------------------------------------------------

    def test_high_risk_message(
        self,
    ) -> None:

        message = build_risk_message(
            90,
            "HIGH RISK / LIKELY PHISHING",
        )

        self.assertIn(
            "Multiple risk signals",
            message,
        )

    # --------------------------------------------------------
    # 15. Risk message low
    # --------------------------------------------------------

    def test_low_risk_message(
        self,
    ) -> None:

        message = build_risk_message(
            0,
            "LOW RISK",
        )

        self.assertIn(
            "does not guarantee",
            message,
        )

    # --------------------------------------------------------
    # 16. Text summary
    # --------------------------------------------------------

    def test_formatted_summary(
        self,
    ) -> None:

        (
            sender,
            content,
            urls,
            attachment,
            risk,
        ) = self._build_sample_inputs()

        result = build_explainable_result(
            risk_result=risk,
            sender_analysis=sender,
            content_analysis=content,
            url_analyses=urls,
            attachment_analysis=attachment,
        )

        summary = format_explainable_summary(
            result
        )

        self.assertIn(
            "PHISHING RISK SCORE: 90/100",
            summary,
        )

        self.assertIn(
            "CLASSIFICATION",
            summary,
        )

        self.assertIn(
            "RECOMMENDED ACTIONS",
            summary,
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )