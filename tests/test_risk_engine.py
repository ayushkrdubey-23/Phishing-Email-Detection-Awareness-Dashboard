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


from backend.services.risk_engine import (  # noqa: E402
    calculate_phishing_score,
    classify_risk,
    format_risk_explanation,
    get_triggered_contributions,
)


# ============================================================
# TEST CLASS
# ============================================================

class RiskEngineTests(
    unittest.TestCase
):
    """
    Unit tests for the rule-based phishing risk engine.
    """

    def test_empty_input(
        self,
    ) -> None:

        result = calculate_phishing_score()

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            0,
        )

        self.assertEqual(
            result[
                "classification"
            ],
            "LOW RISK",
        )

    def test_suspicious_sender_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            sender_analysis={
                "sender_risk_score": 20
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            15,
        )

    def test_urgency_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            content_analysis={
                "categories_detected": [
                    "urgency"
                ]
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            10,
        )

    def test_credential_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            content_analysis={
                "categories_detected": [
                    "credential_request"
                ]
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            20,
        )

    def test_url_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            url_analyses=[
                {
                    "url_risk_score": 25
                }
            ]
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            20,
        )

    def test_attachment_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            attachment_analysis={
                "attachment_risk_score": 30
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            25,
        )

    def test_generic_greeting_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            content_analysis={
                "categories_detected": [
                    "generic_greeting"
                ]
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            5,
        )

    def test_threat_weight(
        self,
    ) -> None:

        result = calculate_phishing_score(
            content_analysis={
                "categories_detected": [
                    "fear"
                ]
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            10,
        )

    def test_all_weights_are_applied(
        self,
    ) -> None:

        result = calculate_phishing_score(
            sender_analysis={
                "sender_risk_score": 50
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
                    "url_risk_score": 50
                }
            ],
            attachment_analysis={
                "attachment_risk_score": 50
            },
        )

        self.assertEqual(
            result[
                "raw_score_before_cap"
            ],
            105,
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            100,
        )

    def test_score_is_capped_at_100(
        self,
    ) -> None:

        result = calculate_phishing_score(
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
                    "url_risk_score": 100
                }
            ],
            attachment_analysis={
                "attachment_risk_score": 100
            },
        )

        self.assertLessEqual(
            result[
                "phishing_risk_score"
            ],
            100,
        )

    def test_low_risk_boundary(
        self,
    ) -> None:

        self.assertEqual(
            classify_risk(20),
            "LOW RISK",
        )

    def test_moderate_risk_boundary(
        self,
    ) -> None:

        self.assertEqual(
            classify_risk(21),
            "MODERATE RISK",
        )

    def test_suspicious_boundary(
        self,
    ) -> None:

        self.assertEqual(
            classify_risk(41),
            "SUSPICIOUS",
        )

    def test_high_risk_boundary(
        self,
    ) -> None:

        self.assertEqual(
            classify_risk(71),
            "HIGH RISK / LIKELY PHISHING",
        )

    def test_feature_fallback(
        self,
    ) -> None:

        result = calculate_phishing_score(
            feature_data={
                "urgent_keyword_count": 1,
                "contains_password_request": True,
                "threat_keyword_count": 1,
                "suspicious_url_count": 1,
                "suspicious_attachment": True,
                "generic_greeting": True,
            }
        )

        self.assertEqual(
            result[
                "phishing_risk_score"
            ],
            90,
        )

    def test_triggered_contributions(
        self,
    ) -> None:

        result = calculate_phishing_score(
            content_analysis={
                "categories_detected": [
                    "urgency",
                    "credential_request",
                ]
            }
        )

        triggered = (
            get_triggered_contributions(
                result
            )
        )

        self.assertEqual(
            len(triggered),
            2,
        )

        signals = {
            item["signal"]
            for item in triggered
        }

        self.assertIn(
            "urgency",
            signals,
        )

        self.assertIn(
            "credential_request",
            signals,
        )

    def test_explainable_output(
        self,
    ) -> None:

        result = calculate_phishing_score(
            content_analysis={
                "categories_detected": [
                    "credential_request"
                ]
            }
        )

        explanations = (
            format_risk_explanation(
                result
            )
        )

        self.assertEqual(
            len(explanations),
            1,
        )

        self.assertIn(
            "+20",
            explanations[0],
        )

        self.assertIn(
            "credential",
            explanations[0].lower(),
        )

    def test_project_assumption_flag(
        self,
    ) -> None:

        result = calculate_phishing_score()

        self.assertTrue(
            result[
                "thresholds_are_project_assumptions"
            ]
        )

        self.assertTrue(
            result[
                "requires_validation_calibration"
            ]
        )

    def test_probability_is_not_fabricated(
        self,
    ) -> None:

        result = calculate_phishing_score()

        self.assertIsNone(
            result[
                "probability"
            ]
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )
    