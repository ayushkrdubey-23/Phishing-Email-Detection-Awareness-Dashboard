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


from backend.services.content_analyzer import (  # noqa: E402
    analyze_email_content,
    detect_generic_greeting,
    detect_language_anomalies,
    detect_unusual_formatting,
    find_pattern_matches,
)


# ============================================================
# TEST CLASS
# ============================================================

class ContentAnalyzerTests(
    unittest.TestCase
):
    """
    Unit tests for the email content analysis engine.
    """

    # --------------------------------------------------------
    # 1. Urgency
    # --------------------------------------------------------

    def test_urgency_detection(
        self,
    ) -> None:

        result = analyze_email_content(
            "URGENT: Act now",
            "Please respond immediately.",
        )

        categories = set(
            result["categories_detected"]
        )

        self.assertIn(
            "urgency",
            categories,
        )

    # --------------------------------------------------------
    # 2. Fear / threat
    # --------------------------------------------------------

    def test_fear_detection(
        self,
    ) -> None:

        result = analyze_email_content(
            "Account warning",
            "Your account will be suspended.",
        )

        self.assertIn(
            "fear",
            set(
                result["categories_detected"]
            ),
        )

    # --------------------------------------------------------
    # 3. Financial pressure
    # --------------------------------------------------------

    def test_financial_pressure(
        self,
    ) -> None:

        result = analyze_email_content(
            "Invoice due",
            "An outstanding payment is required today.",
        )

        self.assertIn(
            "financial_pressure",
            set(
                result["categories_detected"]
            ),
        )

    # --------------------------------------------------------
    # 4. Credential request
    # --------------------------------------------------------

    def test_credential_request(
        self,
    ) -> None:

        result = analyze_email_content(
            "Verify account",
            "Please verify your password immediately.",
        )

        self.assertIn(
            "credential_request",
            set(
                result["categories_detected"]
            ),
        )

    # --------------------------------------------------------
    # 5. Reward detection
    # --------------------------------------------------------

    def test_reward_detection(
        self,
    ) -> None:

        result = analyze_email_content(
            "Congratulations",
            "You have won a special reward.",
        )

        self.assertIn(
            "reward",
            set(
                result["categories_detected"]
            ),
        )

    # --------------------------------------------------------
    # 6. Personal-information request
    # --------------------------------------------------------

    def test_personal_information_detection(
        self,
    ) -> None:

        result = analyze_email_content(
            "Identity verification",
            "Confirm your personal details and address.",
        )

        self.assertIn(
            "personal_information",
            set(
                result["categories_detected"]
            ),
        )

    # --------------------------------------------------------
    # 7. CTA detection
    # --------------------------------------------------------

    def test_call_to_action_detection(
        self,
    ) -> None:

        result = analyze_email_content(
            "Action required",
            "Click here to verify your account.",
        )

        self.assertIn(
            "suspicious_call_to_action",
            set(
                result["categories_detected"]
            ),
        )

    # --------------------------------------------------------
    # 8. Generic greeting
    # --------------------------------------------------------

    def test_generic_greeting(
        self,
    ) -> None:

        self.assertTrue(
            detect_generic_greeting(
                "Dear Customer,\nPlease review this notice."
            )
        )

    # --------------------------------------------------------
    # 9. Specific greeting
    # --------------------------------------------------------

    def test_specific_greeting(
        self,
    ) -> None:

        self.assertFalse(
            detect_generic_greeting(
                "Hello Ayush,\nPlease review this notice."
            )
        )

    # --------------------------------------------------------
    # 10. Formatting anomaly
    # --------------------------------------------------------

    def test_unusual_formatting(
        self,
    ) -> None:

        findings = detect_unusual_formatting(
            "URGENT!!!",
            "ACT NOW!!! VERIFY!!!",
        )

        self.assertTrue(
            len(findings) > 0
        )

    # --------------------------------------------------------
    # 11. Language anomaly
    # --------------------------------------------------------

    def test_repeated_word_anomaly(
        self,
    ) -> None:

        findings = detect_language_anomalies(
            "",
            "Please verify verify your account.",
        )

        self.assertIn(
            "repeated word pattern",
            findings,
        )

    # --------------------------------------------------------
    # 12. Case-insensitive matching
    # --------------------------------------------------------

    def test_case_insensitive_matching(
        self,
    ) -> None:

        matches = find_pattern_matches(
            "ACT NOW for verification",
            [r"\bact now\b"],
        )

        self.assertEqual(
            len(matches),
            1,
        )

        self.assertEqual(
            matches[0].lower(),
            "act now",
        )

    # --------------------------------------------------------
    # 13. Multiple categories
    # --------------------------------------------------------

    def test_multiple_categories(
        self,
    ) -> None:

        result = analyze_email_content(
            "URGENT: Verify your password",
            (
                "Dear Customer, your account will be suspended. "
                "Please verify your password and confirm your "
                "personal details."
            ),
        )

        categories = set(
            result["categories_detected"]
        )

        self.assertGreaterEqual(
            len(categories),
            4,
        )

    # --------------------------------------------------------
    # 14. Empty email
    # --------------------------------------------------------

    def test_empty_email(
        self,
    ) -> None:

        result = analyze_email_content(
            "",
            "",
        )

        self.assertEqual(
            result["content_risk_score"],
            0,
        )

        self.assertEqual(
            result["content_findings"],
            [],
        )

    # --------------------------------------------------------
    # 15. Findings contain explanations
    # --------------------------------------------------------

    def test_findings_are_explainable(
        self,
    ) -> None:

        result = analyze_email_content(
            "URGENT: Verify your password",
            "Your account will be suspended.",
        )

        findings = result[
            "content_findings"
        ]

        self.assertGreater(
            len(findings),
            0,
        )

        for finding in findings:
            self.assertIn(
                "indicator_type",
                finding,
            )

            self.assertIn(
                "severity",
                finding,
            )

            self.assertIn(
                "matched_terms",
                finding,
            )

            self.assertIn(
                "description",
                finding,
            )

    # --------------------------------------------------------
    # 16. Score is within allowed range
    # --------------------------------------------------------

    def test_score_range(
        self,
    ) -> None:

        result = analyze_email_content(
            "URGENT!!!",
            (
                "Dear Customer, verify your password immediately. "
                "Your account will be suspended. "
                "Confirm your personal details and payment information. "
                "You have won a reward. Click here now!!!"
            ),
        )

        score = result[
            "content_risk_score"
        ]

        self.assertGreaterEqual(
            score,
            0,
        )

        self.assertLessEqual(
            score,
            100,
        )


# ============================================================
# TEST RUNNER
# ============================================================

if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )
    