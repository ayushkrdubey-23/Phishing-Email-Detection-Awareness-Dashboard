from __future__ import annotations

import sys
import unittest
from pathlib import Path


# ============================================================
# MAKE PROJECT ROOT IMPORTABLE
# ============================================================

PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from backend.services.sender_analyzer import (  # noqa: E402
    analyze_sender,
    contains_possible_lookalike_pattern,
    count_subdomains,
    display_name_domain_mismatch,
    has_unusual_domain_characters,
    is_valid_email_format,
)


# ============================================================
# TEST CASES
# ============================================================

class SenderAnalyzerTests(
    unittest.TestCase
):
    """
    Unit tests for the sender analysis engine.
    """

    # --------------------------------------------------------
    # 1. Valid sender format
    # --------------------------------------------------------

    def test_valid_email_format(self) -> None:
        self.assertTrue(
            is_valid_email_format(
                "training@example.org"
            )
        )

    # --------------------------------------------------------
    # 2. Invalid sender format
    # --------------------------------------------------------

    def test_invalid_email_format(self) -> None:
        self.assertFalse(
            is_valid_email_format(
                "not-a-valid-email"
            )
        )

    # --------------------------------------------------------
    # 3. Domain extraction through analysis
    # --------------------------------------------------------

    def test_sender_domain(self) -> None:
        result = analyze_sender(
            "alerts@example.org"
        )

        self.assertEqual(
            result["sender_domain"],
            "example.org",
        )

    # --------------------------------------------------------
    # 4. Normal domain does not automatically create risk
    # --------------------------------------------------------

    def test_normal_domain_has_no_sender_risk(
        self,
    ) -> None:

        result = analyze_sender(
            "training@example.org"
        )

        self.assertEqual(
            result["sender_risk_score"],
            0,
        )

    # --------------------------------------------------------
    # 5. Subdomain counting
    # --------------------------------------------------------

    def test_subdomain_count(self) -> None:
        self.assertEqual(
            count_subdomains(
                "secure.mail.example.org"
            ),
            2,
        )

    # --------------------------------------------------------
    # 6. Excessive subdomain finding
    # --------------------------------------------------------

    def test_excessive_subdomains(
        self,
    ) -> None:

        result = analyze_sender(
            "security@a.b.c.example.org"
        )

        self.assertGreaterEqual(
            result["sender_risk_score"],
            10,
        )

        types = {
            finding["indicator_type"]
            for finding in result[
                "sender_findings"
            ]
        }

        self.assertIn(
            "excessive_subdomains",
            types,
        )

    # --------------------------------------------------------
    # 7. Mixed alpha-numeric lookalike
    # --------------------------------------------------------

    def test_lookalike_pattern(
        self,
    ) -> None:

        self.assertTrue(
            contains_possible_lookalike_pattern(
                "examp1e.com"
            )
        )

    # --------------------------------------------------------
    # 8. Lookalike analysis finding
    # --------------------------------------------------------

    def test_lookalike_finding(
        self,
    ) -> None:

        result = analyze_sender(
            "support@examp1e.com"
        )

        types = {
            finding["indicator_type"]
            for finding in result[
                "sender_findings"
            ]
        }

        self.assertIn(
            "possible_lookalike_pattern",
            types,
        )

    # --------------------------------------------------------
    # 9. Unusual domain characters
    # --------------------------------------------------------

    def test_unusual_domain_characters(
        self,
    ) -> None:

        self.assertFalse(
            has_unusual_domain_characters(
                "example.org"
            )
        )

    # --------------------------------------------------------
    # 10. Display-name/domain mismatch
    # --------------------------------------------------------

    def test_display_name_domain_mismatch(
        self,
    ) -> None:

        result = display_name_domain_mismatch(
            "Example Training",
            "example.org",
        )

        self.assertFalse(
            result
        )

        mismatch = display_name_domain_mismatch(
            "Completely Different Organization",
            "example.org",
        )

        self.assertTrue(
            mismatch
        )

    # --------------------------------------------------------
    # 11. Display-name finding in full analysis
    # --------------------------------------------------------

    def test_display_name_finding(
        self,
    ) -> None:

        result = analyze_sender(
            sender="notice@example.org",
            display_name="Completely Different Organization",
        )

        types = {
            finding["indicator_type"]
            for finding in result[
                "sender_findings"
            ]
        }

        self.assertIn(
            "display_name_domain_mismatch",
            types,
        )

    # --------------------------------------------------------
    # 12. Invalid sender produces finding
    # --------------------------------------------------------

    def test_invalid_sender_produces_finding(
        self,
    ) -> None:

        result = analyze_sender(
            "invalid-sender"
        )

        types = {
            finding["indicator_type"]
            for finding in result[
                "sender_findings"
            ]
        }

        self.assertIn(
            "invalid_sender_format",
            types,
        )

        self.assertGreaterEqual(
            result["sender_risk_score"],
            25,
        )


# ============================================================
# TEST RUNNER
# ============================================================

if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )
    