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


from backend.services.url_analyzer import (  # noqa: E402
    analyze_url,
    count_subdomains,
    find_suspicious_keywords,
    is_raw_ip,
    is_shortened_url,
)


# ============================================================
# TEST CLASS
# ============================================================

class URLAnalyzerTests(
    unittest.TestCase
):
    """
    Unit tests for static URL analysis.
    """

    def test_safe_https_url(
        self,
    ) -> None:

        result = analyze_url(
            "https://example.org/training"
        )

        self.assertEqual(
            result["scheme"],
            "https",
        )

        self.assertEqual(
            result["hostname"],
            "example.org",
        )

        self.assertTrue(
            result["https_present"]
        )

        self.assertFalse(
            result["has_ip_address"]
        )

        self.assertEqual(
            result["url_risk_score"],
            0,
        )

    def test_raw_ip_detection(
        self,
    ) -> None:

        self.assertTrue(
            is_raw_ip(
                "198.51.100.10"
            )
        )

        result = analyze_url(
            "http://198.51.100.10/verify-account"
        )

        self.assertTrue(
            result["has_ip_address"]
        )

        self.assertGreater(
            result["url_risk_score"],
            0,
        )

    def test_non_https_detection(
        self,
    ) -> None:

        result = analyze_url(
            "http://example.org/test"
        )

        self.assertFalse(
            result["https_present"]
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "url_findings"
            ]
        }

        self.assertIn(
            "non_https_scheme",
            finding_types,
        )

    def test_url_shortener(
        self,
    ) -> None:

        self.assertTrue(
            is_shortened_url(
                "bit.ly"
            )
        )

        result = analyze_url(
            "https://bit.ly/TrainingDemo"
        )

        self.assertTrue(
            result[
                "shortened_url_pattern"
            ]
        )

    def test_suspicious_keywords(
        self,
    ) -> None:

        matches = find_suspicious_keywords(
            "https://example.org/account/verify-password"
        )

        self.assertIn(
            "account",
            matches,
        )

        self.assertIn(
            "verify",
            matches,
        )

        self.assertIn(
            "password",
            matches,
        )

    def test_subdomain_count(
        self,
    ) -> None:

        self.assertEqual(
            count_subdomains(
                "example.org"
            ),
            0,
        )

        self.assertEqual(
            count_subdomains(
                "mail.example.org"
            ),
            1,
        )

        self.assertEqual(
            count_subdomains(
                "a.b.c.example.org"
            ),
            3,
        )

    def test_excessive_subdomains(
        self,
    ) -> None:

        result = analyze_url(
            "https://a.b.c.example.org/verify"
        )

        self.assertEqual(
            result["subdomain_count"],
            3,
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "url_findings"
            ]
        }

        self.assertIn(
            "excessive_subdomains",
            finding_types,
        )

    def test_displayed_text_mismatch(
        self,
    ) -> None:

        result = analyze_url(
            "https://account.example.net/verify",
            displayed_text="example.org",
        )

        self.assertTrue(
            result[
                "displayed_text_mismatch"
            ]
        )

    def test_matching_displayed_text(
        self,
    ) -> None:

        result = analyze_url(
            "https://example.org/training",
            displayed_text="example.org",
        )

        self.assertFalse(
            result[
                "displayed_text_mismatch"
            ]
        )

    def test_userinfo_detection(
        self,
    ) -> None:

        result = analyze_url(
            "http://login@example.org/verify"
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "url_findings"
            ]
        }

        self.assertIn(
            "userinfo_in_url",
            finding_types,
        )

    def test_long_url(
        self,
    ) -> None:

        long_path = "x" * 130

        result = analyze_url(
            f"https://example.org/{long_path}"
        )

        self.assertGreater(
            result["url_length"],
            120,
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "url_findings"
            ]
        }

        self.assertIn(
            "long_url",
            finding_types,
        )

    def test_unusual_characters(
        self,
    ) -> None:

        result = analyze_url(
            "https://example.org/test value"
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "url_findings"
            ]
        }

        self.assertIn(
            "unusual_characters",
            finding_types,
        )

    def test_query_extraction(
        self,
    ) -> None:

        result = analyze_url(
            "https://example.org/verify?user=demo&mode=test"
        )

        self.assertEqual(
            result["path"],
            "/verify",
        )

        self.assertEqual(
            result["query"],
            "user=demo&mode=test",
        )

        self.assertEqual(
            result["query_parameter_count"],
            2,
        )

    def test_https_warning(
        self,
    ) -> None:

        result = analyze_url(
            "https://example.org/account/verify"
        )

        self.assertIn(
            "does NOT mean",
            result["https_explanation"],
        )

    def test_static_only_flag(
        self,
    ) -> None:

        result = analyze_url(
            "https://example.org/training"
        )

        self.assertTrue(
            result["static_analysis_only"]
        )

    def test_empty_url(
        self,
    ) -> None:

        result = analyze_url(
            ""
        )

        self.assertEqual(
            result["url_risk_score"],
            0,
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )

