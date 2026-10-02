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


from backend.services.attachment_analyzer import (  # noqa: E402
    analyze_attachment,
    extract_extensions,
    get_extension_category,
    get_final_extension,
    has_double_extension,
    is_suspicious_double_extension,
)


# ============================================================
# TEST CLASS
# ============================================================

class AttachmentAnalyzerTests(
    unittest.TestCase
):
    """
    Unit tests for safe attachment filename analysis.
    """

    # --------------------------------------------------------
    # 1. Normal extension
    # --------------------------------------------------------

    def test_normal_extension(
        self,
    ) -> None:

        self.assertEqual(
            extract_extensions(
                "report.pdf"
            ),
            [".pdf"],
        )

        self.assertEqual(
            get_final_extension(
                "report.pdf"
            ),
            ".pdf",
        )

    # --------------------------------------------------------
    # 2. Executable extension
    # --------------------------------------------------------

    def test_executable_extension(
        self,
    ) -> None:

        result = analyze_attachment(
            "program.exe"
        )

        self.assertIn(
            ".exe",
            result["extensions"],
        )

        self.assertGreater(
            result["attachment_risk_score"],
            0,
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "findings"
            ]
        }

        self.assertIn(
            "executable_extension",
            finding_types,
        )

    # --------------------------------------------------------
    # 3. Script extension
    # --------------------------------------------------------

    def test_script_extension(
        self,
    ) -> None:

        result = analyze_attachment(
            "update.js"
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "findings"
            ]
        }

        self.assertIn(
            "script_extension",
            finding_types,
        )

    # --------------------------------------------------------
    # 4. PowerShell extension
    # --------------------------------------------------------

    def test_powershell_extension(
        self,
    ) -> None:

        result = analyze_attachment(
            "maintenance.ps1"
        )

        self.assertIn(
            ".ps1",
            result["extensions"],
        )

        self.assertGreater(
            result["attachment_risk_score"],
            0,
        )

    # --------------------------------------------------------
    # 5. Archive extension
    # --------------------------------------------------------

    def test_archive_extension(
        self,
    ) -> None:

        result = analyze_attachment(
            "documents.zip"
        )

        self.assertIn(
            ".zip",
            result[
                "extension_categories"
            ][
                "archive_extensions"
            ],
        )

        self.assertGreater(
            result["attachment_risk_score"],
            0,
        )

    # --------------------------------------------------------
    # 6. Macro-enabled extension
    # --------------------------------------------------------

    def test_macro_extension(
        self,
    ) -> None:

        result = analyze_attachment(
            "spreadsheet.xlsm"
        )

        self.assertIn(
            ".xlsm",
            result[
                "extension_categories"
            ][
                "macro_or_active_content_extensions"
            ],
        )

    # --------------------------------------------------------
    # 7. Double extension
    # --------------------------------------------------------

    def test_double_extension(
        self,
    ) -> None:

        self.assertTrue(
            has_double_extension(
                "invoice.pdf.exe"
            )
        )

    # --------------------------------------------------------
    # 8. Suspicious double extension
    # --------------------------------------------------------

    def test_suspicious_double_extension(
        self,
    ) -> None:

        self.assertTrue(
            is_suspicious_double_extension(
                "invoice.pdf.exe"
            )
        )

    # --------------------------------------------------------
    # 9. Double-extension finding
    # --------------------------------------------------------

    def test_double_extension_finding(
        self,
    ) -> None:

        result = analyze_attachment(
            "invoice.pdf.exe"
        )

        finding_types = {
            finding["indicator_type"]
            for finding in result[
                "findings"
            ]
        }

        self.assertIn(
            "double_extension",
            finding_types,
        )

    # --------------------------------------------------------
    # 10. Final extension
    # --------------------------------------------------------

    def test_final_extension(
        self,
    ) -> None:

        self.assertEqual(
            get_final_extension(
                "invoice.pdf.exe"
            ),
            ".exe",
        )

    # --------------------------------------------------------
    # 11. Extension categories
    # --------------------------------------------------------

    def test_extension_categories(
        self,
    ) -> None:

        self.assertEqual(
            get_extension_category(
                ".exe"
            ),
            "executable",
        )

        self.assertEqual(
            get_extension_category(
                ".js"
            ),
            "script",
        )

        self.assertEqual(
            get_extension_category(
                ".zip"
            ),
            "archive",
        )

    # --------------------------------------------------------
    # 12. Empty attachment
    # --------------------------------------------------------

    def test_empty_attachment(
        self,
    ) -> None:

        result = analyze_attachment(
            ""
        )

        self.assertEqual(
            result["attachment_risk_score"],
            0,
        )

        self.assertEqual(
            result["attachment_risk"],
            "NO ATTACHMENT",
        )

    # --------------------------------------------------------
    # 13. Normal PDF doesn't execute
    # --------------------------------------------------------

    def test_static_analysis_only(
        self,
    ) -> None:

        result = analyze_attachment(
            "report.pdf"
        )

        self.assertTrue(
            result["static_analysis_only"]
        )

        self.assertFalse(
            result["execution_performed"]
        )

    # --------------------------------------------------------
    # 14. Suspicious attachment doesn't execute
    # --------------------------------------------------------

    def test_suspicious_attachment_not_executed(
        self,
    ) -> None:

        result = analyze_attachment(
            "invoice.pdf.exe"
        )

        self.assertFalse(
            result["execution_performed"]
        )

        self.assertTrue(
            result["static_analysis_only"]
        )

    # --------------------------------------------------------
    # 15. Path-like filename handled safely
    # --------------------------------------------------------

    def test_path_like_filename(
        self,
    ) -> None:

        result = analyze_attachment(
            r"downloads\invoice.pdf.exe"
        )

        self.assertEqual(
            result["final_extension"],
            ".exe",
        )

    # --------------------------------------------------------
    # 16. Findings are explainable
    # --------------------------------------------------------

    def test_findings_have_explanations(
        self,
    ) -> None:

        result = analyze_attachment(
            "invoice.pdf.exe"
        )

        self.assertGreater(
            len(result["findings"]),
            0,
        )

        for finding in result[
            "findings"
        ]:

            self.assertIn(
                "indicator_type",
                finding,
            )

            self.assertIn(
                "description",
                finding,
            )

            self.assertIn(
                "severity",
                finding,
            )

            self.assertIn(
                "score_contribution",
                finding,
            )

    # --------------------------------------------------------
    # 17. Score range
    # --------------------------------------------------------

    def test_score_range(
        self,
    ) -> None:

        result = analyze_attachment(
            "invoice.pdf.exe"
        )

        self.assertGreaterEqual(
            result[
                "attachment_risk_score"
            ],
            0,
        )

        self.assertLessEqual(
            result[
                "attachment_risk_score"
            ],
            100,
        )


# ============================================================
# TEST RUNNER
# ============================================================

if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )
