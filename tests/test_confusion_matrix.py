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


from ml.confusion_matrix import (  # noqa: E402
    get_final_confusion_matrix,
    interpret_matrix,
    validate_matrix,
)


# ============================================================
# TEST CLASS
# ============================================================

class ConfusionMatrixTests(
    unittest.TestCase
):
    """
    Tests for confusion-matrix processing and interpretation.
    """

    # --------------------------------------------------------
    # 1. Basic interpretation
    # --------------------------------------------------------

    def test_matrix_interpretation(
        self,
    ) -> None:

        matrix = [
            [10, 2],
            [3, 15],
        ]

        result = interpret_matrix(
            matrix
        )

        self.assertEqual(
            result["true_negative"],
            10,
        )

        self.assertEqual(
            result["false_positive"],
            2,
        )

        self.assertEqual(
            result["false_negative"],
            3,
        )

        self.assertEqual(
            result["true_positive"],
            15,
        )

    # --------------------------------------------------------
    # 2. Matrix validation
    # --------------------------------------------------------

    def test_valid_matrix(
        self,
    ) -> None:

        matrix = [
            [1, 2],
            [3, 4],
        ]

        # Should not raise.
        validate_matrix(
            matrix
        )

    # --------------------------------------------------------
    # 3. Negative value rejected
    # --------------------------------------------------------

    def test_negative_value_rejected(
        self,
    ) -> None:

        with self.assertRaises(
            ValueError
        ):
            validate_matrix(
                [
                    [1, -1],
                    [2, 3],
                ]
            )

    # --------------------------------------------------------
    # 4. Non-integer rejected
    # --------------------------------------------------------

    def test_non_integer_rejected(
        self,
    ) -> None:

        with self.assertRaises(
            TypeError
        ):
            validate_matrix(
                [
                    [1.5, 2],
                    [3, 4],
                ]
            )

    # --------------------------------------------------------
    # 5. Matrix is 2x2
    # --------------------------------------------------------

    def test_matrix_shape(
        self,
    ) -> None:

        with self.assertRaises(
            ValueError
        ):
            interpret_matrix(
                [
                    [1, 2, 3],
                    [4, 5, 6],
                ]
            )

    # --------------------------------------------------------
    # 6. Actual saved ML matrix
    # --------------------------------------------------------

    def test_saved_ml_results_matrix(
        self,
    ) -> None:

        results_path = (
            PROJECT_ROOT
            / "models"
            / "ml_model_results.json"
        )

        if not results_path.exists():
            self.skipTest(
                "Step 12 ML results file not found."
            )

        import json

        with results_path.open(
            "r",
            encoding="utf-8",
        ) as json_file:
            results = json.load(
                json_file
            )

        matrix = (
            get_final_confusion_matrix(
                results
            )
        )

        self.assertEqual(
            len(matrix),
            2,
        )

        self.assertEqual(
            len(matrix[0]),
            2,
        )

        self.assertEqual(
            len(matrix[1]),
            2,
        )

        validate_matrix(
            matrix
        )


# ============================================================
# TEST RUNNER
# ============================================================

if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )