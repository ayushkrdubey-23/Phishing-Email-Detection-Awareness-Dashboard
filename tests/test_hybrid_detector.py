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


from backend.services.hybrid_detector import (  # noqa: E402
    DEFAULT_ML_WEIGHT,
    DEFAULT_RULE_WEIGHT,
    calculate_hybrid_score,
    validate_weights,
)

from ml.predict import (  # noqa: E402
    build_prediction_text,
    get_class_index,
)


# ============================================================
# TEST CLASS
# ============================================================

class HybridDetectorTests(
    unittest.TestCase
):
    """
    Unit tests for hybrid phishing detection.
    """

    # --------------------------------------------------------
    # 1. Default weights
    # --------------------------------------------------------

    def test_default_weights(
        self,
    ) -> None:

        self.assertEqual(
            DEFAULT_RULE_WEIGHT,
            0.60,
        )

        self.assertEqual(
            DEFAULT_ML_WEIGHT,
            0.40,
        )

    # --------------------------------------------------------
    # 2. Weights sum to one
    # --------------------------------------------------------

    def test_weights_sum_to_one(
        self,
    ) -> None:

        validate_weights(
            0.60,
            0.40,
        )

    # --------------------------------------------------------
    # 3. Invalid weights
    # --------------------------------------------------------

    def test_invalid_weights(
        self,
    ) -> None:

        with self.assertRaises(
            ValueError
        ):
            validate_weights(
                0.70,
                0.20,
            )

    # --------------------------------------------------------
    # 4. Positive hybrid calculation
    # --------------------------------------------------------

    def test_hybrid_calculation(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=70,
            ml_probability=0.84,
            rule_weight=0.60,
            ml_weight=0.40,
        )

        self.assertEqual(
            result[
                "hybrid_risk_score"
            ],
            76,
        )

    # --------------------------------------------------------
    # 5. Rule contribution
    # --------------------------------------------------------

    def test_rule_contribution(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=70,
            ml_probability=0.84,
        )

        self.assertEqual(
            result[
                "weighted_rule_contribution"
            ],
            42.0,
        )

    # --------------------------------------------------------
    # 6. ML contribution
    # --------------------------------------------------------

    def test_ml_contribution(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=70,
            ml_probability=0.84,
        )

        self.assertEqual(
            result[
                "weighted_ml_contribution"
            ],
            33.6,
        )

    # --------------------------------------------------------
    # 7. Probability conversion
    # --------------------------------------------------------

    def test_probability_conversion(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=50,
            ml_probability=0.25,
        )

        self.assertEqual(
            result[
                "ml_probability_percent"
            ],
            25.0,
        )

    # --------------------------------------------------------
    # 8. Classification
    # --------------------------------------------------------

    def test_classification(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=70,
            ml_probability=0.84,
        )

        self.assertEqual(
            result[
                "classification"
            ],
            "HIGH RISK / LIKELY PHISHING",
        )

    # --------------------------------------------------------
    # 9. Low-risk example
    # --------------------------------------------------------

    def test_low_risk(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=10,
            ml_probability=0.10,
        )

        self.assertEqual(
            result[
                "hybrid_risk_score"
            ],
            10,
        )

        self.assertEqual(
            result[
                "classification"
            ],
            "LOW RISK",
        )

    # --------------------------------------------------------
    # 10. Score cap
    # --------------------------------------------------------

    def test_score_cap(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=100,
            ml_probability=1.0,
        )

        self.assertEqual(
            result[
                "hybrid_risk_score"
            ],
            100,
        )

    # --------------------------------------------------------
    # 11. Rule score bounds
    # --------------------------------------------------------

    def test_rule_score_bounds(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=150,
            ml_probability=0.0,
        )

        self.assertEqual(
            result[
                "rule_score"
            ],
            100.0,
        )

    # --------------------------------------------------------
    # 12. ML probability bounds
    # --------------------------------------------------------

    def test_ml_probability_bounds(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=0,
            ml_probability=2.0,
        )

        self.assertEqual(
            result[
                "ml_probability"
            ],
            1.0,
        )

    # --------------------------------------------------------
    # 13. Probability is not certainty
    # --------------------------------------------------------

    def test_probability_not_certainty(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=60,
            ml_probability=0.90,
        )

        self.assertTrue(
            result[
                "probability_is_not_certainty"
            ]
        )

    # --------------------------------------------------------
    # 14. Assumption flag
    # --------------------------------------------------------

    def test_project_assumption_flag(
        self,
    ) -> None:

        result = calculate_hybrid_score(
            rule_score=50,
            ml_probability=0.50,
        )

        self.assertTrue(
            result[
                "weights_are_project_assumptions"
            ]
        )

    # --------------------------------------------------------
    # 15. Exact prediction text
    # --------------------------------------------------------

    def test_prediction_text(
        self,
    ) -> None:

        text = build_prediction_text(
            "Test Subject",
            "Test Body",
        )

        self.assertEqual(
            text,
            "SUBJECT Test Subject BODY Test Body",
        )

    # --------------------------------------------------------
    # 16. PHISHING class index
    # --------------------------------------------------------

    def test_phishing_class_index(
        self,
    ) -> None:

        class MockModel:
            classes_ = [
                "LEGITIMATE",
                "PHISHING",
            ]

        self.assertEqual(
            get_class_index(
                MockModel(),
                "PHISHING",
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )
    