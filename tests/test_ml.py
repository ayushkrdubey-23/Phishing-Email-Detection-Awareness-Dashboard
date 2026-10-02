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


from ml.evaluation import (  # noqa: E402
    calculate_metrics,
    interpret_confusion_matrix,
    metrics_as_percentages,
    validate_metrics,
)

from ml.train_model import (  # noqa: E402
    build_email_text,
    build_models,
    build_tfidf_vectorizer,
    calculate_split_counts,
    select_model,
    split_dataset,
)


# ============================================================
# TEST CLASS
# ============================================================

class MLTests(
    unittest.TestCase
):
    """
    Tests for the baseline machine-learning pipeline.
    """

    # --------------------------------------------------------
    # 1. Evaluation metrics
    # --------------------------------------------------------

    def test_metrics_calculation(
        self,
    ) -> None:

        y_true = [
            "LEGITIMATE",
            "LEGITIMATE",
            "PHISHING",
            "PHISHING",
        ]

        y_pred = [
            "LEGITIMATE",
            "PHISHING",
            "PHISHING",
            "LEGITIMATE",
        ]

        metrics = calculate_metrics(
            y_true,
            y_pred,
        )

        validate_metrics(
            metrics
        )

        self.assertEqual(
            metrics[
                "confusion_matrix"
            ],
            [
                [1, 1],
                [1, 1],
            ],
        )

    # --------------------------------------------------------
    # 2. Confusion-matrix interpretation
    # --------------------------------------------------------

    def test_confusion_matrix_interpretation(
        self,
    ) -> None:

        result = (
            interpret_confusion_matrix(
                [
                    [10, 2],
                    [3, 15],
                ]
            )
        )

        self.assertEqual(
            result[
                "true_negative"
            ],
            10,
        )

        self.assertEqual(
            result[
                "false_positive"
            ],
            2,
        )

        self.assertEqual(
            result[
                "false_negative"
            ],
            3,
        )

        self.assertEqual(
            result[
                "true_positive"
            ],
            15,
        )

    # --------------------------------------------------------
    # 3. Percentage conversion
    # --------------------------------------------------------

    def test_percentage_conversion(
        self,
    ) -> None:

        metrics = calculate_metrics(
            [
                "LEGITIMATE",
                "PHISHING",
            ],
            [
                "LEGITIMATE",
                "PHISHING",
            ],
        )

        percentages = (
            metrics_as_percentages(
                metrics
            )
        )

        self.assertEqual(
            percentages[
                "accuracy_percent"
            ],
            100.0,
        )

    # --------------------------------------------------------
    # 4. Required models exist
    # --------------------------------------------------------

    def test_required_models_exist(
        self,
    ) -> None:

        models = build_models()

        self.assertEqual(
            len(models),
            3,
        )

        self.assertIn(
            "Logistic Regression",
            models,
        )

        self.assertIn(
            "Naive Bayes",
            models,
        )

        self.assertIn(
            "Random Forest",
            models,
        )

    # --------------------------------------------------------
    # 5. TF-IDF vectorizer
    # --------------------------------------------------------

    def test_tfidf_vectorizer(
        self,
    ) -> None:

        vectorizer = (
            build_tfidf_vectorizer()
        )

        matrix = vectorizer.fit_transform(
            [
                "urgent verify account",
                "university workshop reminder",
            ]
        )

        self.assertEqual(
            matrix.shape[0],
            2,
        )

        self.assertGreater(
            matrix.shape[1],
            0,
        )

    # --------------------------------------------------------
    # 6. Email text builder
    # --------------------------------------------------------

    def test_email_text_builder(
        self,
    ) -> None:

        import pandas as pd

        dataframe = pd.DataFrame(
            {
                "subject": [
                    "Test Subject"
                ],
                "body": [
                    "Test Body"
                ],
            }
        )

        text = build_email_text(
            dataframe
        )

        self.assertIn(
            "SUBJECT Test Subject",
            text.iloc[0],
        )

        self.assertIn(
            "BODY Test Body",
            text.iloc[0],
        )

    # --------------------------------------------------------
    # 7. Exact split-count calculation for 100 records
    # --------------------------------------------------------

    def test_split_counts_for_100_records(
        self,
    ) -> None:

        train_count, validation_count, test_count = (
            calculate_split_counts(
                100
            )
        )

        self.assertEqual(
            train_count,
            70,
        )

        self.assertEqual(
            validation_count,
            15,
        )

        self.assertEqual(
            test_count,
            15,
        )

        self.assertEqual(
            train_count
            + validation_count
            + test_count,
            100,
        )

    # --------------------------------------------------------
    # 8. Exact split-count calculation for 600 records
    # --------------------------------------------------------

    def test_split_counts_for_600_records(
        self,
    ) -> None:

        train_count, validation_count, test_count = (
            calculate_split_counts(
                600
            )
        )

        self.assertEqual(
            train_count,
            420,
        )

        self.assertEqual(
            validation_count,
            90,
        )

        self.assertEqual(
            test_count,
            90,
        )

    # --------------------------------------------------------
    # 9. Dataset split
    # --------------------------------------------------------

    def test_dataset_split(
        self,
    ) -> None:

        import pandas as pd

        dataframe = pd.DataFrame(
            {
                "email_id": [
                    f"ID-{i}"
                    for i in range(100)
                ],
                "subject": [
                    "subject"
                    for _ in range(100)
                ],
                "body": [
                    "body"
                    for _ in range(100)
                ],
                "label": [
                    "LEGITIMATE"
                    if i < 50
                    else "PHISHING"
                    for i in range(100)
                ],
            }
        )

        train, validation, test = (
            split_dataset(
                dataframe
            )
        )

        self.assertEqual(
            len(train),
            70,
        )

        self.assertEqual(
            len(validation),
            15,
        )

        self.assertEqual(
            len(test),
            15,
        )

        self.assertEqual(
            len(train)
            + len(validation)
            + len(test),
            100,
        )

    # --------------------------------------------------------
    # 10. Split retains both labels
    # --------------------------------------------------------

    def test_split_retains_both_labels(
        self,
    ) -> None:

        import pandas as pd

        dataframe = pd.DataFrame(
            {
                "email_id": [
                    f"ID-{i}"
                    for i in range(100)
                ],
                "subject": [
                    "subject"
                    for _ in range(100)
                ],
                "body": [
                    "body"
                    for _ in range(100)
                ],
                "label": [
                    "LEGITIMATE"
                    if i < 50
                    else "PHISHING"
                    for i in range(100)
                ],
            }
        )

        train, validation, test = (
            split_dataset(
                dataframe
            )
        )

        self.assertEqual(
            set(train["label"]),
            {
                "LEGITIMATE",
                "PHISHING",
            },
        )

        self.assertEqual(
            set(validation["label"]),
            {
                "LEGITIMATE",
                "PHISHING",
            },
        )

        self.assertEqual(
            set(test["label"]),
            {
                "LEGITIMATE",
                "PHISHING",
            },
        )

    # --------------------------------------------------------
    # 11. Validation model selection
    # --------------------------------------------------------

    def test_model_selection(
        self,
    ) -> None:

        results = {
            "Logistic Regression": {
                "accuracy": 0.90,
                "precision": 0.88,
                "recall": 0.92,
                "f1_score": 0.90,
            },
            "Naive Bayes": {
                "accuracy": 0.91,
                "precision": 0.91,
                "recall": 0.91,
                "f1_score": 0.91,
            },
            "Random Forest": {
                "accuracy": 0.95,
                "precision": 0.94,
                "recall": 0.96,
                "f1_score": 0.95,
            },
        }

        selected = select_model(
            results
        )

        self.assertEqual(
            selected,
            "Random Forest",
        )

    # --------------------------------------------------------
    # 12. Metric range
    # --------------------------------------------------------

    def test_metric_range(
        self,
    ) -> None:

        metrics = calculate_metrics(
            [
                "LEGITIMATE",
                "PHISHING",
                "PHISHING",
            ],
            [
                "LEGITIMATE",
                "PHISHING",
                "LEGITIMATE",
            ],
        )

        for name in [
            "accuracy",
            "precision",
            "recall",
            "f1_score",
        ]:

            self.assertGreaterEqual(
                metrics[name],
                0.0,
            )

            self.assertLessEqual(
                metrics[name],
                1.0,
            )

    # --------------------------------------------------------
    # 13. Positive class
    # --------------------------------------------------------

    def test_phishing_is_positive_class(
        self,
    ) -> None:

        metrics = calculate_metrics(
            [
                "PHISHING"
            ],
            [
                "PHISHING"
            ],
        )

        self.assertEqual(
            metrics[
                "f1_score"
            ],
            1.0,
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )