from __future__ import annotations

from typing import Any, Dict, List

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


# ============================================================
# METRIC CALCULATION
# ============================================================

def calculate_metrics(
    y_true: List[Any],
    y_pred: List[Any],
) -> Dict[str, Any]:
    """
    Calculate standard classification metrics.

    Metrics:
        - accuracy
        - precision
        - recall
        - f1_score
        - confusion_matrix

    For this binary project:
        POSITIVE CLASS = PHISHING
        NEGATIVE CLASS = LEGITIMATE

    zero_division=0 prevents metric calculation from failing when
    a model produces no positive predictions.
    """

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    precision = precision_score(
        y_true,
        y_pred,
        pos_label="PHISHING",
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        pos_label="PHISHING",
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        pos_label="PHISHING",
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[
            "LEGITIMATE",
            "PHISHING",
        ],
    )

    return {
        "accuracy": round(
            float(accuracy),
            6,
        ),
        "precision": round(
            float(precision),
            6,
        ),
        "recall": round(
            float(recall),
            6,
        ),
        "f1_score": round(
            float(f1),
            6,
        ),
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": [
            "LEGITIMATE",
            "PHISHING",
        ],
    }


# ============================================================
# METRIC VALIDATION
# ============================================================

def validate_metrics(
    metrics: Dict[str, Any],
) -> None:
    """
    Validate calculated classification metrics.
    """

    required_metrics = {
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "confusion_matrix",
        "confusion_matrix_labels",
    }

    missing = [
        metric
        for metric in required_metrics
        if metric not in metrics
    ]

    if missing:
        raise ValueError(
            "Missing metrics: "
            f"{missing}"
        )

    for metric_name in [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
    ]:

        value = float(
            metrics[
                metric_name
            ]
        )

        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"{metric_name} must be between 0 and 1."
            )

    matrix = metrics[
        "confusion_matrix"
    ]

    if not isinstance(
        matrix,
        list,
    ):
        raise ValueError(
            "Confusion matrix must be a list."
        )

    if len(matrix) != 2:
        raise ValueError(
            "Binary confusion matrix must contain 2 rows."
        )

    if any(
        not isinstance(
            row,
            list,
        )
        or len(row) != 2
        for row in matrix
    ):
        raise ValueError(
            "Binary confusion matrix must be 2x2."
        )


# ============================================================
# METRIC PERCENTAGES
# ============================================================

def metrics_as_percentages(
    metrics: Dict[str, Any],
) -> Dict[str, float]:
    """
    Convert the four main metrics from 0-1 values to percentages.

    Example:
        0.95 -> 95.0
    """

    return {
        "accuracy_percent": round(
            float(
                metrics["accuracy"]
            )
            * 100,
            2,
        ),
        "precision_percent": round(
            float(
                metrics["precision"]
            )
            * 100,
            2,
        ),
        "recall_percent": round(
            float(
                metrics["recall"]
            )
            * 100,
            2,
        ),
        "f1_score_percent": round(
            float(
                metrics["f1_score"]
            )
            * 100,
            2,
        ),
    }


# ============================================================
# CONFUSION MATRIX INTERPRETATION
# ============================================================

def interpret_confusion_matrix(
    matrix: List[List[int]],
) -> Dict[str, int]:
    """
    Interpret a binary confusion matrix using the project's label order:

        Row 0 = LEGITIMATE
        Row 1 = PHISHING

        Column 0 = LEGITIMATE
        Column 1 = PHISHING

    Therefore:

        TN = matrix[0][0]
        FP = matrix[0][1]
        FN = matrix[1][0]
        TP = matrix[1][1]
    """

    if (
        len(matrix) != 2
        or any(
            len(row) != 2
            for row in matrix
        )
    ):
        raise ValueError(
            "Expected a 2x2 confusion matrix."
        )

    return {
        "true_negative": int(
            matrix[0][0]
        ),
        "false_positive": int(
            matrix[0][1]
        ),
        "false_negative": int(
            matrix[1][0]
        ),
        "true_positive": int(
            matrix[1][1]
        ),
    }


# ============================================================
# PRINTING
# ============================================================

def print_metrics(
    model_name: str,
    split_name: str,
    metrics: Dict[str, Any],
) -> None:
    """
    Print a readable metric summary.
    """

    percentages = (
        metrics_as_percentages(
            metrics
        )
    )

    matrix_values = (
        interpret_confusion_matrix(
            metrics[
                "confusion_matrix"
            ]
        )
    )

    print()
    print("-" * 70)
    print(
        f"MODEL: {model_name}"
    )
    print(
        f"SPLIT: {split_name}"
    )
    print("-" * 70)

    print(
        f"Accuracy  : "
        f"{percentages['accuracy_percent']:.2f}%"
    )

    print(
        f"Precision : "
        f"{percentages['precision_percent']:.2f}%"
    )

    print(
        f"Recall    : "
        f"{percentages['recall_percent']:.2f}%"
    )

    print(
        f"F1 Score  : "
        f"{percentages['f1_score_percent']:.2f}%"
    )

    print()
    print("Confusion Matrix Data:")
    print(
        "  Labels: [LEGITIMATE, PHISHING]"
    )
    print(
        f"  TN={matrix_values['true_negative']} "
        f"FP={matrix_values['false_positive']}"
    )
    print(
        f"  FN={matrix_values['false_negative']} "
        f"TP={matrix_values['true_positive']}"
    )


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Test the evaluation utilities using deterministic examples.
    """

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

    matrix = metrics[
        "confusion_matrix"
    ]

    assert matrix == [
        [1, 1],
        [1, 1],
    ]

    interpreted = (
        interpret_confusion_matrix(
            matrix
        )
    )

    assert (
        interpreted[
            "true_negative"
        ]
        == 1
    )

    assert (
        interpreted[
            "false_positive"
        ]
        == 1
    )

    assert (
        interpreted[
            "false_negative"
        ]
        == 1
    )

    assert (
        interpreted[
            "true_positive"
        ]
        == 1
    )

    percentages = (
        metrics_as_percentages(
            metrics
        )
    )

    assert (
        percentages[
            "accuracy_percent"
        ]
        == 50.0
    )

    print(
        "ML evaluation self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()