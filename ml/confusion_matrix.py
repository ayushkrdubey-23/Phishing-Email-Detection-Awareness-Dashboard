from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


RESULTS_PATH = (
    PROJECT_ROOT
    / "models"
    / "ml_model_results.json"
)

OUTPUT_DIRECTORY = (
    PROJECT_ROOT
    / "screenshots"
)

OUTPUT_PATH = (
    OUTPUT_DIRECTORY
    / "13_confusion_matrix.png"
)


# ============================================================
# LOAD RESULTS
# ============================================================

def load_ml_results(
    results_path: Path = RESULTS_PATH,
) -> Dict[str, Any]:
    """
    Load the actual ML results produced by train_model.py.
    """

    if not results_path.exists():
        raise FileNotFoundError(
            "ML results file was not found:\n"
            f"{results_path}\n\n"
            "Run Step 12 ML training first."
        )

    with results_path.open(
        "r",
        encoding="utf-8",
    ) as json_file:

        results = json.load(
            json_file
        )

    if not isinstance(
        results,
        dict,
    ):
        raise ValueError(
            "ML results JSON must contain an object."
        )

    return results


# ============================================================
# EXTRACT FINAL CONFUSION MATRIX
# ============================================================

def get_final_confusion_matrix(
    results: Dict[str, Any],
) -> List[List[int]]:
    """
    Extract the final test confusion matrix.

    Expected matrix order:

        [[TN, FP],
         [FN, TP]]

    The corresponding labels are:

        [LEGITIMATE, PHISHING]
    """

    final_results = results.get(
        "final_test_results"
    )

    if not isinstance(
        final_results,
        dict,
    ):
        raise ValueError(
            "final_test_results is missing from ML results."
        )

    matrix = final_results.get(
        "confusion_matrix"
    )

    if not isinstance(
        matrix,
        list,
    ):
        raise ValueError(
            "Final confusion matrix is missing."
        )

    if len(matrix) != 2:
        raise ValueError(
            "Confusion matrix must contain exactly two rows."
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
            "Confusion matrix must be 2x2."
        )

    normalized_matrix = [
        [
            int(value)
            for value in row
        ]
        for row in matrix
    ]

    return normalized_matrix


# ============================================================
# INTERPRET CONFUSION MATRIX
# ============================================================

def interpret_matrix(
    matrix: List[List[int]],
) -> Dict[str, int]:
    """
    Interpret a confusion matrix using:

        Row 0 = actual LEGITIMATE
        Row 1 = actual PHISHING

        Column 0 = predicted LEGITIMATE
        Column 1 = predicted PHISHING
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
# VALIDATE MATRIX
# ============================================================

def validate_matrix(
    matrix: List[List[int]],
) -> None:
    """
    Validate that all matrix values are non-negative integers.
    """

    for row in matrix:
        for value in row:
            if not isinstance(
                value,
                int,
            ):
                raise TypeError(
                    "Confusion-matrix values must be integers."
                )

            if value < 0:
                raise ValueError(
                    "Confusion-matrix values cannot be negative."
                )


# ============================================================
# BUILD VISUALIZATION
# ============================================================

def generate_confusion_matrix_plot(
    matrix: List[List[int]],
    model_name: str,
    output_path: Path = OUTPUT_PATH,
) -> Path:
    """
    Generate a confusion-matrix PNG using Matplotlib.

    The matrix itself comes from the actual final test results.
    """

    import matplotlib

    # Non-interactive backend so the script works from a terminal.
    matplotlib.use(
        "Agg"
    )

    import matplotlib.pyplot as plt

    validate_matrix(
        matrix
    )

    values = interpret_matrix(
        matrix
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    figure, axis = plt.subplots(
        figsize=(8, 6)
    )

    image = axis.imshow(
        matrix
    )

    # Colorbar helps readers understand the magnitude of cells.
    figure.colorbar(
        image,
        ax=axis,
        fraction=0.046,
        pad=0.04,
    )

    labels = [
        "LEGITIMATE",
        "PHISHING",
    ]

    axis.set_xticks(
        [0, 1]
    )

    axis.set_yticks(
        [0, 1]
    )

    axis.set_xticklabels(
        labels
    )

    axis.set_yticklabels(
        labels
    )

    axis.set_xlabel(
        "Predicted Label"
    )

    axis.set_ylabel(
        "Actual Label"
    )

    axis.set_title(
        f"Final Test Confusion Matrix - {model_name}"
    )

    # Annotate each cell with the actual count.
    for row in range(2):
        for column in range(2):

            value = matrix[
                row
            ][
                column
            ]

            axis.text(
                column,
                row,
                str(value),
                ha="center",
                va="center",
                fontsize=18,
                fontweight="bold",
            )

    # Add semantic labels below the matrix.
    figure.text(
        0.16,
        0.015,
        f"TN = {values['true_negative']}",
        fontsize=10,
    )

    figure.text(
        0.39,
        0.015,
        f"FP = {values['false_positive']}",
        fontsize=10,
    )

    figure.text(
        0.62,
        0.015,
        f"FN = {values['false_negative']}",
        fontsize=10,
    )

    figure.text(
        0.82,
        0.015,
        f"TP = {values['true_positive']}",
        fontsize=10,
        ha="right",
    )

    figure.tight_layout(
        rect=(
            0,
            0.06,
            1,
            1,
        )
    )

    figure.savefig(
        output_path,
        dpi=160,
        bbox_inches="tight",
    )

    plt.close(
        figure
    )

    return output_path


# ============================================================
# PRINT RESULT
# ============================================================

def print_confusion_matrix_summary(
    model_name: str,
    matrix: List[List[int]],
    output_path: Path,
) -> None:
    """
    Print a readable final confusion-matrix summary.
    """

    values = interpret_matrix(
        matrix
    )

    print()
    print(
        "=" * 70
    )

    print(
        "FINAL TEST CONFUSION MATRIX"
    )

    print(
        "=" * 70
    )

    print(
        f"Model: {model_name}"
    )

    print()
    print(
        "Label order:"
    )

    print(
        "  0 = LEGITIMATE"
    )

    print(
        "  1 = PHISHING"
    )

    print()
    print(
        "Matrix:"
    )

    print(
        f"  [[{matrix[0][0]}, {matrix[0][1]}],"
    )

    print(
        f"   [{matrix[1][0]}, {matrix[1][1]}]]"
    )

    print()
    print(
        f"True Negative  (TN): {values['true_negative']}"
    )

    print(
        f"False Positive (FP): {values['false_positive']}"
    )

    print(
        f"False Negative (FN): {values['false_negative']}"
    )

    print(
        f"True Positive  (TP): {values['true_positive']}"
    )

    print()
    print(
        f"Visualization saved to:\n{output_path}"
    )

    print(
        "=" * 70
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Generate the final confusion-matrix visualization from
    the actual ML test results.
    """

    results = load_ml_results()

    selected_model = str(
        results.get(
            "selected_model",
            "Unknown Model",
        )
    )

    matrix = (
        get_final_confusion_matrix(
            results
        )
    )

    output_path = (
        generate_confusion_matrix_plot(
            matrix,
            selected_model,
        )
    )

    print_confusion_matrix_summary(
        selected_model,
        matrix,
        output_path,
    )


# ============================================================
# SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Test confusion-matrix interpretation and validation
    without requiring the ML results file.
    """

    test_matrix = [
        [12, 3],
        [2, 13],
    ]

    validate_matrix(
        test_matrix
    )

    values = interpret_matrix(
        test_matrix
    )

    assert (
        values["true_negative"]
        == 12
    )

    assert (
        values["false_positive"]
        == 3
    )

    assert (
        values["false_negative"]
        == 2
    )

    assert (
        values["true_positive"]
        == 13
    )

    print(
        "Confusion matrix self-test: PASSED"
    )


if __name__ == "__main__":
    main()
    