from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB


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


from ml.evaluation import (  # noqa: E402
    calculate_metrics,
    print_metrics,
    validate_metrics,
)


DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "feature_engineered_dataset.csv"
)

MODELS_DIR = (
    PROJECT_ROOT
    / "models"
)

RESULTS_PATH = (
    MODELS_DIR
    / "ml_model_results.json"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15

TFIDF_MAX_FEATURES = 5000

TFIDF_NGRAM_RANGE = (
    1,
    2,
)


# ============================================================
# REQUIRED COLUMNS
# ============================================================

REQUIRED_COLUMNS = {
    "email_id",
    "subject",
    "body",
    "label",
}


# ============================================================
# DATASET LOADING
# ============================================================

def load_dataset(
    dataset_path: Path = DATASET_PATH,
) -> pd.DataFrame:
    """
    Load the project's feature-engineered dataset.

    The baseline ML model uses:
        - subject
        - body
        - label

    Structured phishing indicators will be incorporated later
    in the hybrid detection stage.
    """

    if not dataset_path.exists():
        raise FileNotFoundError(
            "Feature-engineered dataset not found:\n"
            f"{dataset_path}"
        )

    dataframe = pd.read_csv(
        dataset_path
    )

    missing_columns = (
        REQUIRED_COLUMNS
        - set(
            dataframe.columns
        )
    )

    if missing_columns:
        raise ValueError(
            "Dataset is missing required ML columns: "
            f"{sorted(missing_columns)}"
        )

    if dataframe.empty:
        raise ValueError(
            "The dataset is empty."
        )

    return dataframe


# ============================================================
# TEXT PREPARATION
# ============================================================

def build_email_text(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Combine subject and body into one text field for TF-IDF.

    The labels SUBJECT and BODY help separate the two text
    sources without using extra structured features.
    """

    subject = (
        dataframe["subject"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    body = (
        dataframe["body"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    return (
        "SUBJECT "
        + subject
        + " BODY "
        + body
    )


# ============================================================
# DATA SPLIT
# ============================================================

def calculate_split_counts(
    total_records: int,
) -> Tuple[int, int, int]:
    """
    Calculate exact integer record counts for:

        Training   = 70%
        Validation = 15%
        Test       = 15%

    Using integer counts avoids rounding errors from performing
    the second split as a percentage of an already-reduced
    dataset.

    Examples:

        100 records
            -> 70 / 15 / 15

        600 records
            -> 420 / 90 / 90
    """

    if total_records < 10:
        raise ValueError(
            "Dataset must contain at least 10 records for "
            "the requested train/validation/test split."
        )

    if round(
        TRAIN_RATIO
        + VALIDATION_RATIO
        + TEST_RATIO,
        10,
    ) != 1.0:
        raise ValueError(
            "Train/validation/test ratios must sum to 1.0."
        )

    validation_count = max(
        1,
        int(
            round(
                total_records
                * VALIDATION_RATIO
            )
        ),
    )

    test_count = max(
        1,
        int(
            round(
                total_records
                * TEST_RATIO
            )
        ),
    )

    train_count = (
        total_records
        - validation_count
        - test_count
    )

    if train_count < 1:
        raise ValueError(
            "The calculated training set is too small."
        )

    if (
        train_count
        + validation_count
        + test_count
        != total_records
    ):
        raise ValueError(
            "Calculated split counts do not equal "
            "the total number of records."
        )

    return (
        train_count,
        validation_count,
        test_count,
    )


def split_dataset(
    dataframe: pd.DataFrame,
) -> Tuple[
    pd.DataFrame,
    pd.DataFrame,
    pd.DataFrame,
]:
    """
    Split the dataset into exact integer counts:

        70% training
        15% validation
        15% test

    Stratification preserves the label distribution as far as
    the available integer counts allow.

    The split is deterministic because RANDOM_STATE is fixed.
    """

    total_records = len(
        dataframe
    )

    (
        train_count,
        validation_count,
        test_count,
    ) = calculate_split_counts(
        total_records
    )

    # --------------------------------------------------------
    # First split:
    #
    # TEST is taken as an exact integer count.
    # --------------------------------------------------------

    train_validation, test = (
        train_test_split(
            dataframe,
            test_size=test_count,
            random_state=RANDOM_STATE,
            stratify=dataframe[
                "label"
            ],
        )
    )

    # --------------------------------------------------------
    # Second split:
    #
    # VALIDATION is taken as an exact integer count from the
    # remaining records.
    # --------------------------------------------------------

    train, validation = (
        train_test_split(
            train_validation,
            test_size=validation_count,
            random_state=RANDOM_STATE,
            stratify=train_validation[
                "label"
            ],
        )
    )

    # --------------------------------------------------------
    # Final sanity checks
    # --------------------------------------------------------

    if len(train) != train_count:
        raise RuntimeError(
            "Training split size is incorrect. "
            f"Expected {train_count}, got {len(train)}."
        )

    if len(validation) != validation_count:
        raise RuntimeError(
            "Validation split size is incorrect. "
            f"Expected {validation_count}, "
            f"got {len(validation)}."
        )

    if len(test) != test_count:
        raise RuntimeError(
            "Test split size is incorrect. "
            f"Expected {test_count}, got {len(test)}."
        )

    return (
        train.reset_index(drop=True),
        validation.reset_index(drop=True),
        test.reset_index(drop=True),
    )


# ============================================================
# TF-IDF
# ============================================================

def build_tfidf_vectorizer() -> TfidfVectorizer:
    """
    Create the TF-IDF vectorizer.

    The vectorizer is fitted only on training data during the
    baseline training phase.
    """

    return TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=TFIDF_NGRAM_RANGE,
        max_features=TFIDF_MAX_FEATURES,
        sublinear_tf=True,
    )


# ============================================================
# MODEL DEFINITIONS
# ============================================================

def build_models() -> Dict[str, Any]:
    """
    Create all three models required by the project prompt.
    """

    return {
        "Logistic Regression": (
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            )
        ),

        "Naive Bayes": (
            MultinomialNB(
                alpha=0.5,
            )
        ),

        "Random Forest": (
            RandomForestClassifier(
                n_estimators=300,
                class_weight="balanced_subsample",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            )
        ),
    }


# ============================================================
# MODEL EVALUATION
# ============================================================

def evaluate_models_on_validation(
    models: Dict[str, Any],
    x_train,
    y_train,
    x_validation,
    y_validation,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Any],
]:
    """
    Train every requested model on the training set and evaluate
    it on the validation set.

    Returns:
        trained_models
        validation_results
    """

    trained_models: Dict[
        str,
        Any,
    ] = {}

    validation_results: Dict[
        str,
        Any,
    ] = {}

    for model_name, model in models.items():

        print()
        print(
            f"Training {model_name}..."
        )

        model.fit(
            x_train,
            y_train,
        )

        predictions = model.predict(
            x_validation
        )

        metrics = calculate_metrics(
            y_validation,
            predictions,
        )

        validate_metrics(
            metrics
        )

        print_metrics(
            model_name,
            "Validation",
            metrics,
        )

        trained_models[
            model_name
        ] = model

        validation_results[
            model_name
        ] = metrics

    return (
        trained_models,
        validation_results,
    )


# ============================================================
# MODEL SELECTION
# ============================================================

def select_model(
    validation_results: Dict[str, Any],
) -> str:
    """
    Select the model with the highest validation F1 score.

    Tie-breaking:
        1. F1 score
        2. Recall
        3. Precision
        4. Model name

    The selection is based on measured validation results.
    """

    if not validation_results:
        raise ValueError(
            "No validation results are available."
        )

    ranked = sorted(
        validation_results.items(),
        key=lambda item: (
            float(
                item[1]["f1_score"]
            ),
            float(
                item[1]["recall"]
            ),
            float(
                item[1]["precision"]
            ),
            item[0],
        ),
        reverse=True,
    )

    return ranked[0][0]


# ============================================================
# FINAL MODEL TRAINING
# ============================================================

def train_final_model(
    model,
    train_validation_text,
    train_validation_labels,
) -> Tuple[
    Any,
    TfidfVectorizer,
]:
    """
    Create a fresh TF-IDF vectorizer and train the selected model
    on Training + Validation data.

    The test set remains untouched until final evaluation.
    """

    final_vectorizer = (
        build_tfidf_vectorizer()
    )

    x_train_validation = (
        final_vectorizer.fit_transform(
            train_validation_text
        )
    )

    model.fit(
        x_train_validation,
        train_validation_labels,
    )

    return (
        model,
        final_vectorizer,
    )


# ============================================================
# DATASET STATISTICS
# ============================================================

def dataset_label_distribution(
    dataframe: pd.DataFrame,
) -> Dict[str, int]:
    """
    Return label counts as normal Python integers.
    """

    counts = (
        dataframe["label"]
        .value_counts()
        .to_dict()
    )

    return {
        str(label): int(count)
        for label, count in counts.items()
    }


def dataset_split_summary(
    train: pd.DataFrame,
    validation: pd.DataFrame,
    test: pd.DataFrame,
) -> Dict[str, Any]:
    """
    Create split size and label-distribution metadata.
    """

    return {
        "training": {
            "records": len(train),
            "label_distribution": (
                dataset_label_distribution(
                    train
                )
            ),
        },
        "validation": {
            "records": len(validation),
            "label_distribution": (
                dataset_label_distribution(
                    validation
                )
            ),
        },
        "test": {
            "records": len(test),
            "label_distribution": (
                dataset_label_distribution(
                    test
                )
            ),
        },
    }


# ============================================================
# MODEL SAVING
# ============================================================

def save_final_model(
    model: Any,
    vectorizer: TfidfVectorizer,
    selected_model_name: str,
) -> Path:
    """
    Save the selected final model and its TF-IDF vectorizer.

    Only the selected final model is saved.

    The .joblib file is intentionally ignored by .gitignore
    because trained binary model files are generated artifacts.
    """

    MODELS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_name = (
        selected_model_name
        .lower()
        .replace(
            " ",
            "_",
        )
    )

    model_path = (
        MODELS_DIR
        / f"tfidf_{safe_name}.joblib"
    )

    package = {
        "model": model,
        "vectorizer": vectorizer,
        "model_name": selected_model_name,
        "feature_type": "TF-IDF subject + body",
        "positive_class": "PHISHING",
        "negative_class": "LEGITIMATE",
        "random_state": RANDOM_STATE,
    }

    joblib.dump(
        package,
        model_path,
    )

    return model_path


# ============================================================
# RESULT SAVING
# ============================================================

def save_results(
    results: Dict[str, Any],
) -> None:
    """
    Save actual ML evaluation results to JSON.
    """

    MODELS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with RESULTS_PATH.open(
        "w",
        encoding="utf-8",
    ) as json_file:

        json.dump(
            results,
            json_file,
            indent=4,
        )


# ============================================================
# MAIN TRAINING WORKFLOW
# ============================================================

def main() -> None:
    """
    Run the complete baseline ML training and evaluation workflow.
    """

    print(
        "=" * 75
    )

    print(
        "PHISHING EMAIL ML TRAINING PIPELINE"
    )

    print(
        "=" * 75
    )

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    dataframe = load_dataset()

    print()
    print(
        f"Loaded dataset records: {len(dataframe)}"
    )

    print(
        "Labels:",
        dataset_label_distribution(
            dataframe
        ),
    )

    # --------------------------------------------------------
    # Build text
    # --------------------------------------------------------

    dataframe = dataframe.copy()

    dataframe[
        "_ml_text"
    ] = build_email_text(
        dataframe
    )

    # --------------------------------------------------------
    # Split data
    # --------------------------------------------------------

    train, validation, test = (
        split_dataset(
            dataframe
        )
    )

    print()
    print(
        "Dataset split:"
    )

    print(
        f"  Training   : {len(train)}"
    )

    print(
        f"  Validation : {len(validation)}"
    )

    print(
        f"  Test       : {len(test)}"
    )

    # --------------------------------------------------------
    # Prepare labels and text
    # --------------------------------------------------------

    train_text = train[
        "_ml_text"
    ]

    validation_text = validation[
        "_ml_text"
    ]

    test_text = test[
        "_ml_text"
    ]

    y_train = train[
        "label"
    ]

    y_validation = validation[
        "label"
    ]

    y_test = test[
        "label"
    ]

    # --------------------------------------------------------
    # Fit TF-IDF on training data only
    # --------------------------------------------------------

    print()
    print(
        "Fitting TF-IDF on training data only..."
    )

    vectorizer = (
        build_tfidf_vectorizer()
    )

    x_train = vectorizer.fit_transform(
        train_text
    )

    x_validation = vectorizer.transform(
        validation_text
    )

    x_test = vectorizer.transform(
        test_text
    )

    print(
        f"TF-IDF training shape   : "
        f"{x_train.shape}"
    )

    print(
        f"TF-IDF validation shape : "
        f"{x_validation.shape}"
    )

    print(
        f"TF-IDF test shape       : "
        f"{x_test.shape}"
    )

    # --------------------------------------------------------
    # Train requested models
    # --------------------------------------------------------

    models = build_models()

    (
        trained_models,
        validation_results,
    ) = evaluate_models_on_validation(
        models=models,
        x_train=x_train,
        y_train=y_train,
        x_validation=x_validation,
        y_validation=y_validation,
    )

    # --------------------------------------------------------
    # Select model
    # --------------------------------------------------------

    selected_model_name = (
        select_model(
            validation_results
        )
    )

    print()
    print(
        "=" * 75
    )

    print(
        "VALIDATION MODEL SELECTION"
    )

    print(
        "=" * 75
    )

    print(
        "Selection criterion: highest validation F1 score"
    )

    print(
        f"Selected model: {selected_model_name}"
    )

    # --------------------------------------------------------
    # Combine training + validation data
    # --------------------------------------------------------

    train_validation = pd.concat(
        [
            train,
            validation,
        ],
        ignore_index=True,
    )

    train_validation_text = (
        train_validation[
            "_ml_text"
        ]
    )

    train_validation_labels = (
        train_validation[
            "label"
        ]
    )

    # --------------------------------------------------------
    # Create a fresh selected model
    # --------------------------------------------------------

    selected_model = (
        build_models()[
            selected_model_name
        ]
    )

    # --------------------------------------------------------
    # Train final selected model
    # --------------------------------------------------------

    (
        final_model,
        final_vectorizer,
    ) = train_final_model(
        model=selected_model,
        train_validation_text=(
            train_validation_text
        ),
        train_validation_labels=(
            train_validation_labels
        ),
    )

    # --------------------------------------------------------
    # Transform untouched test data using final vectorizer
    # --------------------------------------------------------

    final_x_test = (
        final_vectorizer.transform(
            test_text
        )
    )

    # --------------------------------------------------------
    # Final test prediction
    # --------------------------------------------------------

    final_predictions = (
        final_model.predict(
            final_x_test
        )
    )

    final_test_metrics = (
        calculate_metrics(
            y_test,
            final_predictions,
        )
    )

    validate_metrics(
        final_test_metrics
    )

    print()
    print(
        "=" * 75
    )

    print(
        "FINAL TEST RESULT"
    )

    print(
        "=" * 75
    )

    print_metrics(
        selected_model_name,
        "Final Test",
        final_test_metrics,
    )

    # --------------------------------------------------------
    # Save selected final model
    # --------------------------------------------------------

    model_path = save_final_model(
        model=final_model,
        vectorizer=final_vectorizer,
        selected_model_name=(
            selected_model_name
        ),
    )

    print()
    print(
        f"Final model saved to:\n{model_path}"
    )

    # --------------------------------------------------------
    # Save complete ML results
    # --------------------------------------------------------

    results = {
        "project": (
            "Phishing Email Detection & Awareness Dashboard"
        ),
        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "dataset": {
            "path": str(
                DATASET_PATH
            ),
            "total_records": len(
                dataframe
            ),
            "label_distribution": (
                dataset_label_distribution(
                    dataframe
                )
            ),
        },
        "split": dataset_split_summary(
            train,
            validation,
            test,
        ),
        "split_ratios": {
            "training": TRAIN_RATIO,
            "validation": VALIDATION_RATIO,
            "test": TEST_RATIO,
        },
        "tfidf": {
            "ngram_range": list(
                TFIDF_NGRAM_RANGE
            ),
            "max_features": (
                TFIDF_MAX_FEATURES
            ),
            "fit_on_training_data_only": True,
        },
        "models_compared": list(
            validation_results.keys()
        ),
        "validation_results": validation_results,
        "selection_criterion": (
            "Highest validation F1 score; ties are resolved using "
            "recall, precision, then model name."
        ),
        "selected_model": (
            selected_model_name
        ),
        "final_training_data": (
            "Training + Validation"
        ),
        "final_training_records": (
            len(train_validation)
        ),
        "final_test_records": len(test),
        "final_test_results": (
            final_test_metrics
        ),
        "final_model_path": str(
            model_path
        ),
        "positive_class": "PHISHING",
        "negative_class": "LEGITIMATE",
        "results_are_actual_run_output": True,
        "accuracy_warning": (
            "Accuracy alone is not sufficient for phishing detection. "
            "Precision, recall, and F1 must also be considered."
        ),
        "data_source_note": (
            "Results are based only on the project's synthetic dataset "
            "and should not be treated as production performance."
        ),
    }

    save_results(
        results
    )

    print()
    print(
        f"Evaluation results saved to:\n"
        f"{RESULTS_PATH}"
    )

    print()
    print(
        "=" * 75
    )

    print(
        "ML TRAINING COMPLETED SUCCESSFULLY"
    )

    print(
        "=" * 75
    )


if __name__ == "__main__":
    main()