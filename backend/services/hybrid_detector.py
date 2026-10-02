from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent.parent
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from backend.services.risk_engine import (  # noqa: E402
    clamp_score,
    classify_risk,
)
from ml.predict import predict_email  # noqa: E402


# ============================================================
# HYBRID CONFIGURATION
# ============================================================

DEFAULT_RULE_WEIGHT = 0.60
DEFAULT_ML_WEIGHT = 0.40


# ============================================================
# VALIDATION
# ============================================================

def validate_weights(
    rule_weight: float,
    ml_weight: float,
) -> None:
    """
    Validate hybrid weights.

    The weights must:
        - be non-negative
        - sum to 1.0
    """

    if rule_weight < 0:
        raise ValueError(
            "Rule weight cannot be negative."
        )

    if ml_weight < 0:
        raise ValueError(
            "ML weight cannot be negative."
        )

    if abs(
        (rule_weight + ml_weight)
        - 1.0
    ) > 1e-9:

        raise ValueError(
            "Rule weight + ML weight must equal 1.0."
        )


# ============================================================
# MAIN COMBINATION FUNCTION
# ============================================================

def calculate_hybrid_score(
    rule_score: float,
    ml_probability: float,
    rule_weight: float = DEFAULT_RULE_WEIGHT,
    ml_weight: float = DEFAULT_ML_WEIGHT,
) -> Dict[str, Any]:
    """
    Combine the rule-based score and ML probability.

    Both inputs are converted to a 0-100 scale.

    Formula:

        Hybrid Score =
            (Rule Score × Rule Weight)
            +
            (ML Probability × ML Weight)

    Example configuration:

        Rule = 60%
        ML   = 40%

    The ML probability is a model estimate, not certainty.
    """

    validate_weights(
        rule_weight,
        ml_weight,
    )

    # Rule score is already 0-100.
    normalized_rule_score = max(
        0.0,
        min(
            100.0,
            float(rule_score),
        ),
    )

    # ML probability must be supplied as 0-1.
    normalized_ml_probability = max(
        0.0,
        min(
            1.0,
            float(ml_probability),
        ),
    )

    ml_probability_percent = (
        normalized_ml_probability
        * 100.0
    )

    weighted_rule = (
        normalized_rule_score
        * rule_weight
    )

    weighted_ml = (
        ml_probability_percent
        * ml_weight
    )

    hybrid_score = (
        weighted_rule
        + weighted_ml
    )

    hybrid_score = max(
        0.0,
        min(
            100.0,
            hybrid_score,
        ),
    )

    rounded_score = int(
        round(
            hybrid_score
        )
    )

    classification = classify_risk(
        rounded_score
    )

    return {
        "rule_score": round(
            normalized_rule_score,
            2,
        ),
        "ml_probability": round(
            normalized_ml_probability,
            6,
        ),
        "ml_probability_percent": round(
            ml_probability_percent,
            2,
        ),
        "rule_weight": rule_weight,
        "ml_weight": ml_weight,
        "weighted_rule_contribution": round(
            weighted_rule,
            2,
        ),
        "weighted_ml_contribution": round(
            weighted_ml,
            2,
        ),
        "hybrid_risk_score": rounded_score,
        "classification": classification,
        "probability_is_not_certainty": True,
        "weights_are_project_assumptions": True,
    }


# ============================================================
# COMPLETE HYBRID ANALYSIS
# ============================================================

def analyze_with_hybrid_detection(
    subject: str,
    body: str,
    rule_result: Dict[str, Any],
    model_path: Optional[Path] = None,
    rule_weight: float = DEFAULT_RULE_WEIGHT,
    ml_weight: float = DEFAULT_ML_WEIGHT,
) -> Dict[str, Any]:
    """
    Perform ML prediction and combine it with an existing
    rule-engine result.

    Parameters
    ----------
    subject:
        Email subject.

    body:
        Email body.

    rule_result:
        Result from calculate_phishing_score().

    model_path:
        Optional specific saved model path.

    rule_weight:
        Rule contribution weight.

    ml_weight:
        ML contribution weight.

    Returns
    -------
    dict
        Unified hybrid result.
    """

    if not isinstance(
        rule_result,
        dict,
    ):
        raise TypeError(
            "rule_result must be a dictionary."
        )

    rule_score = float(
        rule_result.get(
            "phishing_risk_score",
            0,
        )
    )

    ml_result = predict_email(
        subject=subject,
        body=body,
        model_path=model_path,
    )

    hybrid = calculate_hybrid_score(
        rule_score=rule_score,
        ml_probability=float(
            ml_result[
                "ml_phishing_probability"
            ]
        ),
        rule_weight=rule_weight,
        ml_weight=ml_weight,
    )

    return {
        "hybrid_detection": {
            **hybrid,
            "ml_predicted_label": (
                ml_result[
                    "predicted_label"
                ]
            ),
            "ml_model_name": (
                ml_result[
                    "model_name"
                ]
            ),
            "ml_model_path": (
                ml_result[
                    "model_path"
                ]
            ),
            "ml_feature_type": (
                ml_result[
                    "feature_type"
                ]
            ),
        },
        "rule_based_result": rule_result,
        "ml_result": ml_result,
        "interpretation": (
            "The hybrid score combines an interpretable "
            "rule-based signal with a machine-learning model "
            "estimate. Neither component is treated as certainty."
        ),
    }


# ============================================================
# HUMAN-READABLE OUTPUT
# ============================================================

def format_hybrid_result(
    result: Dict[str, Any],
) -> str:
    """
    Format hybrid detection for terminal demonstration.
    """

    hybrid = result.get(
        "hybrid_detection",
        {},
    )

    lines = [
        "=" * 70,
        "HYBRID PHISHING DETECTION",
        "=" * 70,
        (
            "Rule Score: "
            f"{hybrid.get('rule_score', 0):.2f}/100"
        ),
        (
            "ML Probability Estimate: "
            f"{hybrid.get('ml_probability_percent', 0):.2f}%"
        ),
        (
            "Rule Weight: "
            f"{hybrid.get('rule_weight', 0):.2f}"
        ),
        (
            "ML Weight: "
            f"{hybrid.get('ml_weight', 0):.2f}"
        ),
        (
            "Weighted Rule Contribution: "
            f"{hybrid.get('weighted_rule_contribution', 0):.2f}"
        ),
        (
            "Weighted ML Contribution: "
            f"{hybrid.get('weighted_ml_contribution', 0):.2f}"
        ),
        (
            "Hybrid Risk Score: "
            f"{hybrid.get('hybrid_risk_score', 0)}/100"
        ),
        (
            "Classification: "
            f"{hybrid.get('classification', 'UNKNOWN')}"
        ),
        (
            "ML Model: "
            f"{hybrid.get('ml_model_name', 'UNKNOWN')}"
        ),
        "",
        (
            "Important: ML probability is a model estimate, "
            "not certainty."
        ),
        "=" * 70,
    ]

    return "\n".join(
        lines
    )


# ============================================================
# SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Run deterministic tests without requiring a trained model.
    """

    # --------------------------------------------------------
    # Example calculation
    # --------------------------------------------------------

    result = calculate_hybrid_score(
        rule_score=70,
        ml_probability=0.84,
        rule_weight=0.60,
        ml_weight=0.40,
    )

    # 70*0.60 + 84*0.40 = 75.6 -> 76.
    assert (
        result[
            "hybrid_risk_score"
        ]
        == 76
    )

    assert (
        result[
            "ml_probability_percent"
        ]
        == 84.0
    )

    assert (
        result[
            "weighted_rule_contribution"
        ]
        == 42.0
    )

    assert (
        result[
            "weighted_ml_contribution"
        ]
        == 33.6
    )

    assert (
        result[
            "classification"
        ]
        == "HIGH RISK / LIKELY PHISHING"
    )

    # --------------------------------------------------------
    # Low-risk example
    # --------------------------------------------------------

    low_result = calculate_hybrid_score(
        rule_score=10,
        ml_probability=0.10,
    )

    assert (
        low_result[
            "hybrid_risk_score"
        ]
        == 10
    )

    assert (
        low_result[
            "classification"
        ]
        == "LOW RISK"
    )

    # --------------------------------------------------------
    # Weight validation
    # --------------------------------------------------------

    try:
        calculate_hybrid_score(
            rule_score=50,
            ml_probability=0.50,
            rule_weight=0.70,
            ml_weight=0.20,
        )

        raise AssertionError(
            "Invalid weights should raise ValueError."
        )

    except ValueError:
        pass

    # --------------------------------------------------------
    # Bounds
    # --------------------------------------------------------

    extreme_result = calculate_hybrid_score(
        rule_score=150,
        ml_probability=2.0,
    )

    assert (
        extreme_result[
            "hybrid_risk_score"
        ]
        == 100
    )

    assert (
        extreme_result[
            "ml_probability_percent"
        ]
        == 100.0
    )

    assert (
        extreme_result[
            "probability_is_not_certainty"
        ]
        is True
    )

    print(
        "Hybrid detector self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()