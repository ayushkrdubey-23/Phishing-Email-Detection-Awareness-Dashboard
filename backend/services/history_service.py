"""
Database persistence service for analysis history.

Only safe metadata and explainable findings are persisted.
Raw email bodies are intentionally not stored.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from backend.database import get_connection


def _json_string(value: Any) -> str:
    """Serialize a Python value to JSON safely."""
    return json.dumps(
        value,
        ensure_ascii=False,
        default=str,
    )


def save_analysis(
    analysis_result: dict[str, Any],
) -> int:
    """
    Save analysis metadata, indicators, and safe URL information.

    The raw email body is never written to the database.
    """
    analysis = analysis_result.get("analysis", {})
    explanation = analysis_result.get("explainability", {})
    url_analysis = analysis_result.get("url_analysis", [])

    created_at = datetime.now(timezone.utc).isoformat()

    sender_domain = str(
        analysis.get("sender_domain") or ""
    )

    subject = str(
        analysis.get("subject") or ""
    )

    risk_score = int(
        max(0, min(100, int(analysis.get("risk_score", 0))))
    )

    classification = str(
        analysis.get("classification") or "LOW RISK"
    )

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO analyses (
                sender_domain,
                subject,
                risk_score,
                classification,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sender_domain,
                subject,
                risk_score,
                classification,
                created_at,
            ),
        )

        analysis_id = int(cursor.lastrowid)

        indicators = explanation.get(
            "detected_indicators",
            [],
        )

        if not isinstance(indicators, list):
            indicators = []

        for indicator in indicators:
            if not isinstance(indicator, dict):
                indicator = {
                    "indicator_type": "GENERAL",
                    "description": str(indicator),
                    "severity": "LOW",
                }

            cursor.execute(
                """
                INSERT INTO indicators (
                    analysis_id,
                    indicator_type,
                    description,
                    severity
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    str(
                        indicator.get(
                            "indicator_type",
                            "GENERAL",
                        )
                    ),
                    str(
                        indicator.get(
                            "description",
                            "",
                        )
                    ),
                    str(
                        indicator.get(
                            "severity",
                            "LOW",
                        )
                    ).upper(),
                ),
            )

        for item in url_analysis:
            if not isinstance(item, dict):
                continue

            url = str(
                item.get("url") or ""
            )

            result = item.get(
                "result",
                {},
            )

            url_score = 0

            if isinstance(result, dict):
                url_score = int(
                    max(
                        0,
                        min(
                            100,
                            int(
                                result.get(
                                    "risk_score",
                                    result.get("score", 0),
                                )
                            ),
                        ),
                    )
                )

            findings = []

            if isinstance(result, dict):
                findings = result.get(
                    "findings",
                    result.get("url_findings", []),
                )

            cursor.execute(
                """
                INSERT INTO url_analyses (
                    analysis_id,
                    url_safe_representation,
                    risk_score,
                    findings
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    url,
                    url_score,
                    _json_string(findings),
                ),
            )

        return analysis_id


def list_analyses(
    classification: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    order: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return safe analysis-history records."""
    allowed_sort_fields = {
        "created_at": "created_at",
        "risk_score": "risk_score",
        "subject": "subject",
        "sender_domain": "sender_domain",
        "classification": "classification",
    }

    sort_column = allowed_sort_fields.get(
        sort_by,
        "created_at",
    )

    sort_order = (
        "ASC"
        if order.lower() == "asc"
        else "DESC"
    )

    query = """
        SELECT
            analysis_id,
            sender_domain,
            subject,
            risk_score,
            classification,
            created_at
        FROM analyses
        WHERE 1 = 1
    """

    parameters: list[Any] = []

    if classification:
        query += " AND classification = ?"
        parameters.append(classification)

    if search:
        query += """
            AND (
                subject LIKE ?
                OR sender_domain LIKE ?
                OR classification LIKE ?
            )
        """

        pattern = f"%{search}%"

        parameters.extend(
            [
                pattern,
                pattern,
                pattern,
            ]
        )

    query += (
        f" ORDER BY {sort_column} {sort_order}"
        " LIMIT ? OFFSET ?"
    )

    parameters.extend(
        [
            limit,
            offset,
        ]
    )

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

    return [dict(row) for row in rows]


def get_analysis(
    analysis_id: int,
) -> dict[str, Any] | None:
    """Return one safe analysis record with indicators and URLs."""
    with get_connection() as connection:
        analysis_row = connection.execute(
            """
            SELECT
                analysis_id,
                sender_domain,
                subject,
                risk_score,
                classification,
                created_at
            FROM analyses
            WHERE analysis_id = ?
            """,
            (analysis_id,),
        ).fetchone()

        if analysis_row is None:
            return None

        indicator_rows = connection.execute(
            """
            SELECT
                indicator_id,
                indicator_type,
                description,
                severity
            FROM indicators
            WHERE analysis_id = ?
            ORDER BY indicator_id ASC
            """,
            (analysis_id,),
        ).fetchall()

        url_rows = connection.execute(
            """
            SELECT
                url_analysis_id,
                url_safe_representation,
                risk_score,
                findings
            FROM url_analyses
            WHERE analysis_id = ?
            ORDER BY url_analysis_id ASC
            """,
            (analysis_id,),
        ).fetchall()

    result = dict(analysis_row)

    result["indicators"] = [
        dict(row)
        for row in indicator_rows
    ]

    result["url_analyses"] = []

    for row in url_rows:
        item = dict(row)

        try:
            item["findings"] = json.loads(
                item["findings"]
            )
        except (TypeError, json.JSONDecodeError):
            item["findings"] = []

        result["url_analyses"].append(item)

    return result


def delete_analysis(
    analysis_id: int,
) -> bool:
    """Delete one analysis; child rows are removed by foreign-key cascade."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            DELETE FROM analyses
            WHERE analysis_id = ?
            """,
            (analysis_id,),
        )

        return cursor.rowcount > 0


def get_dashboard_stats() -> dict[str, Any]:
    """Return dashboard summary statistics."""
    with get_connection() as connection:
        total = connection.execute(
            """
            SELECT COUNT(*) AS value
            FROM analyses
            """
        ).fetchone()["value"]

        likely_phishing = connection.execute(
            """
            SELECT COUNT(*) AS value
            FROM analyses
            WHERE classification = 'HIGH RISK / LIKELY PHISHING'
            """
        ).fetchone()["value"]

        suspicious = connection.execute(
            """
            SELECT COUNT(*) AS value
            FROM analyses
            WHERE classification = 'SUSPICIOUS'
            """
        ).fetchone()["value"]

        low_risk = connection.execute(
            """
            SELECT COUNT(*) AS value
            FROM analyses
            WHERE classification = 'LOW RISK'
            """
        ).fetchone()["value"]

        moderate_risk = connection.execute(
            """
            SELECT COUNT(*) AS value
            FROM analyses
            WHERE classification = 'MODERATE RISK'
            """
        ).fetchone()["value"]

        average = connection.execute(
            """
            SELECT AVG(risk_score) AS value
            FROM analyses
            """
        ).fetchone()["value"]

    return {
        "total_emails": int(total or 0),
        "likely_phishing": int(likely_phishing or 0),
        "suspicious": int(suspicious or 0),
        "low_risk": int(low_risk or 0),
        "moderate_risk": int(moderate_risk or 0),
        "average_risk_score": round(
            float(average or 0),
            2,
        ),
    }


def get_indicator_statistics(
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Return the most frequently recorded indicator types."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                indicator_type,
                COUNT(*) AS count
            FROM indicators
            GROUP BY indicator_type
            ORDER BY count DESC, indicator_type ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "indicator_type": row["indicator_type"],
            "count": int(row["count"]),
        }
        for row in rows
    ]