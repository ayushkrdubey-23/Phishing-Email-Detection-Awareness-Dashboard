"""
REST API routes for the Phishing Email Detection & Awareness Dashboard.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from backend.schemas import (
    AnalyzeEmailRequest,
    AnalyzeURLRequest,
)
from backend.services.analysis_service import (
    analyze_email,
)
from backend.services.history_service import (
    delete_analysis,
    get_analysis,
    get_dashboard_stats,
    get_indicator_statistics,
    list_analyses,
    save_analysis,
)


router = APIRouter(
    prefix="/api",
    tags=["Phishing Detection"],
)


@router.post(
    "/analyze",
    status_code=status.HTTP_201_CREATED,
)
def analyze_email_endpoint(
    request: AnalyzeEmailRequest,
) -> dict[str, Any]:
    """
    Analyze an email using the complete defensive pipeline.

    The body is analyzed in memory but is not stored in analysis history.
    """
    try:
        result = analyze_email(
            sender=request.sender,
            display_name=request.display_name,
            subject=request.subject,
            body=request.body,
            attachment_name=request.attachment_name,
            explicit_urls=request.urls,
        )

        analysis_id = save_analysis(result)

        result["analysis_id"] = analysis_id

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "An unexpected error occurred while analyzing "
                "the email."
            ),
        ) from exc


@router.post(
    "/analyze/url",
    status_code=status.HTTP_200_OK,
)
def analyze_url_endpoint(
    request: AnalyzeURLRequest,
) -> dict[str, Any]:
    """
    Perform static URL analysis.

    The supplied URL is never opened or requested.
    """
    try:
        from backend.services.analysis_service import (
            run_url_analysis,
        )

        result = run_url_analysis(
            request.url
        )

        return {
            "url": request.url,
            "static_analysis_only": True,
            "result": result,
            "privacy": {
                "url_visited": False,
                "network_request_made": False,
            },
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "An unexpected error occurred while analyzing "
                "the URL."
            ),
        ) from exc


@router.get(
    "/analyses",
)
def get_analyses_endpoint(
    classification: str | None = Query(
        default=None,
        description="Filter by exact classification.",
    ),
    search: str | None = Query(
        default=None,
        max_length=120,
        description="Search subject, sender domain, or classification.",
    ),
    sort_by: str = Query(
        default="created_at",
        description=(
            "Sort field: created_at, risk_score, subject, "
            "sender_domain, classification."
        ),
    ),
    order: str = Query(
        default="desc",
        pattern="^(?i)(asc|desc)$",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
) -> dict[str, Any]:
    """Return analysis history with filtering and sorting."""
    records = list_analyses(
        classification=classification,
        search=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        offset=offset,
    )

    return {
        "count": len(records),
        "limit": limit,
        "offset": offset,
        "analyses": records,
    }


@router.get(
    "/analyses/{analysis_id}",
)
def get_analysis_endpoint(
    analysis_id: int,
) -> dict[str, Any]:
    """Return one analysis history record."""
    if analysis_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="analysis_id must be a positive integer",
        )

    result = get_analysis(
        analysis_id
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    return result


@router.get(
    "/dashboard/stats",
)
def dashboard_stats_endpoint() -> dict[str, Any]:
    """Return high-level dashboard statistics."""
    return get_dashboard_stats()


@router.get(
    "/dashboard/indicators",
)
def dashboard_indicators_endpoint(
    limit: int = Query(
        default=15,
        ge=1,
        le=100,
    ),
) -> dict[str, Any]:
    """Return frequently detected phishing indicators."""
    indicators = get_indicator_statistics(
        limit=limit
    )

    return {
        "count": len(indicators),
        "indicators": indicators,
    }


@router.delete(
    "/analyses/{analysis_id}",
)
def delete_analysis_endpoint(
    analysis_id: int,
) -> dict[str, Any]:
    """Delete one stored analysis."""
    if analysis_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="analysis_id must be a positive integer",
        )

    deleted = delete_analysis(
        analysis_id
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    return {
        "message": "Analysis deleted successfully",
        "analysis_id": analysis_id,
    }