"""
Pydantic request/response schemas for the REST API.

The schemas validate user input before it reaches the detection engines.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class AnalyzeEmailRequest(BaseModel):
    """Request body for POST /api/analyze."""

    sender: str = Field(
        ...,
        min_length=3,
        max_length=254,
        description="Sender email address.",
    )

    display_name: Optional[str] = Field(
        default=None,
        max_length=120,
        description="Optional sender display name.",
    )

    subject: str = Field(
        default="",
        max_length=500,
        description="Email subject.",
    )

    body: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="Email body supplied for analysis.",
    )

    attachment_name: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional attachment filename. Filename only; never execute it.",
    )

    urls: list[str] = Field(
        default_factory=list,
        description="Optional URLs supplied explicitly for static analysis.",
    )

    @field_validator("sender")
    @classmethod
    def validate_sender(cls, value: str) -> str:
        value = value.strip()

        if "@" not in value:
            raise ValueError("sender must contain an email-style '@' separator")

        return value

    @field_validator("body")
    @classmethod
    def validate_body(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("body cannot be empty")

        return value

    @field_validator("subject")
    @classmethod
    def normalize_subject(cls, value: str) -> str:
        return value.strip()

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(
        cls,
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None

        value = value.strip()
        return value or None

    @field_validator("attachment_name")
    @classmethod
    def validate_attachment_name(
        cls,
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        # Prevent path-like values from being treated as attachment filenames.
        if "/" in value or "\\" in value:
            raise ValueError(
                "attachment_name must contain a filename only, not a path"
            )

        return value

    @field_validator("urls")
    @classmethod
    def normalize_urls(cls, value: list[str]) -> list[str]:
        cleaned_urls: list[str] = []

        for url in value:
            cleaned = url.strip()

            if not cleaned:
                continue

            if len(cleaned) > 2048:
                raise ValueError(
                    "each URL must be 2048 characters or fewer"
                )

            cleaned_urls.append(cleaned)

        return cleaned_urls


class AnalyzeURLRequest(BaseModel):
    """Request body for POST /api/analyze/url."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL for static security analysis.",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("url cannot be empty")

        return value


class IndicatorResponse(BaseModel):
    """Stored indicator information."""

    indicator_id: int
    indicator_type: str
    description: str
    severity: str


class URLAnalysisResponse(BaseModel):
    """Stored URL analysis information."""

    url_analysis_id: int
    url_safe_representation: str
    risk_score: int
    findings: list[Any]


class AnalysisSummaryResponse(BaseModel):
    """Safe analysis metadata."""

    analysis_id: int
    sender_domain: str
    subject: str
    risk_score: int
    classification: str
    created_at: str


class AnalysisDetailResponse(BaseModel):
    """Complete stored analysis record without raw email body."""

    analysis_id: int
    sender_domain: str
    subject: str
    risk_score: int
    classification: str
    created_at: str
    indicators: list[IndicatorResponse]
    url_analyses: list[URLAnalysisResponse]


class DashboardStatsResponse(BaseModel):
    """Dashboard summary statistics."""

    total_emails: int
    likely_phishing: int
    suspicious: int
    low_risk: int
    moderate_risk: int
    average_risk_score: float


class DeleteAnalysisResponse(BaseModel):
    """Deletion confirmation response."""

    message: str
    analysis_id: int
    