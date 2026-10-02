"""
FastAPI application entry point.

Run locally with:

    python -m uvicorn backend.app:app --reload
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import initialize_database
from backend.routes.api import router


@asynccontextmanager
async def lifespan(application: FastAPI):
    """
    Application startup/shutdown lifecycle.

    The SQLite schema is initialized automatically at startup.
    """
    initialize_database()
    yield


app = FastAPI(
    title="Phishing Email Detection & Awareness Dashboard",
    description=(
        "Defensive cybersecurity API for static analysis of synthetic "
        "or authorized email samples."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
#
# These origins support the React/Vite frontend that will be added later.
# Production deployments should replace this list with exact trusted origins.
#
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


app.include_router(router)


@app.get(
    "/",
    tags=["System"],
)
def root() -> dict[str, str]:
    """Basic API information."""
    return {
        "name": "Phishing Email Detection & Awareness Dashboard",
        "status": "running",
        "docs": "/docs",
    }


@app.get(
    "/api/health",
    tags=["System"],
)
def health_check() -> dict[str, str]:
    """Health endpoint for local checks and future deployment monitoring."""
    return {
        "status": "healthy",
        "service": "phishing-detection-api",
    }