"""
SQLite database layer for the Phishing Email Detection & Awareness Dashboard.

Security/privacy principle:
- Store analysis metadata and explainable findings.
- Do not store the raw email body by default.
- URL records contain only safe representations and static analysis results.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator


# Project root: .../Phishing-Email-Detection-Awareness-Dashboard
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Database directory
DATABASE_DIR = PROJECT_ROOT / "data"

# SQLite database file
DATABASE_PATH = DATABASE_DIR / "phishing_dashboard.db"


def ensure_database_directory() -> None:
    """Create the data directory when it does not already exist."""
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Open a SQLite connection with foreign-key support enabled.

    The connection is committed when the block succeeds and rolled back
    when an exception occurs.
    """
    ensure_database_directory()

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    # Enforce relationships between tables.
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    """Create all application tables if they do not already exist."""
    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_domain TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL DEFAULT '',
                risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                classification TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS indicators (
                indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                indicator_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(analysis_id)
                    ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS url_analyses (
                url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                url_safe_representation TEXT NOT NULL,
                risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                findings TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(analysis_id)
                    ON DELETE CASCADE
            )
            """
        )

        # Helpful indexes for dashboard/history queries.
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at
            ON analyses(created_at)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_classification
            ON analyses(classification)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_risk_score
            ON analyses(risk_score)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_indicators_analysis_id
            ON indicators(analysis_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_url_analyses_analysis_id
            ON url_analyses(analysis_id)
            """
        )


def database_exists() -> bool:
    """Return True when the SQLite database file exists."""
    return DATABASE_PATH.exists()


def get_database_path() -> str:
    """Return the database path as a string for diagnostics."""
    return str(DATABASE_PATH)


if __name__ == "__main__":
    print("Initializing phishing dashboard database...")
    initialize_database()

    print(f"Database path: {get_database_path()}")
    print(f"Database exists: {database_exists()}")
    print("Database initialization: PASSED")
    