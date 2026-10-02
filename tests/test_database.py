"""
Unit tests for the SQLite database foundation.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import database


class TestDatabase(unittest.TestCase):
    """Test database initialization and schema creation."""

    def test_database_initialization_creates_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "test_phishing_dashboard.db"

            with patch.object(database, "DATABASE_PATH", temp_path):
                with patch.object(
                    database,
                    "DATABASE_DIR",
                    Path(temp_dir),
                ):
                    database.initialize_database()

                    self.assertTrue(temp_path.exists())

                    connection = sqlite3.connect(temp_path)

                    try:
                        rows = connection.execute(
                            """
                            SELECT name
                            FROM sqlite_master
                            WHERE type = 'table'
                            ORDER BY name
                            """
                        ).fetchall()

                        table_names = {row[0] for row in rows}

                        self.assertIn("analyses", table_names)
                        self.assertIn("indicators", table_names)
                        self.assertIn("url_analyses", table_names)

                    finally:
                        connection.close()

    def test_foreign_key_cascade_is_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "test_phishing_dashboard.db"

            with patch.object(database, "DATABASE_PATH", temp_path):
                with patch.object(
                    database,
                    "DATABASE_DIR",
                    Path(temp_dir),
                ):
                    database.initialize_database()

                    with database.get_connection() as connection:
                        foreign_keys = connection.execute(
                            "PRAGMA foreign_keys"
                        ).fetchone()[0]

                    self.assertEqual(foreign_keys, 1)

    def test_analysis_table_can_store_safe_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "test_phishing_dashboard.db"

            with patch.object(database, "DATABASE_PATH", temp_path):
                with patch.object(
                    database,
                    "DATABASE_DIR",
                    Path(temp_dir),
                ):
                    database.initialize_database()

                    with database.get_connection() as connection:
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
                                "example.org",
                                "Workshop Reminder",
                                10,
                                "LOW RISK",
                                "2026-10-03T00:00:00+05:30",
                            ),
                        )

                        analysis_id = cursor.lastrowid

                    self.assertIsNotNone(analysis_id)

    def test_risk_score_constraint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "test_phishing_dashboard.db"

            with patch.object(database, "DATABASE_PATH", temp_path):
                with patch.object(
                    database,
                    "DATABASE_DIR",
                    Path(temp_dir),
                ):
                    database.initialize_database()

                    with self.assertRaises(sqlite3.IntegrityError):
                        with database.get_connection() as connection:
                            connection.execute(
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
                                    "example.org",
                                    "Invalid Score",
                                    101,
                                    "HIGH RISK",
                                    "2026-10-03T00:00:00+05:30",
                                ),
                            )


if __name__ == "__main__":
    unittest.main(verbosity=2)