"""
API-level tests for the FastAPI application.

Tests use a temporary SQLite database so that the real project database
and its analysis history are never modified or deleted.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import database
from backend.app import app


class TestAPI(unittest.TestCase):
    """FastAPI endpoint tests."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create an isolated temporary database for all API tests."""
        cls.temp_dir = tempfile.TemporaryDirectory()

        cls.test_database_path = (
            Path(cls.temp_dir.name)
            / "test_phishing_dashboard.db"
        )

        cls.database_path_patch = patch.object(
            database,
            "DATABASE_PATH",
            cls.test_database_path,
        )

        cls.database_dir_patch = patch.object(
            database,
            "DATABASE_DIR",
            Path(cls.temp_dir.name),
        )

        cls.database_path_patch.start()
        cls.database_dir_patch.start()

        database.initialize_database()

        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        """Close the temporary test database and restore application state."""
        cls.client.close()
        cls.database_path_patch.stop()
        cls.database_dir_patch.stop()
        cls.temp_dir.cleanup()

    def test_root_endpoint(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

        body = response.json()

        self.assertEqual(
            body["status"],
            "running",
        )

    def test_health_endpoint(self) -> None:
        response = self.client.get(
            "/api/health"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.json()["status"],
            "healthy",
        )

    def test_analyze_validation_rejects_invalid_sender(self) -> None:
        response = self.client.post(
            "/api/analyze",
            json={
                "sender": "invalid-sender",
                "subject": "Test",
                "body": "This is a test message.",
            },
        )

        self.assertEqual(
            response.status_code,
            422,
        )

    def test_url_validation_rejects_empty_url(self) -> None:
        response = self.client.post(
            "/api/analyze/url",
            json={
                "url": "",
            },
        )

        self.assertEqual(
            response.status_code,
            422,
        )

    def test_history_endpoint_is_available(self) -> None:
        response = self.client.get(
            "/api/analyses"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        body = response.json()

        self.assertIn(
            "analyses",
            body,
        )

    def test_dashboard_stats_endpoint_is_available(self) -> None:
        response = self.client.get(
            "/api/dashboard/stats"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        body = response.json()

        expected_fields = {
            "total_emails",
            "likely_phishing",
            "suspicious",
            "low_risk",
            "moderate_risk",
            "average_risk_score",
        }

        self.assertTrue(
            expected_fields.issubset(
                body.keys()
            )
        )

    def test_dashboard_indicators_endpoint_is_available(self) -> None:
        response = self.client.get(
            "/api/dashboard/indicators"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        body = response.json()

        self.assertIn(
            "indicators",
            body,
        )

    def test_nonexistent_analysis_returns_404(self) -> None:
        response = self.client.get(
            "/api/analyses/999999999"
        )

        self.assertEqual(
            response.status_code,
            404,
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )