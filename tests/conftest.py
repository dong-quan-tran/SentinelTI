from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinelti.api import app as fastapi_app
import sentinelti.api.dependencies as deps_module
from sentinelti import cli
from sentinelti import scoring


TEST_API_KEY = "test-key"


@pytest.fixture
def api_key(monkeypatch) -> str:
    monkeypatch.setattr(deps_module, "API_KEY", TEST_API_KEY)
    return TEST_API_KEY


@pytest.fixture
def client(api_key) -> TestClient:
    deps_module._rate_limit_store.clear()
    return TestClient(fastapi_app)


@pytest.fixture
def auth_headers(api_key) -> dict[str, str]:
    return {"X-API-KEY": api_key}


@pytest.fixture
def fake_ml_score(monkeypatch):
    def _apply(*, prob: float = 0.05, label: int = 0):
        def _fake_ml_score_url(url: str) -> dict:
            return {
                "url": url,
                "label": label,
                "prob_malicious": prob,
            }

        monkeypatch.setattr(scoring, "ml_score_url", _fake_ml_score_url)

    return _apply


@pytest.fixture
def fake_cli_enrich_score(monkeypatch):
    def _apply(result: dict | None = None):
        default = {
            "url": "https://example.com",
            "label": 0,
            "prob_malicious": 0.05,
            "final_label": "benign",
            "risk": "low",
            "reasons": [],
            "heuristic": {
                "score": 0.0,
                "reasons": [],
            },
            "explanation": {
                "summary": "This URL currently appears low risk.",
                "why_flagged": "Few malicious patterns were detected.",
                "user_action": "Proceed carefully.",
                "technical_notes": [],
                "risk": "low",
                "final_label": "benign",
            },
        }

        def _fake_enrich_score(url: str) -> dict:
            merged = {**default, **(result or {})}
            merged["url"] = url
            return merged

        monkeypatch.setattr(cli, "enrich_score", _fake_enrich_score)

    return _apply