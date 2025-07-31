import pytest
from fastapi.testclient import TestClient
from api.api import app

client = TestClient(app)

def test_get_latest_features_empty():
    response = client.get("/extract_features")
    assert response.status_code == 200
    assert "flows" in response.json()
    assert isinstance(response.json()["flows"], list)
