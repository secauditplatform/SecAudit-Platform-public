from fastapi.testclient import TestClient

from app.main import app


def test_metrics_endpoint_returns_prometheus_text():
    with TestClient(app) as client:
        client.get("/api/v1/health/live")
        response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "secaudit_http_requests_total" in response.text
