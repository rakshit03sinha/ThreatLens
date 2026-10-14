"""ThreatLens API Routes and Endpoints Verification Test Suite."""

import pytest
from httpx import AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_health_and_readiness(client: AsyncClient):
    # Liveness
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"

    # Readiness
    resp_ready = await client.get("/api/v1/ready")
    assert resp_ready.status_code == 200
    ready_data = resp_ready.json()
    assert ready_data["status"] in ["ready", "degraded"]


@pytest.mark.asyncio
async def test_dashboard_metrics(client: AsyncClient):
    resp = await client.get("/api/v1/metrics/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events" in data
    assert "total_alerts" in data
    assert "critical_alerts" in data


@pytest.mark.asyncio
async def test_api_endpoint_count_and_inventory():
    """Verify that at least 26 functional API endpoints are registered."""
    openapi = app.openapi()
    paths = openapi["paths"]
    count = 0
    for path, methods in paths.items():
        for method in methods.keys():
            if method.lower() in ["get", "post", "put", "patch", "delete"]:
                count += 1
    assert count >= 26, f"Expected at least 26 endpoints, found {count}"


@pytest.mark.asyncio
async def test_ingest_and_alert_api_flow(client: AsyncClient):
    # Ingest event
    payload = {
        "format": "linux",
        "raw_log": "Oct 14 21:00:00 srv01 sshd[123]: Failed password for invalid user admin from 198.51.100.5 port 22 ssh2",
    }
    resp = await client.post("/api/v1/ingest/event", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True

    # List events
    resp_events = await client.get("/api/v1/events?page=1&page_size=10")
    assert resp_events.status_code == 200
    ev_data = resp_events.json()
    assert ev_data["total"] >= 1


@pytest.mark.asyncio
async def test_rules_api_toggle(client: AsyncClient):
    # List rules
    resp = await client.get("/api/v1/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 11

    # Toggle rule
    resp_toggle = await client.patch("/api/v1/rules/RULE-001/status", json={"status": "disabled"})
    assert resp_toggle.status_code == 200
    assert resp_toggle.json()["success"] is True


@pytest.mark.asyncio
async def test_iocs_crud(client: AsyncClient):
    ioc_data = {
        "indicator_value": "198.51.100.99",
        "indicator_type": "ipv4",
        "severity": "critical",
        "confidence": 90,
    }
    resp = await client.post("/api/v1/iocs", json=ioc_data)
    assert resp.status_code == 201
    created = resp.json()
    assert created["indicator_value"] == "198.51.100.99"

    # Search IOC
    resp_search = await client.get("/api/v1/iocs/search?q=198.51.100")
    assert resp_search.status_code == 200
    assert len(resp_search.json()) >= 1

