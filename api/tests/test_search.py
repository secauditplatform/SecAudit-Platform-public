from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.api.v1.routers import search as search_router
from app.core.auth import AuthUser
from app.models import JobScope, JobStatus, UserRole
from app.schemas import SearchResultItem


def test_search_requires_auth(client: TestClient):
    response = client.get("/api/v1/search", params={"q": "web"})
    assert response.status_code == 401


def test_search_empty_query_returns_empty_items(client: TestClient, auth_headers: dict[str, str]):
    response = client.get("/api/v1/search", params={"q": "  "}, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["query"] == ""


@pytest.mark.asyncio
async def test_global_search_aggregates_typed_results(monkeypatch: pytest.MonkeyPatch):
    host = SimpleNamespace(id=1, name="web-01", hostname="10.0.0.5")
    job = SimpleNamespace(
        id=10,
        name="Daily web audit",
        scope=JobScope.STANDARD,
        execution_type=SimpleNamespace(value="ssh"),
    )
    job_run = SimpleNamespace(id=42, status=JobStatus.COMPLETED, job_id=10)
    profile = SimpleNamespace(
        id=3,
        profile_name="CIS Web Benchmark",
        version="1.0.0",
        profile_title="CIS Web",
        summary="Web server hardening",
        os_name="Linux",
    )
    remediation = SimpleNamespace(
        id=9,
        name="Fix web passwords",
        scope=JobScope.STANDARD,
        execution_type=SimpleNamespace(value="ssh"),
    )

    class _Scalars:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _Result:
        def __init__(self, *, scalars=None, rows=None):
            self._scalars = scalars or []
            self._rows = rows or []

        def scalars(self):
            return _Scalars(self._scalars)

        def all(self):
            return self._rows

    calls: list[str] = []

    async def _execute(stmt):
        sql = str(stmt).lower()
        calls.append(sql)
        if "from hosts" in sql:
            return _Result(scalars=[host])
        if "from jobs" in sql and "job_runs" not in sql and "remediation" not in sql:
            return _Result(scalars=[job])
        if "job_runs" in sql:
            return _Result(rows=[(job_run, job)])
        if "from profiles" in sql:
            return _Result(scalars=[profile])
        if "remediation_jobs" in sql:
            return _Result(scalars=[remediation])
        return _Result()

    fake_db = AsyncMock()
    fake_db.execute = _execute

    response = await search_router.global_search(
        q="web",
        limit=25,
        per_type=5,
        db=fake_db,
        user=AuthUser(sub="local:tester", username="tester", roles=[UserRole.OPERATOR.value]),
    )

    assert response.query == "web"
    assert len(response.items) >= 3
    types = {item.type for item in response.items}
    assert "host" in types
    assert "job" in types
    assert "run" in types
    assert "profile" in types
    assert "remediation" in types
    assert all(isinstance(item, SearchResultItem) for item in response.items)
    assert any(item.href == "/hosts?edit=1" for item in response.items if item.type == "host")
    assert any(
        item.href == "/jobs?edit=10&platform=linux" for item in response.items if item.type == "job"
    )
    assert any(item.href.startswith("/reports?run=") for item in response.items if item.type == "run")
    assert any(item.href == "/profiles?id=3" for item in response.items if item.type == "profile")
    assert any(
        item.href == "/remediation?edit=9&platform=linux"
        for item in response.items
        if item.type == "remediation"
    )
    assert len(calls) == 5


def test_job_and_remediation_href_routes():
    assert search_router._job_href(1, scope=JobScope.NETWORK, execution_type="python") == (
        "/network/jobs?edit=1"
    )
    assert search_router._job_href(2, scope=JobScope.STANDARD, execution_type="winrm") == (
        "/jobs?edit=2&platform=windows"
    )
    assert search_router._remediation_href(3, scope=JobScope.NETWORK, execution_type="python") == (
        "/network/remediation?edit=3"
    )


@pytest.mark.asyncio
async def test_global_search_respects_limit(monkeypatch: pytest.MonkeyPatch):
    hosts = [SimpleNamespace(id=i, name=f"host-{i}", hostname=f"h{i}.local") for i in range(5)]

    class _Scalars:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _Result:
        def __init__(self, *, scalars=None, rows=None):
            self._scalars = scalars or []
            self._rows = rows or []

        def scalars(self):
            return _Scalars(self._scalars)

        def all(self):
            return self._rows

    async def _execute(stmt):
        sql = str(stmt).lower()
        if "from hosts" in sql:
            return _Result(scalars=hosts)
        return _Result()

    fake_db = AsyncMock()
    fake_db.execute = _execute

    response = await search_router.global_search(
        q="host",
        limit=2,
        per_type=5,
        db=fake_db,
        user=AuthUser(sub="local:tester", username="tester", roles=[UserRole.OPERATOR.value]),
    )
    assert len(response.items) == 2


def test_score_prefers_exact_and_prefix_matches():
    assert search_router._score("web-01", query="web-01") == 100
    assert search_router._score("web-server", query="web") == 80
    assert search_router._score("my-web-host", query="web") == 50
