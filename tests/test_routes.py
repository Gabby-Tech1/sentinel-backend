import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client():
    # Use an isolated SQLite DB so tests don't touch the dev database.
    tmpdir = tempfile.mkdtemp(prefix="sentinel-test-")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/test.db"
    # Re-import so settings picks up the new env var.
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_scenarios(client):
    r = client.get("/scenarios")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 6
    ids = {s["id"] for s in data}
    assert "scn-recon-min-gov" in ids


def test_get_scenario(client):
    r = client.get("/scenarios/scn-recon-min-gov")
    assert r.status_code == 200
    scn = r.json()
    assert scn["name"] == "Ministry Network — Recon Baseline"
    assert len(scn["topology"]["hosts"]) == 3
    assert len(scn["groundTruth"]) == 3


def test_missing_scenario_404(client):
    assert client.get("/scenarios/does-not-exist").status_code == 404


def test_list_runs(client):
    r = client.get("/runs")
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 2


def test_get_run_with_events(client):
    r = client.get("/runs/run-2026-06-12-1014")
    assert r.status_code == 200
    run = r.json()
    assert run["status"] == "completed"
    assert len(run["events"]) > 0
    assert run["metrics"]["f1"] > 0


def test_list_findings(client):
    r = client.get("/findings")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 12


def test_findings_theme_filter(client):
    r = client.get("/findings?theme=technical")
    assert r.status_code == 200
    for f in r.json():
        assert f["theme"] == "technical"


def test_framework(client):
    r = client.get("/framework")
    assert r.status_code == 200
    fw = r.json()
    assert len(fw["pillars"]) == 5
    assert len(fw["maturityLadder"]) == 5


def test_openapi_docs_available(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert "openapi" in r.json()
