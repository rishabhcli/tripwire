"""Server tests. They need pydantic_core, which this author's Mac refuses to load
(unsigned native code), so they run on the Vultr VM: TRIPWIRE_TEST_SERVER=1 pytest."""
import os
import pytest

pytestmark = pytest.mark.skipif(os.environ.get("TRIPWIRE_TEST_SERVER") != "1",
                                reason="set TRIPWIRE_TEST_SERVER=1 (runs on the VM)")


def client():
    from fastapi.testclient import TestClient
    from tripwire.server import app
    return TestClient(app)


def test_health_and_samples():
    c = client()
    h = c.get("/api/health").json()
    assert h["ok"] and "hostile_conftest" in h["samples"] and len(h["payloads"]) == 8
    assert c.get("/").status_code == 200


def test_unknown_sample_is_404_and_missing_key_is_400(monkeypatch):
    monkeypatch.delenv("VULTR_INFERENCE_API_KEY", raising=False)
    c = client()
    assert c.post("/api/review", json={"sample": "nope"}).status_code == 404
    assert c.post("/api/review", json={"sample": "slugify_ok"}).status_code == 400


def test_oversized_file_is_rejected():
    c = client()
    r = c.post("/api/review", json={"files": {"a.py": "x" * 70000}})
    assert r.status_code == 400
