import pytest

from app.main import app


@pytest.fixture()
def client():
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_search_notes_returns_matching_rows(client):
    rows = client.get("/notes?q=milk").get_json()
    assert len(rows) == 1
    assert rows[0]["owner"] == "alice"


def test_calc_basic_math(client):
    assert client.get("/calc?expr=2%2B3").get_json() == {"result": 5}


def test_hash_returns_32_char_digest(client):
    digest = client.get("/hash?text=abc").get_json()["md5"]
    assert digest == "900150983cd24fb0d6963f7d28e17f72"
