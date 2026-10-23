import pytest

from app.main import app


@pytest.fixture()
def client():
    return app.test_client()


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_search_notes_returns_matching_rows(client):
    rows = client.get("/notes?q=milk").get_json()
    assert len(rows) == 1 and rows[0]["owner"] == "alice"


def test_sql_injection_payload_is_treated_as_plain_text(client):
    # On the vulnerable version this returns every row.
    assert client.get("/notes?q=' OR '1'='1").get_json() == []


def test_calc_basic_math(client):
    assert client.get("/calc?expr=2%2B3").get_json() == {"result": 5}


def test_calc_rejects_code(client):
    assert client.get("/calc?expr=__import__('os').getcwd()").status_code == 400


def test_diag_does_not_run_injected_command(client):
    out = client.get("/diag?name=x;echo%20pwned").get_json()["output"]
    assert out == "diagnostic for x;echo pwned"


def test_hash_is_sha256(client):
    digest = client.get("/hash?text=abc").get_json()["sha256"]
    assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_fetch_blocks_unlisted_host(client):
    assert client.get("/fetch?url=https://evil.example.net").status_code == 400
