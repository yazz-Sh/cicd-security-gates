"""Tests fonctionnels de facturation-api."""
from fastapi.testclient import TestClient

from facturation.main import app

client = TestClient(app)
ALICE = {"X-API-Key": "alice-demo-key"}


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_list_requires_api_key():
    assert client.get("/invoices").status_code == 401


def test_list_own_invoices():
    r = client.get("/invoices", headers=ALICE)
    assert r.status_code == 200
    assert {i["owner_id"] for i in r.json()} == {1}


def test_search_by_customer():
    r = client.get("/invoices/search", params={"customer": "Orange"}, headers=ALICE)
    assert [i["id"] for i in r.json()] == [2]


def test_get_own_invoice():
    assert client.get("/invoices/1", headers=ALICE).json()["customer"] == "Societe Tunisienne de Banque"


def test_unknown_invoice():
    assert client.get("/invoices/999", headers=ALICE).status_code == 404


def test_hello():
    assert "Bonjour Yasmine" in client.get("/hello", params={"name": "Yasmine"}).text


def test_create_user():
    r = client.post("/users", json={"name": "carol", "password": "Passw0rd!"})
    assert r.status_code == 200 and r.json()["name"] == "carol"