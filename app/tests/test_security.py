"""Tests de non-regression securite : chaque faille corrigee a son test.
Si quelqu'un reintroduit la faille, le pipeline echoue au stage unit_tests."""
from fastapi.testclient import TestClient

from facturation.main import app, hash_password

client = TestClient(app)
ALICE = {"X-API-Key": "alice-demo-key"}


def test_sql_injection_does_not_leak_other_users_invoices():
    # Avant correctif, ce payload renvoyait aussi la facture de Bob (id 3)
    r = client.get("/invoices/search", params={"customer": "' OR '1'='1"}, headers=ALICE)
    assert r.status_code == 200
    assert all(i["owner_id"] == 1 for i in r.json())


def test_bola_cannot_read_another_users_invoice():
    # La facture 3 appartient a Bob : Alice ne doit pas pouvoir la lire
    assert client.get("/invoices/3", headers=ALICE).status_code == 404


def test_import_rejects_non_json_payload():
    # L'ancien endpoint acceptait un objet pickle encode en base64 (RCE)
    r = client.post("/invoices/import", headers=ALICE, json={"data": "gASVAAAAAAAAAAB9lC4="})
    assert r.status_code == 422


def test_command_injection_rejected():
    r = client.get("/admin/resolve", params={"host": "localhost; cat /etc/passwd"}, headers=ALICE)
    assert r.status_code == 400


def test_admin_endpoint_requires_authentication():
    assert client.get("/admin/resolve", params={"host": "localhost"}).status_code == 401


def test_xss_is_escaped():
    r = client.get("/hello", params={"name": "<script>alert(1)</script>"})
    assert "<script>" not in r.text and "&lt;script&gt;" in r.text


def test_security_headers_present():
    h = client.get("/health").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"


def test_password_is_not_md5():
    h = hash_password("Un-Mot-De-Passe-Long-2026")
    assert h.startswith("scrypt$") and len(h) > 100


def test_weak_password_rejected():
    r = client.post("/users", json={"name": "dave", "password": "123"})
    assert r.status_code == 422