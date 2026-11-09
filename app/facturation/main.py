"""Point d'entree FastAPI de facturation-api (version corrigee).

Chaque correctif reference la faille detectee par le pipeline DevSecOps.
"""
import hashlib
import html
import ipaddress
import secrets
import socket

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import db

app = FastAPI(title="facturation-api", version="1.1.0")
db.init_db()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """CORRECTIF (DAST/ZAP) : en-tetes de securite HTTP sur toutes les reponses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


class InvoiceIn(BaseModel):
    customer: str = Field(min_length=1, max_length=120)
    amount: float = Field(gt=0, lt=10_000_000)


class ImportRequest(BaseModel):
    """CORRECTIF (CWE-502) : JSON valide par schema au lieu d'un objet pickle."""
    invoices: list[InvoiceIn] = Field(max_length=500)


class NewUser(BaseModel):
    name: str = Field(min_length=2, max_length=40, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=12, max_length=128)


def current_user(api_key: str | None) -> dict:
    conn = db.connect()
    row = conn.execute("SELECT id, name FROM users WHERE api_key = ?", (api_key,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Cle API invalide")
    return dict(row)


def hash_password(password: str) -> str:
    """CORRECTIF (CWE-327/916) : scrypt sale au lieu de MD5."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/invoices")
def list_invoices(x_api_key: str | None = Header(default=None)) -> list[dict]:
    user = current_user(x_api_key)
    conn = db.connect()
    rows = conn.execute("SELECT * FROM invoices WHERE owner_id = ?", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/invoices/search")
def search_invoices(customer: str, x_api_key: str | None = Header(default=None)) -> list[dict]:
    """CORRECTIF (CWE-89) : requete parametree, la saisie n'est jamais interpretee comme du SQL."""
    user = current_user(x_api_key)
    conn = db.connect()
    rows = conn.execute(
        "SELECT * FROM invoices WHERE owner_id = ? AND customer LIKE ?",
        (user["id"], f"%{customer}%"),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, x_api_key: str | None = Header(default=None)) -> dict:
    """CORRECTIF (BOLA / OWASP API1) : la facture doit appartenir a l'appelant."""
    user = current_user(x_api_key)
    conn = db.connect()
    row = conn.execute(
        "SELECT * FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, user["id"])
    ).fetchone()
    conn.close()
    if row is None:  # 404 et non 403 : on ne revele pas l'existence de la facture
        raise HTTPException(status_code=404, detail="Facture introuvable")
    return dict(row)


@app.post("/invoices/import")
def import_invoices(req: ImportRequest, x_api_key: str | None = Header(default=None)) -> dict:
    user = current_user(x_api_key)
    conn = db.connect()
    conn.executemany(
        "INSERT INTO invoices (owner_id, customer, amount) VALUES (?, ?, ?)",
        [(user["id"], i.customer, i.amount) for i in req.invoices],
    )
    conn.commit()
    conn.close()
    return {"imported": len(req.invoices)}


@app.get("/admin/resolve")
def resolve(host: str, x_api_key: str | None = Header(default=None)) -> dict:
    """CORRECTIF (CWE-78) : plus de shell. Resolution DNS en Python, entree validee,
    endpoint d'administration desormais authentifie."""
    current_user(x_api_key)
    if len(host) > 253 or not all(c.isalnum() or c in ".-" for c in host):
        raise HTTPException(status_code=400, detail="Nom d'hote invalide")
    try:
        address = socket.gethostbyname(host)
    except OSError:
        raise HTTPException(status_code=404, detail="Hote introuvable") from None
    return {"host": host, "address": address, "private": ipaddress.ip_address(address).is_private}


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "client") -> str:
    """CORRECTIF (XSS, CWE-79) : echappement HTML de la saisie."""
    return f"<html><body><h1>Bonjour {html.escape(name)}</h1></body></html>"


@app.post("/users")
def create_user(user: NewUser) -> dict:
    conn = db.connect()
    cur = conn.execute(
        "INSERT INTO users (name, api_key, password_hash) VALUES (?, ?, ?)",
        (user.name, secrets.token_urlsafe(32), hash_password(user.password)),
    )
    conn.commit()
    conn.close()
    return {"id": cur.lastrowid, "name": user.name}