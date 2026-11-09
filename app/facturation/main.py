"""Point d'entree FastAPI de facturation-api."""
import base64
import hashlib
import pickle
import subprocess

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import db

app = FastAPI(title="facturation-api", version="1.0.0")
db.init_db()


class ImportRequest(BaseModel):
    data: str


class NewUser(BaseModel):
    name: str
    password: str


def current_user(api_key: str | None) -> dict:
    conn = db.connect()
    row = conn.execute("SELECT id, name FROM users WHERE api_key = ?", (api_key,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Cle API invalide")
    return dict(row)


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
    user = current_user(x_api_key)
    conn = db.connect()
    query = f"SELECT * FROM invoices WHERE owner_id = {user['id']} AND customer LIKE '%{customer}%'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, x_api_key: str | None = Header(default=None)) -> dict:
    current_user(x_api_key)
    conn = db.connect()
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Facture introuvable")
    return dict(row)


@app.post("/invoices/import")
def import_invoices(req: ImportRequest, x_api_key: str | None = Header(default=None)) -> dict:
    current_user(x_api_key)
    invoices = pickle.loads(base64.b64decode(req.data))
    return {"imported": len(invoices)}


@app.get("/admin/ping")
def ping(host: str) -> dict:
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout + out.stderr}


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "client") -> str:
    return f"<html><body><h1>Bonjour {name}</h1></body></html>"


@app.post("/users")
def create_user(user: NewUser) -> dict:
    password_hash = hashlib.md5(user.password.encode()).hexdigest()
    conn = db.connect()
    cur = conn.execute(
        "INSERT INTO users (name, api_key, password_hash) VALUES (?, ?, ?)",
        (user.name, user.name + "-key", password_hash),
    )
    conn.commit()
    conn.close()
    return {"id": cur.lastrowid, "name": user.name}