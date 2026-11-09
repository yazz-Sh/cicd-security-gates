"""Acces a la base SQLite (donnees de demonstration)."""
import sqlite3

from . import config


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, api_key TEXT, password_hash TEXT);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER, customer TEXT, amount REAL);
        INSERT INTO users VALUES (1, 'alice', 'alice-demo-key', '');
        INSERT INTO users VALUES (2, 'bob', 'bob-demo-key', '');
        INSERT INTO invoices VALUES (1, 1, 'Societe Tunisienne de Banque', 1250.0);
        INSERT INTO invoices VALUES (2, 1, 'Orange Tunisie', 830.5);
        INSERT INTO invoices VALUES (3, 2, 'Poulina Group', 99000.0);
        """
    )
    conn.commit()
    conn.close()