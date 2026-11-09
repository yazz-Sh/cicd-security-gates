"""Configuration de l'application.

CORRECTIF (secrets) : aucun secret dans le code. Les valeurs sont injectees a
l'execution par variables d'environnement (en production : coffre Vault /
External Secrets). Les anciennes cles AWS commitees ont ete REVOQUEES.
"""
import os
import tempfile
from pathlib import Path

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

DATABASE_PATH = os.environ.get("DATABASE_PATH", str(Path(tempfile.gettempdir()) / "facturation.db"))
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"