"""
Confidential data store.

Loads the synthetic confidential data that the protected applications serve.
Files live under backend/data/{hr,finance,documents}. Keeping the data behind
this module means the Zero Trust gateway (RBAC-guarded routes) is the only way
to reach it.
"""

import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HR_FILE = os.path.join(DATA_DIR, "hr", "employees.json")
FINANCE_FILE = os.path.join(DATA_DIR, "finance", "financials.json")
PATIENTS_FILE = os.path.join(DATA_DIR, "patients", "patients.json")
DOCS_DIR = os.path.join(DATA_DIR, "documents")


def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def hr_data():
    return _load_json(HR_FILE)


def finance_data():
    return _load_json(FINANCE_FILE)


def patients_data():
    return _load_json(PATIENTS_FILE)


def list_documents():
    """Return metadata for every document file (no content)."""
    docs = []
    if not os.path.isdir(DOCS_DIR):
        return docs
    for name in sorted(os.listdir(DOCS_DIR)):
        path = os.path.join(DOCS_DIR, name)
        if os.path.isfile(path):
            docs.append({
                "name": name,
                "size_bytes": os.path.getsize(path),
                "classification": "CONFIDENTIAL",
            })
    return docs


def read_document(name):
    """Return a document's text content, or None if the name is invalid.

    The basename check prevents path traversal (e.g. ../../etc/passwd)."""
    if name != os.path.basename(name):
        return None
    path = os.path.join(DOCS_DIR, name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None
