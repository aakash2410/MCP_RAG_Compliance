"""Audit result persistence — JSON files in a local directory."""

import json
import os
from pathlib import Path


def _store_dir() -> Path:
    path = Path(os.getenv("RAG_AUDITOR_STORE_DIR", ".rag_audits"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def save(audit_id: str, data: dict) -> None:
    path = _store_dir() / f"{audit_id}.json"
    path.write_text(json.dumps(data, indent=2))


def load(audit_id: str) -> dict:
    path = _store_dir() / f"{audit_id}.json"
    if not path.exists():
        raise KeyError(f"Audit {audit_id} not found")
    return json.loads(path.read_text())


def exists(audit_id: str) -> bool:
    return (_store_dir() / f"{audit_id}.json").exists()


def append_cert_registry(entry: dict) -> None:
    registry = _store_dir() / "cert_registry.jsonl"
    with registry.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def lookup_cert(fingerprint: str) -> dict | None:
    registry = _store_dir() / "cert_registry.jsonl"
    if not registry.exists():
        return None
    for line in registry.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("fingerprint") == fingerprint:
            return entry
    return None
