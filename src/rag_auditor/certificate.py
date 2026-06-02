"""RS256 JWT compliance certificate issuance and verification."""

import hashlib
import json
import os
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from . import store

ISSUER = "rag-auditor.mcp/v1"
DEFAULT_TTL_HOURS = int(os.getenv("RAG_AUDITOR_CERT_TTL_HOURS", "168"))


def _private_key_path() -> Path:
    return Path(os.getenv("RAG_AUDITOR_PRIVATE_KEY_PATH", "./keys/private_key.pem"))


def _public_key_path() -> Path:
    return Path(os.getenv("RAG_AUDITOR_PUBLIC_KEY_PATH", "./keys/public_key.pem"))


def ensure_keys() -> None:
    priv = _private_key_path()
    pub = _public_key_path()
    if priv.exists() and pub.exists():
        return

    priv.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    priv.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _load_private_key():
    ensure_keys()
    return serialization.load_pem_private_key(
        _private_key_path().read_bytes(),
        password=None,
        backend=default_backend(),
    )


def _load_public_key():
    ensure_keys()
    return serialization.load_pem_public_key(
        _public_key_path().read_bytes(),
        backend=default_backend(),
    )


def issue(audit_result: dict, ttl_hours: int | None = None) -> dict:
    """Issue a signed JWT certificate for a completed audit."""
    ttl = ttl_hours or DEFAULT_TTL_HOURS
    now = int(time.time())
    exp = now + ttl * 3600

    endpoint_hash = hashlib.sha256(
        f"{audit_result['endpoint_url']}:{audit_result['probe_pack_version']}".encode()
    ).hexdigest()

    payload = {
        "iss": ISSUER,
        "sub": f"audit:{audit_result['audit_id']}",
        "iat": now,
        "exp": exp,
        "endpoint_hash": f"sha256:{endpoint_hash}",
        "probe_pack": audit_result["probe_pack_version"],
        "frameworks": audit_result["frameworks"],
        "verdict": audit_result["verdict"],
        "dimension_scores": {
            dim: round(info["score"], 4)
            for dim, info in audit_result["dimensions"].items()
        },
        "overall_score": audit_result["overall_score"],
    }

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    fingerprint = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
    payload["fingerprint"] = fingerprint

    token = jwt.encode(payload, _load_private_key(), algorithm="RS256")

    registry_entry = {
        "audit_id": audit_result["audit_id"],
        "fingerprint": fingerprint,
        "issued_at": now,
        "expires_at": exp,
        "verdict": audit_result["verdict"],
    }
    store.append_cert_registry(registry_entry)

    return {
        "certificate_jwt": token,
        "fingerprint": fingerprint,
        "issued_at": now,
        "expires_at": exp,
        "ttl_hours": ttl,
        "verdict": audit_result["verdict"],
        "public_key_pem": _public_key_path().read_text(),
    }


def verify(token: str) -> dict:
    """Verify a certificate JWT. Returns status dict."""
    try:
        payload = jwt.decode(
            token,
            _load_public_key(),
            algorithms=["RS256"],
            options={"verify_exp": True},
        )
        fingerprint = payload.get("fingerprint", "")
        registry_entry = store.lookup_cert(fingerprint)
        return {
            "valid": True,
            "payload": payload,
            "fingerprint": fingerprint,
            "expires_at": payload.get("exp"),
            "verdict": payload.get("verdict"),
            "issuer": payload.get("iss"),
            "in_registry": registry_entry is not None,
        }
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Certificate expired"}
    except jwt.InvalidTokenError as exc:
        return {"valid": False, "error": str(exc)}
