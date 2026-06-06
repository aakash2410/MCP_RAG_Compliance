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

# Public registry — JSONL file committed to the repo and served via GitHub raw.
# Set RAG_AUDITOR_REGISTRY_DIR to override; defaults to ./registry relative to CWD.
def _registry_certs_path() -> Path | None:
    override = os.getenv("RAG_AUDITOR_REGISTRY_DIR")
    base = Path(override) if override else Path("registry")
    if base.is_dir():
        return base / "certs.jsonl"
    return None


def _append_public_registry(entry: dict) -> None:
    path = _registry_certs_path()
    if path is None:
        return
    try:
        with path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # never block cert issuance due to registry write failure


def _lookup_public_registry(fingerprint: str) -> bool:
    path = _registry_certs_path()
    if path is None or not path.exists():
        return False
    try:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            if json.loads(line).get("fingerprint") == fingerprint:
                return True
    except Exception:
        pass
    return False


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
        # Per-dimension probe provenance — who authored each pack and its
        # registry-assigned trust tier. Signed as part of the certificate.
        "probe_manifest": audit_result.get("probe_manifest", {}),
        # Overall trust floor: the lowest tier of any pack used in this audit.
        # Does NOT affect the verdict — it is disclosed so a verifier can judge
        # whether the probes behind a PASS are ones they trust.
        "trust_tier": audit_result.get("trust_tier", "self_authored"),
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
        "endpoint_hash": f"sha256:{endpoint_hash}",
        "issued_at": now,
        "expires_at": exp,
        "verdict": audit_result["verdict"],
        "frameworks": audit_result["frameworks"],
        "trust_tier": audit_result.get("trust_tier", "self_authored"),
    }
    store.append_cert_registry(registry_entry)
    _append_public_registry(registry_entry)

    return {
        "certificate_jwt": token,
        "fingerprint": fingerprint,
        "issued_at": now,
        "expires_at": exp,
        "ttl_hours": ttl,
        "verdict": audit_result["verdict"],
        "trust_tier": audit_result.get("trust_tier", "self_authored"),
        "probe_manifest": audit_result.get("probe_manifest", {}),
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
        in_local   = store.lookup_cert(fingerprint) is not None
        in_public  = _lookup_public_registry(fingerprint)
        return {
            "valid": True,
            "payload": payload,
            "fingerprint": fingerprint,
            "expires_at": payload.get("exp"),
            "verdict": payload.get("verdict"),
            # Trust floor + per-dimension provenance, surfaced so a verifier sees
            # which probe packs (and whose) a PASS was actually earned against.
            "trust_tier": payload.get("trust_tier", "self_authored"),
            "probe_manifest": payload.get("probe_manifest", {}),
            "issuer": payload.get("iss"),
            "in_registry": in_local or in_public,
            "in_local_registry": in_local,
            "in_public_registry": in_public,
        }
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Certificate expired"}
    except jwt.InvalidTokenError as exc:
        return {"valid": False, "error": str(exc)}
