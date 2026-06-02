"""
Sign a probe pack so it can be assigned the `verified` trust tier.

Produces a detached signature file (<pack>.yaml.sig) containing a base64
RS256 (PKCS1v15 / SHA-256) signature over the raw YAML bytes.

The auditor assigns trust_tier=verified to a pack only when this .sig file
validates against a public key in RAG_AUDITOR_TRUSTED_KEYS_DIR.

Usage:
    python -m scripts.sign_probe_pack <pack.yaml> <private_key.pem>
"""

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    if len(sys.argv) != 3:
        print("Usage: python -m scripts.sign_probe_pack <pack.yaml> <private_key.pem>")
        sys.exit(1)

    pack_path = Path(sys.argv[1])
    key_path = Path(sys.argv[2])

    if not pack_path.exists():
        print(f"Pack not found: {pack_path}")
        sys.exit(1)
    if not key_path.exists():
        print(f"Private key not found: {key_path}")
        sys.exit(1)

    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    data = pack_path.read_bytes()
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    sig_path = pack_path.with_suffix(pack_path.suffix + ".sig")
    sig_path.write_text(base64.b64encode(signature).decode())

    print(f"Signature written: {sig_path}")
    print("Distribute the matching public key to verifiers' RAG_AUDITOR_TRUSTED_KEYS_DIR")
    print("for this pack to earn the 'verified' trust tier.")


if __name__ == "__main__":
    main()
