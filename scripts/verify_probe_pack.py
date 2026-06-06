"""
Verify the signature of a signed probe pack before trusting it.

Run this before adding a pack author's public key to RAG_AUDITOR_TRUSTED_KEYS_DIR.
A successful verification means the .yaml file has not been tampered with since
the author signed it — it does NOT vouch for the quality of the probes inside.

Usage:
    python -m scripts.verify_probe_pack <pack.yaml> <author_public_key.pem>

Exit codes:
    0 — signature valid
    1 — signature invalid or files not found
"""

import base64
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    if len(sys.argv) != 3:
        print("Usage: python -m scripts.verify_probe_pack <pack.yaml> <author_public_key.pem>")
        sys.exit(1)

    pack_path = Path(sys.argv[1])
    key_path  = Path(sys.argv[2])

    sig_path = pack_path.with_suffix(pack_path.suffix + ".sig")

    for p, label in [(pack_path, "Pack"), (key_path, "Public key"), (sig_path, "Signature file")]:
        if not p.exists():
            print(f"ERROR: {label} not found: {p}")
            sys.exit(1)

    try:
        pub_key = serialization.load_pem_public_key(key_path.read_bytes())
        signature = base64.b64decode(sig_path.read_text().strip())
        data = pack_path.read_bytes()
        pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print(f"INVALID — signature does not match {pack_path.name} with the provided public key.")
        print("Do NOT add this key to your trusted keys directory.")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR — {exc}")
        sys.exit(1)

    print(f"VALID — {pack_path.name} signature verified against {key_path.name}")
    print()
    print("To trust this pack at the 'verified' tier, add the public key to your trusted keys dir:")
    print(f"  cp {key_path} $RAG_AUDITOR_TRUSTED_KEYS_DIR/")


if __name__ == "__main__":
    main()
