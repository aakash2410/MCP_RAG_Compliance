"""Generate RSA-2048 key pair for certificate signing."""

import os
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    priv_path = Path(os.getenv("RAG_AUDITOR_PRIVATE_KEY_PATH", "./keys/private_key.pem"))
    pub_path = Path(os.getenv("RAG_AUDITOR_PUBLIC_KEY_PATH", "./keys/public_key.pem"))

    if priv_path.exists():
        print(f"Keys already exist at {priv_path.parent}/. Delete them first to regenerate.")
        return

    priv_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    priv_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"Private key: {priv_path}")
    print(f"Public key:  {pub_path}")
    print("Keys generated successfully. Keep private_key.pem secret — never commit it.")


if __name__ == "__main__":
    main()
