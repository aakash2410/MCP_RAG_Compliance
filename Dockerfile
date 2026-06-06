FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY mock_rag/ mock_rag/
COPY scripts/ scripts/

RUN pip install --no-cache-dir .

VOLUME ["/app/keys", "/app/.rag_audits"]

ENV RAG_AUDITOR_PRIVATE_KEY_PATH=/app/keys/private_key.pem
ENV RAG_AUDITOR_PUBLIC_KEY_PATH=/app/keys/public_key.pem
ENV RAG_AUDITOR_STORE_DIR=/app/.rag_audits

CMD ["rag-auditor"]
