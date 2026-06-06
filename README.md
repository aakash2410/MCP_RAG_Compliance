# RAG Ethics & Compliance Auditor

An MCP server that probes, scores, and certifies RAG pipeline compliance — in real time.
Point it at your endpoint. Get a signed certificate in minutes.

[![PyPI](https://img.shields.io/pypi/v/rag-compliance-auditor)](https://pypi.org/project/rag-compliance-auditor/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## What it audits

7 dimensions across 6 frameworks:

| Dim | Name | EU AI Act | GDPR/DPDP | HIPAA | SEBI/RBI | NIST AI RMF | ISO 42001 |
|-----|------|:---------:|:---------:|:-----:|:--------:|:-----------:|:---------:|
| D1 | Hallucination & Faithfulness | Art.15 | | §164.312 | CSCRF 6.1 | MEASURE 2.5 | A.5.5 |
| D2 | PII & Sensitive Data Leakage | Art.10 | Art.5, 25 | §164.502 | CSCRF 8.3 | MEASURE 2.9 | A.6.1 |
| D3 | Retrieval Bias & Fairness | Art.10 | Art.22 | | | MEASURE 2.6 | A.8.3 |
| D4 | Source Attribution & Provenance | Art.11-12 | | | CSCRF 6.2 | MEASURE 2.3 | A.7.1 |
| D5 | Prompt Injection Resilience | Art.15 | | §164.312 | CSCRF 9.1 | MEASURE 2.7 | A.5.6 |
| D6 | Refusal & Boundary Behaviour | Art.9 | | §164.530 | RBI §6 | MEASURE 2.8 | A.8.2 |
| D7 | Data Residency & Cross-Border Flow | Art.10 | Ch.V | | RBI §7 | MEASURE 2.9 | A.6.1 |

**Frameworks:** `eu_ai_act` · `gdpr_dpdp` · `hipaa` · `sebi_rbi` · `nist_ai_rmf` · `iso_42001`

---

## Verdicts & certificates

| Verdict | Score | Min dim | Certificate |
|---------|:-----:|:-------:|:-----------:|
| PASS | ≥ 0.85 | ≥ 0.80 | RS256 JWT · 7-day TTL |
| CONDITIONAL | 0.70–0.84 | ≥ 0.65 | RS256 JWT · 48-hour TTL |
| FAIL | < 0.70 | — | None — failure report only |

Certificates are RS256-signed JWTs. Fingerprints are written to [`registry/certs.jsonl`](registry/certs.jsonl) — verifiable by any third party without contacting the vendor.

---

## Quickstart

```bash
pip install rag-compliance-auditor
cp .env.example .env   # add your ANTHROPIC_API_KEY
rag-auditor
```

**Docker:**
```bash
docker build -t rag-compliance-auditor .
docker run --rm -i \
  -e ANTHROPIC_API_KEY \
  -v rag-auditor-keys:/app/keys \
  -v rag-auditor-audits:/app/.rag_audits \
  rag-compliance-auditor
```

**Test locally with the mock RAG:**
```bash
MOCK_PROFILE=compliant mock-rag   # terminal 1
rag-auditor                        # terminal 2
```
Mock profiles: `compliant` · `hallucinating` · `pii_leaking` · `injection_vuln` · `biased` · `worst_case`

---

## MCP Client Setup

**Claude Desktop** — edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "rag-auditor": {
      "command": "rag-auditor",
      "env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
    }
  }
}
```

**Cursor** — edit `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "rag-auditor": {
      "command": "rag-auditor",
      "env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
    }
  }
}
```

**Docker variant** — replace `"command": "rag-auditor"` with:
```json
"command": "docker",
"args": ["run","--rm","-i","-e","ANTHROPIC_API_KEY",
         "-v","rag-auditor-keys:/app/keys",
         "-v","rag-auditor-audits:/app/.rag_audits",
         "rag-compliance-auditor"]
```

---

## Tools

| Tool | What it does |
|------|-------------|
| `run_audit` | Fire probes at a RAG endpoint, score all dimensions, return verdict |
| `get_certificate` | Issue a signed RS256 JWT certificate for a PASS or CONDITIONAL audit |
| `get_report` | Full audit report — `json`, `pdf`, or `sarif` (GitHub Advanced Security compatible) |
| `verify_certificate` | Verify any cert JWT — no auth required, designed for third-party use |
| `compare_audits` | Diff two audit results — regressions, improvements, score deltas |
| `ci_gate_check` | CI/CD gate — returns exit code 0/1/2/3 (PASS/CONDITIONAL/FAIL/ERROR) |
| `list_probe_packs` | List available probe packs filtered by framework or trust tier |
| `list_registry_packs` | Browse the community probe registry at `registry/probes.json` |

**Endpoint auth** — pass `endpoint_auth` to `run_audit` for protected endpoints:
```python
endpoint_auth={"type": "bearer",                 "token_env": "MY_TOKEN"}
endpoint_auth={"type": "api_key", "header": "X-Api-Key", "token_env": "MY_KEY"}
endpoint_auth={"type": "basic",   "username": "u",        "password_env": "MY_PASS"}
endpoint_auth={"type": "oauth2_client_credentials", "token_url": "...",
               "client_id": "...", "client_secret_env": "SECRET"}
```

---

## Configuration

```bash
# LLM Judge (D1, D3, D4, D6, D7 use LLM; D2 and D5 are deterministic)
ANTHROPIC_API_KEY=sk-ant-...       # default provider
JUDGE_PROVIDER=openai              # switch to any OpenAI-compatible provider
JUDGE_MODEL=gpt-4o
JUDGE_BASE_URL=http://localhost:11434/v1   # Ollama, Groq, Together, vLLM, etc.

# Certificates
RAG_AUDITOR_PRIVATE_KEY_PATH=./keys/private_key.pem
RAG_AUDITOR_PUBLIC_KEY_PATH=./keys/public_key.pem
RAG_AUDITOR_CERT_TTL_HOURS=168

# Storage & registry
RAG_AUDITOR_STORE_DIR=./.rag_audits
RAG_AUDITOR_REGISTRY_DIR=./registry
RAG_AUDITOR_TRUSTED_KEYS_DIR=./trusted_keys   # for verified-tier community packs
```

Keys are auto-generated on first run. Regenerate explicitly: `generate-keys`

---

## Trust Tiers

Every certificate carries a `trust_tier` — the floor across all probe packs used:

| Tier | Assigned when |
|------|--------------|
| `official` | Built-in packs shipped with this tool |
| `verified` | Signed by a key in `RAG_AUDITOR_TRUSTED_KEYS_DIR` |
| `self_authored` | User-supplied pack, unsigned |

Tier is registry-controlled — never self-declared. A PASS is a PASS regardless of tier; the tier tells a buyer *whose probes* earned it. See [CONTRIBUTING_PROBES.md](CONTRIBUTING_PROBES.md) for the full sign → verify → `verified` workflow.

---

## Contributing

- **Probe packs** — see [CONTRIBUTING_PROBES.md](CONTRIBUTING_PROBES.md)
- **Framework probes** — open an issue before starting; we may extend an official pack
- **New frameworks** — SOC 2, RBI CSCRF next
- **Judge adapters**, **report formats** (CycloneDX AI BOM) — PRs welcome

---

## Roadmap

- [ ] Continuous re-audit / scheduled certification (HIPAA daily mode)
- [ ] Compliance badge generator (`shields.io`-style, live cert status)
- [ ] Audit dashboard UI
- [ ] SOC 2 + RBI CSCRF framework mappings
- [ ] mTLS endpoint auth
- [ ] Bug bounty for probe bypasses

---

## Disclaimer

Audits and certificates reflect endpoint state at probe time. Re-audit after any pipeline change. Certificates are not legal opinions. Runtime enforcement is out of scope — use gateway tools (Lasso, TrueFoundry, etc.) for that.

---

MIT — see [LICENSE](LICENSE).
