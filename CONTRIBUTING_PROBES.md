# Contributing Probe Packs

This guide covers everything you need to publish a probe pack and have it listed in the registry at `verified` trust tier.

---

## Trust tiers recap

| Tier | Assigned when | What it means for a certificate |
|------|--------------|----------------------------------|
| `official` | Pack ships with `rag-compliance-auditor` | Maintained by the project |
| `verified` | Pack has a valid signature from a key in `RAG_AUDITOR_TRUSTED_KEYS_DIR` | A third party you trust vouches for it |
| `self_authored` | Pack loaded from a user directory, unsigned | Identifiable but unvouched |

A certificate's overall tier is the **floor** across all packs used. Your goal as a contributor is to get your pack to `verified` in your users' deployments.

---

## Step 1 — Write the probe pack

Use [`examples/custom_toxicity_probe.yaml`](examples/custom_toxicity_probe.yaml) as a template. The full schema is documented inline.

Key rules:
- `dimension` must be unique and not clash with `D1`–`D7` (reserved)
- Each probe needs a unique `id`, a `type` (`benign` or `adversarial`), and a `query`
- Pick a `scoring_strategy`: `llm_judge`, `pii_regex`, or `injection_markers`
- Set `author` and `author_uri` — these are disclosed in certificates as a return address

Test your pack locally before signing:

```bash
export RAG_AUDITOR_PROBES_DIR=/path/to/your/packs
rag-auditor
# Then from any MCP client:
# run_audit(endpoint_url="...", frameworks=[], extra_dimensions=["YOUR_DIM"])
```

---

## Step 2 — Generate a signing key pair

If you don't have one already:

```bash
# Using the bundled tool
generate-keys

# Or with openssl directly
openssl genrsa -out author_private_key.pem 2048
openssl rsa -in author_private_key.pem -pubout -out author_public_key.pem
```

Keep `author_private_key.pem` secret — never commit it, never share it.
Distribute `author_public_key.pem` so verifiers can trust your packs.

---

## Step 3 — Sign your pack

```bash
sign-probe-pack my_packs/my_pack.yaml author_private_key.pem
# Produces: my_packs/my_pack.yaml.sig
```

Distribute both `my_pack.yaml` and `my_pack.yaml.sig` together (e.g. in a GitHub release).

---

## Step 4 — Verifiers trust your key

Anyone who wants your pack to earn `verified` tier adds your public key to their trusted keys directory:

```bash
# Verifier first checks the signature
verify-probe-pack my_pack.yaml author_public_key.pem
# VALID — my_pack.yaml signature verified

# Then adds the key
export RAG_AUDITOR_TRUSTED_KEYS_DIR=/path/to/trusted_keys
cp author_public_key.pem $RAG_AUDITOR_TRUSTED_KEYS_DIR/your-org.pem
```

From that point on, any pack signed by your key loads as `trust_tier: verified` in their environment.

---

## Step 5 — List your pack in the registry

Open a PR that adds an entry to [`registry/probes.json`](registry/probes.json):

```json
{
  "id": "your-org/my-pack-name",
  "dimension": "YOUR_DIMENSION",
  "name": "Human-readable name",
  "version": "1.0.0",
  "author": "Your Name or Org",
  "author_uri": "https://github.com/your-org",
  "download_url": "https://raw.githubusercontent.com/your-org/your-repo/main/packs/my_pack.yaml",
  "signature_url": "https://raw.githubusercontent.com/your-org/your-repo/main/packs/my_pack.yaml.sig",
  "frameworks": ["eu_ai_act"],
  "description": "One sentence describing what this pack tests.",
  "trust_tier": "verified",
  "status": "active"
}
```

The registry entry is purely informational — it lets users discover your pack. The actual `verified` tier is earned at runtime by the signature check, not by appearing in this file.

---

## Review criteria

Before a registry PR is merged, the maintainers check:

- [ ] Pack loads without errors: `python -m yaml my_pack.yaml`
- [ ] Signature verifies: `verify-probe-pack my_pack.yaml author_public_key.pem`
- [ ] `download_url` and `signature_url` are reachable
- [ ] `dimension` ID doesn't conflict with existing entries
- [ ] Probes are clearly scoped — adversarial probes test a specific failure mode, not general quality
- [ ] Framework mappings are accurate (see [`src/rag_auditor/frameworks.py`](src/rag_auditor/frameworks.py) for control references)

Open an issue first if you're building a pack for an existing dimension — we may prefer to extend the official pack rather than add a parallel one.
