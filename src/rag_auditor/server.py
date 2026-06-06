"""MCP server — exposes the six compliance auditor tools."""

import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import Context, FastMCP

load_dotenv()

from . import certificate, report, store
from .auditor import PROBE_PACK_VERSION, run_audit as _run_audit
from .runner import FRAMEWORK_DIMENSIONS, list_all_packs, load_pack

mcp = FastMCP(
    "RAG Compliance Auditor",
    instructions=(
        "Actively probe, score, and certify the ethical and regulatory compliance "
        "of any RAG pipeline. Supported frameworks: eu_ai_act, gdpr_dpdp, hipaa, sebi_rbi."
    ),
)


@mcp.tool()
async def run_audit(
    endpoint_url: str,
    frameworks: list[str],
    probe_pack_version: str = PROBE_PACK_VERSION,
    timeout_ms: int = 10_000,
    concurrency: int = 5,
    dimensions_override: list[str] | None = None,
    extra_dimensions: list[str] | None = None,
    custom_probe_dirs: list[str] | None = None,
    dimension_weights: dict[str, float] | None = None,
    endpoint_auth: dict | None = None,
    ctx: Context | None = None,
) -> dict:
    """
    Run a full compliance audit against a RAG endpoint.

    Args:
        endpoint_url:        HTTP/HTTPS URL of the RAG endpoint (POST with {"query": "..."}).
        frameworks:          Frameworks to audit. Options: eu_ai_act, gdpr_dpdp, hipaa, sebi_rbi.
        probe_pack_version:  Probe pack version tag recorded in the audit result.
        timeout_ms:          Per-probe request timeout in ms (default: 10000, max: 60000).
        concurrency:         Max parallel probe requests (default: 5, max: 20).
        dimensions_override: Replace framework-derived dimensions entirely (e.g. ["D1","D2"]).
        extra_dimensions:    Append extra dimensions to the framework-derived list.
                             Each entry can be a built-in ID ("D1"), a custom ID ("TOXICITY"),
                             or a direct path to a YAML file ("/path/to/toxicity.yaml").
        custom_probe_dirs:   Directories containing custom YAML probe packs. Custom dimensions
                             found here are automatically added to the audit. Also configurable
                             via the RAG_AUDITOR_PROBES_DIR environment variable.
        dimension_weights:   Override per-dimension weights for the overall score
                             (default: all 1.0). Example: {"D2": 2.0, "D5": 2.0}.
        endpoint_auth:       Auth config for protected RAG endpoints. Supported types:

                             Bearer token (reads token from env var MY_TOKEN):
                               {"type": "bearer", "token_env": "MY_TOKEN"}
                             Bearer token (inline — use for testing only):
                               {"type": "bearer", "token": "sk-..."}

                             Custom header (e.g. X-Api-Key):
                               {"type": "api_key", "header": "X-Api-Key", "token_env": "MY_KEY"}

                             HTTP Basic Auth:
                               {"type": "basic", "username": "user", "password_env": "MY_PASS"}

                             OAuth2 Client Credentials (Azure AD, Okta, GCP, etc.):
                               {"type": "oauth2_client_credentials",
                                "token_url": "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token",
                                "client_id": "abc123",
                                "client_secret_env": "AZURE_CLIENT_SECRET",
                                "scope": "api://my-rag/.default"}

                             Tokens are never stored in audit results or certificates.

    Returns:
        audit_id, dimension_scores, overall_score, verdict, duration_ms
    """
    timeout_ms = min(timeout_ms, 60_000)
    concurrency = min(concurrency, 20)

    async def _on_dim_complete(dim_id, verdict, score, completed, total):
        if ctx is None:
            return
        label = "PASS" if verdict == "pass" else ("WARN" if verdict == "warn" else "FAIL")
        await ctx.info(f"[{completed}/{total}] {dim_id} — {label} ({score:.3f})")
        await ctx.report_progress(completed, total)

    if ctx:
        await ctx.info(f"Starting audit of {endpoint_url} ({len(frameworks)} framework(s))")

    result = await _run_audit(
        endpoint_url=endpoint_url,
        frameworks=frameworks,
        probe_pack_version=probe_pack_version,
        timeout_ms=timeout_ms,
        concurrency=concurrency,
        dimensions_override=dimensions_override,
        extra_dimensions=extra_dimensions,
        custom_probe_dirs=custom_probe_dirs,
        dimension_weights=dimension_weights,
        endpoint_auth=endpoint_auth,
        on_dimension_complete=_on_dim_complete,
    )

    return {
        "audit_id": result["audit_id"],
        "verdict": result["verdict"],
        "overall_score": result["overall_score"],
        "trust_tier": result["trust_tier"],
        "dimension_scores": {
            dim: {"score": info["score"], "verdict": info["verdict"]}
            for dim, info in result["dimensions"].items()
        },
        "probe_manifest": result["probe_manifest"],
        "duration_ms": result["duration_ms"],
        "probe_pack_version": result["probe_pack_version"],
        "frameworks": result["frameworks"],
    }


@mcp.tool()
def get_certificate(audit_id: str, ttl_hours: int | None = None) -> dict:
    """
    Issue or retrieve the compliance certificate for a completed audit.

    Args:
        audit_id: The audit ID returned by run_audit.
        ttl_hours: Certificate TTL override in hours (default: 168 for PASS, 48 for CONDITIONAL).

    Returns:
        Signed RS256 JWT certificate bundle, fingerprint, TTL, verdict.
    """
    if not store.exists(audit_id):
        return {"error": f"Audit {audit_id} not found"}

    audit_result = store.load(audit_id)

    if audit_result["verdict"] == "FAIL":
        return {
            "error": "No certificate issued for FAIL verdicts.",
            "verdict": "FAIL",
            "audit_id": audit_id,
            "overall_score": audit_result["overall_score"],
        }

    cert_ttl = ttl_hours or (48 if audit_result["verdict"] == "CONDITIONAL" else 168)
    return certificate.issue(audit_result, ttl_hours=cert_ttl)


@mcp.tool()
def get_report(audit_id: str, format: str = "json") -> dict | str:
    """
    Retrieve the audit report for a completed audit.

    Args:
        audit_id: The audit ID returned by run_audit.
        format: Report format — "json" (default), "sarif", or "pdf" (base64-encoded bytes).
                "sarif" returns a SARIF 2.1.0 document compatible with GitHub Advanced Security,
                Semgrep, and any other SARIF-consuming CI tool. Write the output to a .sarif
                file and upload it as a GitHub Actions artifact or security scan result.

    Returns:
        Audit report with per-probe detail and remediation guidance.
    """
    if not store.exists(audit_id):
        return {"error": f"Audit {audit_id} not found"}

    audit_result = store.load(audit_id)

    if format == "sarif":
        return report.generate_sarif(audit_result)

    if format == "pdf":
        import base64
        pdf_bytes = report.generate_pdf(audit_result)
        return {
            "format": "pdf",
            "encoding": "base64",
            "data": base64.b64encode(pdf_bytes).decode(),
            "size_bytes": len(pdf_bytes),
        }

    return report.generate_json(audit_result)


@mcp.tool()
def compare_audits(audit_id_before: str, audit_id_after: str) -> dict:
    """
    Compare two audit results and return a structured diff.

    Useful as a PR gate to detect regressions: run an audit on the base branch,
    run another on the feature branch, then call this to see what changed.

    Args:
        audit_id_before: Audit ID of the baseline (e.g. main branch).
        audit_id_after:  Audit ID of the candidate (e.g. feature branch).

    Returns:
        overall_score_delta, verdict change, per-dimension deltas, regressions,
        improvements, and any dimensions that were added or removed between audits.
    """
    for aid in (audit_id_before, audit_id_after):
        if not store.exists(aid):
            return {"error": f"Audit {aid} not found"}

    before = store.load(audit_id_before)
    after  = store.load(audit_id_after)
    return report.generate_diff(before, after)


@mcp.tool()
def list_probe_packs(
    framework: str | None = None,
    custom_probe_dirs: list[str] | None = None,
) -> dict:
    """
    List all available probe packs — built-in and custom.

    Args:
        framework:         Optional framework filter (eu_ai_act, gdpr_dpdp, hipaa, sebi_rbi).
                           Filters built-in dimensions only; custom packs always appear.
        custom_probe_dirs: Extra directories to scan for custom YAML probe packs.

    Returns:
        Dict of dimension_id → pack metadata (name, version, probe_count, source, scoring_strategy).
    """
    all_packs = list_all_packs(extra_dirs=custom_probe_dirs)

    if framework:
        allowed = set(FRAMEWORK_DIMENSIONS.get(framework, []))
        # Keep custom dims (not in the built-in set) regardless of framework filter
        builtin_ids = {"D1", "D2", "D3", "D4", "D5", "D6", "D7"}
        all_packs = {
            k: v for k, v in all_packs.items()
            if k in allowed or k not in builtin_ids
        }

    return all_packs


@mcp.tool()
def verify_certificate(cert_jwt: str) -> dict:
    """
    Verify a compliance certificate JWT.

    Args:
        cert_jwt: The signed JWT string from get_certificate.

    Returns:
        Verification result: valid/invalid, expiry, issuer, verdict, registry status.
    """
    return certificate.verify(cert_jwt)


@mcp.tool()
def ci_gate_check(
    audit_id: str,
    pass_threshold: float = 0.85,
    conditional_threshold: float = 0.70,
    mandatory_dim_min: float = 0.80,
    fail_on: str = "FAIL",
) -> dict:
    """
    CI/CD gate check — returns pass/conditional/fail verdict with exit code.

    Args:
        audit_id: The audit ID returned by run_audit.
        pass_threshold: Overall score required for PASS (default: 0.85).
        conditional_threshold: Overall score required for CONDITIONAL (default: 0.70).
        mandatory_dim_min: Minimum score any dimension must achieve for PASS (default: 0.80).
        fail_on: Block pipeline on "FAIL" (default) or "CONDITIONAL" (stricter).

    Returns:
        verdict, exit_code (0=pass, 1=conditional, 2=fail, 3=error), reason, dimension_scores.
    """
    if not store.exists(audit_id):
        return {
            "verdict": "ERROR",
            "exit_code": 3,
            "reason": f"Audit {audit_id} not found",
        }

    audit_result = store.load(audit_id)
    overall = audit_result["overall_score"]
    dim_scores = {dim: info["score"] for dim, info in audit_result["dimensions"].items()}
    min_dim = min(dim_scores.values()) if dim_scores else 0.0
    min_dim_name = min(dim_scores, key=dim_scores.get) if dim_scores else "unknown"

    if overall >= pass_threshold and min_dim >= mandatory_dim_min:
        verdict = "PASS"
        exit_code = 0
        reason = f"All thresholds met. Overall: {overall:.3f}, Min dim ({min_dim_name}): {min_dim:.3f}"
    elif overall >= conditional_threshold and min_dim >= 0.65:
        verdict = "CONDITIONAL"
        exit_code = 1
        reason = f"Conditional pass. Overall: {overall:.3f}. Remediation required for: {[d for d,s in dim_scores.items() if s < pass_threshold]}"
    else:
        verdict = "FAIL"
        exit_code = 2
        reason = f"Failed. Overall: {overall:.3f}, failing dimension: {min_dim_name} ({min_dim:.3f})"

    # Stricter gate: block on CONDITIONAL too
    if fail_on == "CONDITIONAL" and verdict == "CONDITIONAL":
        exit_code = 2

    return {
        "verdict": verdict,
        "exit_code": exit_code,
        "reason": reason,
        "overall_score": overall,
        "dimension_scores": dim_scores,
        "pipeline_action": "CONTINUE" if exit_code == 0 else ("WARN" if exit_code == 1 else "BLOCK"),
    }


@mcp.tool()
def list_registry_packs(
    framework: str | None = None,
    trust_tier: str | None = None,
    status: str = "active",
) -> dict:
    """
    List probe packs from the hosted probe pack registry.

    The registry (registry/probes.json) is a curated index of published probe packs —
    both official packs bundled with this tool and community-contributed verified packs.
    Probe authors can add their pack by opening a PR against the registry file.

    Args:
        framework:  Filter by framework (eu_ai_act, gdpr_dpdp, hipaa, sebi_rbi).
        trust_tier: Filter by trust tier (official, verified, self_authored).
        status:     Filter by status — "active" (default) or "all".

    Returns:
        List of probe pack descriptors with download URLs and trust metadata.
    """
    registry_dir = Path(os.getenv("RAG_AUDITOR_REGISTRY_DIR", "registry"))
    registry_file = registry_dir / "probes.json"

    if not registry_file.exists():
        return {"error": "Probe registry not found. Expected registry/probes.json relative to CWD."}

    try:
        packs = json.loads(registry_file.read_text())
    except Exception as exc:
        return {"error": f"Failed to read probe registry: {exc}"}

    if status != "all":
        packs = [p for p in packs if p.get("status", "active") == status]
    if framework:
        packs = [p for p in packs if framework in p.get("frameworks", [])]
    if trust_tier:
        packs = [p for p in packs if p.get("trust_tier") == trust_tier]

    return {
        "total": len(packs),
        "packs": packs,
        "registry_source": str(registry_file.resolve()),
    }


def main():
    mcp.run()


if __name__ == "__main__":
    main()
