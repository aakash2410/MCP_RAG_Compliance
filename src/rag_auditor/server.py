"""MCP server — exposes the six compliance auditor tools."""

import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

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

    Returns:
        audit_id, dimension_scores, overall_score, verdict, duration_ms
    """
    timeout_ms = min(timeout_ms, 60_000)
    concurrency = min(concurrency, 20)

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
        format: Report format — "json" (default) or "pdf" (returns base64-encoded bytes).

    Returns:
        Audit report with per-probe detail and remediation guidance.
    """
    if not store.exists(audit_id):
        return {"error": f"Audit {audit_id} not found"}

    audit_result = store.load(audit_id)

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


def main():
    mcp.run()


if __name__ == "__main__":
    main()
