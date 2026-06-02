"""Report generator — JSON and PDF audit reports."""

import json
import time

from fpdf import FPDF


def generate_json(audit_result: dict) -> dict:
    """Return a structured JSON report dict from an audit result."""
    dims = audit_result.get("dimensions", {})
    manifest = audit_result.get("probe_manifest", {})

    return {
        "report_version": "1.0",
        "generated_at": int(time.time()),
        "audit_id": audit_result["audit_id"],
        "endpoint_url": audit_result["endpoint_url"],
        "frameworks": audit_result["frameworks"],
        "probe_pack_version": audit_result["probe_pack_version"],
        "trust_tier": audit_result.get("trust_tier", "self_authored"),
        "probe_manifest": manifest,
        "duration_ms": audit_result.get("duration_ms", 0),
        "verdict": audit_result["verdict"],
        "overall_score": audit_result["overall_score"],
        "dimensions": {
            dim: {
                "score": info["score"],
                "verdict": info["verdict"],
                "provenance": manifest.get(dim, {}),
                "probes": [
                    {
                        "probe_id": p["probe_id"],
                        "type": p["probe_type"],
                        "query": p["query"],
                        "score": p["score"],
                        "rationale": p["rationale"],
                        "latency_ms": p["latency_ms"],
                        "error": p.get("error"),
                    }
                    for p in info.get("probe_results", [])
                ],
                "remediation": _remediation(dim, info["score"]),
            }
            for dim, info in dims.items()
        },
    }


def generate_pdf(audit_result: dict) -> bytes:
    """Return PDF bytes for the audit report."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "RAG Ethics & Compliance Audit Report", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Audit ID: {audit_result['audit_id']}", ln=True)
    pdf.cell(0, 6, f"Endpoint: {audit_result['endpoint_url']}", ln=True)
    pdf.cell(0, 6, f"Frameworks: {', '.join(audit_result['frameworks'])}", ln=True)
    pdf.cell(0, 6, f"Probe Pack: {audit_result['probe_pack_version']}", ln=True)
    pdf.cell(0, 6, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}", ln=True)
    pdf.ln(4)

    # Verdict banner
    verdict = audit_result["verdict"]
    score = audit_result["overall_score"]
    color = {"PASS": (0, 150, 0), "CONDITIONAL": (200, 150, 0), "FAIL": (200, 0, 0)}.get(verdict, (100, 100, 100))
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 12, f"  Verdict: {verdict}   Overall Score: {score:.2f}", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Dimension summary table
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Dimension Summary", ln=True)
    pdf.set_font("Helvetica", "B", 9)
    col_w = [15, 80, 25, 25, 45]
    headers = ["ID", "Dimension", "Score", "Verdict", "Remediation"]
    for i, h in enumerate(headers):
        pdf.cell(col_w[i], 7, h, border=1)
    pdf.ln()

    dim_names = {
        "D1": "Hallucination & Faithfulness",
        "D2": "PII & Sensitive Data Leakage",
        "D3": "Retrieval Bias & Fairness",
        "D4": "Source Attribution & Provenance",
        "D5": "Prompt Injection Resilience",
        "D6": "Refusal & Boundary Behaviour",
        "D7": "Data Residency & Cross-Border Flow",
    }

    pdf.set_font("Helvetica", "", 9)
    for dim, info in audit_result.get("dimensions", {}).items():
        dim_verdict = info["verdict"].upper()
        fill_color = {"PASS": (220, 255, 220), "WARN": (255, 255, 200), "FAIL": (255, 220, 220)}.get(dim_verdict, (255, 255, 255))
        pdf.set_fill_color(*fill_color)
        remediation = _remediation(dim, info["score"])
        pdf.cell(col_w[0], 6, dim, border=1, fill=True)
        pdf.cell(col_w[1], 6, dim_names.get(dim, dim), border=1, fill=True)
        pdf.cell(col_w[2], 6, f"{info['score']:.3f}", border=1, fill=True)
        pdf.cell(col_w[3], 6, dim_verdict, border=1, fill=True)
        pdf.cell(col_w[4], 6, remediation[:35] + ("..." if len(remediation) > 35 else ""), border=1, fill=True)
        pdf.ln()

    pdf.set_fill_color(255, 255, 255)
    pdf.ln(6)

    # Per-dimension probe detail
    for dim, info in audit_result.get("dimensions", {}).items():
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, f"{dim}: {dim_names.get(dim, dim)}  (Score: {info['score']:.3f})", ln=True)
        pdf.set_font("Helvetica", "", 9)
        rem = _remediation(dim, info["score"])
        if rem:
            pdf.set_text_color(180, 0, 0)
            pdf.multi_cell(0, 5, f"Remediation: {rem}")
            pdf.set_text_color(0, 0, 0)

        for p in info.get("probe_results", []):
            score_str = f"{p['score']:.2f}"
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 5, f"  [{p['probe_id']}] ({p['probe_type']}) Score: {score_str}", ln=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_x(15)
            query_truncated = p["query"][:120] + ("..." if len(p["query"]) > 120 else "")
            pdf.multi_cell(0, 4, f"Q: {query_truncated}")
            if p.get("rationale"):
                pdf.set_x(15)
                rationale_truncated = p["rationale"][:200] + ("..." if len(p["rationale"]) > 200 else "")
                pdf.multi_cell(0, 4, f"Rationale: {rationale_truncated}")
            if p.get("error"):
                pdf.set_x(15)
                pdf.set_text_color(200, 0, 0)
                pdf.multi_cell(0, 4, f"Error: {p['error']}")
                pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
        pdf.ln(4)

    # Footer disclaimer
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(
        0, 4,
        "DISCLAIMER: This certificate is based on automated probing at the time of audit. "
        "It does not constitute legal advice and does not transfer liability. "
        "Re-audit required after any changes to the RAG pipeline or after certificate expiry.",
    )

    return bytes(pdf.output())


_REMEDIATION = {
    "D1": "Review retrieval faithfulness — implement source-grounded generation and add a faithfulness re-ranker.",
    "D2": "Audit your chunking pipeline for PII; apply NER-based PII redaction before indexing. Review GDPR Art.25 data minimisation.",
    "D3": "Audit embedding model for demographic bias; test with diverse query sets; apply fairness re-ranking.",
    "D4": "Implement citation extraction in your generation step; add staleness metadata to indexed documents.",
    "D5": "Add a prompt injection detection layer (e.g., LLM guard) before retrieval; sanitise user-provided context.",
    "D6": "Implement intent classification to detect out-of-scope queries; add guardrails for medical/legal/financial advice.",
    "D7": "Verify all data processing occurs in compliant regions; document cross-border flows in your DPDP/GDPR records of processing activities.",
}


def _remediation(dim: str, score: float) -> str:
    if score >= 0.85:
        return ""
    return _REMEDIATION.get(dim, "Review and remediate this dimension.")
