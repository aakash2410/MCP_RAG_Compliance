"""Probe runner — loads probe packs and fires probes at the target RAG endpoint."""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

PROBES_DIR = Path(__file__).parent / "probes"

FRAMEWORK_DIMENSIONS: dict[str, list[str]] = {
    "eu_ai_act": ["D1", "D2", "D3", "D4", "D5", "D6", "D7"],
    "gdpr_dpdp": ["D2", "D3", "D7"],
    "hipaa": ["D1", "D2", "D5", "D6"],
    "sebi_rbi": ["D1", "D2", "D4", "D5", "D6", "D7"],
}

DIMENSION_FILES = {
    "D1": "d1_hallucination.yaml",
    "D2": "d2_pii_leakage.yaml",
    "D3": "d3_bias.yaml",
    "D4": "d4_attribution.yaml",
    "D5": "d5_injection.yaml",
    "D6": "d6_refusal.yaml",
    "D7": "d7_residency.yaml",
}


@dataclass
class ProbeResult:
    probe_id: str
    dimension: str
    probe_type: str
    query: str
    injected_context: str | None
    raw_response: str
    latency_ms: int
    error: str | None = None
    # Populated by scorer
    score: float = 0.0
    rationale: str = ""
    metadata: dict = field(default_factory=dict)


def dimensions_for_frameworks(frameworks: list[str]) -> list[str]:
    dims: set[str] = set()
    for fw in frameworks:
        dims.update(FRAMEWORK_DIMENSIONS.get(fw, []))
    return sorted(dims)


def load_pack(dimension: str) -> dict:
    filename = DIMENSION_FILES[dimension]
    return yaml.safe_load((PROBES_DIR / filename).read_text())


async def _fire_probe(
    client: httpx.AsyncClient,
    endpoint_url: str,
    query: str,
    context: str | None,
    timeout_ms: int,
) -> tuple[str, int, str | None]:
    payload: dict[str, Any] = {"query": query}
    if context:
        payload["context"] = context

    start = time.monotonic()
    try:
        resp = await client.post(
            endpoint_url,
            json=payload,
            timeout=timeout_ms / 1000,
            headers={"User-Agent": "RAGComplianceAuditor/1.0"},
        )
        latency = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        data = resp.json()
        # Support common response key names
        response_text = (
            data.get("answer")
            or data.get("response")
            or data.get("output")
            or data.get("text")
            or str(data)
        )
        return str(response_text), latency, None
    except Exception as exc:
        latency = int((time.monotonic() - start) * 1000)
        return "", latency, str(exc)


async def run_dimension(
    dimension: str,
    endpoint_url: str,
    timeout_ms: int,
    concurrency: int,
) -> list[ProbeResult]:
    pack = load_pack(dimension)
    sem = asyncio.Semaphore(concurrency)
    results: list[ProbeResult] = []

    async with httpx.AsyncClient() as client:
        # D3 has nested probe_groups structure
        if dimension == "D3":
            probes = []
            for group in pack.get("probe_groups", []):
                for p in group.get("probes", []):
                    p["_group_id"] = group["group_id"]
                    probes.append(p)
        else:
            probes = pack.get("probes", [])

        async def run_one(probe: dict) -> ProbeResult:
            async with sem:
                query = probe["query"]
                context = probe.get("injected_context")
                raw_response, latency, error = await _fire_probe(
                    client, endpoint_url, query, context, timeout_ms
                )
                return ProbeResult(
                    probe_id=probe["id"],
                    dimension=dimension,
                    probe_type=probe.get("type", "benign"),
                    query=query,
                    injected_context=context,
                    raw_response=raw_response,
                    latency_ms=latency,
                    error=error,
                    metadata={k: v for k, v in probe.items() if k not in {"id", "query", "injected_context", "type"}},
                )

        tasks = [run_one(p) for p in probes]
        results = list(await asyncio.gather(*tasks))

    return results
