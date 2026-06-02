"""Probe runner — loads probe packs and fires probes at the target RAG endpoint.

Probe resolution order (first match wins):
  1. Explicit file path passed directly (e.g. "/home/user/my_probes/custom.yaml")
  2. RAG_AUDITOR_PROBES_DIR env var directory
  3. Built-in package probes directory

This means users can fully override or extend any dimension without touching
the package source — just drop a YAML file in their probes directory.
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

# Built-in probes shipped with the package
_BUILTIN_PROBES_DIR = Path(__file__).parent / "probes"

FRAMEWORK_DIMENSIONS: dict[str, list[str]] = {
    "eu_ai_act": ["D1", "D2", "D3", "D4", "D5", "D6", "D7"],
    "gdpr_dpdp": ["D2", "D3", "D7"],
    "hipaa": ["D1", "D2", "D5", "D6"],
    "sebi_rbi": ["D1", "D2", "D4", "D5", "D6", "D7"],
}

# Built-in dimension → filename mapping
_BUILTIN_FILES = {
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


def _user_probes_dir() -> Path | None:
    """Return the user-configured probes directory, if set."""
    p = os.getenv("RAG_AUDITOR_PROBES_DIR")
    return Path(p) if p else None


def _probe_search_dirs() -> list[Path]:
    """Ordered list of directories to search for probe packs."""
    dirs = []
    user_dir = _user_probes_dir()
    if user_dir:
        dirs.append(user_dir)
    dirs.append(_BUILTIN_PROBES_DIR)
    return dirs


def load_pack(dimension_or_path: str) -> dict:
    """
    Load a probe pack by dimension ID (e.g. "D1") or direct file path.

    Resolution order:
      1. If dimension_or_path is an existing file path — load it directly.
      2. Search RAG_AUDITOR_PROBES_DIR for any .yaml file whose `dimension`
         field matches, or whose filename stem matches (case-insensitive).
      3. Fall back to built-in package probes.
    """
    # Direct file path
    p = Path(dimension_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return yaml.safe_load(p.read_text())

    dim = dimension_or_path.upper()

    for search_dir in _probe_search_dirs():
        if not search_dir.exists():
            continue
        for yaml_file in sorted(search_dir.glob("*.yaml")):
            # Match by built-in filename
            if search_dir == _BUILTIN_PROBES_DIR and _BUILTIN_FILES.get(dim) == yaml_file.name:
                return yaml.safe_load(yaml_file.read_text())
            # Match by dimension field inside the YAML
            try:
                pack = yaml.safe_load(yaml_file.read_text())
                if str(pack.get("dimension", "")).upper() == dim:
                    return pack
            except Exception:
                continue

    raise FileNotFoundError(f"No probe pack found for dimension '{dimension_or_path}'")


def list_all_packs(extra_dirs: list[str] | None = None) -> dict[str, dict]:
    """
    Discover all available probe packs across built-in and user directories.
    Returns a dict of dimension_id → pack metadata.
    """
    seen: dict[str, dict] = {}
    search_dirs = list(_probe_search_dirs())
    if extra_dirs:
        search_dirs = [Path(d) for d in extra_dirs] + search_dirs

    for search_dir in search_dirs:
        if not search_dir.is_dir():
            continue
        for yaml_file in sorted(search_dir.glob("*.yaml")):
            try:
                pack = yaml.safe_load(yaml_file.read_text())
                dim = str(pack.get("dimension", yaml_file.stem)).upper()
                if dim not in seen:
                    seen[dim] = {
                        "name": pack.get("name", dim),
                        "version": pack.get("version", "?"),
                        "description": pack.get("description", ""),
                        "frameworks": pack.get("frameworks", []),
                        "source": str(yaml_file),
                        "probe_count": len(pack.get("probes", pack.get("probe_groups", []))),
                        "scoring_strategy": pack.get("scoring_strategy", "llm_judge"),
                        "changelog": pack.get("changelog", {}),
                    }
            except Exception:
                continue

    return seen


def dimensions_for_frameworks(frameworks: list[str]) -> list[str]:
    dims: set[str] = set()
    for fw in frameworks:
        dims.update(FRAMEWORK_DIMENSIONS.get(fw, []))
    return sorted(dims)


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
    """
    dimension may be a built-in ID ("D1"), a custom ID ("CUSTOM_TOXICITY"),
    or a direct file path ("/path/to/my_probes/toxicity.yaml").
    """
    pack = load_pack(dimension)
    # Normalise dimension ID from the pack itself (handles direct file paths)
    dim_id = str(pack.get("dimension", dimension)).upper()

    sem = asyncio.Semaphore(concurrency)

    # D3 and any pack with probe_groups uses the grouped structure
    if pack.get("probe_groups"):
        probes = []
        for group in pack["probe_groups"]:
            for p in group.get("probes", []):
                p["_group_id"] = group["group_id"]
                probes.append(p)
    else:
        probes = pack.get("probes", [])

    async with httpx.AsyncClient() as client:
        async def run_one(probe: dict) -> ProbeResult:
            async with sem:
                query = probe["query"]
                context = probe.get("injected_context")
                raw_response, latency, error = await _fire_probe(
                    client, endpoint_url, query, context, timeout_ms
                )
                return ProbeResult(
                    probe_id=probe["id"],
                    dimension=dim_id,
                    probe_type=probe.get("type", "benign"),
                    query=query,
                    injected_context=context,
                    raw_response=raw_response,
                    latency_ms=latency,
                    error=error,
                    metadata={k: v for k, v in probe.items() if k not in {"id", "query", "injected_context", "type"}},
                )

        return list(await asyncio.gather(*[run_one(p) for p in probes]))
