"""Probe runner — loads probe packs and fires probes at the target RAG endpoint.

Probe resolution order (first match wins):
  1. Explicit file path passed directly (e.g. "/home/user/my_probes/custom.yaml")
  2. RAG_AUDITOR_PROBES_DIR env var directory
  3. Built-in package probes directory

This means users can fully override or extend any dimension without touching
the package source — just drop a YAML file in their probes directory.
"""

import asyncio
import base64
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from . import auth as _auth

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


# ─── Trust tiers (registry-controlled, never self-declared) ──────────────────
# Tier is derived from WHERE a pack came from, not from any field in the YAML.
#   official      — bundled with the package; the project vouches for it
#   verified      — third-party pack with a valid signature from a trusted key
#   self_authored — loaded from a user directory; identifiable but unvouched
# A pack's own `trust_tier:` field (if present) is ignored.
TRUST_TIER_ORDER = {"self_authored": 0, "verified": 1, "official": 2}


def _trusted_keys_dir() -> Path | None:
    p = os.getenv("RAG_AUDITOR_TRUSTED_KEYS_DIR")
    return Path(p) if p else None


def _is_builtin(source: Path) -> bool:
    try:
        source.resolve().relative_to(_BUILTIN_PROBES_DIR.resolve())
        return True
    except ValueError:
        return False


def _has_trusted_signature(source: Path) -> bool:
    """True if a sibling <pack>.sig validates against any key in the trusted keys dir."""
    keys_dir = _trusted_keys_dir()
    if not keys_dir or not keys_dir.is_dir():
        return False
    sig_file = source.with_suffix(source.suffix + ".sig")
    if not sig_file.exists():
        return False
    try:
        signature = base64.b64decode(sig_file.read_text().strip())
        data = source.read_bytes()
    except Exception:
        return False
    for key_path in sorted(keys_dir.glob("*.pem")):
        try:
            pub = serialization.load_pem_public_key(key_path.read_bytes())
            pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            continue
    return False


def compute_trust_tier(source: Path) -> str:
    """Registry-controlled tier assignment based on pack provenance."""
    if _is_builtin(source):
        return "official"
    if _has_trusted_signature(source):
        return "verified"
    return "self_authored"


def trust_floor(tiers: list[str]) -> str:
    """The lowest (least-trusted) tier across a set — the floor for a certificate."""
    if not tiers:
        return "self_authored"
    return min(tiers, key=lambda t: TRUST_TIER_ORDER.get(t, 0))


def resolve_pack(dimension_or_path: str) -> tuple[dict, Path]:
    """
    Resolve a probe pack by dimension ID (e.g. "D1") or direct file path.
    Returns (parsed_pack, source_path).

    Resolution order:
      1. If dimension_or_path is an existing file path — load it directly.
      2. Search RAG_AUDITOR_PROBES_DIR for a .yaml whose `dimension` field matches.
      3. Fall back to built-in package probes.
    """
    # Direct file path
    p = Path(dimension_or_path)
    if p.suffix in (".yaml", ".yml") and p.exists():
        return yaml.safe_load(p.read_text()), p

    dim = dimension_or_path.upper()

    for search_dir in _probe_search_dirs():
        if not search_dir.exists():
            continue
        for yaml_file in sorted(search_dir.glob("*.yaml")):
            if search_dir == _BUILTIN_PROBES_DIR and _BUILTIN_FILES.get(dim) == yaml_file.name:
                return yaml.safe_load(yaml_file.read_text()), yaml_file
            try:
                pack = yaml.safe_load(yaml_file.read_text())
                if str(pack.get("dimension", "")).upper() == dim:
                    return pack, yaml_file
            except Exception:
                continue

    raise FileNotFoundError(f"No probe pack found for dimension '{dimension_or_path}'")


def load_pack(dimension_or_path: str) -> dict:
    """Load a probe pack by dimension ID or file path. See resolve_pack()."""
    return resolve_pack(dimension_or_path)[0]


def pack_provenance(dimension_or_path: str) -> dict:
    """
    Return signed-into-certificate provenance for a pack: pack name, version,
    declared author (disclosed, not trusted), source, and registry-assigned trust_tier.
    """
    pack, source = resolve_pack(dimension_or_path)
    dim = str(pack.get("dimension", source.stem)).upper()
    return {
        "dimension": dim,
        "pack": source.stem,
        "version": str(pack.get("version", "?")),
        "author": pack.get("author"),          # disclosed provenance, earns no trust
        "author_uri": pack.get("author_uri"),
        "trust_tier": compute_trust_tier(source),
    }


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
                        "author": pack.get("author"),
                        "author_uri": pack.get("author_uri"),
                        "trust_tier": compute_trust_tier(yaml_file),
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
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, int, str | None]:
    payload: dict[str, Any] = {"query": query}
    if context:
        payload["context"] = context

    headers = {"User-Agent": "RAGComplianceAuditor/1.0"}
    if extra_headers:
        headers.update(extra_headers)

    start = time.monotonic()
    try:
        resp = await client.post(
            endpoint_url,
            json=payload,
            timeout=timeout_ms / 1000,
            headers=headers,
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
    auth_config: dict | None = None,
) -> list[ProbeResult]:
    """
    dimension may be a built-in ID ("D1"), a custom ID ("CUSTOM_TOXICITY"),
    or a direct file path ("/path/to/my_probes/toxicity.yaml").
    """
    pack = load_pack(dimension)
    # Normalise dimension ID from the pack itself (handles direct file paths)
    dim_id = str(pack.get("dimension", dimension)).upper()

    sem = asyncio.Semaphore(concurrency)

    # Resolve auth once per dimension (OAuth2 token fetch happens here)
    extra_headers, httpx_auth = await _auth.resolve_auth(auth_config)

    # D3 and any pack with probe_groups uses the grouped structure
    if pack.get("probe_groups"):
        probes = []
        for group in pack["probe_groups"]:
            for p in group.get("probes", []):
                p["_group_id"] = group["group_id"]
                probes.append(p)
    else:
        probes = pack.get("probes", [])

    async with httpx.AsyncClient(auth=httpx_auth) as client:
        async def run_one(probe: dict) -> ProbeResult:
            async with sem:
                query = probe["query"]
                context = probe.get("injected_context")
                raw_response, latency, error = await _fire_probe(
                    client, endpoint_url, query, context, timeout_ms, extra_headers
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
