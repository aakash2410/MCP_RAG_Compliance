"""
Pluggable LLM-as-judge.

Configure via environment variables:

  JUDGE_PROVIDER   anthropic | openai (default: anthropic)
  JUDGE_MODEL      model name (default: claude-sonnet-4-6 for anthropic, gpt-4o for openai)
  JUDGE_API_KEY    API key (falls back to ANTHROPIC_API_KEY or OPENAI_API_KEY)
  JUDGE_BASE_URL   base URL for any OpenAI-compatible endpoint
                   e.g. http://localhost:11434/v1  (Ollama)
                        https://api.groq.com/openai/v1  (Groq)
                        https://api.together.xyz/v1  (Together AI)

Any OpenAI-compatible provider works with JUDGE_PROVIDER=openai + JUDGE_BASE_URL.
Anthropic's own API is the default.
"""

import json
import os


def _provider() -> str:
    return os.getenv("JUDGE_PROVIDER", "anthropic").lower()


def _model() -> str:
    defaults = {"anthropic": "claude-sonnet-4-6", "openai": "gpt-4o"}
    return os.getenv("JUDGE_MODEL", defaults.get(_provider(), "gpt-4o"))


def _api_key() -> str | None:
    explicit = os.getenv("JUDGE_API_KEY")
    if explicit:
        return explicit
    if _provider() == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY")
    return os.getenv("OPENAI_API_KEY")


def _base_url() -> str | None:
    return os.getenv("JUDGE_BASE_URL")


def call_raw(system: str, user: str) -> str:
    """
    Call the judge and return the raw response text (unparsed).
    Use this when the expected JSON schema differs from the standard {"score", "rationale"} shape.
    """
    provider = _provider()
    try:
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=_api_key())
            resp = client.messages.create(
                model=_model(),
                max_tokens=512,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            text = resp.content[0].text.strip()
        else:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ImportError("pip install openai") from exc
            kwargs: dict = {"api_key": _api_key() or "none"}
            base_url = _base_url()
            if base_url:
                kwargs["base_url"] = base_url
            client = OpenAI(**kwargs)
            resp = client.chat.completions.create(
                model=_model(),
                max_tokens=512,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            text = resp.choices[0].message.content or ""
        # Strip markdown fences
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(l for l in lines if not l.startswith("```")).strip()
        return text
    except Exception as exc:
        return f'{{"scores": [], "rationale": "Judge error: {exc}"}}'


def call(system: str, user: str) -> tuple[float, str]:
    """
    Call the configured LLM judge.

    The judge is expected to return valid JSON: {"score": <0.0-1.0>, "rationale": "<text>"}

    Returns (score, rationale). On any failure returns (0.5, error_message).
    """
    provider = _provider()
    try:
        if provider == "anthropic":
            return _call_anthropic(system, user)
        else:
            return _call_openai_compatible(system, user)
    except Exception as exc:
        return 0.5, f"Judge error ({provider}/{_model()}): {exc}"


def _call_anthropic(system: str, user: str) -> tuple[float, str]:
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key())
    resp = client.messages.create(
        model=_model(),
        max_tokens=256,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return _parse(resp.content[0].text)


def _call_openai_compatible(system: str, user: str) -> tuple[float, str]:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise ImportError(
            "openai package is required for JUDGE_PROVIDER=openai. "
            "Install with: pip install openai"
        ) from exc

    kwargs: dict = {"api_key": _api_key() or "none"}
    base_url = _base_url()
    if base_url:
        kwargs["base_url"] = base_url

    client = OpenAI(**kwargs)
    resp = client.chat.completions.create(
        model=_model(),
        max_tokens=256,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return _parse(resp.choices[0].message.content or "")


def _parse(text: str) -> tuple[float, str]:
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(l for l in lines if not l.startswith("```")).strip()
    data = json.loads(text)
    return float(data["score"]), str(data.get("rationale", ""))


def describe() -> str:
    """Human-readable description of the current judge configuration."""
    provider = _provider()
    model = _model()
    base = _base_url()
    if base:
        return f"{model} via {base} (openai-compatible)"
    return f"{model} ({provider})"
