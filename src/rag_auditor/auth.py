"""Auth config resolution for authenticated RAG endpoints.

Supported types:
  bearer                   — Authorization: Bearer <token>
  api_key                  — arbitrary header + value
  basic                    — HTTP Basic Auth
  oauth2_client_credentials — fetch bearer token via client-credentials grant

Secrets should always be supplied via *_env keys (name of an env var to read)
rather than inline. Inline values are supported for local testing only.
"""

import os
from typing import Any

import httpx


def _resolve(config: dict, value_key: str, env_key: str) -> str:
    """Return the secret from an inline key or an env-var indirection key."""
    if value_key in config:
        return str(config[value_key])
    if env_key in config:
        var = config[env_key]
        val = os.getenv(var)
        if not val:
            raise ValueError(
                f"Auth env var '{var}' (from '{env_key}') is not set or empty."
            )
        return val
    raise ValueError(
        f"Auth config missing '{value_key}' or '{env_key}'. "
        f"Provide one of them in endpoint_auth."
    )


def build_headers(auth_config: dict) -> dict[str, str]:
    """Return extra HTTP headers for bearer and api_key auth types."""
    auth_type = auth_config.get("type", "")

    if auth_type == "bearer":
        token = _resolve(auth_config, "token", "token_env")
        return {"Authorization": f"Bearer {token}"}

    if auth_type == "api_key":
        header = auth_config.get("header")
        if not header:
            raise ValueError("api_key auth requires a 'header' field (e.g. 'X-Api-Key').")
        token = _resolve(auth_config, "token", "token_env")
        return {header: token}

    return {}


def build_httpx_auth(auth_config: dict) -> httpx.BasicAuth | None:
    """Return an httpx.BasicAuth instance for basic auth, else None."""
    if auth_config.get("type") == "basic":
        username = auth_config.get("username")
        if not username:
            raise ValueError("basic auth requires a 'username' field.")
        password = _resolve(auth_config, "password", "password_env")
        return httpx.BasicAuth(username, password)
    return None


async def fetch_oauth2_token(auth_config: dict) -> str:
    """Fetch a bearer token via OAuth2 client-credentials grant.

    Required fields: token_url, client_id, and client_secret / client_secret_env.
    Optional: scope (space-separated string).
    """
    token_url = auth_config.get("token_url")
    if not token_url:
        raise ValueError("oauth2_client_credentials auth requires 'token_url'.")
    client_id = auth_config.get("client_id")
    if not client_id:
        raise ValueError("oauth2_client_credentials auth requires 'client_id'.")
    client_secret = _resolve(auth_config, "client_secret", "client_secret_env")

    data: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if "scope" in auth_config:
        data["scope"] = auth_config["scope"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, data=data, timeout=15)
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise ValueError(
                f"OAuth2 token response from {token_url} did not contain 'access_token'."
            )
        return str(token)


async def resolve_auth(auth_config: dict | None) -> tuple[dict[str, str], httpx.BasicAuth | None]:
    """Return (extra_headers, httpx_auth) ready to pass to httpx.

    Handles all auth types. For oauth2_client_credentials, fetches the token
    once here so every probe in the audit shares it.
    """
    if not auth_config:
        return {}, None

    auth_type = auth_config.get("type", "")

    if auth_type == "oauth2_client_credentials":
        token = await fetch_oauth2_token(auth_config)
        return {"Authorization": f"Bearer {token}"}, None

    return build_headers(auth_config), build_httpx_auth(auth_config)


def sanitize(auth_config: dict | None) -> dict[str, Any] | None:
    """Return a secrets-free descriptor safe to store in audit results."""
    if not auth_config:
        return None
    auth_type = auth_config.get("type", "unknown")
    descriptor: dict[str, Any] = {"type": auth_type}
    if auth_type == "api_key":
        descriptor["header"] = auth_config.get("header")
    if auth_type == "oauth2_client_credentials":
        descriptor["token_url"] = auth_config.get("token_url")
        descriptor["client_id"] = auth_config.get("client_id")
    return descriptor
