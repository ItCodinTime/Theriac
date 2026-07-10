"""Vultr IAM/OIDC bearer authentication for privileged operator actions."""

from __future__ import annotations

import os

from fastapi import Header, HTTPException


async def require_operator(authorization: str | None = Header(default=None)) -> str:
    issuer = os.getenv("VULTR_OIDC_ISSUER", "").rstrip("/")
    strict = os.getenv("VULTR_NATIVE_STRICT", "false").lower() == "true"
    if not issuer:
        if strict:
            raise HTTPException(status_code=503, detail="Vultr IAM/OIDC is not configured")
        return "development-operator"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        import jwt
        import httpx

        async with httpx.AsyncClient(timeout=5) as client:
            discovery = await client.get(f"{issuer}/.well-known/openid-configuration")
            discovery.raise_for_status()
            jwks_uri = discovery.json()["jwks_uri"]
        signing_key = jwt.PyJWKClient(jwks_uri).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=os.getenv("VULTR_OIDC_AUDIENCE") or None,
            issuer=issuer,
            options={"verify_aud": bool(os.getenv("VULTR_OIDC_AUDIENCE"))},
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid operator token") from exc

    required_role = os.getenv("PANACEA_OPERATOR_ROLE", "panacea-operator")
    roles = claims.get("roles", [])
    scope = str(claims.get("scope", "")).split()
    if required_role not in roles and required_role not in scope:
        raise HTTPException(status_code=403, detail=f"Role {required_role} required")
    return str(claims.get("sub", "unknown-operator"))
