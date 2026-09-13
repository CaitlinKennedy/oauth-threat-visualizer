"""Real cryptographic primitives for the OAuth actors.

Phase 0 needs genuine asymmetric key material and real JWS signing and
verification for access tokens: the authorization server signs a JWT with a
generated RSA key and publishes the public half as a JWKS; the resource server
verifies the signature against that JWKS. No security-relevant step is mocked.

PKCE, DPoP proofs, and JWK thumbprints are introduced in later phases; this
module intentionally stays scoped to what Phase 0 exercises.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_ALG = "RS256"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class SigningKey:
    """An RSA signing key plus the public JWK the JWKS endpoint serves."""

    kid: str
    _private_pem: bytes
    _public_pem: bytes

    @classmethod
    def generate(cls, kid: str | None = None) -> "SigningKey":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls(
            kid=kid or f"key-{uuid.uuid4().hex[:8]}",
            _private_pem=private_pem,
            _public_pem=public_pem,
        )

    def public_jwk(self) -> Dict[str, Any]:
        """Return the public key as a JWK dict (with ``kid``, ``use``, ``alg``)."""
        # PyJWT emits a spec-correct RSA public JWK (n, e); we enrich the metadata.
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self._public_key_obj()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": _ALG})
        return jwk

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [self.public_jwk()]}

    def _private_key_obj(self):
        return serialization.load_pem_private_key(self._private_pem, password=None)

    def _public_key_obj(self):
        return serialization.load_pem_public_key(self._public_pem)


def sign_access_token(
    key: SigningKey,
    *,
    issuer: str,
    subject: str,
    audience: str,
    client_id: str,
    scope: str,
    ttl_seconds: int = 300,
    extra_claims: Dict[str, Any] | None = None,
) -> str:
    """Sign a real JWT access token (RS256) with the given key.

    The header carries the ``kid`` so the resource server can select the right
    JWK from the JWKS when verifying.
    """
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(
        claims,
        key._private_pem,
        algorithm=_ALG,
        headers={"kid": key.kid, "typ": "at+jwt"},
    )


def verify_access_token(
    token: str,
    *,
    jwks: Dict[str, Any],
    issuer: str,
    audience: str,
) -> Dict[str, Any]:
    """Verify a JWT against a JWKS, enforcing signature, ``exp``, ``iss``, ``aud``.

    Raises a ``jwt.PyJWTError`` subclass on any failure (bad signature, expired,
    wrong issuer/audience, unknown ``kid``). Returns the decoded claims on success.
    """
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    signing_key = _select_jwk(jwks, kid)
    public_key = jwt.PyJWK.from_dict(signing_key).key
    return jwt.decode(
        token,
        public_key,
        algorithms=[_ALG],
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "iss", "aud"]},
    )


def decode_claims_unverified(token: str) -> Dict[str, Any]:
    """Decode claims without verifying — for display/knowledge-ledger use only."""
    return jwt.decode(token, options={"verify_signature": False})


def _select_jwk(jwks: Dict[str, Any], kid: str | None) -> Dict[str, Any]:
    keys: List[Dict[str, Any]] = jwks.get("keys", [])
    if kid is not None:
        for k in keys:
            if k.get("kid") == kid:
                return k
        raise jwt.InvalidKeyError(f"no JWK with kid {kid!r} in JWKS")
    if len(keys) == 1:
        return keys[0]
    raise jwt.InvalidKeyError("token header has no kid and JWKS is ambiguous")


def new_opaque_token(prefix: str = "") -> str:
    """A random, URL-safe opaque value (authorization codes, correlation ids)."""
    raw = _b64url(uuid.uuid4().bytes + uuid.uuid4().bytes)
    return f"{prefix}{raw}" if prefix else raw
