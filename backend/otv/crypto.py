"""Real cryptographic primitives for the OAuth actors.

Phase 0 needs genuine asymmetric key material and real JWS signing and
verification for access tokens: the authorization server signs a JWT with a
generated RSA key and publishes the public half as a JWKS; the resource server
verifies the signature against that JWKS. No security-relevant step is mocked.

Phase 1 adds **real PKCE** (RFC 7636): a per-request ``code_verifier`` and the
``code_challenge`` derived from it via S256, plus the token-endpoint verification
``S256(code_verifier) == code_challenge``. These are genuine (SHA-256 over the
ASCII verifier, base64url without padding), so a code-injection attack that lacks
the verifier fails because the maths, not a script, says so.

DPoP proofs and JWK thumbprints are introduced in later phases; this module
intentionally stays scoped to what Phases 0–1 exercise.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_ALG = "RS256"

# PKCE code-challenge methods this build understands (RFC 7636 §4.2). ``S256`` is
# the only method OAuth 2.1 permits; ``plain`` is accepted so a later phase can
# contrast it, but the presets use S256.
PKCE_METHODS = ("S256", "plain")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --- PKCE (RFC 7636) -------------------------------------------------------


def new_code_verifier() -> str:
    """Generate a real, high-entropy PKCE ``code_verifier`` (RFC 7636 §4.1).

    43–128 characters from the unreserved set; here the base64url encoding of 32
    random bytes (a 43-char verifier), exactly as a real client would produce.
    """
    return _b64url(uuid.uuid4().bytes + uuid.uuid4().bytes)


def code_challenge_for(verifier: str, method: str = "S256") -> str:
    """Derive the ``code_challenge`` from a ``code_verifier`` (RFC 7636 §4.2).

    ``S256`` is ``BASE64URL(SHA256(ASCII(verifier)))`` with no padding; ``plain``
    echoes the verifier. Raises :class:`ValueError` for an unknown method.
    """
    if method == "S256":
        return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    if method == "plain":
        return verifier
    raise ValueError(f"unsupported code_challenge_method {method!r}")


def verify_pkce(verifier: str | None, challenge: str, method: str = "S256") -> bool:
    """Verify a presented ``code_verifier`` against a stored ``code_challenge``.

    This is the real token-endpoint check (RFC 7636 §4.6):
    ``code_challenge_for(verifier, method) == challenge``. Returns ``False`` for a
    missing verifier or an unknown method — never raises — so the caller can emit
    a truthful PASS/FAIL check event.
    """
    if not verifier or not challenge:
        return False
    try:
        return code_challenge_for(verifier, method) == challenge
    except ValueError:
        return False


@dataclass
class SigningKey:
    """A signing key plus the public JWK the JWKS endpoint serves.

    Defaults to a 2048-bit RSA key (RS256), used for access tokens and the JWT
    bearer grant's user assertions. Pass ``alg="ES256"`` to generate an EC
    (P-256) key instead — used by ``private_key_jwt`` client authentication
    (RFC 7523 §2.2), which conventionally proves possession of a key rather
    than an RSA modulus. Both key types share the same assertion sign/verify
    helpers below (:func:`sign_assertion` / :func:`verify_assertion`); the
    correct algorithm always travels with the key, never hard-coded per call
    site.
    """

    kid: str
    _private_pem: bytes
    _public_pem: bytes
    alg: str = _ALG

    @classmethod
    def generate(cls, kid: str | None = None, alg: str = _ALG) -> "SigningKey":
        if alg == "ES256":
            key = ec.generate_private_key(ec.SECP256R1())
        elif alg == "RS256":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise ValueError(f"unsupported signing algorithm {alg!r}")
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
            alg=alg,
        )

    def public_jwk(self) -> Dict[str, Any]:
        """Return the public key as a JWK dict (with ``kid``, ``use``, ``alg``)."""
        # PyJWT emits a spec-correct public JWK (RSA: n, e; EC: crv, x, y); we
        # enrich the metadata the same way for either key type.
        algorithm_cls = (
            jwt.algorithms.ECAlgorithm if self.alg == "ES256" else jwt.algorithms.RSAAlgorithm
        )
        jwk = json.loads(algorithm_cls.to_jwk(self._public_key_obj()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": self.alg})
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
    not-yet-valid, wrong issuer/audience, unknown ``kid``, or wrong token type).
    Returns the decoded claims on success.

    Enforces RFC 9068 §4: the JWS header ``typ`` must declare an access token
    (``at+jwt``, or the media-type form ``application/at+jwt``), so a JWT the same
    AS key signed for another purpose (e.g. an ID token) cannot be replayed here.
    """
    header = jwt.get_unverified_header(token)
    _require_access_token_typ(header.get("typ"))
    kid = header.get("kid")
    signing_key = _select_jwk(jwks, kid)
    public_key = jwt.PyJWK.from_dict(signing_key).key
    return jwt.decode(
        token,
        public_key,
        algorithms=[_ALG],
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "nbf", "iss", "aud"]},
    )


def _require_access_token_typ(typ: Any) -> None:
    """Reject a JWT whose header ``typ`` is not an access token (RFC 9068 §4)."""
    normalized = str(typ or "").strip().lower()
    if normalized.startswith("application/"):
        normalized = normalized[len("application/") :]
    if normalized != "at+jwt":
        raise jwt.InvalidTokenError(
            f"unexpected token typ {typ!r}; expected at+jwt (RFC 9068 §4)"
        )


def decode_claims_unverified(token: str) -> Dict[str, Any]:
    """Decode claims without verifying — for display/knowledge-ledger use only."""
    return jwt.decode(token, options={"verify_signature": False})


# --- JWT bearer assertions (RFC 7523) --------------------------------------


def sign_assertion(
    key: SigningKey,
    *,
    issuer: str,
    subject: str,
    audience: str,
    ttl_seconds: int = 60,
    jti: str | None = None,
    iat_offset: int = 0,
    extra_claims: Dict[str, Any] | None = None,
) -> str:
    """Sign a real JWT assertion (RFC 7523 §3) with ``key``'s own algorithm.

    The canonical assertion helper for BOTH uses in this codebase: the JWT
    bearer grant's user assertion (Phase 4, an RS256 ``SigningKey``) and
    ``private_key_jwt`` client authentication's ``client_assertion`` (Phase 5,
    an ES256 ``SigningKey``) — the claim shape and the one-time/short-lived
    properties that defeat replay are identical either way; only the key type
    differs, and that travels with ``key.alg``.

    The assertion vouches for ``subject`` (the principal — a user for the JWT
    bearer grant, or the client itself for ``private_key_jwt``) and is signed
    by ``issuer``: a party the authorization server trusts and whose public key
    it holds. ``audience`` MUST be the AS token endpoint, so an assertion
    minted for one endpoint cannot be presented to another. A fresh ``jti`` and
    a short ``exp`` are what make the assertion one-time and short-lived (RFC
    7523 §3, items 4/6) — the two properties, with the audience binding, that a
    replay cannot get around. ``iat_offset`` lets a caller mint an assertion as
    if issued in the past (a negative offset) — used to model an artifact
    captured from an earlier flow that is now expired.
    """
    now = int(time.time()) + iat_offset
    claims: Dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": jti or uuid.uuid4().hex,
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(
        claims,
        key._private_pem,
        algorithm=key.alg,
        headers={"kid": key.kid, "typ": "JWT"},
    )


_ASSERTION_ALGS = ("RS256", "ES256")


def verify_assertion(
    token: str,
    *,
    jwks: Dict[str, Any],
    issuer: str,
    audience: str,
) -> Dict[str, Any]:
    """Verify a JWT assertion against the issuer's JWKS (RFC 7523 §3).

    The canonical counterpart to :func:`sign_assertion`, used by both the JWT
    bearer grant (RSA assertions) and ``private_key_jwt`` client authentication
    (EC/ES256 assertions) — either ``RS256`` or ``ES256`` is accepted since the
    actual public key in ``jwks`` (selected by the token's ``kid``) is what
    verification is against; a key of one type can never produce a valid
    signature for the other algorithm, so allowing both here narrows nothing.

    Enforces the JWS signature (against the issuer's published key), ``iss``,
    ``aud`` = the token endpoint, and the ``exp``/``nbf`` time window, and requires
    a ``sub`` (the principal the assertion authorizes) and a ``jti``. Raises a
    ``jwt.PyJWTError`` subclass on any failure (bad signature, expired, wrong
    issuer/audience, missing claim, unknown ``kid``); returns the decoded claims on
    success. Replay defence (``jti`` one-time use) is enforced by the caller's
    seen-``jti`` store, not here — this function has no memory across calls.
    """
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    signing_key = _select_jwk(jwks, kid)
    public_key = jwt.PyJWK.from_dict(signing_key).key
    return jwt.decode(
        token,
        public_key,
        algorithms=list(_ASSERTION_ALGS),
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
    )


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
