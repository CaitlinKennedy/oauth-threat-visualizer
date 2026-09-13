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

Phase 6 adds **real DPoP** (RFC 9449): a proof-of-possession EC keypair (ES256),
the JWK SHA-256 thumbprint (RFC 7638) that binds a token via ``cnf.jkt``, and
genuine DPoP proof JWTs (``htm``/``htu``/``iat``/``jti``) signed by that key and
verified by the resource server. These are real signatures over real keys, so a
stolen token dies at the resource server because the attacker cannot produce a
proof from a key whose thumbprint matches the token's ``cnf.jkt`` — the maths,
not a script, says so.
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
# DPoP proofs are signed with an EC key over P-256 (RFC 9449 recommends an
# asymmetric alg the RS accepts; ES256 is the interoperable default).
_DPOP_ALG = "ES256"

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


# --- DPoP: sender-constrained tokens (RFC 9449) ----------------------------


def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """The RFC 7638 JWK SHA-256 thumbprint, base64url without padding.

    The thumbprint is computed over the JSON of the key's *required* members in
    lexicographic order, with no whitespace — so it is a stable, canonical
    fingerprint of the public key. This is exactly the value an access token
    carries in ``cnf.jkt`` to bind itself to a client key (RFC 9449 §6).
    """
    kty = jwk.get("kty")
    if kty == "EC":
        canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise ValueError(f"unsupported JWK kty {kty!r} for thumbprint")
    data = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("ascii")
    return _b64url(hashlib.sha256(data).digest())


@dataclass
class DpopKey:
    """A client proof-of-possession keypair for DPoP (RFC 9449), ES256/P-256.

    The private half never leaves the client; the public half is embedded in each
    proof (the ``jwk`` header) and its thumbprint is what the token is bound to.
    Possessing a DPoP-bound token is therefore worthless without this private key —
    which is precisely why a stolen token fails at the resource server.
    """

    _private_pem: bytes

    @classmethod
    def generate(cls) -> "DpopKey":
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cls(_private_pem=pem)

    def _private_key_obj(self):
        return serialization.load_pem_private_key(self._private_pem, password=None)

    def public_jwk(self) -> Dict[str, Any]:
        """The public key as a minimal EC JWK (``kty``/``crv``/``x``/``y``)."""
        jwk = json.loads(
            jwt.algorithms.ECAlgorithm.to_jwk(self._private_key_obj().public_key())
        )
        return {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}

    def thumbprint(self) -> str:
        """This key's RFC 7638 thumbprint — the value bound into ``cnf.jkt``."""
        return jwk_thumbprint(self.public_jwk())


def create_dpop_proof(
    key: DpopKey,
    *,
    htm: str,
    htu: str,
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    """Create a real DPoP proof JWT for one HTTP request (RFC 9449 §4.2).

    The proof is signed with ``key`` and carries the HTTP method (``htm``), the
    target URI (``htu``), an issued-at (``iat``) and a unique id (``jti``); its
    header declares ``typ=dpop+jwt`` and embeds the public ``jwk``. The resource
    server recomputes the thumbprint of that embedded key and requires it to equal
    the token's ``cnf.jkt``.
    """
    now = iat if iat is not None else int(time.time())
    claims = {
        "jti": jti or uuid.uuid4().hex,
        "htm": htm,
        "htu": htu,
        "iat": now,
    }
    return jwt.encode(
        claims,
        key._private_pem,
        algorithm=_DPOP_ALG,
        headers={"typ": "dpop+jwt", "jwk": key.public_jwk()},
    )


def verify_dpop_proof(proof: str, *, htm: str, htu: str) -> Dict[str, Any]:
    """Verify a DPoP proof's signature and ``htm``/``htu`` (RFC 9449 §4.3).

    Uses the proof's own embedded ``jwk`` to check the signature (the key claims
    itself; the binding to the token is enforced separately, by comparing the
    returned ``jkt`` to the token's ``cnf.jkt``). Requires the ``dpop+jwt`` type,
    the four registered proof claims, and an exact method/URI match. Raises a
    ``jwt.PyJWTError`` subclass on any failure; returns
    ``{"jkt": <thumbprint>, "claims": {...}, "jwk": {...}}`` on success.
    """
    header = jwt.get_unverified_header(proof)
    typ = str(header.get("typ") or "").strip().lower()
    if typ != "dpop+jwt":
        raise jwt.InvalidTokenError(
            f"unexpected DPoP proof typ {header.get('typ')!r}; expected dpop+jwt"
        )
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or not jwk:
        raise jwt.InvalidTokenError("DPoP proof header is missing an embedded jwk")
    public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(
        proof,
        public_key,
        algorithms=[_DPOP_ALG],
        options={"require": ["htm", "htu", "iat", "jti"]},
    )
    if claims.get("htm") != htm:
        raise jwt.InvalidTokenError(
            f"DPoP htm mismatch: proof {claims.get('htm')!r} != request {htm!r}"
        )
    if claims.get("htu") != htu:
        raise jwt.InvalidTokenError(
            f"DPoP htu mismatch: proof {claims.get('htu')!r} != request {htu!r}"
        )
    return {"jkt": jwk_thumbprint(jwk), "claims": claims, "jwk": jwk}
